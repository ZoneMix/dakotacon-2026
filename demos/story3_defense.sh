#!/bin/bash
set -euo pipefail

# Story 3: Runner Exploit — Defense Demo
# Shows how ExternalId on cross-account roles stops the runner chain,
# scoped runner config, and re-attempting the full chain after fixes.

source "$(dirname "$0")/demo_runner.sh"

TF_DIR="<YOUR_PATH>"

set_prompt "secops $"

banner "Story 3 Defense: Blocking the Runner Chain"

# ── Fix 1: Show the runner config ──
banner "Fix 1: Scope the GitLab Runner"

narrate "Runner config controls which jobs it executes."
narrate "BEFORE: accepts ANY project, ANY branch."
narrate "AFTER: only tagged jobs from protected branches."

type_cmd "cat /etc/gitlab-runner/config.toml"

echo '[[runners]]'
echo '  name = "production-deployer"'
echo '  url = "https://gitlab.example.com/"'
echo '  token = "REDACTED"'
echo '  executor = "docker"'
echo '  # Security: only tagged, protected branch jobs'
success '  limit = 1'
success '  [runners.custom_build_dir]'
success '    enabled = false'
success '  [runners.docker]'
success '    privileged = false'
success '    allowed_images = ["registry.example.com/deploy:*"]'
success '    volumes = ["/cache"]'
echo '  # Runner tags restrict which pipelines use this'
success '  tag_list = "production-deploy"'

hr
narrate "Key changes:"
echo "  - privileged: false -- no Docker socket"
echo "  - allowed_images -- only approved images"
echo "  - tag_list -- only 'production-deploy' jobs"
echo "  - limit: 1 -- single concurrent job"
echo "  - custom_build_dir: false -- no path traversal"

# ── Fix 2: ExternalId on trust policies ──
banner "Fix 2: ExternalId on Trust Policies"

narrate "Every cross-account role now requires ExternalId."
narrate "Here's the fixed trust policy..."

type_cmd "aws iam get-role --role-name fixed-dev-role ..."

echo "{"
echo "  \"Version\": \"2012-10-17\","
echo "  \"Statement\": [{"
echo "    \"Effect\": \"Allow\","
echo "    \"Principal\": {"
success "      \"AWS\": \".../role/gitlab-runner-role\""
echo "    },"
echo "    \"Action\": \"sts:AssumeRole\","
success "    \"Condition\": {"
success "      \"StringEquals\": {"
success "        \"sts:ExternalId\": \"demo-unique-secret\""
success "      }"
success "    }"
echo "  }]"
echo "}"

hr
narrate "Two changes from the broken version:"
echo "  1. Principal: specific role ARN, not :root"
echo "     Only runner-role can assume"
echo "  2. ExternalId: shared secret required"
echo "     Attacker doesn't know the secret"

# ── Fix 3: Attempt the chain with fixes ──
banner "Fix 3: Re-attempt the Attack Chain"

narrate "Let's try the 4-hop chain with the fixes..."

if is_live; then
    FIXED_ROLE=$(terraform -chdir="${TF_DIR}" output -raw target_dev_fixed_role_arn 2>/dev/null || echo "")

    if [[ -z "${FIXED_ROLE}" ]]; then
        alert "Cannot get fixed role ARN from terraform"
        info "Showing expected behavior:"
        echo ""
        echo "  Without ExternalId: AccessDenied"
        echo "  With ExternalId:    Success (ReadOnlyAccess)"
        exit 0
    fi

    # ── Attempt 1: WITHOUT ExternalId ──
    step 1 "Attacker tries WITHOUT ExternalId"

    type_cmd "aws sts assume-role --role-arn ${FIXED_ROLE} ..."

    NO_EXTID=$(aws sts assume-role \
        --role-arn "${FIXED_ROLE}" \
        --role-session-name "attacker-no-extid" \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || true)

    if echo "${NO_EXTID}" | grep -q "AccessDenied"; then
        echo "  An error occurred (AccessDenied)"
        echo "  Not authorized: sts:AssumeRole"
        echo ""
        success "BLOCKED at hop 1 -- ExternalId required"
        alert "Chain dead. Cannot reach hop 2, 3, or 4."
    else
        echo "  Result: ${NO_EXTID}"
    fi

    narrate "Can't get past the FIRST hop."
    narrate "The entire 4-hop chain collapses at step 1."

    # ── Attempt 2: WITH ExternalId (authorized caller) ──
    step 2 "Legitimate pipeline with ExternalId"

    type_cmd "aws sts assume-role ... --external-id demo-unique-secret-2026"

    WITH_EXTID=$(aws sts assume-role \
        --role-arn "${FIXED_ROLE}" \
        --role-session-name "legit-with-extid" \
        --external-id "demo-unique-secret-2026" \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || true)

    if echo "${WITH_EXTID}" | grep -q "AccessDenied"; then
        alert "Denied even with ExternalId -- check trust policy"
    else
        echo "${WITH_EXTID}" | python3 -c "
import json,sys
d=json.load(sys.stdin)
arn=d['AssumedRoleUser']['Arn']
print(f'  Assumed: {arn}')
" 2>/dev/null || echo "${WITH_EXTID}"
        echo ""
        success "Legitimate caller: access granted"
        success "But with ReadOnly, not AdministratorAccess"
    fi

else
    # ── Sim mode ──

    step 1 "Attacker tries WITHOUT ExternalId"

    show_cmd "aws sts assume-role --role-arn .../fixed-dev-role ..." "$(cat <<'SIMOUT'
  An error occurred (AccessDenied)
  Not authorized: sts:AssumeRole on resource:
  arn:aws:iam::222222222222:role/fixed-dev-role
SIMOUT
)"

    success "BLOCKED at hop 1 -- ExternalId required"
    alert "Chain dead. Cannot reach hop 2, 3, or 4."

    narrate "Can't get past the FIRST hop."
    narrate "The entire 4-hop chain collapses at step 1."

    step 2 "Remaining hops: all dead"

    show_cmd "aws sts assume-role --role-arn .../fixed-staging-role ..." "$(cat <<'SIMOUT'
  An error occurred (AccessDenied)
  Not authorized: sts:AssumeRole
  (no valid credentials -- previous hop failed)
SIMOUT
)"

    alert "Hop 2: DEAD -- no credentials from hop 1"
    alert "Hop 3: DEAD"
    alert "Hop 4: DEAD"

    step 3 "Legitimate pipeline with ExternalId"

    show_cmd "aws sts assume-role ... --external-id demo-unique-secret-2026" "$(cat <<'SIMOUT'
  Assumed: ...assumed-role/fixed-dev-role/legit-with-extid
  AccessKeyId:    ASIAXXXXXXXXXXXXXXXX
  Expiration:     2026-03-22T17:00:00Z
  SecretAccessKey: [REDACTED]
  SessionToken:    [REDACTED]
SIMOUT
)"

    success "Legitimate caller: access granted"
    success "But with ReadOnly, not AdministratorAccess"
fi

# ── Summary ──
banner "Three Settings That Stop the Chain"

echo "  1. ExternalId on the trust policy"
echo "     Attacker doesn't know the shared secret"
echo "     Even stolen creds can't assume without it"
echo "     Result: AccessDenied at hop 1"
echo ""
echo "  2. Scoped principal (specific role, not :root)"
echo "     Only the intended caller can assume"
echo "     Confused deputy attack blocked"
echo "     Result: wrong role -> AccessDenied"
echo ""
echo "  3. Least-privilege attached policy"
echo "     ReadOnlyAccess not AdministratorAccess"
echo "     Even if breached, blast radius contained"
echo "     Result: can read but not modify/delete"
echo ""
echo "  Bonus: Runner config scoping"
echo "     privileged: false, allowed_images, tag_list"
echo "     Limits what the runner can execute"

echo ""
hr
success "Three settings. Zero new services. Zero cost."
success "The 4-hop chain becomes a 0-hop dead end."
hr
info "Before: attacker -> runner -> dev -> staging -> PROD"
info "After:  attacker -> AccessDenied. Full stop."
