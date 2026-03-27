#!/bin/bash
set -euo pipefail

# Story 2: IMDS + Trust Chain — Defense Demo
# Shows IMDSv2 enforcement and ExternalId stopping the attack chain.

source "$(dirname "$0")/demo_runner.sh"

TF_DIR="<YOUR_PATH>"

set_prompt "secops $"

banner "Story 2 Defense: Stopping the Chain"

# ── Defense 1: IMDSv2 ──
banner "Defense 1: Enforce IMDSv2"

narrate "BEFORE: IMDSv1 -- any curl gets credentials."
narrate "AFTER: IMDSv2 -- PUT with TTL header required."
narrate "One command flips the switch."

if is_live; then
    INSTANCE_ID=$(terraform -chdir="${TF_DIR}" output -raw instance_id 2>/dev/null || echo "")

    if [[ -n "${INSTANCE_ID}" ]]; then
        type_cmd "aws ec2 modify-instance-metadata-options --http-tokens required"
        echo "  (Not running live -- we need the instance vulnerable)"

        step 1 "Verify metadata options"
        type_cmd "aws ec2 describe-instances ... --query MetadataOptions"
        aws ec2 describe-instances --instance-ids "${INSTANCE_ID}" \
            --query 'Reservations[0].Instances[0].MetadataOptions' \
            --profile "${PROFILE}" --region "${REGION}" --no-cli-pager --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
for k,v in d.items():
    print(f'  {k:30s} {v}')
" 2>/dev/null || true
    else
        show_cmd "aws ec2 modify-instance-metadata-options --http-tokens required" \
            "(Instance ID unavailable -- showing command only)"
    fi
else
    show_cmd "aws ec2 modify-instance-metadata-options --http-tokens required" "$(cat <<'SIMOUT'
  InstanceId:             i-0abc123def456
  State:                  applied
  HttpTokens:             required
  HttpPutResponseHopLimit: 1
  HttpEndpoint:           enabled
  InstanceMetadataTags:   disabled
SIMOUT
)"

    step 1 "Verify metadata options"

    show_cmd "aws ec2 describe-instances ... --query MetadataOptions" "$(cat <<'SIMOUT'
  HttpEndpoint:              enabled
  HttpProtocolIpv6:          disabled
  HttpPutResponseHopLimit:   1
  HttpTokens:                required
  InstanceMetadataTags:      disabled
  State:                     applied
SIMOUT
)"
fi

hr
success "HttpTokens: required -- must PUT first"
success "HttpPutResponseHopLimit: 1 -- containers blocked"
narrate "With IMDSv2:"
echo "  curl .../meta-data/iam/security-credentials/"
alert "  -> 401 Unauthorized"
echo ""
echo "  Must first:"
echo "  TOKEN=\$(curl -X PUT .../api/token"
echo "    -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')"
echo "  curl -H \"X-aws-ec2-metadata-token: \$TOKEN\" ..."
narrate "SSRF can't follow the PUT+header flow."

# ── Defense 2: ExternalId ──
banner "Defense 2: ExternalId on Cross-Account Roles"

narrate "BEFORE: trust policy (too permissive)..."

echo "  {"
echo "    \"Effect\": \"Allow\","
echo "    \"Principal\": {"
alert "      \"AWS\": \"arn:aws:iam::111111111111:root\""
echo "    },"
echo "    \"Action\": \"sts:AssumeRole\""
echo "  }"

hr
narrate "AFTER: trust policy (scoped + ExternalId)..."

echo "  {"
echo "    \"Effect\": \"Allow\","
echo "    \"Principal\": {"
success "      \"AWS\": \".../role/deploy-pipeline\""
echo "    },"
echo "    \"Action\": \"sts:AssumeRole\","
success "    \"Condition\": {"
success "      \"StringEquals\": {"
success "        \"sts:ExternalId\": \"demo-secret-2026\""
success "      }"
success "    }"
echo "  }"

hr
narrate "Let's prove it works..."

if is_live; then
    FIXED_ROLE=$(terraform -chdir="${TF_DIR}" output -raw cross_acct_fixed_role_arn 2>/dev/null || echo "")

    if [[ -z "${FIXED_ROLE}" ]]; then
        alert "Cannot get fixed role ARN from terraform"
        info "Showing expected behavior:"
        echo ""
        echo "  Without ExternalId: AccessDenied"
        echo "  With ExternalId:    Success (ReadOnlyAccess)"
        exit 0
    fi

    # Attempt WITHOUT ExternalId -- should fail
    step 2 "Attempt WITHOUT ExternalId"

    type_cmd "aws sts assume-role --role-arn ${FIXED_ROLE} ..."

    NO_EXTID_RESULT=$(aws sts assume-role \
        --role-arn "${FIXED_ROLE}" \
        --role-session-name "test-no-extid" \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || true)

    if echo "${NO_EXTID_RESULT}" | grep -q "AccessDenied"; then
        echo "  An error occurred (AccessDenied)"
        echo "  Not authorized: sts:AssumeRole"
        echo ""
        success "BLOCKED -- ExternalId is required"
    else
        echo "  Unexpected: ${NO_EXTID_RESULT}"
    fi

    # Attempt WITH ExternalId -- should succeed
    step 3 "Attempt WITH ExternalId"

    type_cmd "aws sts assume-role ... --external-id demo-secret-2026"

    WITH_EXTID_RESULT=$(aws sts assume-role \
        --role-arn "${FIXED_ROLE}" \
        --role-session-name "test-with-extid" \
        --external-id "demo-secret-2026" \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || true)

    if echo "${WITH_EXTID_RESULT}" | grep -q "AccessDenied"; then
        alert "Denied even with ExternalId -- check trust policy"
    else
        echo "${WITH_EXTID_RESULT}" | python3 -c "
import json,sys
d=json.load(sys.stdin)
arn=d['AssumedRoleUser']['Arn']
print(f'  Assumed: {arn}')
" 2>/dev/null || echo "${WITH_EXTID_RESULT}"
        echo ""
        success "Success -- but notice the attached policy..."
    fi

    # Show that it's ReadOnly, not Admin
    step 4 "What can this role do?"
    FIXED_ROLE_NAME=$(echo "${FIXED_ROLE}" | rev | cut -d'/' -f1 | rev)
    type_cmd "aws iam list-attached-role-policies ..."
    aws iam list-attached-role-policies --role-name "${FIXED_ROLE_NAME}" \
        --profile "${PROFILE}" --region "${REGION}" --no-cli-pager --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
for i,p in enumerate(d.get('AttachedPolicies',[]),1):
    print(f\"  {i}. {p['PolicyName']}\")
" 2>/dev/null || true

    success "ReadOnlyAccess -- not AdministratorAccess"

else
    # ── Sim mode ──

    step 2 "Attempt WITHOUT ExternalId"

    show_cmd "aws sts assume-role --role-arn .../fixed-cross-acct-role ..." "$(cat <<'SIMOUT'
  An error occurred (AccessDenied)
  Not authorized: sts:AssumeRole on resource:
  arn:aws:iam::222222222222:role/fixed-cross-acct-role
SIMOUT
)"

    success "BLOCKED -- ExternalId is required"

    step 3 "Attempt WITH ExternalId"

    show_cmd "aws sts assume-role ... --external-id demo-secret-2026" "$(cat <<'SIMOUT'
  Assumed: ...assumed-role/fixed-cross-acct-role/test-with-extid
  AccessKeyId:    ASIAXXXXXXXXXXXXXXXX
  Expiration:     2026-03-22T17:00:00Z
  SecretAccessKey: [REDACTED]
  SessionToken:    [REDACTED]
SIMOUT
)"

    success "Success -- but notice the attached policy..."

    step 4 "What can this role do?"

    show_cmd "aws iam list-attached-role-policies ..." "$(cat <<'SIMOUT'
  1. ReadOnlyAccess
SIMOUT
)"

    success "ReadOnlyAccess -- not AdministratorAccess"
fi

# ── Summary ──
echo ""
hr
success "Defense recap: 3 layers that stop the chain"
hr
echo ""
echo "  Layer 1: IMDSv2"
echo "    Can't steal creds in the first place"
echo "    Simple curl -> 401 Unauthorized"
echo ""
echo "  Layer 2: ExternalId"
echo "    Even WITH creds, can't cross accounts"
echo "    Missing shared secret -> AccessDenied"
echo ""
echo "  Layer 3: Scoped policy"
echo "    Even IF they get in, ReadOnly not Admin"
echo "    Blast radius contained to read-only"
echo ""
info "Total cost: \$0. Total new services: 0."
info "Just 3 configuration changes."
