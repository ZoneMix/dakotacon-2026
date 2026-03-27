#!/bin/bash
set -euo pipefail

# DakotaCon Pre-Talk Preflight Validation
# Run before the presentation to verify all demo infrastructure,
# warm caches, configure CLI profiles, and set demo mode.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEMO_MODE_FILE="${SCRIPT_DIR}/.demo_mode"
CACHE_DIR="${SCRIPT_DIR}/.cache"
PROFILE="default"
REGION="us-east-2"
ACCOUNT_ID="111111111111"

TF_BASE="<YOUR_PATH>"
TF_SHARED="${TF_BASE}/shared/terraform"
TF_S1="${TF_BASE}/story1-broken-policy/terraform"
TF_S2="${TF_BASE}/story2-imds-trust-chain/terraform"
TF_S3="${TF_BASE}/story3-runner-exploit/terraform"
TF_S4="${TF_BASE}/story4-guardduty-chain/terraform"

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

print_header() {
    echo ""
    echo -e "${BOLD}${CYAN}$1${RESET}"
    echo -e "${CYAN}$(printf '%.0s─' $(seq 1 ${#1}))${RESET}"
}

check_pass() {
    echo -e "  ${GREEN}[PASS]${RESET} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

check_fail() {
    echo -e "  ${RED}[FAIL]${RESET} $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

check_warn() {
    echo -e "  ${YELLOW}[WARN]${RESET} $1"
    WARN_COUNT=$((WARN_COUNT + 1))
}

echo -e "${BOLD}${CYAN}DakotaCon 2026 — Demo Preflight Check${RESET}"
echo -e "${CYAN}$(printf '%.0s═' $(seq 1 38))${RESET}"
echo ""
echo "  Profile:  ${PROFILE}"
echo "  Region:   ${REGION}"
echo "  Account:  ${ACCOUNT_ID}"
echo "  Time:     $(date)"

# ─────────────────────────────────────────
# Step 1: AWS Authentication
# ─────────────────────────────────────────
print_header "Step 1: AWS Authentication"

CALLER=$(aws sts get-caller-identity \
    --profile "${PROFILE}" \
    --region "${REGION}" \
    --no-cli-pager \
    --output json 2>&1 || echo "FAILED")

if echo "${CALLER}" | python3 -c "import json,sys; json.load(sys.stdin)['Account']" &>/dev/null; then
    CALLER_ACCOUNT=$(echo "${CALLER}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Account'])")
    CALLER_ARN=$(echo "${CALLER}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Arn'])")
    if [[ "${CALLER_ACCOUNT}" == "${ACCOUNT_ID}" ]]; then
        check_pass "AWS auth OK — ${CALLER_ARN}"
    else
        check_fail "Wrong account: ${CALLER_ACCOUNT} (expected ${ACCOUNT_ID})"
    fi
else
    check_fail "AWS auth failed — check 'demo' profile"
    echo ""
    echo -e "${RED}Cannot continue without AWS auth. Fix and re-run.${RESET}"
    echo "sim" > "${DEMO_MODE_FILE}"
    exit 1
fi

# ─────────────────────────────────────────
# Step 2: Terraform Outputs — Story 1
# ─────────────────────────────────────────
print_header "Step 2: Story 1 — Broken Policy Resources"

S1_BUCKET=$(terraform -chdir="${TF_S1}" output -raw demo_bucket_name 2>/dev/null || echo "")
S1_ACCESS_KEY=$(terraform -chdir="${TF_S1}" output -raw restricted_admin_access_key_id 2>/dev/null || echo "")
S1_SECRET_KEY=$(terraform -chdir="${TF_S1}" output -raw restricted_admin_secret_key 2>/dev/null || echo "")

if [[ -n "${S1_BUCKET}" ]]; then
    check_pass "S3 bucket: ${S1_BUCKET}"
else
    check_fail "S3 bucket not found — run: terraform -chdir=${TF_S1} apply"
fi

if [[ -n "${S1_ACCESS_KEY}" && -n "${S1_SECRET_KEY}" ]]; then
    check_pass "Restricted admin credentials available"

    # Configure the demo-story1 CLI profile
    aws configure set aws_access_key_id "${S1_ACCESS_KEY}" --profile demo-story1
    aws configure set aws_secret_access_key "${S1_SECRET_KEY}" --profile demo-story1
    aws configure set region "${REGION}" --profile demo-story1
    check_pass "Configured CLI profile: demo-story1"

    # Verify the profile works
    S1_IDENTITY=$(aws sts get-caller-identity \
        --profile demo-story1 \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || echo "FAILED")

    if echo "${S1_IDENTITY}" | python3 -c "import json,sys; json.load(sys.stdin)['Arn']" &>/dev/null; then
        S1_ARN=$(echo "${S1_IDENTITY}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Arn'])")
        check_pass "Profile verified: ${S1_ARN}"
    else
        check_fail "Profile demo-story1 auth failed"
    fi
else
    check_fail "Restricted admin credentials not available"
fi

BROKEN_POLICY="${TF_BASE}/broken_policy.json"
if [[ -f "${BROKEN_POLICY}" ]]; then
    check_pass "broken_policy.json exists"
else
    check_warn "broken_policy.json not found (created by terraform apply)"
fi

# ─────────────────────────────────────────
# Step 3: Terraform Outputs — Story 2
# ─────────────────────────────────────────
print_header "Step 3: Story 2 — IMDS & Trust Chain Resources"

S2_INSTANCE=$(terraform -chdir="${TF_S2}" output -raw instance_id 2>/dev/null || echo "")
S2_DEV_ROLE=$(terraform -chdir="${TF_S2}" output -raw cross_acct_dev_role_arn 2>/dev/null || echo "")
S2_PROD_ROLE=$(terraform -chdir="${TF_S2}" output -raw cross_acct_prod_role_arn 2>/dev/null || echo "")
S2_FIXED_ROLE=$(terraform -chdir="${TF_S2}" output -raw cross_acct_fixed_role_arn 2>/dev/null || echo "")

if [[ -n "${S2_INSTANCE}" ]]; then
    check_pass "EC2 instance: ${S2_INSTANCE}"

    # Check if instance is running
    INSTANCE_STATE=$(aws ec2 describe-instance-status \
        --instance-ids "${S2_INSTANCE}" \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || echo '{"InstanceStatuses":[]}')

    STATE=$(echo "${INSTANCE_STATE}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
statuses = data.get('InstanceStatuses', [])
if statuses:
    print(statuses[0].get('InstanceState', {}).get('Name', 'unknown'))
else:
    print('stopped-or-pending')
" 2>/dev/null || echo "unknown")

    if [[ "${STATE}" == "running" ]]; then
        check_pass "Instance state: running"
    else
        check_warn "Instance state: ${STATE} (may need to start)"
    fi

    # Check SSM connectivity
    SSM_STATUS=$(aws ssm describe-instance-information \
        --filters "Key=InstanceIds,Values=${S2_INSTANCE}" \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || echo '{"InstanceInformationList":[]}')

    SSM_ONLINE=$(echo "${SSM_STATUS}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
instances = data.get('InstanceInformationList', [])
if instances and instances[0].get('PingStatus') == 'Online':
    print('online')
else:
    print('offline')
" 2>/dev/null || echo "offline")

    if [[ "${SSM_ONLINE}" == "online" ]]; then
        check_pass "SSM agent: online"
    else
        check_warn "SSM agent: offline (IMDS demo will use cache or simulation)"
    fi
else
    check_fail "EC2 instance not found — run: terraform -chdir=${TF_S2} apply"
fi

if [[ -n "${S2_DEV_ROLE}" ]]; then
    check_pass "Dev role: ${S2_DEV_ROLE}"
else
    check_fail "Dev role not found"
fi

if [[ -n "${S2_PROD_ROLE}" ]]; then
    check_pass "Prod role: ${S2_PROD_ROLE}"
else
    check_fail "Prod role not found"
fi

if [[ -n "${S2_FIXED_ROLE}" ]]; then
    check_pass "Fixed role: ${S2_FIXED_ROLE}"
else
    check_fail "Fixed role not found"
fi

# ─────────────────────────────────────────
# Step 4: Terraform Outputs — Story 3
# ─────────────────────────────────────────
print_header "Step 4: Story 3 — Runner Exploit Resources"

S3_RUNNER_ROLE=$(terraform -chdir="${TF_S3}" output -raw gitlab_runner_role_arn 2>/dev/null || echo "")
S3_DEV_ROLE=$(terraform -chdir="${TF_S3}" output -raw target_dev_role_arn 2>/dev/null || echo "")
S3_PROD_ROLE=$(terraform -chdir="${TF_S3}" output -raw target_prod_role_arn 2>/dev/null || echo "")
S3_FIXED_ROLE=$(terraform -chdir="${TF_S3}" output -raw target_dev_fixed_role_arn 2>/dev/null || echo "")
S3_ACCESS_KEY=$(terraform -chdir="${TF_S3}" output -raw attacker_access_key_id 2>/dev/null || echo "")
S3_SECRET_KEY=$(terraform -chdir="${TF_S3}" output -raw attacker_secret_key 2>/dev/null || echo "")

if [[ -n "${S3_RUNNER_ROLE}" ]]; then
    check_pass "Runner role: ${S3_RUNNER_ROLE}"
else
    check_fail "Runner role not found — run: terraform -chdir=${TF_S3} apply"
fi

if [[ -n "${S3_DEV_ROLE}" && -n "${S3_PROD_ROLE}" ]]; then
    check_pass "Target roles: dev, staging, prod"
else
    check_fail "Target roles missing"
fi

if [[ -n "${S3_FIXED_ROLE}" ]]; then
    check_pass "Fixed role: ${S3_FIXED_ROLE}"
else
    check_fail "Fixed role not found"
fi

if [[ -n "${S3_ACCESS_KEY}" && -n "${S3_SECRET_KEY}" ]]; then
    # Configure the demo-story3 CLI profile
    aws configure set aws_access_key_id "${S3_ACCESS_KEY}" --profile demo-story3
    aws configure set aws_secret_access_key "${S3_SECRET_KEY}" --profile demo-story3
    aws configure set region "${REGION}" --profile demo-story3
    check_pass "Configured CLI profile: demo-story3"

    # Verify
    S3_IDENTITY=$(aws sts get-caller-identity \
        --profile demo-story3 \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || echo "FAILED")

    if echo "${S3_IDENTITY}" | python3 -c "import json,sys; json.load(sys.stdin)['Arn']" &>/dev/null; then
        S3_ARN=$(echo "${S3_IDENTITY}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Arn'])")
        check_pass "Profile verified: ${S3_ARN}"
    else
        check_fail "Profile demo-story3 auth failed"
    fi
else
    check_fail "Runner attacker credentials not available"
fi

# ─────────────────────────────────────────
# Step 5: Terraform Outputs — Story 4
# ─────────────────────────────────────────
print_header "Step 5: Story 4 — GuardDuty & Detection Resources"

S4_DETECTOR=$(terraform -chdir="${TF_S4}" output -raw detector_id 2>/dev/null || echo "")
if [[ -z "${S4_DETECTOR}" ]]; then
    S4_DETECTOR=$(terraform -chdir="${TF_SHARED}" output -raw guardduty_detector_id 2>/dev/null || echo "")
fi

if [[ -n "${S4_DETECTOR}" ]]; then
    check_pass "GuardDuty detector: ${S4_DETECTOR}"

    # Check for findings
    FINDING_COUNT=$(aws guardduty list-findings \
        --detector-id "${S4_DETECTOR}" \
        --max-results 1 \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('FindingIds',[])))" 2>/dev/null || echo "0")

    if [[ "${FINDING_COUNT}" -gt 0 ]]; then
        check_pass "GuardDuty has findings"
    else
        check_warn "No GuardDuty findings — run story4_stratus_preflight.sh"
    fi
else
    check_fail "GuardDuty detector not found"
fi

EB_RULE=$(terraform -chdir="${TF_SHARED}" output -raw eventbridge_rule_name 2>/dev/null || echo "")
if [[ -n "${EB_RULE}" ]]; then
    check_pass "EventBridge rule: ${EB_RULE}"
else
    check_warn "EventBridge rule not found"
fi

SNS_TOPIC=$(terraform -chdir="${TF_SHARED}" output -raw sns_topic_arn 2>/dev/null || echo "")
if [[ -n "${SNS_TOPIC}" ]]; then
    check_pass "SNS topic: $(echo "${SNS_TOPIC}" | sed 's/.*://')"
else
    check_warn "SNS topic not found"
fi

# ─────────────────────────────────────────
# Step 6: Pre-warm AWS CLI Token Cache
# ─────────────────────────────────────────
print_header "Step 6: Pre-warming AWS CLI Cache"

# Run a few fast commands to warm the STS token cache
aws sts get-caller-identity --profile "${PROFILE}" --region "${REGION}" --no-cli-pager &>/dev/null && \
    check_pass "Token cache warmed: ${PROFILE}" || \
    check_warn "Token cache warm failed: ${PROFILE}"

if aws sts get-caller-identity --profile demo-story1 --region "${REGION}" --no-cli-pager &>/dev/null; then
    check_pass "Token cache warmed: demo-story1"
else
    check_warn "Token cache warm failed: demo-story1"
fi

if aws sts get-caller-identity --profile demo-story3 --region "${REGION}" --no-cli-pager &>/dev/null; then
    check_pass "Token cache warmed: demo-story3"
else
    check_warn "Token cache warm failed: demo-story3"
fi

# ─────────────────────────────────────────
# Step 7: Pre-cache SSM Output for Story 2
# ─────────────────────────────────────────
print_header "Step 7: Pre-caching IMDS Output (Story 2)"

if [[ -n "${S2_INSTANCE}" ]] && [[ "${SSM_ONLINE:-offline}" == "online" ]]; then
    mkdir -p "${CACHE_DIR}"

    # Get role name
    ROLE_CMD="curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    CMD_OUTPUT=$(aws ssm send-command \
        --instance-ids "${S2_INSTANCE}" \
        --document-name "AWS-RunShellScript" \
        --parameters "commands=[\"${ROLE_CMD}\"]" \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || echo "")

    CMD_ID=$(echo "${CMD_OUTPUT}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Command']['CommandId'])" 2>/dev/null || echo "")

    if [[ -n "${CMD_ID}" ]]; then
        ROLE_NAME=""
        for i in $(seq 1 20); do
            RESULT=$(aws ssm get-command-invocation \
                --command-id "${CMD_ID}" \
                --instance-id "${S2_INSTANCE}" \
                --profile "${PROFILE}" \
                --region "${REGION}" \
                --no-cli-pager \
                --output json 2>&1 || echo '{"Status":"Pending"}')

            STATUS=$(echo "${RESULT}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('Status','Pending'))" 2>/dev/null || echo "Pending")

            if [[ "${STATUS}" == "Success" ]]; then
                ROLE_NAME=$(echo "${RESULT}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('StandardOutputContent','').strip())" 2>/dev/null || echo "")
                break
            elif [[ "${STATUS}" == "Failed" || "${STATUS}" == "TimedOut" ]]; then
                break
            fi
            sleep 1
        done

        if [[ -n "${ROLE_NAME}" ]]; then
            # Now get full creds
            CREDS_CMD="curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE_NAME}"
            CREDS_OUTPUT=$(aws ssm send-command \
                --instance-ids "${S2_INSTANCE}" \
                --document-name "AWS-RunShellScript" \
                --parameters "commands=[\"${CREDS_CMD}\"]" \
                --profile "${PROFILE}" \
                --region "${REGION}" \
                --no-cli-pager \
                --output json 2>&1 || echo "")

            CREDS_CMD_ID=$(echo "${CREDS_OUTPUT}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Command']['CommandId'])" 2>/dev/null || echo "")

            if [[ -n "${CREDS_CMD_ID}" ]]; then
                for i in $(seq 1 20); do
                    CREDS_RESULT=$(aws ssm get-command-invocation \
                        --command-id "${CREDS_CMD_ID}" \
                        --instance-id "${S2_INSTANCE}" \
                        --profile "${PROFILE}" \
                        --region "${REGION}" \
                        --no-cli-pager \
                        --output json 2>&1 || echo '{"Status":"Pending"}')

                    CREDS_STATUS=$(echo "${CREDS_RESULT}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('Status','Pending'))" 2>/dev/null || echo "Pending")

                    if [[ "${CREDS_STATUS}" == "Success" ]]; then
                        CREDS_JSON=$(echo "${CREDS_RESULT}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('StandardOutputContent','').strip())" 2>/dev/null || echo "")
                        break
                    elif [[ "${CREDS_STATUS}" == "Failed" || "${CREDS_STATUS}" == "TimedOut" ]]; then
                        break
                    fi
                    sleep 1
                done

                if [[ -n "${CREDS_JSON}" ]]; then
                    {
                        echo -e "\033[0;31m${ROLE_NAME}\033[0m"
                        echo ""
                        echo -e "\033[0;31m[!] Got role name without any authentication\033[0m"
                        echo ""
                        echo "${CREDS_JSON}" | python3 -m json.tool 2>/dev/null || echo "${CREDS_JSON}"
                    } > "${CACHE_DIR}/imds_output.txt"
                    check_pass "IMDS output cached: ${CACHE_DIR}/imds_output.txt"
                else
                    check_warn "Could not cache IMDS creds output"
                fi
            fi
        else
            check_warn "Could not get role name via SSM"
        fi
    else
        check_warn "SSM send-command failed"
    fi
else
    check_warn "Skipping IMDS cache (instance offline or unavailable)"
fi

# ─────────────────────────────────────────
# Step 8: Set Demo Mode
# ─────────────────────────────────────────
print_header "Step 8: Setting Demo Mode"

if [[ "${FAIL_COUNT}" -eq 0 ]]; then
    echo "live" > "${DEMO_MODE_FILE}"
    check_pass "Demo mode: LIVE"
else
    echo "sim" > "${DEMO_MODE_FILE}"
    check_warn "Demo mode: SIM (${FAIL_COUNT} checks failed)"
fi

# ─────────────────────────────────────────
# Summary
# ─────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}═══════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}  Preflight Summary${RESET}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════${RESET}"
echo ""
echo -e "  ${GREEN}PASS:${RESET} ${PASS_COUNT}"
echo -e "  ${YELLOW}WARN:${RESET} ${WARN_COUNT}"
echo -e "  ${RED}FAIL:${RESET} ${FAIL_COUNT}"
echo ""

DEMO_MODE=$(cat "${DEMO_MODE_FILE}" 2>/dev/null || echo "sim")
if [[ "${DEMO_MODE}" == "live" ]]; then
    echo -e "  ${GREEN}${BOLD}Mode: LIVE — all demos will use real AWS${RESET}"
else
    echo -e "  ${YELLOW}${BOLD}Mode: SIM — demos will use Python simulations${RESET}"
    echo -e "  ${YELLOW}Fix failures above and re-run to enable live mode${RESET}"
fi

echo ""
echo -e "  ${CYAN}Demo mode file: ${DEMO_MODE_FILE}${RESET}"
echo -e "  ${CYAN}To force mode:  echo 'live' > ${DEMO_MODE_FILE}${RESET}"
echo ""
