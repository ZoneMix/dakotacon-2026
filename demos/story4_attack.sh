#!/bin/bash
set -euo pipefail

# Story 4: GuardDuty Findings — The Alerts Nobody Checked
# Shows real GuardDuty findings from the demo account, sorted by severity.

source "$(dirname "$0")/demo_runner.sh"

TF_S4_DIR="<YOUR_PATH>"
TF_SHARED_DIR="<YOUR_PATH>"

set_prompt "secops $"

banner "Story 4: The Alerts Nobody Checked"

narrate "GuardDuty has been running the whole time."
narrate "It watched every API call from stories 1-3."
narrate "Let's see what it caught..."

# ── Trigger a live PenTest:IAMUser/KaliLinux finding ──
hr
narrate "First -- give GuardDuty something fresh."
narrate "Our Kali user-agent slipped through once."

type_cmd "AWS_EXECUTION_ENV=kali aws sts get-caller-identity"
AWS_EXECUTION_ENV=kali aws sts get-caller-identity \
  --profile "${PROFILE}" \
  --region "${REGION}" \
  --no-cli-pager \
  --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f\"  Account:  {d['Account']}\")
print(f\"  Arn:      {d['Arn']}\")
print(f\"  UserId:   {d['UserId']}\")
"

alert "API call sent with Kali Linux user-agent"
alert "GuardDuty flags PenTest:IAMUser/KaliLinux ~15 min"
info "SNS alert should arrive during Q&A"

if is_live; then
  # Get detector ID -- try story4 first, then shared
  DETECTOR_ID=$(terraform -chdir="${TF_S4_DIR}" output -raw detector_id 2>/dev/null || echo "")
  if [[ -z "${DETECTOR_ID}" ]]; then
    DETECTOR_ID=$(terraform -chdir="${TF_SHARED_DIR}" output -raw guardduty_detector_id 2>/dev/null || echo "")
  fi

  if [[ -z "${DETECTOR_ID}" ]]; then
    alert "Cannot get GuardDuty detector ID -- falling back to simulation"
    python3 "${SCRIPT_DIR}/guardduty_sim.py"
    exit 0
  fi

  info "GuardDuty detector: ${DETECTOR_ID}"

  # ── Step 1: Count findings ──
  step 1 "How many findings are waiting?"

  type_cmd "aws guardduty list-findings ..."

  FINDINGS_LIST=$(aws guardduty list-findings \
    --detector-id "${DETECTOR_ID}" \
    --sort-criteria '{"AttributeName":"severity","OrderBy":"DESC"}' \
    --max-results 10 \
    --profile "${PROFILE}" \
    --region "${REGION}" \
    --no-cli-pager \
    --output json 2>&1 || echo '{"FindingIds":[]}')

  FINDING_IDS=$(echo "${FINDINGS_LIST}" | python3 -c "import json,sys; ids=json.load(sys.stdin).get('FindingIds',[]); print(' '.join(ids))" 2>/dev/null || echo "")

  if [[ -z "${FINDING_IDS}" ]]; then
    info "No findings found -- GuardDuty may need more time"
    info "(Run story4_stratus_preflight.sh 60 min before talk)"
    narrate "Falling back to simulation..."
    python3 "${SCRIPT_DIR}/guardduty_sim.py"
    exit 0
  fi

  FINDING_COUNT=$(echo "${FINDING_IDS}" | wc -w | tr -d ' ')
  alert "${FINDING_COUNT} findings detected"

  # ── Step 2: Get finding details ──
  step 2 "Full details on every finding"

  type_cmd "aws guardduty get-findings ..."

  FINDINGS_DETAIL=$(aws guardduty get-findings \
    --detector-id "${DETECTOR_ID}" \
    --finding-ids ${FINDING_IDS} \
    --profile "${PROFILE}" \
    --region "${REGION}" \
    --no-cli-pager \
    --output json 2>&1 || echo '{"Findings":[]}')

  echo ""
  echo "${FINDINGS_DETAIL}" | python3 -c "
import json, sys

data = json.load(sys.stdin)
findings = data.get('Findings', [])
findings.sort(key=lambda f: f.get('Severity', 0), reverse=True)

for i, f in enumerate(findings[:8]):
    sev = f.get('Severity', 0)
    if sev >= 7:
        label = 'HIGH'
    elif sev >= 4:
        label = 'MEDIUM'
    else:
        label = 'LOW'

    ftype = f.get('Type', 'Unknown')
    # Truncate type to fit 65 chars
    if len(ftype) > 55:
        ftype = ftype[:52] + '...'
    title = f.get('Title', 'No title')
    if len(title) > 50:
        title = title[:47] + '...'
    desc = f.get('Description', 'No description')
    account = f.get('AccountId', 'N/A')
    region = f.get('Region', 'N/A')
    created = f.get('CreatedAt', 'N/A')
    updated = f.get('UpdatedAt', 'N/A')
    count = f.get('Service', {}).get('Count', 1)

    resource = f.get('Resource', {})
    resource_type = resource.get('ResourceType', 'N/A')
    access_key = resource.get('AccessKeyDetails', {})
    principal = access_key.get('UserName', 'N/A')
    principal_type = access_key.get('UserType', 'N/A')

    print(f'  [{label} {sev}]  {ftype}')
    print(f'    Title:    {title}')
    print(f'    Resource: {resource_type} / {principal}')
    print(f'    Account:  {account}  Region: {region}')
    print(f'    Count:    {count}')
    print(f'    Created:  {created}')
    if len(desc) > 55:
        desc = desc[:52] + '...'
    print(f'    Detail:   {desc}')
    print()

print(f'  Total: {len(findings[:8])} of {len(findings)}')
" 2>/dev/null || alert "(Error parsing findings)"

  # ── Step 3: Timeline analysis ──
  step 3 "Detection timeline vs. response"

  echo "${FINDINGS_DETAIL}" | python3 -c "
import json, sys

data = json.load(sys.stdin)
findings = data.get('Findings', [])
findings.sort(key=lambda f: f.get('CreatedAt', ''))

print('  Timeline:')
print('  ' + '-' * 55)
for f in findings[:8]:
    created = f.get('CreatedAt', 'N/A')[:19]
    ftype = f.get('Type', 'Unknown').split('/')[-1]
    sev = f.get('Severity', 0)
    if sev >= 7:
        label = 'HIGH'
    elif sev >= 4:
        label = 'MED '
    else:
        label = 'LOW '
    if len(ftype) > 25:
        ftype = ftype[:22] + '...'
    print(f'  {created}  [{label}]  {ftype}')

print()
print('  GuardDuty latency: ~15 min after activity')
print('  Human response time: ???')
" 2>/dev/null || true

else
  # ── Sim mode ──

  info "GuardDuty detector: 4ab2c3d4e5f6a7b8c9d0e1f2"

  # Step 1: Count findings
  step 1 "How many findings are waiting?"

  show_cmd "aws guardduty list-findings ..." "$(
    cat <<'SIMOUT'
  FindingIds: [
    "4ab1111111111111111111111111111111",
    "4ab2222222222222222222222222222222",
    "4ab3333333333333333333333333333333",
    "4ab4444444444444444444444444444444",
    "4ab5555555555555555555555555555555",
    "4ab6666666666666666666666666666666"
  ]
SIMOUT
  )"

  alert "findings detected"

  # Step 2: Full details
  step 2 "Full details on every finding"

  show_cmd "aws guardduty get-findings ..." "$(
    cat <<'SIMOUT'

  [HIGH 8.0]  IAMUser/InstanceCredentialExfiltration
    Title:    Credentials used from external IP
    Resource: AccessKey / EKS-Node-Role
    Account:  111111111111  Region: us-east-2
    Count:    47
    Created:  2026-03-22T10:15:22Z
    Detail:   API invoked using EC2 credentials
              from IP not associated with AWS...

  [HIGH 8.0]  Discovery:S3/MaliciousIPCaller.Custom
    Title:    S3 API from a known malicious IP
    Resource: S3Bucket / demo-tfstate
    Account:  111111111111  Region: us-east-2
    Count:    12
    Created:  2026-03-22T10:17:45Z
    Detail:   Discovery API from malicious IP
              198.51.100.42...

  [HIGH 7.0]  UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
    Title:    Unusual console login location
    Resource: AccessKey / restricted-admin
    Account:  111111111111  Region: us-east-2
    Count:    3
    Created:  2026-03-22T09:15:00Z
    Detail:   Console login from unusual location

  [MEDIUM 5.0]  Recon:IAMUser/MaliciousIPCaller.Custom
    Title:    API from known malicious IP
    Resource: AccessKey / restricted-admin
    Account:  111111111111  Region: us-east-2
    Count:    89
    Created:  2026-03-22T10:10:00Z
    Detail:   API from IP 198.51.100.42 on
              custom threat list...

  [MEDIUM 4.0]  Persistence:IAMUser/UserPermissions
    Title:    Principal modified IAM permissions
    Resource: AccessKey / deploy-bot
    Account:  111111111111  Region: us-east-2
    Count:    5
    Created:  2026-03-22T10:20:00Z
    Detail:   CreateAccessKey invoked by
              deploy-bot for attacker-persistence

  [LOW 2.0]  Recon:IAMUser/ResourcePermissions
    Title:    Enumerated resource permissions
    Resource: AccessKey / restricted-admin
    Account:  111111111111  Region: us-east-2
    Count:    23
    Created:  2026-03-22T10:10:00Z
    Detail:   ListAttachedUserPolicies invoked
              by restricted-admin...

  Total: 6 of 6
SIMOUT
  )"

  # Step 3: Timeline
  step 3 "Detection timeline vs. response"

  echo "  Timeline:"
  echo "  -------------------------------------------------------"
  echo "  2026-03-22T09:15:00  [HIGH]  ConsoleLoginSuccess.B"
  echo "  2026-03-22T10:10:00  [MED ]  MaliciousIPCaller.Custom"
  echo "  2026-03-22T10:10:00  [LOW ]  ResourcePermissions"
  echo "  2026-03-22T10:15:22  [HIGH]  CredentialExfiltration"
  echo "  2026-03-22T10:17:45  [HIGH]  MaliciousIPCaller (S3)"
  echo "  2026-03-22T10:20:00  [MED ]  UserPermissions"
  echo ""
  echo "  GuardDuty latency: ~15 min after activity"
  echo "  Human response time: ???"
fi

# ── Summary ──
echo ""
hr
alert "The platform SAW everything. Every hop. Every call."
alert "Findings without response = expensive logging"
hr
echo ""
info "Avg detect: 15 min (GuardDuty is fast)"
info "Avg respond: ??? (nobody was watching)"
info "Detection without response = expensive logging"
