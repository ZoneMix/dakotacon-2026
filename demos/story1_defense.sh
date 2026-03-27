#!/bin/bash
set -euo pipefail

# Story 1: Broken Deny Policy — Defense Demo
# Shows IAM Access Analyzer catching the unsupported condition key,
# and CloudTrail revealing the unauthorized S3 access.

source "$(dirname "$0")/demo_runner.sh"

BROKEN_POLICY="<YOUR_PATH>"

set_prompt "secops $"

banner "Story 1 Defense: Catching the Broken Guardrail"

# ── Step 1: Show the broken policy ──
step 1 "The policy they trusted"

if is_live && [[ -f "${BROKEN_POLICY}" ]]; then
    type_cmd "cat broken_policy.json"
    python3 -c "import json; print(json.dumps(json.load(open('${BROKEN_POLICY}')), indent=2))" 2>/dev/null
else
    show_cmd "cat broken_policy.json" "$(cat <<'SIMOUT'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyS3ByTag",
    "Effect": "Deny",
    "Action": ["s3:*"],
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "aws:ResourceTag/ResourceOwner": "my-kubernetes"
      }
    }
  }]
}
SIMOUT
)"
fi

narrate "Looks fine -- deny s3:* with a tag condition."
narrate "But aws:ResourceTag is NOT supported for S3."
narrate "S3 uses s3:ExistingObjectTag/* instead."

# ── Step 2: Show corrected policy side-by-side ──
step 2 "What a WORKING deny looks like"

if is_live; then
    type_cmd "cat fixed_deny_s3.json"
fi

echo ""
info "BROKEN (no-op):            FIXED (works):"
echo "  \"Condition\": {             \"Condition\": {"
echo "    \"StringEquals\": {          \"StringEquals\": {"
alert "      \"aws:ResourceTag/...\"     \"s3:ExistingObjectTag/...\""
echo "    }                          }"
echo "  }                          }"
echo ""
info "Or deny ALL s3:* unconditionally:"
echo "  {"
echo "    \"Effect\": \"Deny\","
echo "    \"Action\": [\"s3:*\"],"
echo "    \"Resource\": \"*\""
echo "  }"

# ── Step 3: Access Analyzer validate-policy ──
step 3 "Access Analyzer catches this in 5 sec"

if is_live; then
    POLICY_DOC=""
    if [[ -f "${BROKEN_POLICY}" ]]; then
        POLICY_DOC="file://${BROKEN_POLICY}"
    else
        TEMP_POLICY=$(mktemp)
        trap "rm -f '${TEMP_POLICY}'" EXIT
        cat > "${TEMP_POLICY}" <<'POLICY'
{"Version":"2012-10-17","Statement":[{"Sid":"S3Actions","Effect":"Deny","Action":["s3:*"],"Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/ResourceOwner":"my-kubernetes"}}}]}
POLICY
        POLICY_DOC="file://${TEMP_POLICY}"
    fi

    type_cmd "aws accessanalyzer validate-policy ..."
    aws accessanalyzer validate-policy \
        --policy-type IDENTITY_POLICY \
        --policy-document "${POLICY_DOC}" \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = data.get('findings', [])
for f in findings:
    ftype = f.get('findingType', 'UNKNOWN')
    code = f.get('issueCode', 'N/A')
    msg = f.get('findingDetails', 'N/A')
    link = f.get('learnMoreLink', '')
    print(f'  Finding Type:  {ftype}')
    print(f'  Issue Code:    {code}')
    print(f'  Message:       {msg}')
    if link:
        print(f'  Learn More:    {link}')
    print()
print(f'  Total findings: {len(findings)}')
" 2>/dev/null || true
else
    show_cmd "aws accessanalyzer validate-policy ..." "$(cat <<'SIMOUT'
  Finding Type:  ERROR
  Issue Code:    UNSUPPORTED_RESOURCE_CONDITION_KEY
  Message:       The condition key aws:ResourceTag
                 is not supported for the service s3.
                 Use s3:ExistingObjectTag or other
                 supported S3 condition keys.

  Finding Type:  SUGGESTION
  Issue Code:    MISSING_RESOURCE_ARN
  Message:       Resource * is overly broad. Scope
                 to specific bucket ARNs.

  Total findings: 2
SIMOUT
)"
fi

hr
success "Access Analyzer flags the unsupported key"
success "Finding type: ERROR -- not a warning"
success "This check takes < 5 seconds via API"
narrate "Run in CI/CD on every policy change."
narrate "terraform plan -> validate-policy -> block."

# ── Step 4: CloudTrail — show S3 access events ──
step 4 "CloudTrail shows what already happened"

narrate "The damage is done. Let's see the evidence."

if is_live; then
    type_cmd "aws cloudtrail lookup-events ..."

    TRAIL_OUTPUT=$(aws cloudtrail lookup-events \
        --lookup-attributes "AttributeKey=EventName,AttributeValue=GetObject" \
        --max-results 5 \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || echo '{"Events":[]}')

    EVENT_COUNT=$(echo "${TRAIL_OUTPUT}" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('Events',[])))" 2>/dev/null || echo "0")

    if [[ "${EVENT_COUNT}" -gt 0 ]]; then
        echo "${TRAIL_OUTPUT}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for e in data.get('Events', [])[:5]:
    print(f\"  Time:      {e.get('EventTime', 'N/A')}\")
    print(f\"  User:      {e.get('Username', 'N/A')}\")
    print(f\"  Event:     {e.get('EventName', 'N/A')}\")
    print(f\"  Source IP: {e.get('SourceIPAddress', 'N/A')}\")
    res = json.loads(e.get('CloudTrailEvent', '{}')).get('requestParameters', {})
    bucket = res.get('bucketName', 'N/A')
    key = res.get('key', 'N/A')
    if bucket != 'N/A':
        print(f\"  Bucket:    {bucket}\")
        print(f\"  Key:       {key}\")
    print(f\"  Status:    Success\")
    print()
print(f'  Total events: {len(data.get(\"Events\", []))}')
"
    else
        info "(No recent GetObject events -- trying ListBuckets...)"
        FALLBACK=$(aws cloudtrail lookup-events \
            --lookup-attributes "AttributeKey=EventName,AttributeValue=ListBuckets" \
            --max-results 3 \
            --profile "${PROFILE}" \
            --region "${REGION}" \
            --no-cli-pager \
            --output json 2>&1 || echo '{"Events":[]}')
        FALLBACK_COUNT=$(echo "${FALLBACK}" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('Events',[])))" 2>/dev/null || echo "0")
        if [[ "${FALLBACK_COUNT}" -gt 0 ]]; then
            echo "${FALLBACK}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for e in data.get('Events', [])[:3]:
    print(f\"  Time:      {e.get('EventTime', 'N/A')}\")
    print(f\"  User:      {e.get('Username', 'N/A')}\")
    print(f\"  Event:     {e.get('EventName', 'N/A')}\")
    print(f\"  Source IP: {e.get('SourceIPAddress', 'N/A')}\")
    print()
print(f'  Total events: {len(data.get(\"Events\", []))}')
"
            info "Data events (GetObject) may take 5-15 min"
        else
            info "(CloudTrail may take 5-15 min to deliver)"
        fi
    fi
else
    show_cmd "aws cloudtrail lookup-events ..." "$(cat <<'SIMOUT'
  Time:      2026-03-18T14:32:11Z
  User:      restricted-admin
  Event:     GetObject
  Source IP: 198.51.100.42
  Bucket:    demo-tfstate-a1b2c3d4
  Key:       production/terraform.tfstate
  Status:    Success

  Time:      2026-03-18T14:31:58Z
  User:      restricted-admin
  Event:     GetObject
  Source IP: 198.51.100.42
  Bucket:    demo-tfstate-a1b2c3d4
  Key:       staging/terraform.tfstate
  Status:    Success

  Time:      2026-03-18T14:31:45Z
  User:      restricted-admin
  Event:     GetObject
  Source IP: 198.51.100.42
  Bucket:    demo-tfstate-a1b2c3d4
  Key:       dev/terraform.tfstate
  Status:    Success

  Time:      2026-03-18T14:31:30Z
  User:      restricted-admin
  Event:     ListObjects
  Source IP: 198.51.100.42
  Bucket:    demo-tfstate-a1b2c3d4
  Key:       N/A
  Status:    Success

  Total events: 4
SIMOUT
)"
fi

hr
narrate "All 3 state files downloaded in 45 seconds."
narrate "Source IP: external (not corporate)."
alert "CloudTrail SAW it. Nobody was watching."

# ── Summary ──
echo ""
hr
success "validate-policy in CI catches BEFORE deploy"
success "CloudTrail + Athena catches AFTER (too late)"
hr
info "Prevention > Detection"
info "5-second API check vs. 5-month breach window"
info "Add validate-policy to every Terraform pipeline"
info "Cost: \$0. Time: 5 seconds. Excuses: 0."
