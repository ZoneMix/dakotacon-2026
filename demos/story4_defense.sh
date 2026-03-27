#!/bin/bash
set -euo pipefail

# Story 4: Detection & Response Chain — Defense Demo
# Shows EventBridge -> SNS alerting, and CloudWatch Insights queries
# for hunting AssumeRole anomalies.

source "$(dirname "$0")/demo_runner.sh"

TF_SHARED_DIR="<YOUR_PATH>"

set_prompt "secops $"

banner "Story 4 Defense: Detection That Responds"

narrate "GuardDuty detects. EventBridge routes. SNS notifies."
narrate "Does someone's phone actually ring?"

if is_live; then
  # Get shared outputs
  EB_RULE=$(terraform -chdir="${TF_SHARED_DIR}" output -raw eventbridge_rule_name 2>/dev/null || echo "demo-guardduty-high-severity")
  SNS_TOPIC=$(terraform -chdir="${TF_SHARED_DIR}" output -raw sns_topic_arn 2>/dev/null || echo "")
  LOG_GROUP=$(terraform -chdir="${TF_SHARED_DIR}" output -raw cloudtrail_log_group 2>/dev/null || echo "/aws/cloudtrail/demo")

  # ── Step 1: EventBridge rule ──
  step 1 "EventBridge -- Automated Routing"

  narrate "EventBridge watches for GuardDuty findings."

  type_cmd "aws events describe-rule --name ${EB_RULE}"

  EB_OUTPUT=$(aws events describe-rule \
    --name "${EB_RULE}" \
    --profile "${PROFILE}" \
    --region "${REGION}" \
    --no-cli-pager \
    --output json 2>&1 || echo "")

  if [[ -n "${EB_OUTPUT}" ]] && echo "${EB_OUTPUT}" | python3 -c "import json,sys; json.load(sys.stdin)['Name']" &>/dev/null; then
    echo "${EB_OUTPUT}" | python3 -c "
import json, sys
r = json.load(sys.stdin)
print(f\"  Name:        {r['Name']}\")
print(f\"  State:       {r['State']}\")
desc = r.get('Description', 'N/A')
if len(desc) > 45:
    desc = desc[:42] + '...'
print(f\"  Description: {desc}\")
pattern = json.loads(r.get('EventPattern', '{}'))
print(f\"  Source:      {pattern.get('source', ['N/A'])[0]}\")
detail_type = pattern.get('detail-type', ['N/A'])
if isinstance(detail_type, list):
    detail_type = detail_type[0] if detail_type else 'N/A'
print(f\"  Detail-Type: {detail_type}\")
severity = pattern.get('detail', {}).get('severity', 'N/A')
print(f\"  Severity:    {severity}\")
print()
print('  Event Pattern:')
print(json.dumps(pattern, indent=4))
" 2>/dev/null
    echo ""
    success "HIGH findings (severity >= 7) -> SNS"
  else
    info "(EventBridge rule not found -- check terraform)"
  fi

  # Show targets
  hr
  narrate "Where do matched events go?"

  type_cmd "aws events list-targets-by-rule --rule ${EB_RULE}"

  EB_TARGETS=$(aws events list-targets-by-rule \
    --rule "${EB_RULE}" \
    --profile "${PROFILE}" \
    --region "${REGION}" \
    --no-cli-pager \
    --output json 2>&1 || echo '{"Targets":[]}')

  echo "${EB_TARGETS}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
targets = data.get('Targets', [])
for t in targets:
    print(f\"  Target ID:  {t.get('Id', 'N/A')}\")
    arn = t.get('Arn', 'N/A')
    if len(arn) > 55:
        arn = '...' + arn[-52:]
    print(f\"  ARN:        {arn}\")
    print()
if not targets:
    print('  (No targets configured)')
" 2>/dev/null

  # ── Step 2: SNS topic and subscriptions ──
  step 2 "SNS Topic -- Who Gets Paged?"

  if [[ -n "${SNS_TOPIC}" ]]; then
    narrate "SNS receives events from EventBridge."
    narrate "Subscriptions determine who gets alerted."

    type_cmd "aws sns get-topic-attributes ..."

    aws sns get-topic-attributes --topic-arn "${SNS_TOPIC}" \
      --query 'Attributes.{DisplayName:DisplayName,SubscriptionsConfirmed:SubscriptionsConfirmed,SubscriptionsPending:SubscriptionsPending}' \
      --profile "${PROFILE}" --region "${REGION}" --no-cli-pager --output json 2>&1 | python3 -c "
import json,sys
d=json.load(sys.stdin)
for k,v in d.items():
    print(f'  {k:25s} {v}')
" 2>/dev/null || true

    hr
    type_cmd "aws sns list-subscriptions-by-topic ..."

    SNS_SUBS=$(aws sns list-subscriptions-by-topic \
      --topic-arn "${SNS_TOPIC}" \
      --profile "${PROFILE}" \
      --region "${REGION}" \
      --no-cli-pager \
      --output json 2>&1 || echo '{"Subscriptions":[]}')

    echo "${SNS_SUBS}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
subs = data.get('Subscriptions', [])
if not subs:
    print('  (No subscriptions found)')
for s in subs:
    protocol = s.get('Protocol', 'N/A')
    endpoint = s.get('Endpoint', 'N/A')
    if '@' in endpoint:
        parts = endpoint.split('@')
        masked = parts[0][:3] + '***@' + parts[1]
    elif len(endpoint) > 45:
        masked = endpoint[:42] + '...'
    else:
        masked = endpoint
    print(f'  Protocol:     {protocol}')
    print()
print(f'  Total subscriptions: {len(subs)}')
" 2>/dev/null
    success "Alerts routed to email + SMS"
  else
    info "(SNS topic ARN unavailable)"
  fi

  hr
  narrate "email = 'I'll check it Monday'"
  narrate "Slack = 'maybe someone reads the channel'"

  # ── Step 3: CloudWatch Insights ──
  step 3 "CloudWatch Insights -- Hunting"

  QUERY='fields @timestamp, eventName, sourceIPAddress, userIdentity.arn, requestParameters.roleArn
| filter eventName = "AssumeRole"
| stats count(*) as cnt by sourceIPAddress, userIdentity.arn
| sort cnt desc
| limit 10'

  narrate "Query: IPs making most AssumeRole calls (24h)"

  type_cmd "aws logs start-query ..."

  # Calculate time range (last 24 hours)
  END_TIME=$(date +%s)
  START_TIME=$((END_TIME - 86400))

  QUERY_ID=$(aws logs start-query \
    --log-group-name "${LOG_GROUP}" \
    --start-time "${START_TIME}" \
    --end-time "${END_TIME}" \
    --query-string "${QUERY}" \
    --profile "${PROFILE}" \
    --region "${REGION}" \
    --no-cli-pager \
    --output text 2>&1 || echo "")

  if [[ -n "${QUERY_ID}" ]] && [[ "${QUERY_ID}" != *"error"* ]] && [[ "${QUERY_ID}" != *"Error"* ]]; then
    info "Query ID: ${QUERY_ID}"
    narrate "Waiting for results..."

    # Wait for query to complete (max 10 seconds)
    QUERY_STATUS="Running"
    for i in $(seq 1 10); do
      QUERY_RESULT=$(aws logs get-query-results \
        --query-id "${QUERY_ID}" \
        --profile "${PROFILE}" \
        --region "${REGION}" \
        --no-cli-pager \
        --output json 2>&1 || echo '{"status":"Failed"}')

      QUERY_STATUS=$(echo "${QUERY_RESULT}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status','Failed'))" 2>/dev/null || echo "Failed")

      if [[ "${QUERY_STATUS}" == "Complete" ]]; then
        break
      elif [[ "${QUERY_STATUS}" == "Failed" || "${QUERY_STATUS}" == "Cancelled" ]]; then
        break
      fi
      sleep 1
    done

    if [[ "${QUERY_STATUS}" == "Complete" ]]; then
      echo "${QUERY_RESULT}" | python3 -c "
import json, sys

data = json.load(sys.stdin)
results = data.get('results', [])

if not results:
    print('  (No AssumeRole events in the last 24h)')
else:
    print('  Source IP         Identity               Count')
    print('  ' + '-' * 55)
    for row in results:
        fields = {f['field']: f['value'] for f in row}
        ip = fields.get('sourceIPAddress', 'N/A')
        arn = fields.get('userIdentity.arn', 'N/A')
        cnt = fields.get('cnt', '0')
        if len(arn) > 25:
            arn = '...' + arn[-22:]
        print(f'  {ip:<18} {arn:<25} {cnt}')

stats = data.get('statistics', {})
records = stats.get('recordsScanned', 0)
matched = stats.get('recordsMatched', 0)
print(f'\n  Scanned: {records}  Matched: {matched}')
" 2>/dev/null
    else
      info "Query status: ${QUERY_STATUS}"
    fi
  else
    info "(CloudWatch query failed -- no data yet)"
  fi

  # ── Step 4: Show the full chain timeline ──
  step 4 "The Full Response Chain"

else
  # ── Sim mode ──

  # Step 1
  step 1 "EventBridge -- Automated Routing"

  narrate "EventBridge watches for GuardDuty findings."

  show_cmd "aws events describe-rule ..." "$(
    cat <<'SIMOUT'
  Name:        demo-guardduty-high-severity
  State:       ENABLED
  Description: Route HIGH GuardDuty findings to SNS

  Source:      aws.guardduty
  Detail-Type: GuardDuty Finding
  Severity:    [{"numeric": [">=", 7]}]

  Event Pattern:
  {
      "source": ["aws.guardduty"],
      "detail-type": ["GuardDuty Finding"],
      "detail": {
          "severity": [{"numeric": [">=", 7]}]
      }
  }
SIMOUT
  )"

  success "HIGH findings (severity >= 7) -> SNS"

  hr
  narrate "Where do matched events go?"

  show_cmd "aws events list-targets-by-rule ..." "$(
    cat <<'SIMOUT'
  Target ID:  sns-alert
  ARN:        ...sns:us-east-2:111111111111:demo-alerts

  Target ID:  lambda-enricher
  ARN:        ...function:enrich-guardduty-finding
SIMOUT
  )"

  # Step 2
  step 2 "SNS Topic -- Who Gets Paged?"

  narrate "SNS receives events from EventBridge."
  narrate "Subscriptions determine who gets alerted."

  show_cmd "aws sns get-topic-attributes ..." "$(
    cat <<'SIMOUT'
  DisplayName:              DakotaCon Alerts
  SubscriptionsConfirmed:   2
  SubscriptionsPending:     0
SIMOUT
  )"

  show_cmd "aws sns list-subscriptions-by-topic ..." "$(
    cat <<'SIMOUT'
  Protocol:     email
  Endpoint:     sec***@company.com

  Protocol:     sms
  Endpoint:     +1770***1697

  Total subscriptions: 2
SIMOUT
  )"

  success "Alerts routed to email + SMS"

  hr
  narrate "The key: someone gets notified AND acts on it"

  # Step 3
  step 3 "CloudWatch Insights -- Hunting"

  narrate "Query: IPs making most AssumeRole calls (24h)"

  show_cmd "aws logs start-query ..." "$(
    cat <<'SIMOUT'
  Query ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
SIMOUT
  )"

  info "Query ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  narrate "Waiting for results..."

  show_cmd "aws logs get-query-results ..." "$(
    cat <<'SIMOUT'
  Source IP         Identity               Count
  -------------------------------------------------------
  198.51.100.42     ...assumed-role/EKS-No  47
  198.51.100.42     ...assumed-role/cross-a  23
  198.51.100.42     ...assumed-role/admin-r  12
  203.0.113.10      ...user/deploy-bot       12
  10.0.1.55         ...role/gitlab-runner    8
  10.0.2.100        ...role/lambda-exec      3

  Scanned: 14,832  Matched: 105
SIMOUT
  )"

  narrate "198.51.100.42 appears in 3 accounts"
  alert "Same IP chaining = lateral movement"
  alert "47 + 23 + 12 = 82 AssumeRole from one IP"

  # Step 4
  step 4 "The Full Response Chain"
fi

narrate "The complete detection-to-response pipeline:"
echo ""
echo "  GuardDuty          EventBridge"
echo "  +-----------------+  +-----------------------+"
echo "  | Detect:         |->| Rule: severity >= 7   |"
echo "  | - API anomalies |  | Match: GuardDuty      |"
echo "  | - Cred misuse   |  | Targets:              |"
echo "  | - Recon         |  |   -> SNS topic        |"
echo "  | - Lateral move  |  |   -> Lambda enricher  |"
echo "  +-----------------+  +-----------------------+"
echo "                              |"
echo "                              v"
echo "  Alert Team         SNS Topic"
echo "  +-----------------+  +-----------------------+"
echo "  | Respond:        |<-| Subscriptions:        |"
echo "  | - Investigate   |  |   -> email            |"
echo "  | - Follow up     |  |   -> SMS              |"
echo "  | - Escalate      |  |   -> Slack            |"
echo "  +-----------------+  +-----------------------+"
echo ""
echo "  Timeline:"
echo "    T+0m   Attack activity begins"
echo "    T+15m  GuardDuty creates finding"
echo "    T+15m  EventBridge -> SNS -> your team"
echo "    T+20m  On-call begins investigation"
echo "    T+30m  Credentials revoked, access blocked"

# ── Summary ──
echo ""
hr
success "The defense chain:"
echo "  GuardDuty -> EventBridge -> SNS -> Your Team"
echo "  15 min detect -> instant notify -> human response"
hr
echo ""
info "GuardDuty without EventBridge = nobody sees"
info "EventBridge without SNS = events lost"
info "SNS without follow-through = alerts nobody acts on"
info "The chain only works if someone investigates"
info "Detection is a product. Response is a process."
