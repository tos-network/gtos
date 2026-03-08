#!/usr/bin/env bash
# validator_guard.sh — validator safety/journal watchdog for GTOS clusters.
set -euo pipefail

NODES="${NODES:-http://127.0.0.1:8545,http://127.0.0.1:8547,http://127.0.0.1:8549}"
POLL_SEC="${POLL_SEC:-15}"
DURATION="${DURATION:-0}"
JOURNAL_DIR="${JOURNAL_DIR:-/data/gtos/ops/validator_guard}"
INCIDENT_DIR="${INCIDENT_DIR:-/data/gtos/ops/incidents}"
MAINTENANCE_WARN_SEC="${MAINTENANCE_WARN_SEC:-7200}"
MAINTENANCE_CRITICAL_SEC="${MAINTENANCE_CRITICAL_SEC:-21600}"
MAINTENANCE_EMERGENCY_SEC="${MAINTENANCE_EMERGENCY_SEC:-86400}"
FINALITY_LAG_MAX_BLOCKS="${FINALITY_LAG_MAX_BLOCKS:-512}"
HALT_TOLERANCE="${HALT_TOLERANCE:-4}"
PEER_MIN="${PEER_MIN:-1}"
GROUP_SAMPLE_FACTOR="${GROUP_SAMPLE_FACTOR:-2}"
BASE_DIR="${BASE_DIR:-/data/gtos}"
ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"
ALERT_WEBHOOK_TIMEOUT_SEC="${ALERT_WEBHOOK_TIMEOUT_SEC:-5}"
ALERT_EMAIL_TO="${ALERT_EMAIL_TO:-}"
ALERT_EMAIL_FROM="${ALERT_EMAIL_FROM:-}"
ALERT_EMAIL_SUBJECT_PREFIX="${ALERT_EMAIL_SUBJECT_PREFIX:-[GTOS Validator Guard]}"
SMTP_HOST="${SMTP_HOST:-}"
SMTP_PORT="${SMTP_PORT:-587}"
SMTP_USERNAME="${SMTP_USERNAME:-}"
SMTP_PASSWORD="${SMTP_PASSWORD:-}"
SMTP_TLS="${SMTP_TLS:-true}"

usage() {
	cat <<'USAGE'
Usage: scripts/validator_guard.sh [options]

Continuously watches a GTOS validator cluster and writes operational journals.

Options:
  --nodes <url,url,...>             comma-separated node HTTP endpoints
  --poll-sec <n>                    poll interval in seconds (default: 15)
  --duration <value>                total runtime, e.g. 2h, 30m, 0=forever
  --journal-dir <path>              directory for events.jsonl and alerts.jsonl
  --incident-dir <path>             directory for incident outbox JSON records
  --maintenance-warn-sec <n>        warning threshold for maintenance age
  --maintenance-critical-sec <n>    critical threshold for maintenance age
  --maintenance-emergency-sec <n>   emergency threshold for maintenance age
  --finality-lag-max-blocks <n>     alert threshold for head-finalized lag
  --halt-tolerance <n>              consecutive no-growth polls before halt alert
  --peer-min <n>                    minimum healthy peer count per node
  --group-sample-factor <n>         grouped-turn sample multiplier (default: 2)
  --base-dir <path>                 cluster base dir for maintenance state files
  --alert-webhook-url <url>         optional webhook endpoint for alert delivery
  --alert-webhook-timeout-sec <n>   webhook timeout in seconds (default: 5)
  --alert-email-to <addr[,addr]>    optional alert email recipients
  --alert-email-from <addr>         sender address for alert email
  --alert-email-subject-prefix <s>  mail subject prefix
  --smtp-host <host>                SMTP host for email delivery
  --smtp-port <n>                   SMTP port (default: 587)
  --smtp-username <user>            SMTP username
  --smtp-password <pass>            SMTP password
  --smtp-tls <true|false>           enable STARTTLS (default: true)
  -h, --help                        show help
USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--nodes) NODES="$2"; shift 2 ;;
	--poll-sec) POLL_SEC="$2"; shift 2 ;;
	--duration) DURATION="$2"; shift 2 ;;
	--journal-dir) JOURNAL_DIR="$2"; shift 2 ;;
	--incident-dir) INCIDENT_DIR="$2"; shift 2 ;;
	--maintenance-warn-sec) MAINTENANCE_WARN_SEC="$2"; shift 2 ;;
	--maintenance-critical-sec) MAINTENANCE_CRITICAL_SEC="$2"; shift 2 ;;
	--maintenance-emergency-sec) MAINTENANCE_EMERGENCY_SEC="$2"; shift 2 ;;
	--finality-lag-max-blocks) FINALITY_LAG_MAX_BLOCKS="$2"; shift 2 ;;
	--halt-tolerance) HALT_TOLERANCE="$2"; shift 2 ;;
	--peer-min) PEER_MIN="$2"; shift 2 ;;
	--group-sample-factor) GROUP_SAMPLE_FACTOR="$2"; shift 2 ;;
	--base-dir) BASE_DIR="$2"; shift 2 ;;
	--alert-webhook-url) ALERT_WEBHOOK_URL="$2"; shift 2 ;;
	--alert-webhook-timeout-sec) ALERT_WEBHOOK_TIMEOUT_SEC="$2"; shift 2 ;;
	--alert-email-to) ALERT_EMAIL_TO="$2"; shift 2 ;;
	--alert-email-from) ALERT_EMAIL_FROM="$2"; shift 2 ;;
	--alert-email-subject-prefix) ALERT_EMAIL_SUBJECT_PREFIX="$2"; shift 2 ;;
	--smtp-host) SMTP_HOST="$2"; shift 2 ;;
	--smtp-port) SMTP_PORT="$2"; shift 2 ;;
	--smtp-username) SMTP_USERNAME="$2"; shift 2 ;;
	--smtp-password) SMTP_PASSWORD="$2"; shift 2 ;;
	--smtp-tls) SMTP_TLS="$2"; shift 2 ;;
	-h|--help) usage; exit 0 ;;
	*) echo "unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

duration_to_sec() {
	local d="$1"
	if [[ "$d" == "0" ]]; then
		echo 0
		return
	fi
	python3 -c '
import re, sys
s = sys.argv[1]
total = 0
for val, unit in re.findall(r"(\d+)([smhd])", s):
    total += int(val) * {"s":1,"m":60,"h":3600,"d":86400}[unit]
if total == 0:
    raise SystemExit("invalid duration: " + s)
print(total)
' "$d"
}

TOTAL_SEC="$(duration_to_sec "${DURATION}")"
START_TS="$(date -u +%s)"
DEADLINE=0
if (( TOTAL_SEC > 0 )); then
	DEADLINE=$(( START_TS + TOTAL_SEC ))
fi

IFS=',' read -ra NODE_URLS <<< "${NODES}"
mkdir -p "${JOURNAL_DIR}" "${INCIDENT_DIR}"
EVENTS_FILE="${JOURNAL_DIR}/events.jsonl"
ALERTS_FILE="${JOURNAL_DIR}/alerts.jsonl"
STATE_FILE="${JOURNAL_DIR}/state.json"

rpc() {
	local url="$1" method="$2" params="$3"
	python3 - <<PY
import json, urllib.request, sys
try:
    params = json.loads(r'''${params}''')
    data = json.dumps({"jsonrpc":"2.0","id":1,"method":"${method}","params":params}).encode()
    req = urllib.request.Request("${url}", data=data, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        d = json.loads(r.read())
    if "error" in d:
        sys.exit("rpc error: " + str(d["error"]))
    print(json.dumps(d["result"]))
except Exception as e:
    sys.exit(str(e))
PY
}

hex_to_dec() {
	python3 -c 'import sys; v=sys.argv[1]; print(int(v,16) if v.startswith("0x") else int(v))' "$1"
}

alert() {
	local level="$1" kind="$2" message="$3" detail_json="${4:-}"
	local ts
	if [[ -z "${detail_json}" ]]; then
		detail_json='{}'
	fi
	ts="$(date -u +%s)"
	python3 - <<PY >>"${ALERTS_FILE}"
import json, time
print(json.dumps({
    "ts": int(${ts}),
    "level": ${level@Q},
    "kind": ${kind@Q},
    "message": ${message@Q},
    "detail": json.loads(${detail_json@Q}),
}, sort_keys=True))
PY
	echo "${level}: ${message}"
	send_webhook_alert "${ts}" "${level}" "${kind}" "${message}" "${detail_json}" || true
	send_email_alert "${ts}" "${level}" "${kind}" "${message}" "${detail_json}" || true
}

emit_incident() {
	local kind="$1" severity="$2" dedupe_key="$3" title="$4" detail_json="${5:-{}}"
	local path="${INCIDENT_DIR}/${kind}-${dedupe_key}-${severity}.json"
	if [[ -f "${path}" ]]; then
		return 0
	fi
	python3 - <<PY >"${path}"
import json, time
print(json.dumps({
    "ts": int(time.time()),
    "kind": ${kind@Q},
    "severity": ${severity@Q},
    "title": ${title@Q},
    "detail": json.loads(${detail_json@Q}),
}, indent=2, sort_keys=True))
PY
}

marker_exists() {
	local name="$1"
	[[ -f "${INCIDENT_DIR}/${name}.sent" ]]
}

write_marker() {
	local name="$1"
	: >"${INCIDENT_DIR}/${name}.sent"
}

maintenance_severity() {
	local age="$1"
	if (( age >= MAINTENANCE_EMERGENCY_SEC )); then
		echo "EMERGENCY"
	elif (( age >= MAINTENANCE_CRITICAL_SEC )); then
		echo "CRITICAL"
	elif (( age >= MAINTENANCE_WARN_SEC )); then
		echo "WARN"
	else
		echo ""
	fi
}

send_webhook_alert() {
	local ts="$1" level="$2" kind="$3" message="$4" detail_json="$5"
	if [[ -z "${ALERT_WEBHOOK_URL}" ]]; then
		return 0
	fi
	if ! python3 - "${ts}" "${level}" "${kind}" "${message}" "${detail_json}" <<'PY'
import json, os, sys, urllib.request
payload = {
    "ts": int(sys.argv[1]),
    "level": sys.argv[2],
    "kind": sys.argv[3],
    "message": sys.argv[4],
    "detail": json.loads(sys.argv[5]),
}
req = urllib.request.Request(
    os.environ["ALERT_WEBHOOK_URL"],
    data=json.dumps(payload, sort_keys=True).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(req, timeout=int(os.environ.get("ALERT_WEBHOOK_TIMEOUT_SEC", "5"))) as _:
    pass
PY
	then
		echo "WARN: webhook delivery failed for alert kind=${kind}" >&2
		return 0
	fi
}

send_email_alert() {
	local ts="$1" level="$2" kind="$3" message="$4" detail_json="$5"
	if [[ -z "${ALERT_EMAIL_TO}" ]]; then
		return 0
	fi
	if [[ -z "${ALERT_EMAIL_FROM}" || -z "${SMTP_HOST}" ]]; then
		echo "WARN: email alert requested but ALERT_EMAIL_FROM or SMTP_HOST is unset" >&2
		return 0
	fi
	if ! python3 - "${ts}" "${level}" "${kind}" "${message}" "${detail_json}" <<'PY'
import json, os, smtplib, sys
from email.message import EmailMessage

recipients = [item.strip() for item in os.environ["ALERT_EMAIL_TO"].split(",") if item.strip()]
if not recipients:
    raise SystemExit(0)
detail = json.loads(sys.argv[5])
msg = EmailMessage()
msg["Subject"] = f'{os.environ.get("ALERT_EMAIL_SUBJECT_PREFIX", "[GTOS Validator Guard]")} [{sys.argv[2]}] {sys.argv[3]}'
msg["From"] = os.environ["ALERT_EMAIL_FROM"]
msg["To"] = ", ".join(recipients)
body = {
    "ts": int(sys.argv[1]),
    "level": sys.argv[2],
    "kind": sys.argv[3],
    "message": sys.argv[4],
    "detail": detail,
}
msg.set_content(json.dumps(body, indent=2, sort_keys=True))
host = os.environ["SMTP_HOST"]
port = int(os.environ.get("SMTP_PORT", "587"))
use_tls = os.environ.get("SMTP_TLS", "true").strip().lower() not in ("0", "false", "no")
username = os.environ.get("SMTP_USERNAME", "")
password = os.environ.get("SMTP_PASSWORD", "")
with smtplib.SMTP(host, port, timeout=10) as smtp:
    smtp.ehlo()
    if use_tls:
        smtp.starttls()
        smtp.ehlo()
    if username:
        smtp.login(username, password)
    smtp.send_message(msg)
PY
	then
		echo "WARN: email delivery failed for alert kind=${kind}" >&2
		return 0
	fi
}

declare -A prev_block
for i in "${!NODE_URLS[@]}"; do
	prev_block[$i]=0
done
declare -A no_growth_streak

echo "==> validator guard started"
echo "nodes: ${NODES}"
echo "journal: ${JOURNAL_DIR}"

while true; do
	now="$(date -u +%s)"
	if (( DEADLINE > 0 && now >= DEADLINE )); then
		break
	fi

	latest_records=()
	for i in "${!NODE_URLS[@]}"; do
		url="${NODE_URLS[$i]}"
		node_n=$((i + 1))
		block_json="$(rpc "${url}" "tos_getBlockByNumber" '["latest", false]' 2>/dev/null || echo "")"
		peer_json="$(rpc "${url}" "net_peerCount" '[]' 2>/dev/null || echo "")"
		if [[ -z "${block_json}" || -z "${peer_json}" ]]; then
			alert "ERROR" "rpc" "node${node_n} RPC unreachable" '{}'
			no_growth_streak[$i]=$(( ${no_growth_streak[$i]:-0} + 1 ))
			continue
		fi
		block_number="$(python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["number"])' <<<"${block_json}")"
		block_hash="$(python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["hash"].lower())' <<<"${block_json}")"
		block_miner="$(python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["miner"].lower())' <<<"${block_json}")"
		peer_count_raw="$(python3 -c 'import json,sys; print(json.load(sys.stdin))' <<<"${peer_json}")"
		block_dec="$(hex_to_dec "${block_number}")"
		peer_dec="$(hex_to_dec "${peer_count_raw}")"
		if (( block_dec <= ${prev_block[$i]:-0} )); then
			no_growth_streak[$i]=$(( ${no_growth_streak[$i]:-0} + 1 ))
			if (( ${no_growth_streak[$i]} >= HALT_TOLERANCE )); then
				alert "ERROR" "halt" "node${node_n} stuck at block ${block_dec}" "{\"node\":${node_n},\"block\":${block_dec}}"
			fi
		else
			prev_block[$i]="${block_dec}"
			no_growth_streak[$i]=0
		fi
		if (( peer_dec < PEER_MIN )); then
			alert "WARN" "peers" "node${node_n} peer count below threshold: ${peer_dec}" "{\"node\":${node_n},\"peers\":${peer_dec}}"
		fi
		latest_records+=("${node_n}|${block_dec}|${block_hash}|${block_miner}|${peer_dec}")
	done

	# Approximate double-sign / fork alert: same miner at same height with different hashes across nodes.
	if (( ${#latest_records[@]} > 1 )); then
		latest_blob="$(printf '%s\n' "${latest_records[@]}")"
		conflicts="$(python3 -c '
import sys, json
seen = {}
conflicts = []
for line in sys.stdin.read().splitlines():
    if not line:
        continue
    node, height, block_hash, miner, peers = line.split("|")
    key = (height, miner)
    prev = seen.get(key)
    if prev and prev != block_hash:
        conflicts.append({"height": int(height), "miner": miner, "hashes": sorted({prev, block_hash})})
    else:
        seen[key] = block_hash
print(json.dumps(conflicts))
' <<<"${latest_blob}")"
		if python3 -c 'import json,sys; sys.exit(0 if json.loads(sys.stdin.read()) else 1)' <<<"${conflicts}"; then
			alert "ERROR" "conflict" "observed conflicting latest blocks for the same miner/height" "${conflicts}"
		fi
	fi

	analysis="$(python3 - <<PY
import json, urllib.request
url = ${NODE_URLS[0]@Q}
finality_lag_max = int(${FINALITY_LAG_MAX_BLOCKS})
group_factor = max(int(${GROUP_SAMPLE_FACTOR}), 1)

def rpc(method, params):
    data = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        body = json.loads(r.read())
    if "error" in body:
        raise RuntimeError(f"{method} error: {body['error']}")
    return body["result"]

def dec(value):
    if value is None:
        return 0
    if isinstance(value, str) and value.startswith("0x"):
        return int(value, 16)
    return int(value)

latest = dec(rpc("tos_blockNumber", []))
finalized = rpc("tos_getFinalizedBlock", [])
epoch_info = rpc("dpos_getEpochInfo", ["latest"])
validators = [str(v).lower() for v in (rpc("dpos_getValidators", ["latest"]) or [])]
genesis = rpc("tos_getBlockByNumber", ["0x0", False])
period_ms = dec(epoch_info.get("targetBlockPeriodMs") or "0x0")
turn_length = dec(epoch_info.get("turnLength") or "0x0")
if period_ms <= 0 or turn_length <= 0 or not validators:
    print(json.dumps({"error": "invalid epoch info"}))
    raise SystemExit(0)
lag = latest - dec(finalized["number"]) if finalized else 0
sample_len = min(latest, max(turn_length * group_factor, 16))
start = max(1, latest - sample_len + 1)
group_counts = {}
group_totals = {}
group_order = []
for num in range(start, latest + 1):
    block = rpc("tos_getBlockByNumber", [hex(num), False])
    miner = str(block["miner"]).lower()
    ts = dec(block["timestamp"])
    slot = (ts - dec(genesis["timestamp"])) // period_ms
    if slot < 1:
        print(json.dumps({"error": f"block {num} has invalid slot {slot}"}))
        raise SystemExit(0)
    group = (slot - 1) // turn_length
    if group not in group_counts:
        group_counts[group] = {}
        group_order.append(group)
    group_counts[group][miner] = group_counts[group].get(miner, 0) + 1
    group_totals[group] = group_totals.get(group, 0) + 1
dominant = {}
strict_groups = group_order[1:-1] if len(group_order) > 2 else group_order
for group, counts in group_counts.items():
    miner, count = max(counts.items(), key=lambda item: item[1])
    dominant[group] = miner
    if group in strict_groups and count * 2 <= group_totals[group]:
        print(json.dumps({"error": f"group {group} has no dominant proposer: {counts}"}))
        raise SystemExit(0)
for group in strict_groups:
    expected = validators[group % len(validators)]
    if dominant[group] != expected:
        print(json.dumps({"error": f"group {group} dominant proposer {dominant[group]} != expected {expected}"}))
        raise SystemExit(0)
print(json.dumps({
    "head": latest,
    "finalized": dec(finalized["number"]) if finalized else 0,
    "finalityLag": lag,
    "finalityAlert": lag > finality_lag_max,
    "turnLength": turn_length,
    "turnGroupDurationMs": turn_length * period_ms,
    "groupsObserved": len(group_counts),
}))
PY
2>/dev/null || true)"
	if [[ -n "${analysis}" ]]; then
		if python3 -c 'import json,sys; sys.exit(0 if "error" in json.loads(sys.stdin.read()) else 1)' <<<"${analysis}"; then
			msg="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["error"])' <<<"${analysis}")"
			alert "WARN" "grouped-turn" "${msg}" '{}'
		else
			if python3 -c 'import json,sys; sys.exit(0 if json.loads(sys.stdin.read())["finalityAlert"] else 1)' <<<"${analysis}"; then
				lag="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["finalityLag"])' <<<"${analysis}")"
				alert "WARN" "finality" "finalized lag ${lag} exceeds threshold ${FINALITY_LAG_MAX_BLOCKS}" "${analysis}"
			fi
		fi
	fi

	maintenance_rows=()
	for idx in 1 2 3; do
		state_file="${BASE_DIR}/ops/maintenance/node${idx}.env"
		if [[ ! -f "${state_file}" ]]; then
			continue
		fi
		# shellcheck disable=SC1090
		source "${state_file}"
		if [[ "${STATE:-}" == "maintenance" && -n "${UPDATED_AT:-}" ]]; then
			age=$(( now - UPDATED_AT ))
			severity="$(maintenance_severity "${age}")"
			maintenance_rows+=("${idx}|maintenance|${age}|${severity}|${VALIDATOR_ADDR:-}|${TX_HASH:-}|${UPDATED_AT}")
			if [[ -n "${severity}" ]]; then
				detail="{\"node\":${idx},\"ageSec\":${age},\"validator\":\"${VALIDATOR_ADDR:-}\",\"txHash\":\"${TX_HASH:-}\",\"warnSec\":${MAINTENANCE_WARN_SEC},\"criticalSec\":${MAINTENANCE_CRITICAL_SEC},\"emergencySec\":${MAINTENANCE_EMERGENCY_SEC}}"
				marker="maintenance-node${idx}-${UPDATED_AT}-${severity}"
				if marker_exists "${marker}"; then
					continue
				fi
				case "${severity}" in
				WARN)
					alert "WARN" "maintenance" "node${idx} maintenance exceeds ${MAINTENANCE_WARN_SEC}s" "${detail}"
					;;
				CRITICAL)
					alert "ERROR" "maintenance" "node${idx} maintenance exceeds ${MAINTENANCE_CRITICAL_SEC}s" "${detail}"
					emit_incident "maintenance" "critical" "node${idx}-${UPDATED_AT}" "Validator maintenance overrun requires incident handling" "${detail}"
					;;
				EMERGENCY)
					alert "CRITICAL" "maintenance" "node${idx} maintenance exceeds ${MAINTENANCE_EMERGENCY_SEC}s" "${detail}"
					emit_incident "maintenance" "emergency" "node${idx}-${UPDATED_AT}" "Validator maintenance emergency requires governance action" "${detail}"
					;;
				esac
				write_marker "${marker}"
			fi
		else
			maintenance_rows+=("${idx}|${STATE:-unknown}|0||${VALIDATOR_ADDR:-}|${TX_HASH:-}|${UPDATED_AT:-0}")
		fi
	done
	maintenance_summary_json="$(python3 -c '
import json, sys
items = []
for line in sys.stdin.read().splitlines():
    if not line:
        continue
    node, state, age, severity, validator, txhash, updated_at = line.split("|", 6)
    items.append({
        "node": int(node),
        "state": state,
        "ageSec": int(age),
        "severity": severity,
        "validator": validator,
        "txHash": txhash,
        "updatedAt": int(updated_at) if updated_at else 0,
    })
print(json.dumps(items, sort_keys=True))
' <<<"$(printf '%s\n' "${maintenance_rows[@]}")")"

	latest_json="$(python3 -c '
import json, sys
items = []
for line in sys.stdin.read().splitlines():
    if not line:
        continue
    node, height, block_hash, miner, peers = line.split("|")
    items.append({
        "node": int(node),
        "height": int(height),
        "hash": block_hash,
        "miner": miner,
        "peers": int(peers),
    })
print(json.dumps(items, sort_keys=True))
' <<<"$(printf '%s\n' "${latest_records[@]}")")"
	analysis_json="${analysis:-null}"
	python3 - <<PY >>"${EVENTS_FILE}"
import json, time
analysis = json.loads(${analysis_json@Q}) if ${analysis_json@Q} not in ("", "null") else None
latest = json.loads(${latest_json@Q})
print(json.dumps({
    "ts": int(time.time()),
    "latest": latest,
    "analysis": analysis,
}, sort_keys=True))
PY

	python3 - <<PY >"${STATE_FILE}"
import json, time
analysis = json.loads(${analysis_json@Q}) if ${analysis_json@Q} not in ("", "null") else None
latest = json.loads(${latest_json@Q})
print(json.dumps({
    "updated_at": int(time.time()),
    "latest": latest,
    "analysis": analysis,
    "maintenance": json.loads(r'''${maintenance_summary_json:-[]}'''),
}, indent=2, sort_keys=True))
PY

	sleep "${POLL_SEC}"
done

echo "validator guard finished; journals written under ${JOURNAL_DIR}"
