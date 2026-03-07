#!/usr/bin/env bash
# dpos_livenet_soak.sh — grouped-turn-aware DPoS liveness and finality soak.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DURATION="${DURATION:-24h}"
INTERVAL="${INTERVAL:-30}"
NODES="${NODES:-http://127.0.0.1:8545,http://127.0.0.1:8547,http://127.0.0.1:8549}"
OUT="${OUT:-}"
HALT_TOLERANCE="${HALT_TOLERANCE:-3}"
FINALITY_LAG_MAX_BLOCKS="${FINALITY_LAG_MAX_BLOCKS:-512}"
GROUP_SAMPLE_FACTOR="${GROUP_SAMPLE_FACTOR:-2}"

usage() {
	cat <<'USAGE'
Usage: scripts/dpos_livenet_soak.sh [options]

Polls a running GTOS validator cluster and records liveness/finality evidence.

Options:
  --duration <value>            total soak duration (default: 24h)
  --interval <seconds>          poll interval in seconds (default: 30)
  --nodes <url,url,...>         comma-separated node HTTP endpoints
  --out <file>                  JSON evidence report output path
  --halt-tolerance <n>          consecutive no-growth polls before halt (default: 3)
  --finality-lag-max-blocks <n> alert threshold for head-finalized lag (default: 512)
  --group-sample-factor <n>     sample factor for grouped-turn validation (default: 2)
  -h, --help                    show help
USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--duration) DURATION="$2"; shift 2 ;;
	--interval) INTERVAL="$2"; shift 2 ;;
	--nodes) NODES="$2"; shift 2 ;;
	--out) OUT="$2"; shift 2 ;;
	--halt-tolerance) HALT_TOLERANCE="$2"; shift 2 ;;
	--finality-lag-max-blocks) FINALITY_LAG_MAX_BLOCKS="$2"; shift 2 ;;
	--group-sample-factor) GROUP_SAMPLE_FACTOR="$2"; shift 2 ;;
	-h|--help) usage; exit 0 ;;
	*) echo "unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

duration_to_sec() {
	local d="$1"
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
DEADLINE=$(( START_TS + TOTAL_SEC ))

if [[ -z "${OUT}" ]]; then
	OUT="/tmp/dpos_livenet_soak_$(date -u +%Y%m%dT%H%M%SZ).json"
fi

IFS=',' read -ra NODE_URLS <<< "${NODES}"

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

polls=0
halts=0
peer_losses=0
group_errors=0
finality_alerts=0
max_finality_lag=0
errors=()
groups_seen=()
declare -A prev_block
declare -A no_growth_streak

for i in "${!NODE_URLS[@]}"; do
	prev_block[$i]=0
	no_growth_streak[$i]=0
done

for i in "${!NODE_URLS[@]}"; do
	url="${NODE_URLS[$i]}"
	raw="$(rpc "${url}" "tos_blockNumber" "[]" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin))' 2>/dev/null || echo "0x0")"
	prev_block[$i]="$(hex_to_dec "${raw}")"
done

BLOCKS_START="${prev_block[0]}"

echo "==> grouped-turn DPoS soak"
echo "date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "duration: ${DURATION} (${TOTAL_SEC}s)"
echo "interval: ${INTERVAL}s"
echo "nodes:    ${NODES}"
echo "out:      ${OUT}"
echo ""

while true; do
	now="$(date -u +%s)"
	if (( now >= DEADLINE )); then
		break
	fi

	sleep "${INTERVAL}"
	polls=$(( polls + 1 ))
	ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

	for i in "${!NODE_URLS[@]}"; do
		url="${NODE_URLS[$i]}"
		node_n=$(( i + 1 ))

		raw_block="$(rpc "${url}" "tos_blockNumber" "[]" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin))' 2>/dev/null || echo "")"
		if [[ -z "${raw_block}" ]]; then
			msg="${ts} node${node_n}: RPC unreachable"
			echo "${msg}"
			errors+=("${msg}")
			no_growth_streak[$i]=$(( no_growth_streak[$i] + 1 ))
		else
			cur="$(hex_to_dec "${raw_block}")"
			if (( cur <= prev_block[$i] )); then
				no_growth_streak[$i]=$(( no_growth_streak[$i] + 1 ))
				if (( no_growth_streak[$i] >= HALT_TOLERANCE )); then
					msg="${ts} node${node_n}: HALT detected — block stuck at ${cur} for ${no_growth_streak[$i]} polls"
					echo "ERROR: ${msg}"
					errors+=("${msg}")
					halts=$(( halts + 1 ))
				fi
			else
				no_growth_streak[$i]=0
				prev_block[$i]="${cur}"
			fi
		fi

		raw_peers="$(rpc "${url}" "net_peerCount" "[]" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin))' 2>/dev/null || echo "")"
		if [[ -n "${raw_peers}" ]]; then
			pc="$(hex_to_dec "${raw_peers}")"
			if (( pc < 1 )); then
				msg="${ts} node${node_n}: peer loss — peerCount=${pc}"
				echo "WARN: ${msg}"
				errors+=("${msg}")
				peer_losses=$(( peer_losses + 1 ))
			fi
		fi
	done

	analysis="$(python3 - <<PY
import json, urllib.request, sys
nodes = ${NODES@Q}.split(',')
url = nodes[0]
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
genesis = rpc("tos_getBlockByNumber", ["0x0", False])
period_ms = dec(epoch_info.get("targetBlockPeriodMs") or "0x0")
turn_length = dec(epoch_info.get("turnLength") or "0x0")
if period_ms <= 0 or turn_length <= 0:
    raise SystemExit(json.dumps({"error": "invalid epoch info", "group_errors": 1}))
lag = latest - dec(finalized["number"]) if finalized else 0
sample_len = min(latest, max(turn_length * group_factor, 16))
start = max(1, latest - sample_len + 1)
group_counts = {}
ordered_groups = []
group_totals = {}
records = []
for num in range(start, latest + 1):
    block = rpc("tos_getBlockByNumber", [hex(num), False])
    miner = str(block["miner"]).lower()
    ts = dec(block["timestamp"])
    slot = (ts - dec(genesis["timestamp"])) // period_ms
    if slot < 1:
        raise SystemExit(json.dumps({"error": f"block {num} has invalid slot {slot}", "group_errors": 1}))
    group = (slot - 1) // turn_length
    records.append({"number": num, "miner": miner, "slot": slot, "group": group})
    if group not in group_counts:
        group_counts[group] = {}
        ordered_groups.append(group)
    group_counts[group][miner] = group_counts[group].get(miner, 0) + 1
    group_totals[group] = group_totals.get(group, 0) + 1
if len(ordered_groups) >= 2:
    dominant = {}
    out_of_turn = 0
    strict_groups = ordered_groups[1:-1] if len(ordered_groups) > 2 else ordered_groups
    for group in ordered_groups:
        miner, count = max(group_counts[group].items(), key=lambda item: item[1])
        dominant[group] = miner
        out_of_turn += group_totals[group] - count
        if group in strict_groups and count * 2 <= group_totals[group]:
            raise SystemExit(json.dumps({"error": f"group {group} has no dominant proposer: {group_counts[group]}", "group_errors": 1}))
    for i in range(1, len(strict_groups)):
        prev_group = strict_groups[i - 1]
        curr_group = strict_groups[i]
        if dominant[prev_group] == dominant[curr_group]:
            raise SystemExit(json.dumps({"error": f"group rotation stalled across {prev_group}->{curr_group}", "group_errors": 1}))
print(json.dumps({
    "latest": latest,
    "turnLength": turn_length,
    "groupCount": len(ordered_groups),
    "groups": ordered_groups,
    "maxGroup": ordered_groups[-1] if ordered_groups else None,
    "rotationObserved": len(ordered_groups) >= 2,
    "outOfTurnBlocks": out_of_turn if len(ordered_groups) >= 2 else 0,
    "group_errors": 0,
    "finalityLag": lag,
    "finalityAlert": lag > finality_lag_max,
    "records": records,
}))
PY
2>/dev/null || true)"

	if [[ -z "${analysis}" ]]; then
		msg="${ts} grouped-turn analysis failed"
		echo "WARN: ${msg}"
		errors+=("${msg}")
		group_errors=$(( group_errors + 1 ))
	else
		if python3 -c 'import json,sys; body=json.loads(sys.stdin.read()); sys.exit(0 if "error" in body else 1)' <<<"${analysis}"; then
			msg="${ts} $(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["error"])' <<<"${analysis}")"
			echo "WARN: ${msg}"
			errors+=("${msg}")
			group_errors=$(( group_errors + 1 ))
		else
			lag="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["finalityLag"])' <<<"${analysis}")"
			if (( lag > max_finality_lag )); then
				max_finality_lag="${lag}"
			fi
			if python3 -c 'import json,sys; sys.exit(0 if json.loads(sys.stdin.read())["finalityAlert"] else 1)' <<<"${analysis}"; then
				msg="${ts} finalized lag ${lag} exceeds threshold ${FINALITY_LAG_MAX_BLOCKS}"
				echo "WARN: ${msg}"
				errors+=("${msg}")
				finality_alerts=$(( finality_alerts + 1 ))
			fi
			groups_csv="$(python3 -c 'import json,sys; print(",".join(str(x) for x in json.loads(sys.stdin.read())["groups"]))' <<<"${analysis}")"
			if [[ -n "${groups_csv}" ]]; then
				IFS=',' read -ra groups_arr <<< "${groups_csv}"
				for g in "${groups_arr[@]}"; do
					if [[ -n "${g}" && ! " ${groups_seen[*]} " =~ " ${g} " ]]; then
						groups_seen+=("${g}")
					fi
				done
			fi
		fi
	fi

	if (( polls % 10 == 0 )); then
		elapsed=$(( $(date -u +%s) - START_TS ))
		remaining=$(( DEADLINE - $(date -u +%s) ))
		echo "${ts} polls=${polls} blocks=${prev_block[0]} halts=${halts} peer_losses=${peer_losses} group_errors=${group_errors} max_finality_lag=${max_finality_lag} elapsed=${elapsed}s remaining=${remaining}s"
	fi
done

END_TS="$(date -u +%s)"
ELAPSED=$(( END_TS - START_TS ))
BLOCKS_END="${prev_block[0]}"
RESULT="PASS"
if (( halts > 0 || group_errors > 0 )); then RESULT="FAIL"; fi

echo ""
echo "==> soak complete"
echo "result:            ${RESULT}"
echo "duration:          ${ELAPSED}s"
echo "polls:             ${polls}"
echo "halts:             ${halts}"
echo "peer_losses:       ${peer_losses}"
echo "group_errors:      ${group_errors}"
echo "finality_alerts:   ${finality_alerts}"
echo "max_finality_lag:  ${max_finality_lag}"
echo "blocks:            ${BLOCKS_START} -> ${BLOCKS_END}"
echo "groups_seen:       ${#groups_seen[@]}"
echo "errors:            ${#errors[@]}"

ERRORS_JSON="$(python3 -c 'import json,sys; print(json.dumps([l for l in sys.stdin.read().splitlines() if l]))' <<< "$(printf '%s\n' "${errors[@]+${errors[@]}}")")"
GROUPS_JSON="$(python3 -c 'import json,sys; print(json.dumps([int(l) for l in sys.stdin.read().splitlines() if l]))' <<< "$(printf '%s\n' "${groups_seen[@]+${groups_seen[@]}}")")"

python3 - "${START_TS}" "${END_TS}" "${ELAPSED}" "${DURATION}" "${INTERVAL}" \
          "${polls}" "${halts}" "${peer_losses}" "${group_errors}" "${finality_alerts}" \
          "${max_finality_lag}" "${BLOCKS_START}" "${BLOCKS_END}" "${RESULT}" \
          "${OUT}" "${ERRORS_JSON}" "${GROUPS_JSON}" <<'PY'
import json, sys, datetime
(start_ts, end_ts, elapsed, target_dur, interval,
 polls, halts, peer_losses, group_errors, finality_alerts,
 max_finality_lag, blocks_start, blocks_end, result,
 out, errors_json, groups_json) = sys.argv[1:]
report = {
    "start_time": datetime.datetime.utcfromtimestamp(int(start_ts)).isoformat() + "Z",
    "end_time": datetime.datetime.utcfromtimestamp(int(end_ts)).isoformat() + "Z",
    "duration_sec": int(elapsed),
    "target_duration": target_dur,
    "interval_sec": int(interval),
    "polls": int(polls),
    "halts": int(halts),
    "peer_losses": int(peer_losses),
    "group_errors": int(group_errors),
    "finality_alerts": int(finality_alerts),
    "max_finality_lag": int(max_finality_lag),
    "blocks_start": int(blocks_start),
    "blocks_end": int(blocks_end),
    "groups_seen": json.loads(groups_json),
    "result": result,
    "errors": json.loads(errors_json),
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
print(out)
PY
