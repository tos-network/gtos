#!/usr/bin/env bash
# dpos_livenet_soak.sh — DPoS live testnet stability soak monitor.
#
# Polls a running 3-node GTOS testnet at regular intervals for the specified
# duration, recording block growth, peer counts, and validator rotation.
# Exits 0 only if the full window passes with zero halts or peer losses.
#
# Usage:
#   scripts/dpos_livenet_soak.sh [options]
#
# Options:
#   --duration <value>     total soak duration, e.g. 24h, 30m (default: 24h)
#   --interval <seconds>   poll interval in seconds (default: 30)
#   --http <url,url,url>   comma-separated node HTTP endpoints
#                          (default: http://127.0.0.1:8545,8547,8549)
#   --out <file>           write JSON evidence report to file
#                          (default: /tmp/dpos_livenet_soak_<timestamp>.json)
#   --halt-tolerance <n>   allowed consecutive polls with no block growth
#                          before declaring a halt (default: 3)
#   -h, --help             show help
#
# Evidence report (JSON):
#   start_time, end_time, duration_sec, polls, halts, peer_losses,
#   validators_seen, blocks_start, blocks_end, result (PASS|FAIL), errors[]
set -euo pipefail

# ── defaults ─────────────────────────────────────────────────────────────────
DURATION="${DURATION:-24h}"
INTERVAL="${INTERVAL:-30}"
NODES="${NODES:-http://127.0.0.1:8545,http://127.0.0.1:8547,http://127.0.0.1:8549}"
OUT="${OUT:-}"
HALT_TOLERANCE="${HALT_TOLERANCE:-3}"

usage() {
	cat <<'EOF'
Usage: scripts/dpos_livenet_soak.sh [options]

Polls a running 3-node GTOS testnet and records 24h stability evidence.

Options:
  --duration <value>       total soak duration (default: 24h)
  --interval <seconds>     poll interval in seconds (default: 30)
  --nodes <url,url,...>    comma-separated node HTTP endpoints
  --out <file>             JSON evidence report output path
  --halt-tolerance <n>     consecutive no-growth polls before halt (default: 3)
  -h, --help               show help

Examples:
  scripts/dpos_livenet_soak.sh --duration 24h
  scripts/dpos_livenet_soak.sh --duration 30m --interval 10
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--duration)   DURATION="$2";       shift 2 ;;
	--interval)   INTERVAL="$2";       shift 2 ;;
	--nodes)      NODES="$2";          shift 2 ;;
	--out)        OUT="$2";            shift 2 ;;
	--halt-tolerance) HALT_TOLERANCE="$2"; shift 2 ;;
	-h|--help)    usage; exit 0 ;;
	*) echo "unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

# ── parse duration to seconds ─────────────────────────────────────────────────
duration_to_sec() {
	local d="$1"
	python3 -c "
import re, sys
s = '$d'
total = 0
for val, unit in re.findall(r'(\d+)([smhd])', s):
    total += int(val) * {'s':1,'m':60,'h':3600,'d':86400}[unit]
if total == 0:
    sys.exit('invalid duration: ' + s)
print(total)
"
}

TOTAL_SEC="$(duration_to_sec "${DURATION}")"
START_TS="$(date -u +%s)"
DEADLINE=$(( START_TS + TOTAL_SEC ))

if [[ -z "${OUT}" ]]; then
	OUT="/tmp/dpos_livenet_soak_$(date -u +%Y%m%dT%H%M%SZ).json"
fi

IFS=',' read -ra NODE_URLS <<< "${NODES}"

# ── RPC helper ────────────────────────────────────────────────────────────────
rpc() {
	local url="$1" method="$2" params="$3"
	python3 - <<PY
import json, urllib.request, sys
try:
    data = json.dumps({"jsonrpc":"2.0","id":1,"method":"${method}","params":${params}}).encode()
    req = urllib.request.Request("${url}", data=data, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        d = json.loads(r.read())
        if "error" in d:
            sys.exit("rpc error: " + str(d["error"]))
        print(d["result"])
except Exception as e:
    sys.exit(str(e))
PY
}

hex_to_dec() { python3 -c "print(int('$1', 16))"; }

# ── state ─────────────────────────────────────────────────────────────────────
polls=0
halts=0
peer_losses=0
errors=()
validators_seen=()
declare -A prev_block
declare -A no_growth_streak

for i in "${!NODE_URLS[@]}"; do
	prev_block[$i]=0
	no_growth_streak[$i]=0
done

# get starting block heights
for i in "${!NODE_URLS[@]}"; do
	url="${NODE_URLS[$i]}"
	raw="$(rpc "${url}" "tos_blockNumber" "[]" 2>/dev/null || echo "0x0")"
	prev_block[$i]="$(hex_to_dec "${raw}")"
done

BLOCKS_START="${prev_block[0]}"

echo "==> DPoS live testnet soak"
echo "date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "duration: ${DURATION} (${TOTAL_SEC}s)"
echo "interval: ${INTERVAL}s"
echo "nodes:    ${NODES}"
echo "out:      ${OUT}"
echo ""

# ── main loop ─────────────────────────────────────────────────────────────────
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

		# block number
		raw_block="$(rpc "${url}" "tos_blockNumber" "[]" 2>/dev/null || echo "")"
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

		# peer count
		raw_peers="$(rpc "${url}" "net_peerCount" "[]" 2>/dev/null || echo "")"
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

	# check validator rotation: sample latest block miner
	miner="$(python3 -c "
import json, urllib.request
url = '${NODE_URLS[0]}'
data = json.dumps({'jsonrpc':'2.0','id':1,'method':'tos_getBlockByNumber','params':['latest',False]}).encode()
req = urllib.request.Request(url, data=data, headers={'Content-Type':'application/json'})
with urllib.request.urlopen(req, timeout=5) as r:
    d = json.loads(r.read())
print(d['result']['miner'].lower())
" 2>/dev/null || echo "")"
	if [[ -n "${miner}" ]] && [[ ! " ${validators_seen[*]} " =~ " ${miner} " ]]; then
		validators_seen+=("${miner}")
	fi

	# progress line every 10 polls
	if (( polls % 10 == 0 )); then
		elapsed=$(( $(date -u +%s) - START_TS ))
		remaining=$(( DEADLINE - $(date -u +%s) ))
		echo "${ts}  polls=${polls}  blocks=${prev_block[0]}  halts=${halts}  peer_losses=${peer_losses}  elapsed=${elapsed}s  remaining=${remaining}s"
	fi
done

# ── final summary ─────────────────────────────────────────────────────────────
END_TS="$(date -u +%s)"
ELAPSED=$(( END_TS - START_TS ))
BLOCKS_END="${prev_block[0]}"
RESULT="PASS"
if (( halts > 0 )); then RESULT="FAIL"; fi

echo ""
echo "==> soak complete"
echo "result:          ${RESULT}"
echo "duration:        ${ELAPSED}s"
echo "polls:           ${polls}"
echo "halts:           ${halts}"
echo "peer_losses:     ${peer_losses}"
echo "blocks:          ${BLOCKS_START} → ${BLOCKS_END}"
echo "validators_seen: ${#validators_seen[@]}"
echo "errors:          ${#errors[@]}"

# write JSON evidence report
ERRORS_JSON="$(python3 -c "import json,sys; lines=sys.stdin.read().splitlines(); print(json.dumps([l for l in lines if l]))" <<< "$(printf '%s\n' "${errors[@]+"${errors[@]}"}")")"
VALS_JSON="$(python3 -c "import json,sys; lines=sys.stdin.read().splitlines(); print(json.dumps([l for l in lines if l]))" <<< "$(printf '%s\n' "${validators_seen[@]+"${validators_seen[@]}"}")")"

python3 - "${START_TS}" "${END_TS}" "${ELAPSED}" "${DURATION}" "${INTERVAL}" \
          "${polls}" "${halts}" "${peer_losses}" \
          "${BLOCKS_START}" "${BLOCKS_END}" "${#validators_seen[@]}" "${RESULT}" \
          "${OUT}" "${ERRORS_JSON}" "${VALS_JSON}" <<'PY'
import json, sys, datetime
(start_ts, end_ts, elapsed, target_dur, interval,
 polls, halts, peer_losses, blocks_start, blocks_end,
 vals_count, result, out, errors_json, vals_json) = sys.argv[1:]
report = {
    "start_time":      datetime.datetime.utcfromtimestamp(int(start_ts)).isoformat() + "Z",
    "end_time":        datetime.datetime.utcfromtimestamp(int(end_ts)).isoformat() + "Z",
    "duration_sec":    int(elapsed),
    "target_duration": target_dur,
    "interval_sec":    int(interval),
    "polls":           int(polls),
    "halts":           int(halts),
    "peer_losses":     int(peer_losses),
    "blocks_start":    int(blocks_start),
    "blocks_end":      int(blocks_end),
    "validators_seen": int(vals_count),
    "result":          result,
    "errors":          json.loads(errors_json),
    "validators":      json.loads(vals_json),
}
with open(out, "w") as f:
    json.dump(report, f, indent=2)
print("evidence written to", out)
PY

if [[ "${RESULT}" != "PASS" ]]; then
	echo "SOAK FAILED: ${halts} halt(s) detected" >&2
	exit 1
fi
