#!/usr/bin/env bash
set -euo pipefail

# TPS matrix benchmark on an existing running GTOS network.
# Metrics:
# 1) submit TPS    : RPC-accepted txs / run duration
# 2) committed TPS : receipts found (mined) / run duration
# 3) finalized TPS : mined txs with confirmations >= FINALITY_DEPTH / run duration

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
NODES="${NODES:-http://127.0.0.1:8545,http://127.0.0.1:8547,http://127.0.0.1:8549}"
DURATION="${DURATION:-120}"
WALLETS="${WALLETS:-24}"
PROFILES="${PROFILES:-2,4,8}"
FINALITY_DEPTH="${FINALITY_DEPTH:-12}"
PERIOD_MS="${PERIOD_MS:-360}"
FINALITY_WAIT_SEC="${FINALITY_WAIT_SEC:-8}"
WORKER_DELAY_MS="${WORKER_DELAY_MS:-30}"
TX_VALUE_WEI="${TX_VALUE_WEI:-1}"
FUND_WEI="${FUND_WEI:-1000000000000000}"
FUNDING_RECEIPT_TIMEOUT="${FUNDING_RECEIPT_TIMEOUT:-30}"
FUNDER="${FUNDER:-0x25e8750786adb41f9725d7bfc8dec9de30521661c53750b142a8ebfa68b85bbe}"
FUNDER_SIGNER="${FUNDER_SIGNER:-elgamal}"
OUT_ROOT="${OUT_ROOT:-${ROOT_DIR}/benchmarks/transfer/matrix}"

usage() {
	cat <<'EOF'
Usage: scripts/tps_matrix.sh [options]

Run transfer TPS profiles on a live GTOS network and output submit/committed/finalized TPS.

Options:
  --rpc <url>               RPC endpoint (default: http://127.0.0.1:8545)
  --nodes <csv>             node endpoints for status context
  --duration <sec>          load duration per profile (default: 120)
  --wallets <n>             wallet count for load generation (default: 24)
  --profiles <csv>          worker profiles, e.g. 2,4,8 (default: 2,4,8)
  --finality-depth <n>      confirmations depth for finalized metric (default: 12)
  --period-ms <ms>          target block period (default: 360)
  --finality-wait <sec>     wait before finalized scan (default: 8)
  --worker-delay-ms <ms>    delay per worker loop (default: 30)
  --tx-value-wei <n>        transfer value in wei (default: 1)
  --fund-wei <n>            prefund value per wallet (default: 1000000000000000)
  --funding-receipt-timeout <sec>
                            timeout waiting each funding receipt (default: 30)
  --funder <addr>           optional funder override
  --funder-signer <type>    optional funder signer type override
  --out-root <path>         output root dir
  -h, --help                show help
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--rpc)
		RPC_URL="$2"
		shift 2
		;;
	--nodes)
		NODES="$2"
		shift 2
		;;
	--duration)
		DURATION="$2"
		shift 2
		;;
	--wallets)
		WALLETS="$2"
		shift 2
		;;
	--profiles)
		PROFILES="$2"
		shift 2
		;;
	--finality-depth)
		FINALITY_DEPTH="$2"
		shift 2
		;;
	--period-ms)
		PERIOD_MS="$2"
		shift 2
		;;
	--finality-wait)
		FINALITY_WAIT_SEC="$2"
		shift 2
		;;
	--worker-delay-ms)
		WORKER_DELAY_MS="$2"
		shift 2
		;;
	--tx-value-wei)
		TX_VALUE_WEI="$2"
		shift 2
		;;
	--fund-wei)
		FUND_WEI="$2"
		shift 2
		;;
	--funding-receipt-timeout)
		FUNDING_RECEIPT_TIMEOUT="$2"
		shift 2
		;;
	--funder)
		FUNDER="$2"
		shift 2
		;;
	--funder-signer)
		FUNDER_SIGNER="$2"
		shift 2
		;;
	--out-root)
		OUT_ROOT="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "Unknown argument: $1" >&2
		usage
		exit 1
		;;
	esac
done

for cmd in curl jq python3; do
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "Missing required command: ${cmd}" >&2
		exit 1
	fi
done

if [[ ! "${DURATION}" =~ ^[0-9]+$ ]] || (( DURATION <= 0 )); then
	echo "Invalid --duration: ${DURATION}" >&2
	exit 1
fi
if [[ ! "${WALLETS}" =~ ^[0-9]+$ ]] || (( WALLETS < 3 )); then
	echo "Invalid --wallets: ${WALLETS}" >&2
	exit 1
fi
if [[ ! "${FINALITY_DEPTH}" =~ ^[0-9]+$ ]] || (( FINALITY_DEPTH < 0 )); then
	echo "Invalid --finality-depth: ${FINALITY_DEPTH}" >&2
	exit 1
fi
if [[ ! "${PERIOD_MS}" =~ ^[0-9]+$ ]] || (( PERIOD_MS <= 0 )); then
	echo "Invalid --period-ms: ${PERIOD_MS}" >&2
	exit 1
fi
if [[ ! "${FINALITY_WAIT_SEC}" =~ ^[0-9]+$ ]] || (( FINALITY_WAIT_SEC < 0 )); then
	echo "Invalid --finality-wait: ${FINALITY_WAIT_SEC}" >&2
	exit 1
fi
if [[ ! "${FUNDING_RECEIPT_TIMEOUT}" =~ ^[0-9]+$ ]] || (( FUNDING_RECEIPT_TIMEOUT < 0 )); then
	echo "Invalid --funding-receipt-timeout: ${FUNDING_RECEIPT_TIMEOUT}" >&2
	exit 1
fi

rpc_get_block_dec() {
	local raw
	raw="$(curl -sS --max-time 8 -H 'Content-Type: application/json' \
		--data '{"jsonrpc":"2.0","id":1,"method":"tos_blockNumber","params":[]}' \
		"${RPC_URL}" | jq -r '.result')"
	if [[ "${raw}" =~ ^0x[0-9a-fA-F]+$ ]]; then
		echo $((16#${raw:2}))
		return 0
	fi
	echo "0"
}

STAMP="$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="${OUT_ROOT}/${STAMP}"
mkdir -p "${RUN_DIR}"

SUMMARY_TSV="${RUN_DIR}/summary.tsv"
SUMMARY_MD="${RUN_DIR}/summary.md"

echo -e "profile\tworkers\tduration_s\tsubmitted\tsubmit_tps\tcommitted\tcommitted_tps\tfinalized\tfinalized_tps\tfinality_depth\thead_before\thead_after_run\thead_after_finalize\trun_dir" >"${SUMMARY_TSV}"

echo "==> TPS matrix benchmark"
echo "run_dir=${RUN_DIR}"
echo "rpc=${RPC_URL}"
echo "nodes=${NODES}"
echo "duration=${DURATION}s per profile"
echo "profiles=${PROFILES}"
echo "finality_depth=${FINALITY_DEPTH}"
echo "period_ms=${PERIOD_MS}"
echo "wallets=${WALLETS}"
echo "funding_receipt_timeout=${FUNDING_RECEIPT_TIMEOUT}s"
if [[ -n "${FUNDER}" ]]; then
	echo "funder_override=${FUNDER}"
fi
if [[ -n "${FUNDER_SIGNER}" ]]; then
	echo "funder_signer_override=${FUNDER_SIGNER}"
fi

if [[ -x "${ROOT_DIR}/scripts/local_testnet_3nodes.sh" ]]; then
	"${ROOT_DIR}/scripts/local_testnet_3nodes.sh" status || true
fi

IFS=',' read -r -a profile_workers <<<"${PROFILES}"

for workers in "${profile_workers[@]}"; do
	workers="$(echo "${workers}" | xargs)"
	if [[ -z "${workers}" ]]; then
		continue
	fi
	if [[ ! "${workers}" =~ ^[0-9]+$ ]] || (( workers <= 0 )); then
		echo "Invalid worker profile: ${workers}" >&2
		exit 1
	fi

	profile="w${workers}"
	profile_dir="${RUN_DIR}/${profile}"
	log_file="${RUN_DIR}/${profile}.log"
	mkdir -p "${profile_dir}"

	head_before="$(rpc_get_block_dec)"
	echo
	echo "[${profile}] head_before=${head_before}"
	echo "[${profile}] start load"

	(
		cd "${ROOT_DIR}"
		cmd=(
			./scripts/plain_transfer_soak.sh
			--rpc "${RPC_URL}"
			--nodes "${NODES}"
			--duration "${DURATION}s"
			--wallets "${WALLETS}"
			--workers "${workers}"
			--fund-wei "${FUND_WEI}"
			--funding-receipt-timeout "${FUNDING_RECEIPT_TIMEOUT}"
			--tx-value-wei "${TX_VALUE_WEI}"
			--nonce-source latest
			--max-pending-gap 0
			--worker-delay-ms "${WORKER_DELAY_MS}"
			--skip-dpos-monitor
			--out-dir "${profile_dir}"
		)
		if [[ -n "${FUNDER}" ]]; then
			cmd+=(--funder "${FUNDER}")
		fi
		if [[ -n "${FUNDER_SIGNER}" ]]; then
			cmd+=(--funder-signer "${FUNDER_SIGNER}")
		fi
		"${cmd[@]}" | tee "${log_file}"
	)

	head_after_run="$(rpc_get_block_dec)"
	if (( FINALITY_WAIT_SEC > 0 )); then
		sleep "${FINALITY_WAIT_SEC}"
	fi
	head_after_finalize="$(rpc_get_block_dec)"

	report_json="${profile_dir}/plain_transfer_report.json"
	accept_log="${profile_dir}/tx_accept.log"
	analysis_json="${profile_dir}/analysis.json"

	python3 - "${RPC_URL}" "${report_json}" "${accept_log}" "${FINALITY_DEPTH}" "${PERIOD_MS}" "${head_before}" "${head_after_run}" "${head_after_finalize}" "${DURATION}" "${analysis_json}" <<'PY'
import json
import sys
import urllib.request

(
    rpc_url,
    report_json,
    accept_log,
    finality_depth,
    period_ms,
    head_before,
    head_after_run,
    head_after_finalize,
    configured_duration,
    out_json,
) = sys.argv[1:]

finality_depth = int(finality_depth)
period_ms = int(period_ms)
head_before = int(head_before)
head_after_run = int(head_after_run)
head_after_finalize = int(head_after_finalize)

with open(report_json, "r", encoding="utf-8") as f:
    report = json.load(f)

duration_sec = max(1, int(configured_duration))
wall_duration_sec = int(report.get("duration_sec", duration_sec))
submitted = int(report.get("accepted", 0))

def rpc(method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        raw = resp.read().decode()
    obj = json.loads(raw)
    if "error" in obj:
        return None
    return obj.get("result")

def block_tx_count(start_inclusive, end_inclusive):
    if end_inclusive < start_inclusive:
        return 0
    total = 0
    for n in range(start_inclusive, end_inclusive + 1):
        block = rpc("tos_getBlockByNumber", [hex(n), False])
        if not block:
            continue
        total += len(block.get("transactions", []))
    return total

committed_from = head_before + 1
committed_to = head_after_run
finalized_limit = head_after_finalize - finality_depth
finalized_to = min(committed_to, finalized_limit)

committed = block_tx_count(committed_from, committed_to)
finalized = block_tx_count(committed_from, finalized_to)

submit_tps = submitted / duration_sec if duration_sec > 0 else 0.0
committed_tps = committed / duration_sec if duration_sec > 0 else 0.0
finalized_tps = finalized / duration_sec if duration_sec > 0 else 0.0

out = {
    "duration_sec": duration_sec,
    "wall_duration_sec": wall_duration_sec,
    "submitted": submitted,
    "committed": committed,
    "finalized": finalized,
    "submit_tps": round(submit_tps, 2),
    "committed_tps": round(committed_tps, 2),
    "finalized_tps": round(finalized_tps, 2),
    "finality_depth": finality_depth,
    "head_before": head_before,
    "head_after_run": head_after_run,
    "head_after_finalize": head_after_finalize,
    "committed_range": [committed_from, committed_to],
    "finalized_range": [committed_from, finalized_to],
    "finalized_limit_block": finalized_limit,
}

with open(out_json, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)

print(json.dumps(out))
PY

	readarray -t metrics < <(python3 - "${analysis_json}" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(d["duration_sec"])
print(d["submitted"])
print(d["submit_tps"])
print(d["committed"])
print(d["committed_tps"])
print(d["finalized"])
print(d["finalized_tps"])
print(d["head_before"])
print(d["head_after_run"])
print(d["head_after_finalize"])
print(d["finality_depth"])
PY
)

	duration_s="${metrics[0]}"
	submitted="${metrics[1]}"
	submit_tps="${metrics[2]}"
	committed="${metrics[3]}"
	committed_tps="${metrics[4]}"
	finalized="${metrics[5]}"
	finalized_tps="${metrics[6]}"
	head_before_m="${metrics[7]}"
	head_after_run_m="${metrics[8]}"
	head_after_finalize_m="${metrics[9]}"
	fdepth="${metrics[10]}"

	echo -e "${profile}\t${workers}\t${duration_s}\t${submitted}\t${submit_tps}\t${committed}\t${committed_tps}\t${finalized}\t${finalized_tps}\t${fdepth}\t${head_before_m}\t${head_after_run_m}\t${head_after_finalize_m}\t${profile_dir}" >>"${SUMMARY_TSV}"
	echo "[${profile}] submit_tps=${submit_tps} committed_tps=${committed_tps} finalized_tps=${finalized_tps}"
done

python3 - "${SUMMARY_TSV}" "${SUMMARY_MD}" "${STAMP}" "${RPC_URL}" <<'PY'
import csv
import datetime
import sys

tsv, out_md, stamp, rpc = sys.argv[1:]
rows = []
with open(tsv, newline="", encoding="utf-8") as f:
    rd = csv.DictReader(f, delimiter="\t")
    rows.extend(rd)

now = datetime.datetime.utcnow().isoformat() + "Z"
lines = []
lines.append("# GTOS TPS Matrix Results")
lines.append("")
lines.append(f"- run_id: `{stamp}`")
lines.append(f"- generated_at: `{now}`")
lines.append(f"- rpc: `{rpc}`")
lines.append("")
lines.append("| profile | workers | duration_s | submitted | submit_tps | committed | committed_tps | finalized | finalized_tps | finality_depth |")
lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
for r in rows:
    lines.append(
        f"| {r['profile']} | {r['workers']} | {r['duration_s']} | {r['submitted']} | {r['submit_tps']} | {r['committed']} | {r['committed_tps']} | {r['finalized']} | {r['finalized_tps']} | {r['finality_depth']} |"
    )
with open(out_md, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
PY

echo
echo "==> Done"
echo "summary_tsv: ${SUMMARY_TSV}"
echo "summary_md : ${SUMMARY_MD}"
echo "Rendered summary:"
column -t -s $'\t' "${SUMMARY_TSV}"
