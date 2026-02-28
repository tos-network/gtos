#!/usr/bin/env bash
# plain_transfer_soak.sh — 3-node DPoS public transfer stability soak.
#
# Runs two workloads in parallel for the same duration:
# 1) dpos_livenet_soak.sh consensus health monitor (halts/peer losses/validators seen)
# 2) Multi-wallet concurrent plain transfers via tos_sendTransaction
#
# Outputs a single evidence directory containing logs and JSON reports.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GTOS_BIN="${GTOS_BIN:-${REPO_ROOT}/build/bin/gtos}"

DURATION="${DURATION:-4h}"
RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
NODES="${NODES:-http://127.0.0.1:8545,http://127.0.0.1:8547,http://127.0.0.1:8549}"
UNLOCK_IPC="${UNLOCK_IPC:-/data/gtos/node1/gtos.ipc}"
PASSFILE="${PASSFILE:-/data/gtos/pass.txt}"
NODE_DATADIR="${NODE_DATADIR:-/data/gtos/node1}"
WALLETS="${WALLETS:-12}"
WORKERS="${WORKERS:-12}"
FUND_TOS="${FUND_TOS:-1000}"
FUND_WEI="${FUND_WEI:-0}"
FUNDING_RECEIPT_TIMEOUT="${FUNDING_RECEIPT_TIMEOUT:-120}"
TX_VALUE_WEI="${TX_VALUE_WEI:-1}"
NONCE_SOURCE="${NONCE_SOURCE:-pending}"
MAX_PENDING_GAP="${MAX_PENDING_GAP:-1000000000}"
WORKER_DELAY_MS="${WORKER_DELAY_MS:-30}"
DPOS_INTERVAL="${DPOS_INTERVAL:-30}"
OUT_DIR="${OUT_DIR:-/tmp/plain_transfer_soak_$(date -u +%Y%m%dT%H%M%SZ)}"
SKIP_DPOS_MONITOR="${SKIP_DPOS_MONITOR:-0}"
FUNDER_ADDR_OVERRIDE="${FUNDER_ADDR_OVERRIDE:-}"
FUNDER_SIGNER_TYPE_OVERRIDE="${FUNDER_SIGNER_TYPE_OVERRIDE:-}"

usage() {
	cat <<'EOF'
Usage: scripts/plain_transfer_soak.sh [options]

Run plain transfer soak and DPoS liveness monitor together.

Options:
  --duration <value>      total soak duration, e.g. 4h, 30m (default: 4h)
  --rpc <url>             tx RPC endpoint (default: http://127.0.0.1:8545)
  --nodes <csv>           node HTTP endpoints for dpos monitor
                          (default: 8545,8547,8549 localhost)
  --unlock-ipc <path>     IPC endpoint for personal_newAccount/unlock
                          (default: /data/gtos/node1/gtos.ipc)
  --passfile <path>       password file for personal RPC unlock
                          (default: /data/gtos/pass.txt)
  --node-datadir <path>   datadir for creating additional local accounts
                          (default: /data/gtos/node1)
  --wallets <n>           total wallets participating (default: 12)
  --workers <n>           concurrent transfer workers (default: 12)
  --fund-tos <n>          prefund amount for each wallet in TOS (default: 1000)
  --fund-wei <n>          prefund amount for each wallet in wei (overrides --fund-tos)
  --funding-receipt-timeout <sec>
                          timeout when waiting each funding tx receipt
                          (default: 120, set 0 to skip waiting)
  --tx-value-wei <n>      per transfer value in wei (default: 1)
  --nonce-source <mode>   pending|latest (default: pending)
  --max-pending-gap <n>   skip accounts with pending-latest nonce gap > n
                          (default: 1000000000)
  --funder <addr>         override funding account address
  --funder-signer <type>  override funding signer type
  --worker-delay-ms <n>   sleep per worker loop in ms (default: 30)
  --dpos-interval <n>     dpos monitor poll interval in sec (default: 30)
  --skip-dpos-monitor     skip launching dpos_livenet_soak inside this script
  --out-dir <path>        evidence output directory
  -h, --help              show help
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--duration)
		DURATION="$2"
		shift 2
		;;
	--rpc)
		RPC_URL="$2"
		shift 2
		;;
	--nodes)
		NODES="$2"
		shift 2
		;;
	--unlock-ipc)
		UNLOCK_IPC="$2"
		shift 2
		;;
	--passfile)
		PASSFILE="$2"
		shift 2
		;;
	--node-datadir)
		NODE_DATADIR="$2"
		shift 2
		;;
	--wallets)
		WALLETS="$2"
		shift 2
		;;
	--workers)
		WORKERS="$2"
		shift 2
		;;
	--fund-tos)
		FUND_TOS="$2"
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
	--tx-value-wei)
		TX_VALUE_WEI="$2"
		shift 2
		;;
	--nonce-source)
		NONCE_SOURCE="$2"
		shift 2
		;;
	--max-pending-gap)
		MAX_PENDING_GAP="$2"
		shift 2
		;;
	--funder)
		FUNDER_ADDR_OVERRIDE="$2"
		shift 2
		;;
	--funder-signer)
		FUNDER_SIGNER_TYPE_OVERRIDE="$2"
		shift 2
		;;
	--worker-delay-ms)
		WORKER_DELAY_MS="$2"
		shift 2
		;;
	--dpos-interval)
		DPOS_INTERVAL="$2"
		shift 2
		;;
	--skip-dpos-monitor)
		SKIP_DPOS_MONITOR=1
		shift
		;;
	--out-dir)
		OUT_DIR="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		usage
		exit 1
		;;
	esac
done

if [[ "${NONCE_SOURCE}" != "pending" && "${NONCE_SOURCE}" != "latest" ]]; then
	echo "invalid --nonce-source: ${NONCE_SOURCE}, expected pending|latest" >&2
	exit 1
fi
if [[ ! "${MAX_PENDING_GAP}" =~ ^[0-9]+$ ]]; then
	echo "invalid --max-pending-gap: ${MAX_PENDING_GAP}" >&2
	exit 1
fi

duration_to_sec() {
	local d="$1"
	python3 -c "
import re, sys
s = '$d'
total = 0
for val, unit in re.findall(r'(\d+)([smhd])', s):
    total += int(val) * {'s':1,'m':60,'h':3600,'d':86400}[unit]
if total == 0:
    raise SystemExit('invalid duration: ' + s)
print(total)
"
}

to_hex() {
	printf '0x%x' "$1"
}

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

rpc_call() {
	local method="$1"
	local params="$2"
	curl -sS --max-time 8 \
		-H 'Content-Type: application/json' \
		--data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}" \
		"${RPC_URL}" 2>/dev/null || true
}

rpc_result_hex() {
	local method="$1"
	local params="$2"
	local resp
	resp="$(rpc_call "${method}" "${params}")"
	echo "${resp}" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p' | head -n1
}

rpc_pending_nonce_dec() {
	local addr="$1"
	local raw
	raw="$(rpc_result_hex "tos_getTransactionCount" "[\"${addr}\",\"pending\"]")"
	if [[ -z "${raw}" ]]; then
		echo 0
		return 0
	fi
	hex_to_dec "${raw}"
}

rpc_latest_nonce_dec() {
	local addr="$1"
	local raw
	raw="$(rpc_result_hex "tos_getTransactionCount" "[\"${addr}\",\"latest\"]")"
	if [[ -z "${raw}" ]]; then
		echo 0
		return 0
	fi
	hex_to_dec "${raw}"
}

rpc_block_number_dec() {
	local raw
	raw="$(rpc_result_hex "tos_blockNumber" "[]")"
	if [[ -z "${raw}" ]]; then
		echo 0
		return 0
	fi
	hex_to_dec "${raw}"
}

rpc_tx_send() {
	local from="$1"
	local to="$2"
	local value_hex="$3"
	local signer_type="${4:-}"
	local nonce_hex="${5:-}"
	local signer_json nonce_json payload response txhash errmsg
	signer_json=""
	if [[ -n "${signer_type}" ]]; then
		signer_json=",\"signerType\":\"${signer_type}\""
	fi
	nonce_json=""
	if [[ -n "${nonce_hex}" ]]; then
		nonce_json=",\"nonce\":\"${nonce_hex}\""
	fi
	payload="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tos_sendTransaction\",\"params\":[{\"from\":\"${from}\",\"to\":\"${to}\",\"value\":\"${value_hex}\",\"gas\":\"0x5208\"${signer_json}${nonce_json}}]}"
	response="$(curl -sS --max-time 8 -H 'Content-Type: application/json' --data "${payload}" "${RPC_URL}" 2>/dev/null || true)"
	txhash="$(echo "${response}" | sed -n 's/.*"result":"\(0x[0-9a-fA-F]\{64\}\)".*/\1/p' | head -n1)"
	if [[ -n "${txhash}" ]]; then
		echo "${txhash}"
		return 0
	fi
	errmsg="$(echo "${response}" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n1)"
	if [[ -z "${errmsg}" ]]; then
		errmsg="rpc_error_or_invalid_response"
	fi
	echo "${errmsg}"
	return 1
}

wait_receipt_ok() {
	local txhash="$1"
	local timeout_sec="${2:-90}"
	local i resp status
	for ((i = 0; i < timeout_sec; i++)); do
		resp="$(rpc_call "tos_getTransactionReceipt" "[\"${txhash}\"]")"
		if [[ -n "${resp}" ]] && ! grep -q '"result":null' <<<"${resp}"; then
			status="$(echo "${resp}" | sed -n 's/.*"status":"\(0x[0-9a-fA-F]\+\)".*/\1/p' | head -n1)"
			if [[ -z "${status}" || "${status}" == "0x1" || "${status}" == "0x01" ]]; then
				return 0
			fi
			return 1
		fi
		sleep 1
	done
	return 1
}

hex_to_dec() {
	local raw
	raw="$(echo "$1" | tr -d '"[:space:]')"
	if [[ "${raw}" =~ ^0[xX][0-9a-fA-F]+$ ]]; then
		echo $((16#${raw:2}))
		return 0
	fi
	echo 0
}

ipc_exec_result() {
	local js="$1"
	"${GTOS_BIN}" --exec "${js}" attach "${UNLOCK_IPC}" 2>/dev/null | tr -d '\r\n'
}

create_wallet_with_signer() {
	local signer_type="$1"
	local out addr
	out="$("${GTOS_BIN}" --datadir "${NODE_DATADIR}" account new --signer "${signer_type}" --password "${PASSFILE}" 2>&1 || true)"
	addr="$(echo "${out}" | sed -n 's/^Public address of the key:[[:space:]]*\(0x[0-9A-Fa-f]\{64\}\).*/\1/p' | tail -n1 | tr 'A-F' 'a-f')"
	if [[ -z "${addr}" && "${signer_type}" == "secp256k1" ]]; then
		# If datadir is locked by a running node, create through personal API.
		addr="$(ipc_exec_result "web3.currentProvider.send({jsonrpc:\"2.0\",method:\"personal_newAccount\",params:[\"${NODE_PASS}\"],id:1}).result" | tr -d '\"[:space:]' | tr 'A-F' 'a-f')"
		if [[ ! "${addr}" =~ ^0x[0-9a-f]{64}$ ]]; then
			addr=""
		fi
	fi
	[[ -n "${addr}" ]] || return 1
	echo "${addr}"
}

unlock_wallet() {
	local addr="$1"
	local sec="$2"
	local out
	out="$(ipc_exec_result "web3.currentProvider.send({jsonrpc:\"2.0\",method:\"personal_unlockAccount\",params:[\"${addr}\",\"${NODE_PASS}\",${sec}],id:1}).result")"
	out="$(echo "${out}" | tr -d '"[:space:]')"
	[[ "${out}" == "true" ]]
}

declare -A LOCAL_SIGNER_TYPE

load_local_signer_types() {
	local ks_dir="${NODE_DATADIR}/keystore"
	[[ -d "${ks_dir}" ]] || return 0
	while read -r addr st; do
		[[ -n "${addr}" && -n "${st}" ]] || continue
		LOCAL_SIGNER_TYPE["${addr}"]="${st}"
	done < <(python3 - "${ks_dir}" <<'PY'
import glob, json, os, sys
ks_dir = sys.argv[1]
for path in sorted(glob.glob(os.path.join(ks_dir, "*"))):
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception:
        continue
    addr = str(data.get("address", "")).strip().lower()
    if not addr:
        continue
    if not addr.startswith("0x"):
        addr = "0x" + addr
    st = str(data.get("signerType", "secp256k1")).strip().lower() or "secp256k1"
    print(addr, st)
PY
)
}

local_signer_type_of() {
	local addr="${1,,}"
	echo "${LOCAL_SIGNER_TYPE[${addr}]:-secp256k1}"
}

choose_tx_signer_type() {
	local addr st c
	local best=""
	local best_count=0
	declare -A counts=()
	for addr in "${!LOCAL_SIGNER_TYPE[@]}"; do
		st="${LOCAL_SIGNER_TYPE[${addr}]}"
		# Exclude UNO-only key type from plain transfer sender pool.
		if [[ "${st}" == "elgamal" ]]; then
			continue
		fi
		c=$(( ${counts[${st}]:-0} + 1 ))
		counts["${st}"]="${c}"
		if (( c > best_count )); then
			best_count="${c}"
			best="${st}"
		fi
	done
	echo "${best}"
}

TOTAL_SEC="$(duration_to_sec "${DURATION}")"
START_TS="$(date -u +%s)"
DEADLINE=$((START_TS + TOTAL_SEC))
END_TS="${DEADLINE}"

require_cmd python3
require_cmd curl

[[ -x "${GTOS_BIN}" ]] || {
	echo "gtos binary not found: ${GTOS_BIN}" >&2
	exit 1
}
[[ -S "${UNLOCK_IPC}" ]] || {
	echo "unlock ipc not found: ${UNLOCK_IPC}" >&2
	exit 1
}
[[ -s "${PASSFILE}" ]] || {
	echo "passfile not found or empty: ${PASSFILE}" >&2
	exit 1
}

mkdir -p "${OUT_DIR}"
RUN_META="${OUT_DIR}/run.meta"
WALLETS_FILE="${OUT_DIR}/wallets.txt"
SETUP_LOG="${OUT_DIR}/setup.log"
PROGRESS_LOG="${OUT_DIR}/progress.log"
SUCCESS_LOG="${OUT_DIR}/tx_accept.log"
FAIL_LOG="${OUT_DIR}/tx_fail.log"
SOFT_FAIL_LOG="${OUT_DIR}/tx_soft_fail.log"
REPORT_JSON="${OUT_DIR}/plain_transfer_report.json"
DPOS_LOG="${OUT_DIR}/dpos_livenet.log"
DPOS_REPORT="${OUT_DIR}/dpos_livenet_report.json"

touch "${SUCCESS_LOG}" "${FAIL_LOG}" "${SOFT_FAIL_LOG}" "${PROGRESS_LOG}"

NODE_PASS="$(head -n1 "${PASSFILE}" | tr -d '\r\n')"
[[ -n "${NODE_PASS}" ]] || {
	echo "empty password from ${PASSFILE}" >&2
	exit 1
}

load_local_signer_types

if [[ "${FUND_WEI}" =~ ^[0-9]+$ ]] && (( FUND_WEI > 0 )); then
	FUND_VALUE_HEX="$(to_hex "${FUND_WEI}")"
else
	FUND_VALUE_HEX="$(python3 -c "print(hex(int('${FUND_TOS}') * 10**18))")"
fi
TX_VALUE_HEX="$(to_hex "${TX_VALUE_WEI}")"

cat >"${RUN_META}" <<EOF
start_utc=$(date -u -d "@${START_TS}" +%Y-%m-%dT%H:%M:%SZ)
run_root=${OUT_DIR}
duration=${DURATION}
duration_sec=${TOTAL_SEC}
end_ts=${END_TS}
rpc=${RPC_URL}
node_datadir=${NODE_DATADIR}
nodes=${NODES}
wallets=${WALLETS}
workers=${WORKERS}
fund_tos=${FUND_TOS}
fund_wei=${FUND_WEI}
funding_receipt_timeout=${FUNDING_RECEIPT_TIMEOUT}
tx_value_wei=${TX_VALUE_WEI}
nonce_source=${NONCE_SOURCE}
max_pending_gap=${MAX_PENDING_GAP}
dpos_interval=${DPOS_INTERVAL}
skip_dpos_monitor=${SKIP_DPOS_MONITOR}
funder_override=${FUNDER_ADDR_OVERRIDE}
funder_signer_override=${FUNDER_SIGNER_TYPE_OVERRIDE}
EOF

echo "==> plain transfer soak setup" | tee -a "${SETUP_LOG}"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${SETUP_LOG}"
echo "out:  ${OUT_DIR}" | tee -a "${SETUP_LOG}"
echo "rpc:  ${RPC_URL}" | tee -a "${SETUP_LOG}"
echo "ipc:  ${UNLOCK_IPC}" | tee -a "${SETUP_LOG}"
echo "duration: ${DURATION} (${TOTAL_SEC}s)" | tee -a "${SETUP_LOG}"

DPOS_PID=""
if [[ "${SKIP_DPOS_MONITOR}" != "1" ]]; then
	# Start dpos monitor in parallel.
	"${REPO_ROOT}/scripts/dpos_livenet_soak.sh" \
		--duration "${DURATION}" \
		--interval "${DPOS_INTERVAL}" \
		--nodes "${NODES}" \
		--out "${DPOS_REPORT}" >"${DPOS_LOG}" 2>&1 &
	DPOS_PID=$!
	echo "started dpos_livenet_soak pid=${DPOS_PID}" | tee -a "${SETUP_LOG}"
else
	echo "skip dpos monitor: enabled" | tee -a "${SETUP_LOG}"
fi

cleanup() {
	set +e
	for p in "${WORKER_PIDS[@]:-}"; do
		if [[ -n "${p:-}" ]] && kill -0 "${p}" 2>/dev/null; then
			kill "${p}" 2>/dev/null || true
		fi
	done
	if [[ -n "${DPOS_PID:-}" ]] && kill -0 "${DPOS_PID}" 2>/dev/null; then
		kill "${DPOS_PID}" 2>/dev/null || true
	fi
}
trap cleanup INT TERM

# Pick funder account and signer type.
FUNDER_ADDR="$(echo "${FUNDER_ADDR_OVERRIDE}" | tr 'A-F' 'a-f' | tr -d '[:space:]')"
if [[ -z "${FUNDER_ADDR}" ]]; then
	FUNDER_ADDR="$(sed -n 's/^node1=\(0x[0-9a-fA-F]\{64\}\).*/\1/p' /data/gtos/validator_accounts.txt 2>/dev/null | head -n1 | tr 'A-F' 'a-f')"
fi
if [[ -z "${FUNDER_ADDR}" ]]; then
	FUNDER_ADDR="$(echo "$(rpc_call "tos_accounts" "[]")" | grep -o '0x[0-9a-fA-F]\{64\}' | head -n1 | tr 'A-F' 'a-f')"
fi
[[ -n "${FUNDER_ADDR}" ]] || {
	echo "failed to find funder account" >&2
	exit 1
}
FUNDER_SIGNER_TYPE="$(echo "${FUNDER_SIGNER_TYPE_OVERRIDE}" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"
# For funding txs, signer type auto-detection inside node is safer.
# Only force signerType when caller explicitly overrides it.
TX_SIGNER_TYPE="$(choose_tx_signer_type)"
if [[ -z "${TX_SIGNER_TYPE}" ]]; then
	TX_SIGNER_TYPE="${FUNDER_SIGNER_TYPE}"
fi
echo "funder=${FUNDER_ADDR}" | tee -a "${SETUP_LOG}"
if [[ -n "${FUNDER_SIGNER_TYPE}" ]]; then
	echo "funder_signer_type=${FUNDER_SIGNER_TYPE}" | tee -a "${SETUP_LOG}"
else
	echo "funder_signer_type=auto" | tee -a "${SETUP_LOG}"
fi
echo "tx_signer_type=${TX_SIGNER_TYPE}" | tee -a "${SETUP_LOG}"

# Build wallet set from existing node accounts (same signer type as tx pool).
declare -a wallets=()
existing_resp="$(rpc_call "tos_accounts" "[]")"
candidate_file="$(mktemp)"
while IFS= read -r addr; do
	[[ -n "${addr}" ]] || continue
	st="$(local_signer_type_of "${addr}")"
	[[ "${st}" == "${TX_SIGNER_TYPE}" ]] || continue
	latest_nonce="$(rpc_latest_nonce_dec "${addr}")"
	pending_nonce="$(rpc_pending_nonce_dec "${addr}")"
	gap=$((pending_nonce - latest_nonce))
	if (( gap < 0 )); then
		gap=0
	fi
	if (( gap > MAX_PENDING_GAP )); then
		continue
	fi
	printf '%s %s %s\n' "${gap}" "${latest_nonce}" "${addr}" >>"${candidate_file}"
done < <(echo "${existing_resp}" | grep -o '0x[0-9a-fA-F]\{64\}' | tr 'A-F' 'a-f' | awk '!seen[$0]++')

while read -r _gap _latest addr; do
	[[ -n "${addr}" ]] || continue
	wallets+=("${addr}")
	if (( ${#wallets[@]} >= WALLETS )); then
		break
	fi
done < <(sort -n -k1,1 -k2,2 "${candidate_file}")
rm -f "${candidate_file}"

while (( ${#wallets[@]} < WALLETS )); do
	new_addr="$(create_wallet_with_signer "${TX_SIGNER_TYPE}" || true)"
	if [[ -z "${new_addr}" ]]; then
		echo "failed to create new wallet with signer ${TX_SIGNER_TYPE}" | tee -a "${SETUP_LOG}"
		break
	fi
	if ! grep -q "^${new_addr}$" <(printf '%s\n' "${wallets[@]}"); then
		wallets+=("${new_addr}")
		LOCAL_SIGNER_TYPE["${new_addr}"]="${TX_SIGNER_TYPE}"
		echo "created wallet ${new_addr}" | tee -a "${SETUP_LOG}"
	fi
done

if (( ${#wallets[@]} < 3 )); then
	echo "need at least 3 wallets, got ${#wallets[@]}" >&2
	exit 1
fi

printf '%s\n' "${wallets[@]}" >"${WALLETS_FILE}"
echo "wallet_count=${#wallets[@]}" | tee -a "${SETUP_LOG}"

UNLOCK_SEC=$((TOTAL_SEC + 1800))
echo "unlocking wallets for ${UNLOCK_SEC}s" | tee -a "${SETUP_LOG}"
declare -a unlocked_wallets=()
for addr in "${wallets[@]}"; do
	if unlock_wallet "${addr}" "${UNLOCK_SEC}"; then
		unlocked_wallets+=("${addr}")
		echo "unlock ok ${addr}" >>"${SETUP_LOG}"
	else
		echo "unlock failed ${addr}" | tee -a "${SETUP_LOG}"
	fi
done
unlock_wallet "${FUNDER_ADDR}" "${UNLOCK_SEC}" >/dev/null 2>&1 || true

if (( ${#unlocked_wallets[@]} < 3 )); then
	echo "need at least 3 unlocked wallets, got ${#unlocked_wallets[@]}" >&2
	exit 1
fi
wallets=("${unlocked_wallets[@]}")
printf '%s\n' "${wallets[@]}" >"${WALLETS_FILE}"
echo "wallet_count_unlocked=${#wallets[@]}" | tee -a "${SETUP_LOG}"

echo "funding wallets (value=${FUND_VALUE_HEX} per wallet)" | tee -a "${SETUP_LOG}"
echo "to,txhash,status" >"${OUT_DIR}/funding.csv"
for addr in "${wallets[@]}"; do
	if [[ "${addr}" == "${FUNDER_ADDR}" ]]; then
		echo "${addr},self,skip" >>"${OUT_DIR}/funding.csv"
		continue
	fi
	tx_out="$(rpc_tx_send "${FUNDER_ADDR}" "${addr}" "${FUND_VALUE_HEX}" "${FUNDER_SIGNER_TYPE}" || true)"
	if [[ "${tx_out}" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
		if (( FUNDING_RECEIPT_TIMEOUT <= 0 )); then
			echo "${addr},${tx_out},submitted_no_wait" >>"${OUT_DIR}/funding.csv"
		elif wait_receipt_ok "${tx_out}" "${FUNDING_RECEIPT_TIMEOUT}"; then
			echo "${addr},${tx_out},ok" >>"${OUT_DIR}/funding.csv"
		else
			echo "${addr},${tx_out},receipt_timeout_or_failed" >>"${OUT_DIR}/funding.csv"
		fi
	else
		echo "${addr},,send_failed:${tx_out}" >>"${OUT_DIR}/funding.csv"
	fi
done

echo "==> start concurrent transfer workers" | tee -a "${SETUP_LOG}"
declare -a WORKER_PIDS
worker_sleep="$(python3 -c "print(${WORKER_DELAY_MS}/1000.0)")"

worker_loop() {
	local wid="$1"
	local from="$2"
	local to="$3"
	local deadline="$4"
	local attempts=0
	local nonce=0
	local nonce_hex=""
	local err_lc=""
	local worker_log="${OUT_DIR}/worker_${wid}.log"
	if [[ "${NONCE_SOURCE}" == "latest" ]]; then
		nonce="$(rpc_latest_nonce_dec "${from}")"
	else
		nonce="$(rpc_pending_nonce_dec "${from}")"
	fi
	echo "worker=${wid} from=${from} to=${to} started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"${worker_log}"
	echo "worker=${wid} initial_nonce=${nonce}" >>"${worker_log}"
	while (( "$(date -u +%s)" < deadline )); do
		attempts=$((attempts + 1))
		nonce_hex="$(to_hex "${nonce}")"
		out="$(rpc_tx_send "${from}" "${to}" "${TX_VALUE_HEX}" "${TX_SIGNER_TYPE}" "${nonce_hex}" || true)"
		if [[ "${out}" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
			printf '%s worker=%s from=%s to=%s nonce=%s tx=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${wid}" "${from}" "${to}" "${nonce_hex}" "${out}" >>"${SUCCESS_LOG}"
			nonce=$((nonce + 1))
		else
			err_lc="$(echo "${out}" | tr 'A-Z' 'a-z')"
			if [[ "${err_lc}" == *"already known"* || "${err_lc}" == *"nonce too low"* ]]; then
				# This nonce is already in pool/chain; move forward and avoid duplicate spam.
				printf '%s worker=%s from=%s to=%s nonce=%s soft_err=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${wid}" "${from}" "${to}" "${nonce_hex}" "${out}" >>"${SOFT_FAIL_LOG}"
				nonce=$((nonce + 1))
			elif [[ "${err_lc}" == *"nonce too high"* ]]; then
				# Refresh from pool view and continue.
				printf '%s worker=%s from=%s to=%s nonce=%s soft_err=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${wid}" "${from}" "${to}" "${nonce_hex}" "${out}" >>"${SOFT_FAIL_LOG}"
				if [[ "${NONCE_SOURCE}" == "latest" ]]; then
					nonce="$(rpc_latest_nonce_dec "${from}")"
				else
					nonce="$(rpc_pending_nonce_dec "${from}")"
				fi
			else
				printf '%s worker=%s from=%s to=%s nonce=%s err=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${wid}" "${from}" "${to}" "${nonce_hex}" "${out}" >>"${FAIL_LOG}"
			fi
		fi
		sleep "${worker_sleep}"
	done
	echo "worker=${wid} attempts=${attempts} ended_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"${worker_log}"
}

wallet_count="${#wallets[@]}"
for ((i = 0; i < WORKERS; i++)); do
	from_idx=$((i % wallet_count))
	to_idx=$(((i + 1) % wallet_count))
	if (( from_idx == to_idx )); then
		to_idx=$(((to_idx + 1) % wallet_count))
	fi
	worker_loop "${i}" "${wallets[$from_idx]}" "${wallets[$to_idx]}" "${DEADLINE}" &
	WORKER_PIDS+=("$!")
done

echo "workers_started=${#WORKER_PIDS[@]}" | tee -a "${SETUP_LOG}"

prev_block=0
halt_streak=0
while (( "$(date -u +%s)" < DEADLINE )); do
	sleep 30
	accepted_count="$(wc -l <"${SUCCESS_LOG}" | tr -d ' ')"
	fail_count="$(wc -l <"${FAIL_LOG}" | tr -d ' ')"
	soft_fail_count="$(wc -l <"${SOFT_FAIL_LOG}" | tr -d ' ')"
	cur_block="$(rpc_block_number_dec)"
	if (( prev_block > 0 )); then
		if (( cur_block <= prev_block )); then
			halt_streak=$((halt_streak + 1))
		else
			halt_streak=0
		fi
	fi
	prev_block="${cur_block}"
	printf '%s block=%s accepted=%s failed=%s soft_failed=%s halt_streak=%s\n' \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		"${cur_block}" "${accepted_count}" "${fail_count}" "${soft_fail_count}" "${halt_streak}" >>"${PROGRESS_LOG}"
done

for p in "${WORKER_PIDS[@]}"; do
	wait "${p}" || true
done

if [[ -n "${DPOS_PID}" ]]; then
	wait "${DPOS_PID}" || true
fi

END_ACTUAL="$(date -u +%s)"
ACCEPTED_COUNT="$(wc -l <"${SUCCESS_LOG}" | tr -d ' ')"
FAILED_COUNT="$(wc -l <"${FAIL_LOG}" | tr -d ' ')"
SOFT_FAILED_COUNT="$(wc -l <"${SOFT_FAIL_LOG}" | tr -d ' ')"
ATTEMPTS=$((ACCEPTED_COUNT + FAILED_COUNT + SOFT_FAILED_COUNT))

DPOS_RESULT="UNKNOWN"
if [[ -f "${DPOS_REPORT}" ]]; then
	DPOS_RESULT="$(sed -n 's/.*"result":[[:space:]]*"\([^"]*\)".*/\1/p' "${DPOS_REPORT}" | head -n1)"
fi
if [[ "${SKIP_DPOS_MONITOR}" == "1" ]] && [[ ! -f "${DPOS_REPORT}" ]]; then
	DPOS_RESULT="SKIPPED"
fi
if [[ -z "${DPOS_RESULT}" ]]; then
	DPOS_RESULT="UNKNOWN"
fi

python3 - "${REPORT_JSON}" \
	"${START_TS}" "${END_ACTUAL}" "$((END_ACTUAL - START_TS))" \
	"${DURATION}" "${RPC_URL}" "${wallet_count}" "${WORKERS}" \
	"${FUND_TOS}" "${FUND_WEI}" "${TX_VALUE_WEI}" "${ATTEMPTS}" "${ACCEPTED_COUNT}" \
	"${FAILED_COUNT}" "${SOFT_FAILED_COUNT}" "${DPOS_RESULT}" "${DPOS_REPORT}" "${DPOS_LOG}" \
	"${WALLETS_FILE}" "${OUT_DIR}/funding.csv" "${PROGRESS_LOG}" \
	"${SUCCESS_LOG}" "${FAIL_LOG}" "${SOFT_FAIL_LOG}" <<'PY'
import datetime, json, sys

(
    out_path,
    start_ts,
    end_ts,
    duration_sec,
    target_duration,
    rpc,
    wallets,
    workers,
    fund_tos,
    fund_wei,
    tx_value_wei,
    attempts,
    accepted,
    failed,
    soft_failed,
    dpos_result,
    dpos_report,
    dpos_log,
    wallets_file,
    funding_csv,
    progress_log,
    accept_log,
    fail_log,
    soft_fail_log,
) = sys.argv[1:]

report = {
    "start_time": datetime.datetime.utcfromtimestamp(int(start_ts)).isoformat() + "Z",
    "end_time": datetime.datetime.utcfromtimestamp(int(end_ts)).isoformat() + "Z",
    "duration_sec": int(duration_sec),
    "target_duration": target_duration,
    "rpc": rpc,
    "wallets": int(wallets),
    "workers": int(workers),
    "fund_tos": int(fund_tos),
    "fund_wei": int(fund_wei),
    "tx_value_wei": int(tx_value_wei),
    "attempts": int(attempts),
    "accepted": int(accepted),
    "failed": int(failed),
    "soft_failed": int(soft_failed),
    "dpos_result": dpos_result,
    "artifacts": {
        "dpos_report": dpos_report,
        "dpos_log": dpos_log,
        "wallets_file": wallets_file,
        "funding_csv": funding_csv,
        "progress_log": progress_log,
        "accept_log": accept_log,
        "fail_log": fail_log,
        "soft_fail_log": soft_fail_log,
    },
}

with open(out_path, "w") as f:
    json.dump(report, f, indent=2)
PY

echo "==> plain transfer soak complete"
echo "out_dir:  ${OUT_DIR}"
echo "report:   ${REPORT_JSON}"
echo "accepted: ${ACCEPTED_COUNT}"
echo "failed:   ${FAILED_COUNT}"
echo "soft_failed: ${SOFT_FAILED_COUNT}"
echo "dpos:     ${DPOS_RESULT}"
