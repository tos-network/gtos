#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOSKEY_BIN="${TOSKEY_BIN:-${REPO_ROOT}/build/bin/toskey}"
GTOS_BIN="${GTOS_BIN:-${REPO_ROOT}/build/bin/gtos}"
RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
UNLOCK_IPC="${UNLOCK_IPC:-/data/gtos/node1/gtos.ipc}"

KEY_A=""
KEY_B=""
PASSFILE="${PASSFILE:-/data/gtos/pass.txt}"
ITERATIONS="${ITERATIONS:-20}"
SHIELD_AMOUNT="${SHIELD_AMOUNT:-4}"
TRANSFER_AMOUNT="${TRANSFER_AMOUNT:-2}"
UNSHIELD_AMOUNT="${UNSHIELD_AMOUNT:-1}"
CONFIRM_TIMEOUT_SEC="${CONFIRM_TIMEOUT_SEC:-120}"
POLL_SEC="${POLL_SEC:-1}"
MAX_BALANCE_SEARCH="${MAX_BALANCE_SEARCH:-1000000000}"
OUT_DIR="${OUT_DIR:-/data/gtos/uno_e2e/run_$(date -u +%Y%m%d_%H%M%S)}"

usage() {
	cat <<'EOF'
Usage: scripts/uno_e2e_soak.sh --key-a <path> --key-b <path> [options]

Run repeated UNO e2e cycles on a live node:
  A shield -> A transfer to B -> B unshield to A

Required:
  --key-a <path>            ElGamal keyfile for account A
  --key-b <path>            ElGamal keyfile for account B

Options:
  --rpc <url>               RPC endpoint (default: http://127.0.0.1:8545)
  --unlock-ipc <path>       IPC endpoint used for personal.unlockAccount
  --passfile <path>         password file for keyfiles and RPC unlock
  --iterations <n>          number of cycles (default: 20)
  --shield <n>              shield amount per cycle (default: 4)
  --transfer <n>            transfer amount per cycle (default: 2)
  --unshield <n>            unshield amount per cycle (default: 1)
  --confirm-timeout <sec>   tx receipt timeout (default: 120)
  --poll <sec>              polling interval for receipts (default: 1)
  --max-balance <n>         toskey uno-balance max-amount (default: 1000000000)
  --out-dir <path>          output directory
  -h, --help                show this help

Environment overrides:
  TOSKEY_BIN GTOS_BIN RPC_URL UNLOCK_IPC PASSFILE ITERATIONS SHIELD_AMOUNT TRANSFER_AMOUNT
  UNSHIELD_AMOUNT CONFIRM_TIMEOUT_SEC POLL_SEC MAX_BALANCE_SEARCH OUT_DIR
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--key-a)
		KEY_A="$2"
		shift 2
		;;
	--key-b)
		KEY_B="$2"
		shift 2
		;;
	--rpc)
		RPC_URL="$2"
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
	--iterations)
		ITERATIONS="$2"
		shift 2
		;;
	--shield)
		SHIELD_AMOUNT="$2"
		shift 2
		;;
	--transfer)
		TRANSFER_AMOUNT="$2"
		shift 2
		;;
	--unshield)
		UNSHIELD_AMOUNT="$2"
		shift 2
		;;
	--confirm-timeout)
		CONFIRM_TIMEOUT_SEC="$2"
		shift 2
		;;
	--poll)
		POLL_SEC="$2"
		shift 2
		;;
	--max-balance)
		MAX_BALANCE_SEARCH="$2"
		shift 2
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

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require_cmd curl
require_cmd python3

[[ -n "${KEY_A}" ]] || fail "--key-a is required"
[[ -n "${KEY_B}" ]] || fail "--key-b is required"
[[ -f "${KEY_A}" ]] || fail "key A not found: ${KEY_A}"
[[ -f "${KEY_B}" ]] || fail "key B not found: ${KEY_B}"
[[ -f "${PASSFILE}" ]] || fail "passfile not found: ${PASSFILE}"
[[ -x "${TOSKEY_BIN}" ]] || fail "toskey binary not executable: ${TOSKEY_BIN}"
[[ -x "${GTOS_BIN}" ]] || fail "gtos binary not executable: ${GTOS_BIN}"
[[ -S "${UNLOCK_IPC}" ]] || fail "unlock IPC socket not found: ${UNLOCK_IPC}"

if (( SHIELD_AMOUNT == 0 || TRANSFER_AMOUNT == 0 || UNSHIELD_AMOUNT == 0 )); then
	fail "amounts must be > 0"
fi

mkdir -p "${OUT_DIR}"
LOG_FILE="${OUT_DIR}/run.log"
CSV_FILE="${OUT_DIR}/balances.csv"

exec > >(tee -a "${LOG_FILE}") 2>&1

json_get() {
	local json="$1"
	local expr="$2"
	python3 - "${expr}" "${json}" <<'PY'
import json, sys
expr = sys.argv[1]
data = json.loads(sys.argv[2])
cur = data
for p in expr.split('.'):
    if not p:
        continue
    cur = cur[p]
if isinstance(cur, bool):
    print("true" if cur else "false")
else:
    print(cur)
PY
}

rpc_call() {
	local method="$1"
	local params_json="$2"
	curl -fsS --max-time 10 \
		-H 'Content-Type: application/json' \
		--data "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params_json},\"id\":1}" \
		"${RPC_URL}"
}

rpc_result() {
	local method="$1"
	local params_json="$2"
	local out
	out="$(rpc_call "${method}" "${params_json}")"
	python3 - "${out}" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if "error" in resp:
    msg = resp["error"]
    raise SystemExit(f"rpc error: {msg}")
print(json.dumps(resp.get("result")))
PY
}

rpc_block_number_dec() {
	local out hex
	out="$(rpc_result "tos_blockNumber" "[]")"
	hex="$(python3 - "${out}" <<'PY'
import json, sys
v = json.loads(sys.argv[1])
print(v)
PY
)"
	python3 - "${hex}" <<'PY'
import sys
print(int(sys.argv[1], 16))
PY
}

address_from_keyfile() {
	local keyfile="$1"
	local out
	out="$("${TOSKEY_BIN}" inspect --json --passwordfile "${PASSFILE}" "${keyfile}")"
	python3 - "${out}" <<'PY'
import json, sys
obj = json.loads(sys.argv[1])
if obj.get("SignerType") != "elgamal":
    raise SystemExit(f"key signer type must be elgamal, got {obj.get('SignerType')}")
print(obj["Address"])
PY
}

uno_balance_json() {
	local keyfile="$1"
	"${TOSKEY_BIN}" uno-balance \
		--json \
		--rpc "${RPC_URL}" \
		--passwordfile "${PASSFILE}" \
		--max-amount "${MAX_BALANCE_SEARCH}" \
		"${keyfile}"
}

unlock_account() {
	local addr="$1"
	local pass
	pass="$(<"${PASSFILE}")"
	local result
	result="$("${GTOS_BIN}" --exec "web3.currentProvider.send({jsonrpc:\"2.0\",method:\"personal_unlockAccount\",params:[\"${addr}\",\"${pass}\",600],id:1}).result" attach "${UNLOCK_IPC}" 2>/dev/null | tr -d '"\r\n[:space:]')"
	[[ "${result}" == "true" ]] || fail "failed to unlock account ${addr}"
}

wait_receipt_ok() {
	local txhash="$1"
	local timeout="$2"
	local waited=0
	while (( waited < timeout )); do
		local out
		out="$(rpc_result "tos_getTransactionReceipt" "[\"${txhash}\"]")"
		if [[ "${out}" != "null" ]]; then
			local status
			status="$(python3 - "${out}" <<'PY'
import json, sys
obj = json.loads(sys.argv[1])
print(obj.get("status", ""))
PY
)"
			[[ "${status}" == "0x1" ]] || fail "tx ${txhash} failed with status=${status}"
			return 0
		fi
		sleep "${POLL_SEC}"
		waited=$((waited + POLL_SEC))
	done
	fail "timeout waiting receipt for ${txhash}"
}

submit_uno_tx() {
	local mode="$1"
	local keyfile="$2"
	local to_addr="${3:-}"
	local amount="$4"
	local out txhash

	case "${mode}" in
	shield)
		out="$("${TOSKEY_BIN}" uno-shield --json --rpc "${RPC_URL}" --passwordfile "${PASSFILE}" --amount "${amount}" "${keyfile}")"
		;;
	transfer)
		out="$("${TOSKEY_BIN}" uno-transfer --json --rpc "${RPC_URL}" --passwordfile "${PASSFILE}" --to "${to_addr}" --amount "${amount}" "${keyfile}")"
		;;
	unshield)
		out="$("${TOSKEY_BIN}" uno-unshield --json --rpc "${RPC_URL}" --passwordfile "${PASSFILE}" --to "${to_addr}" --amount "${amount}" "${keyfile}")"
		;;
	*)
		fail "unknown mode: ${mode}"
		;;
	esac

	txhash="$(json_get "${out}" "txHash")"
	[[ "${txhash}" =~ ^0x[0-9a-fA-F]{64}$ ]] || fail "failed to parse txHash from ${mode}: ${out}"
	echo "${txhash}"
}

A_ADDR="$(address_from_keyfile "${KEY_A}")"
B_ADDR="$(address_from_keyfile "${KEY_B}")"

echo "==> UNO e2e soak"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "rpc: ${RPC_URL}"
echo "unlock ipc: ${UNLOCK_IPC}"
echo "key A: ${KEY_A} (${A_ADDR})"
echo "key B: ${KEY_B} (${B_ADDR})"
echo "iterations: ${ITERATIONS}"
echo "amounts: shield=${SHIELD_AMOUNT}, transfer=${TRANSFER_AMOUNT}, unshield=${UNSHIELD_AMOUNT}"
echo "out dir: ${OUT_DIR}"

echo "iter,block,a_before,a_after,b_before,b_after,tx_shield,tx_transfer,tx_unshield" >"${CSV_FILE}"

for ((i = 1; i <= ITERATIONS; i++)); do
	echo
	echo "==> iteration ${i}/${ITERATIONS}"
	unlock_account "${A_ADDR}"
	unlock_account "${B_ADDR}"

	a_before_json="$(uno_balance_json "${KEY_A}")"
	b_before_json="$(uno_balance_json "${KEY_B}")"
	a_before="$(json_get "${a_before_json}" "balance")"
	b_before="$(json_get "${b_before_json}" "balance")"

	tx_shield="$(submit_uno_tx shield "${KEY_A}" "" "${SHIELD_AMOUNT}")"
	wait_receipt_ok "${tx_shield}" "${CONFIRM_TIMEOUT_SEC}"
	tx_transfer="$(submit_uno_tx transfer "${KEY_A}" "${B_ADDR}" "${TRANSFER_AMOUNT}")"
	wait_receipt_ok "${tx_transfer}" "${CONFIRM_TIMEOUT_SEC}"
	tx_unshield="$(submit_uno_tx unshield "${KEY_B}" "${A_ADDR}" "${UNSHIELD_AMOUNT}")"
	wait_receipt_ok "${tx_unshield}" "${CONFIRM_TIMEOUT_SEC}"

	a_after_json="$(uno_balance_json "${KEY_A}")"
	b_after_json="$(uno_balance_json "${KEY_B}")"
	a_after="$(json_get "${a_after_json}" "balance")"
	b_after="$(json_get "${b_after_json}" "balance")"
	block_now="$(rpc_block_number_dec)"

	expected_a=$((a_before + SHIELD_AMOUNT - TRANSFER_AMOUNT))
	expected_b=$((b_before + TRANSFER_AMOUNT - UNSHIELD_AMOUNT))
	if (( a_after != expected_a )); then
		fail "iteration ${i}: A UNO balance mismatch, got=${a_after}, expected=${expected_a}"
	fi
	if (( b_after != expected_b )); then
		fail "iteration ${i}: B UNO balance mismatch, got=${b_after}, expected=${expected_b}"
	fi

	echo "iteration ${i} ok: block=${block_now} A ${a_before}->${a_after} B ${b_before}->${b_after}"
	echo "${i},${block_now},${a_before},${a_after},${b_before},${b_after},${tx_shield},${tx_transfer},${tx_unshield}" >>"${CSV_FILE}"
done

echo
echo "UNO e2e soak completed successfully."
echo "artifacts:"
echo "  ${LOG_FILE}"
echo "  ${CSV_FILE}"
