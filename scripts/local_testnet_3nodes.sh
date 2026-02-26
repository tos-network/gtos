#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GTOS_BIN="${GTOS_BIN:-${REPO_ROOT}/build/bin/gtos}"

BASE_DIR="${BASE_DIR:-/data/gtos}"
PASSFILE="${PASSFILE:-${BASE_DIR}/pass.txt}"
NETWORK_ID="${NETWORK_ID:-1666}"
SIGNER_TYPE="${SIGNER_TYPE:-ed25519}"
PERIOD_MS="${PERIOD_MS:-360}"
EPOCH="${EPOCH:-1667}"
MAX_VALIDATORS="${MAX_VALIDATORS:-15}"
VERBOSITY="${VERBOSITY:-3}"
VERIFY_SLEEP_SEC="${VERIFY_SLEEP_SEC:-3}"

VANITY_HEX="0000000000000000000000000000000000000000000000000000000000000000"
FUNDED_BALANCE_HEX="0x33b2e3c9fd0803ce8000000"

action="up"
ENODE_MAP_FILE="${BASE_DIR}/node_enodes.txt"
BOOTNODES_FILE="${BASE_DIR}/bootnodes.csv"

usage() {
	cat <<EOF
Usage: scripts/local_testnet_3nodes.sh [action] [options]

Actions:
  up       setup + start + verify (default)
  setup    create accounts/genesis and run init for 3 nodes
  precollect-enode
           start temporary nodes, collect enodes, write peer artifacts, stop
  start    start 3 nodes from prepared datadirs
  verify   check peers, block growth, and miner rotation
  status   print node status summary
  stop     stop 3 nodes
  down     same as stop
  clean    stop nodes and remove chain db/log/pid (keystore kept)

Options:
  --base-dir <path>     data root (default: /data/gtos)
  --passfile <path>     password file for account unlock
  --network-id <id>     network id (default: 1666)
  --period-ms <n>       dpos periodMs in genesis (default: 360)
  --epoch <n>           dpos epoch in genesis (default: 1667)
  --max-validators <n>  dpos maxValidators in genesis (default: 15)
  --signer <type>       signer type for account creation (default: ed25519)
  --verbosity <n>       gtos log verbosity (default: 3)
  -h, --help            show this help

Environment overrides:
  GTOS_BIN, BASE_DIR, PASSFILE, NETWORK_ID, PERIOD_MS, EPOCH, MAX_VALIDATORS,
  SIGNER_TYPE, VERBOSITY, VERIFY_SLEEP_SEC
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	up | setup | precollect-enode | start | verify | status | stop | down | clean)
		action="$1"
		shift
		;;
	--base-dir)
		BASE_DIR="$2"
		shift 2
		;;
	--passfile)
		PASSFILE="$2"
		shift 2
		;;
	--network-id)
		NETWORK_ID="$2"
		shift 2
		;;
	--period-ms)
		PERIOD_MS="$2"
		shift 2
		;;
	--epoch)
		EPOCH="$2"
		shift 2
		;;
	--max-validators)
		MAX_VALIDATORS="$2"
		shift 2
		;;
	--signer)
		SIGNER_TYPE="$2"
		shift 2
		;;
	--verbosity)
		VERBOSITY="$2"
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

node_dir() { echo "${BASE_DIR}/node$1"; }
node_ipc() { echo "$(node_dir "$1")/gtos.ipc"; }
node_pid_file() { echo "${BASE_DIR}/node$1.pid"; }
node_addr_file() { echo "$(node_dir "$1")/validator.address"; }
node_account_log() { echo "$(node_dir "$1")/account_create.log"; }
node_log_file() { echo "${BASE_DIR}/logs/node$1.log"; }
node_init_log() { echo "${BASE_DIR}/logs/init_node$1.log"; }

node_p2p_port() {
	case "$1" in
	1) echo 30311 ;;
	2) echo 30312 ;;
	3) echo 30313 ;;
	*) return 1 ;;
	esac
}

node_http_port() {
	case "$1" in
	1) echo 8545 ;;
	2) echo 8547 ;;
	3) echo 8549 ;;
	*) return 1 ;;
	esac
}

node_ws_port() {
	case "$1" in
	1) echo 8645 ;;
	2) echo 8647 ;;
	3) echo 8649 ;;
	*) return 1 ;;
	esac
}

node_authrpc_port() {
	case "$1" in
	1) echo 9551 ;;
	2) echo 9552 ;;
	3) echo 9553 ;;
	*) return 1 ;;
	esac
}

ensure_dirs() {
	mkdir -p "${BASE_DIR}/logs" "$(node_dir 1)" "$(node_dir 2)" "$(node_dir 3)"
}

ensure_gtos_bin() {
	if [[ -x "${GTOS_BIN}" ]]; then
		return
	fi
	echo "gtos binary not found at ${GTOS_BIN}, building..."
	(cd "${REPO_ROOT}" && go run build/ci.go install ./cmd/gtos)
}

ensure_passfile() {
	if [[ -s "${PASSFILE}" ]]; then
		return
	fi
	umask 077
	mkdir -p "$(dirname "${PASSFILE}")"
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -hex 16 >"${PASSFILE}"
	else
		head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"${PASSFILE}"
	fi
	echo "created password file: ${PASSFILE}"
}

valid_addr() {
	[[ "$1" =~ ^0x[0-9a-fA-F]{64}$ ]]
}

normalize_addr() {
	echo "$1" | tr '[:upper:]' '[:lower:]'
}

extract_addr_from_log() {
	local file="$1"
	[[ -f "${file}" ]] || return 1
	sed -n 's/^Public address of the key:[[:space:]]*\(0x[0-9A-Fa-f]\{64\}\).*/\1/p' "${file}" | tail -n1
}

infer_addr_from_keystore() {
	local dir="$1"
	local keyfile addrhex
	keyfile="$(find "${dir}/keystore" -maxdepth 1 -type f | sort | head -n1 || true)"
	[[ -n "${keyfile}" ]] || return 1
	addrhex="$(grep -m1 -o '"address":"[0-9a-fA-F]\{64\}"' "${keyfile}" | sed -n 's/.*"address":"\([0-9a-fA-F]\{64\}\)".*/\1/p')"
	[[ -n "${addrhex}" ]] || return 1
	echo "0x${addrhex}"
}

load_or_create_node_address() {
	local idx="$1"
	local nodedir addrfile acctlog out addr
	nodedir="$(node_dir "${idx}")"
	addrfile="$(node_addr_file "${idx}")"
	acctlog="$(node_account_log "${idx}")"

	if [[ -f "${addrfile}" ]]; then
		addr="$(tr -d '\n\r\t ' <"${addrfile}")"
		if valid_addr "${addr}"; then
			echo "$(normalize_addr "${addr}")"
			return 0
		fi
	fi

	addr="$(extract_addr_from_log "${acctlog}" || true)"
	if valid_addr "${addr}"; then
		addr="$(normalize_addr "${addr}")"
		echo "${addr}" >"${addrfile}"
		echo "${addr}"
		return 0
	fi

	addr="$(infer_addr_from_keystore "${nodedir}" || true)"
	if valid_addr "${addr}"; then
		addr="$(normalize_addr "${addr}")"
		echo "${addr}" >"${addrfile}"
		echo "${addr}"
		return 0
	fi

	out="$("${GTOS_BIN}" --datadir "${nodedir}" account new --signer "${SIGNER_TYPE}" --password "${PASSFILE}" 2>&1)"
	echo "${out}" >"${acctlog}"
	addr="$(echo "${out}" | sed -n 's/^Public address of the key:[[:space:]]*\(0x[0-9A-Fa-f]\{64\}\).*/\1/p' | tail -n1)"
	if ! valid_addr "${addr}"; then
		echo "failed to parse generated address for node${idx}" >&2
		echo "${out}" >&2
		return 1
	fi
	addr="$(normalize_addr "${addr}")"
	echo "${addr}" >"${addrfile}"
	echo "${addr}"
}

write_validators_files() {
	local addr1 addr2 addr3
	addr1="$(load_or_create_node_address 1)"
	addr2="$(load_or_create_node_address 2)"
	addr3="$(load_or_create_node_address 3)"

	cat >"${BASE_DIR}/validator_accounts.txt" <<EOF
node1=${addr1}
node2=${addr2}
node3=${addr3}
EOF
	printf '%s\n%s\n%s\n' "${addr1}" "${addr2}" "${addr3}" | sort >"${BASE_DIR}/validators.sorted"
}

write_genesis() {
	local v1 v2 v3 h1 h2 h3 extra genesis
	genesis="${BASE_DIR}/genesis_testnet_3vals.json"
	v1="$(sed -n '1p' "${BASE_DIR}/validators.sorted")"
	v2="$(sed -n '2p' "${BASE_DIR}/validators.sorted")"
	v3="$(sed -n '3p' "${BASE_DIR}/validators.sorted")"

	if ! (valid_addr "${v1}" && valid_addr "${v2}" && valid_addr "${v3}"); then
		echo "invalid validator addresses, check ${BASE_DIR}/validators.sorted" >&2
		exit 1
	fi

	h1="${v1#0x}"
	h2="${v2#0x}"
	h3="${v3#0x}"
	extra="0x${VANITY_HEX}${h1}${h2}${h3}"

	cat >"${genesis}" <<EOF
{
  "config": {
    "chainId": ${NETWORK_ID},
    "dpos": {
      "periodMs": ${PERIOD_MS},
      "epoch": ${EPOCH},
      "maxValidators": ${MAX_VALIDATORS},
      "sealSignerType": "ed25519"
    }
  },
  "nonce": "0x676",
  "timestamp": "0x0",
  "extraData": "${extra}",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x1",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "alloc": {
    "${v1}": {"balance": "${FUNDED_BALANCE_HEX}"},
    "${v2}": {"balance": "${FUNDED_BALANCE_HEX}"},
    "${v3}": {"balance": "${FUNDED_BALANCE_HEX}"}
  },
  "number": "0x0",
  "gasUsed": "0x0",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
EOF
}

init_datadirs() {
	local genesis idx
	genesis="${BASE_DIR}/genesis_testnet_3vals.json"
	for idx in 1 2 3; do
		rm -rf "$(node_dir "${idx}")/gtos"
		"${GTOS_BIN}" --datadir "$(node_dir "${idx}")" init "${genesis}" >"$(node_init_log "${idx}")" 2>&1
	done
}

wait_for_ipc() {
	local idx="$1" timeout_s="${2:-30}" ipc elapsed=0
	ipc="$(node_ipc "${idx}")"
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		if [[ -S "${ipc}" ]]; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
}

wait_for_attach() {
	local idx="$1" timeout_s="${2:-30}" elapsed=0
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		if "${GTOS_BIN}" --exec 'admin.nodeInfo.id' attach "$(node_ipc "${idx}")" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
}

wait_for_block_growth() {
	local idx="$1" timeout_s="${2:-90}" min_growth="${3:-2}" elapsed=0
	local port prev now growth
	port="$(node_http_port "${idx}")"
	prev="$(hex_to_dec "$(rpc_hex_result "${port}" "tos_blockNumber" "[]" || echo 0x0)")"
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		sleep 1
		now="$(hex_to_dec "$(rpc_hex_result "${port}" "tos_blockNumber" "[]" || echo 0x0)")"
		growth=$((now - prev))
		if (( growth >= min_growth )); then
			return 0
		fi
		elapsed=$((elapsed + 1))
	done
	return 1
}

is_pid_running() {
	local pid="$1"
	kill -0 "${pid}" 2>/dev/null
}

find_node_pid() {
	local idx="$1"
	pgrep -f -- "gtos --datadir $(node_dir "${idx}")" | head -n1 || true
}

start_node() {
	local idx="$1" bootnodes="$2" addr pidfile logfile
	local p2p http ws authrpc
	addr="$(tr -d '\n\r\t ' <"$(node_addr_file "${idx}")")"
	if ! valid_addr "${addr}"; then
		echo "node${idx} address invalid: ${addr}" >&2
		exit 1
	fi

	pidfile="$(node_pid_file "${idx}")"
	logfile="$(node_log_file "${idx}")"
	p2p="$(node_p2p_port "${idx}")"
	http="$(node_http_port "${idx}")"
	ws="$(node_ws_port "${idx}")"
	authrpc="$(node_authrpc_port "${idx}")"

	if [[ -f "${pidfile}" ]]; then
		local oldpid
		oldpid="$(cat "${pidfile}" || true)"
		if [[ -n "${oldpid}" ]] && is_pid_running "${oldpid}"; then
			echo "node${idx} already running (pid=${oldpid})"
			return 0
		fi
		rm -f "${pidfile}"
	fi
	local livepid
	livepid="$(find_node_pid "${idx}")"
	if [[ -n "${livepid}" ]] && is_pid_running "${livepid}"; then
		echo "${livepid}" >"${pidfile}"
		echo "node${idx} already running (pid=${livepid})"
		return 0
	fi

	local cmd=(
		"${GTOS_BIN}"
		--datadir "$(node_dir "${idx}")"
		--networkid "${NETWORK_ID}"
		--port "${p2p}"
		--netrestrict 127.0.0.0/8
		--nat none
		--http --http.addr 127.0.0.1 --http.port "${http}" --http.api admin,net,web3,tos,dpos,miner
		--ws --ws.addr 127.0.0.1 --ws.port "${ws}" --ws.api net,web3,tos,dpos
		--authrpc.addr 127.0.0.1 --authrpc.port "${authrpc}"
		--unlock "${addr}" --password "${PASSFILE}" --allow-insecure-unlock
		--mine --miner.coinbase "${addr}"
		--syncmode full
		--verbosity "${VERBOSITY}"
	)
	if [[ -n "${bootnodes}" ]]; then
		cmd+=(--bootnodes "${bootnodes}")
	fi

	nohup "${cmd[@]}" >"${logfile}" 2>&1 &
	echo $! >"${pidfile}"

	if ! wait_for_ipc "${idx}" 30; then
		echo "node${idx} failed to start (ipc not ready)" >&2
		tail -n 80 "${logfile}" >&2 || true
		exit 1
	fi
	echo "node${idx} started (pid=$(cat "${pidfile}"), http=127.0.0.1:${http})"
}

get_node_enode() {
	local idx="$1" timeout_s="${2:-30}" elapsed=0 enode=""
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		enode="$("${GTOS_BIN}" --exec 'admin.nodeInfo.enode' attach "$(node_ipc "${idx}")" 2>/dev/null | tr -d '"\r\n[:space:]')"
		if [[ "${enode}" =~ ^enode:// ]]; then
			echo "${enode}"
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
}

write_peer_artifacts() {
	local e1="$1" e2="$2" e3="$3"
	local n1 n2 n3
	n1="$(node_dir 1)/gtos/static-nodes.json"
	n2="$(node_dir 2)/gtos/static-nodes.json"
	n3="$(node_dir 3)/gtos/static-nodes.json"

	cat >"${ENODE_MAP_FILE}" <<EOF
node1=${e1}
node2=${e2}
node3=${e3}
EOF
	printf '%s,%s,%s\n' "${e1}" "${e2}" "${e3}" >"${BOOTNODES_FILE}"

	cat >"${n1}" <<EOF
[
  "${e2}",
  "${e3}"
]
EOF
	cat >"${n2}" <<EOF
[
  "${e1}",
  "${e3}"
]
EOF
	cat >"${n3}" <<EOF
[
  "${e1}",
  "${e2}"
]
EOF
}

load_precollected_enodes() {
	local e1 e2 e3
	[[ -f "${ENODE_MAP_FILE}" ]] || return 1
	e1="$(sed -n 's/^node1=\(enode:\/\/.*\)$/\1/p' "${ENODE_MAP_FILE}" | tail -n1)"
	e2="$(sed -n 's/^node2=\(enode:\/\/.*\)$/\1/p' "${ENODE_MAP_FILE}" | tail -n1)"
	e3="$(sed -n 's/^node3=\(enode:\/\/.*\)$/\1/p' "${ENODE_MAP_FILE}" | tail -n1)"
	if [[ "${e1}" =~ ^enode:// && "${e2}" =~ ^enode:// && "${e3}" =~ ^enode:// ]]; then
		printf '%s\n%s\n%s\n' "${e1}" "${e2}" "${e3}"
		return 0
	fi
	return 1
}

assert_network_prepared() {
	local idx addr
	for idx in 1 2 3; do
		if [[ ! -d "$(node_dir "${idx}")/gtos/chaindata" ]]; then
			echo "node${idx} is not initialized. run: scripts/local_testnet_3nodes.sh setup" >&2
			exit 1
		fi
		addr="$(tr -d '\n\r\t ' <"$(node_addr_file "${idx}")" 2>/dev/null || true)"
		if ! valid_addr "${addr}"; then
			echo "node${idx} validator address missing/invalid. run setup again." >&2
			exit 1
		fi
	done
}

precollect_enodes() {
	local e1 e2 e3 bootnodes
	ensure_dirs
	ensure_gtos_bin
	ensure_passfile
	assert_network_prepared

	stop_nodes
	start_node 1 ""
	wait_for_attach 1 30 || {
		echo "node1 attach not ready during precollect-enode" >&2
		exit 1
	}
	e1="$(get_node_enode 1 30 || true)"
	[[ "${e1}" =~ ^enode:// ]] || {
		echo "failed to collect node1 enode" >&2
		exit 1
	}

	start_node 2 "${e1}"
	wait_for_attach 2 30 || {
		echo "node2 attach not ready during precollect-enode" >&2
		exit 1
	}
	e2="$(get_node_enode 2 30 || true)"
	[[ "${e2}" =~ ^enode:// ]] || {
		echo "failed to collect node2 enode" >&2
		exit 1
	}

	bootnodes="${e1},${e2}"
	start_node 3 "${bootnodes}"
	wait_for_attach 3 30 || {
		echo "node3 attach not ready during precollect-enode" >&2
		exit 1
	}
	e3="$(get_node_enode 3 30 || true)"
	[[ "${e3}" =~ ^enode:// ]] || {
		echo "failed to collect node3 enode" >&2
		exit 1
	}

	connect_mesh "${e1}" "${e2}" "${e3}"
	write_peer_artifacts "${e1}" "${e2}" "${e3}"
	stop_nodes
	echo "precollect-enode done:"
	echo "  ${ENODE_MAP_FILE}"
	echo "  ${BOOTNODES_FILE}"
}

add_peer() {
	local src_idx="$1" dst_enode="$2"
	"${GTOS_BIN}" --exec "admin.addPeer(\"${dst_enode}\")" attach "$(node_ipc "${src_idx}")" >/dev/null 2>&1 || true
}

connect_mesh() {
	local e1="$1" e2="$2" e3="$3"
	add_peer 1 "${e2}"
	add_peer 1 "${e3}"
	add_peer 2 "${e1}"
	add_peer 2 "${e3}"
	add_peer 3 "${e1}"
	add_peer 3 "${e2}"
}

rpc_call() {
	local port="$1" method="$2" params="$3"
	curl -fsS --max-time 5 \
		-H 'Content-Type: application/json' \
		--data "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
		"http://127.0.0.1:${port}"
}

rpc_hex_result() {
	local out
	out="$(rpc_call "$1" "$2" "$3")"
	echo "${out}" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p'
}

hex_to_dec() {
	local h="${1#0x}"
	if [[ -z "${h}" ]]; then
		echo 0
	else
		echo $((16#${h}))
	fi
}

start_nodes() {
	local enode1 enode2 enode3 bootnodes pre
	if pre="$(load_precollected_enodes 2>/dev/null)"; then
		enode1="$(echo "${pre}" | sed -n '1p')"
		enode2="$(echo "${pre}" | sed -n '2p')"
		enode3="$(echo "${pre}" | sed -n '3p')"
		echo "using precollected enodes from ${ENODE_MAP_FILE}"
	else
		enode1=""
		enode2=""
		enode3=""
	fi
	start_node 1 ""
	if ! wait_for_attach 1 30; then
		echo "node1 attach not ready" >&2
		tail -n 80 "$(node_log_file 1)" >&2 || true
		exit 1
	fi
	if [[ ! "${enode1}" =~ ^enode:// ]]; then
		enode1="$(get_node_enode 1 30 || true)"
	fi
	if [[ ! "${enode1}" =~ ^enode:// ]]; then
		echo "failed to read node1 enode: ${enode1}" >&2
		exit 1
	fi
	if ! wait_for_block_growth 1 120 2; then
		echo "warning: node1 did not show solo block growth within timeout; continuing to start node2" >&2
	fi
	start_node 2 "${enode1}"
	if ! wait_for_attach 2 30; then
		echo "node2 attach not ready" >&2
		tail -n 80 "$(node_log_file 2)" >&2 || true
		exit 1
	fi
	if [[ ! "${enode2}" =~ ^enode:// ]]; then
		enode2="$(get_node_enode 2 30 || true)"
	fi
	if [[ ! "${enode2}" =~ ^enode:// ]]; then
		echo "failed to read node2 enode: ${enode2}" >&2
		exit 1
	fi
	bootnodes="${enode1},${enode2}"
	start_node 3 "${bootnodes}"
	if ! wait_for_attach 3 30; then
		echo "node3 attach not ready" >&2
		tail -n 80 "$(node_log_file 3)" >&2 || true
		exit 1
	fi
	if [[ ! "${enode3}" =~ ^enode:// ]]; then
		enode3="$(get_node_enode 3 30 || true)"
	fi
	if [[ ! "${enode3}" =~ ^enode:// ]]; then
		echo "failed to read node3 enode: ${enode3}" >&2
		exit 1
	fi
	connect_mesh "${enode1}" "${enode2}" "${enode3}"
	write_peer_artifacts "${enode1}" "${enode2}" "${enode3}"
	echo "mesh connected:"
	echo "  node1=${enode1}"
	echo "  node2=${enode2}"
	echo "  node3=${enode3}"
}

verify_nodes() {
	local n phex b1hex b2hex pdec b1dec b2dec
	local -A peer_count_hex block_before_hex block_after_hex

	for n in 1 2 3; do
		peer_count_hex["${n}"]="$(rpc_hex_result "$(node_http_port "${n}")" "net_peerCount" "[]")"
		block_before_hex["${n}"]="$(rpc_hex_result "$(node_http_port "${n}")" "tos_blockNumber" "[]")"
	done

	sleep "${VERIFY_SLEEP_SEC}"

	for n in 1 2 3; do
		block_after_hex["${n}"]="$(rpc_hex_result "$(node_http_port "${n}")" "tos_blockNumber" "[]")"
	done

	echo "==> peer + block summary"
	for n in 1 2 3; do
		phex="${peer_count_hex["${n}"]}"
		b1hex="${block_before_hex["${n}"]}"
		b2hex="${block_after_hex["${n}"]}"
		pdec="$(hex_to_dec "${phex}")"
		b1dec="$(hex_to_dec "${b1hex}")"
		b2dec="$(hex_to_dec "${b2hex}")"
		echo "node${n}: peerCount=${pdec} block=${b1dec}->${b2dec}"
	done

	if (( "$(hex_to_dec "${peer_count_hex[2]}")" < 1 )); then
		echo "verify failed: node2 peerCount < 1" >&2
		exit 1
	fi
	if (( "$(hex_to_dec "${peer_count_hex[3]}")" < 1 )); then
		echo "verify failed: node3 peerCount < 1" >&2
		exit 1
	fi
	if (( "$(hex_to_dec "${peer_count_hex[1]}")" < 1 )); then
		echo "verify failed: node1 peerCount < 1" >&2
		exit 1
	fi
	for n in 1 2 3; do
		if (( "$(hex_to_dec "${block_after_hex["${n}"]}")" <= "$(hex_to_dec "${block_before_hex["${n}"]}")" )); then
			echo "verify failed: node${n} block number did not grow" >&2
			exit 1
		fi
	done

	python3 - <<'PY'
import json, urllib.request, sys
url = "http://127.0.0.1:8545"
def rpc(method, params):
    data = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())["result"]

latest = int(rpc("tos_blockNumber", []), 16)
start = max(1, latest - 14)
miners = []
for num in range(start, latest + 1):
    block = rpc("tos_getBlockByNumber", [hex(num), False])
    miners.append(block["miner"].lower())
uniq = sorted(set(miners))
print("miner sample:", len(miners), "blocks,", len(uniq), "unique miners")
for m in uniq:
    print(" ", m)
if len(uniq) < 2:
    print("verify failed: miner rotation not observed", file=sys.stderr)
    sys.exit(1)
PY

	echo "verify passed"
}

stop_nodes() {
	local idx pidfile pid waited
	for idx in 1 2 3; do
		pidfile="$(node_pid_file "${idx}")"
		pid=""
		if [[ -f "${pidfile}" ]]; then
			pid="$(cat "${pidfile}" || true)"
		fi
		if [[ -z "${pid}" ]]; then
			pid="$(find_node_pid "${idx}")"
		fi
		if [[ -z "${pid}" ]]; then
			rm -f "${pidfile}" || true
			continue
		fi
		if ! is_pid_running "${pid}"; then
			rm -f "${pidfile}"
			continue
		fi
		kill "${pid}" || true
		waited=0
		while is_pid_running "${pid}" && [[ "${waited}" -lt 20 ]]; do
			sleep 1
			waited=$((waited + 1))
		done
		if is_pid_running "${pid}"; then
			kill -9 "${pid}" || true
		fi
		rm -f "${pidfile}"
		echo "node${idx} stopped"
	done
}

status_nodes() {
	local idx pidfile pid state port block peers
	echo "==> local testnet status (${BASE_DIR})"
	for idx in 1 2 3; do
		pidfile="$(node_pid_file "${idx}")"
		port="$(node_http_port "${idx}")"
		state="stopped"
		if [[ -f "${pidfile}" ]]; then
			pid="$(cat "${pidfile}" || true)"
			if [[ -n "${pid}" ]] && is_pid_running "${pid}"; then
				state="running(pid=${pid})"
			fi
		fi
		if [[ "${state}" == "stopped" ]]; then
			pid="$(find_node_pid "${idx}")"
			if [[ -n "${pid}" ]] && is_pid_running "${pid}"; then
				echo "${pid}" >"${pidfile}"
				state="running(pid=${pid})"
			fi
		fi
		block="-"
		peers="-"
		if [[ "${state}" == running* ]]; then
			block="$(rpc_hex_result "${port}" "tos_blockNumber" "[]" || true)"
			peers="$(rpc_hex_result "${port}" "net_peerCount" "[]" || true)"
			if [[ -n "${block}" ]]; then
				block="$(hex_to_dec "${block}")"
			fi
			if [[ -n "${peers}" ]]; then
				peers="$(hex_to_dec "${peers}")"
			fi
		fi
		echo "node${idx}: ${state}, http=127.0.0.1:${port}, block=${block}, peers=${peers}"
	done
}

setup_network() {
	ensure_dirs
	ensure_gtos_bin
	ensure_passfile
	write_validators_files
	write_genesis
	init_datadirs
	echo "setup done:"
	echo "  validators: ${BASE_DIR}/validator_accounts.txt"
	echo "  genesis:    ${BASE_DIR}/genesis_testnet_3vals.json"
}

clean_network() {
	stop_nodes
	rm -rf "$(node_dir 1)/gtos" "$(node_dir 2)/gtos" "$(node_dir 3)/gtos"
	rm -f "$(node_pid_file 1)" "$(node_pid_file 2)" "$(node_pid_file 3)"
	rm -f "${BASE_DIR}/logs/node1.log" "${BASE_DIR}/logs/node2.log" "${BASE_DIR}/logs/node3.log"
	echo "clean done (keystore preserved)"
}

case "${action}" in
up)
	setup_network
	start_nodes
	verify_nodes
	;;
setup)
	setup_network
	;;
start)
	ensure_dirs
	ensure_gtos_bin
	ensure_passfile
	assert_network_prepared
	start_nodes
	;;
precollect-enode)
	precollect_enodes
	;;
verify)
	verify_nodes
	;;
status)
	status_nodes
	;;
stop | down)
	stop_nodes
	;;
clean)
	clean_network
	;;
*)
	echo "unsupported action: ${action}" >&2
	exit 1
	;;
esac
