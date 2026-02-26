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
VERIFY_SLEEP_SEC="${VERIFY_SLEEP_SEC:-3}"
SERVICE_PREFIX="${SERVICE_PREFIX:-gtos-node}"

VANITY_HEX="0000000000000000000000000000000000000000000000000000000000000000"
FUNDED_BALANCE_HEX="0x33b2e3c9fd0803ce8000000"

action="up"
ENODE_MAP_FILE="${BASE_DIR}/node_enodes.txt"
BOOTNODES_FILE="${BASE_DIR}/bootnodes.csv"

usage() {
	cat <<EOF_USAGE
Usage: scripts/local_testnet_3nodes.sh [action] [options]

Actions:
  up       setup + start + verify (default)
  setup    create accounts/genesis and run init for 3 nodes
  precollect-enode
           start services, collect enodes, write peer artifacts, stop services
  start    start 3 systemd services from prepared datadirs
  restart  restart 3 systemd services
  verify   check peers, block growth, and miner rotation
  status   print node status summary
  stop     stop 3 systemd services
  down     same as stop
  clean    stop services and remove chain db/log files (keystore kept)

Options:
  --base-dir <path>     data root (default: /data/gtos)
  --passfile <path>     password file for account unlock
  --network-id <id>     network id (default: 1666)
  --period-ms <n>       dpos periodMs in genesis (default: 360)
  --epoch <n>           dpos epoch in genesis (default: 1667)
  --max-validators <n>  dpos maxValidators in genesis (default: 15)
  --signer <type>       signer type for account creation (default: ed25519)
  -h, --help            show this help

Environment overrides:
  GTOS_BIN, BASE_DIR, PASSFILE, NETWORK_ID, PERIOD_MS, EPOCH, MAX_VALIDATORS,
  SIGNER_TYPE, VERIFY_SLEEP_SEC, SERVICE_PREFIX
EOF_USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	up | setup | precollect-enode | start | restart | verify | status | stop | down | clean)
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
node_addr_file() { echo "$(node_dir "$1")/validator.address"; }
node_account_log() { echo "$(node_dir "$1")/account_create.log"; }
node_init_log() { echo "${BASE_DIR}/logs/init_node$1.log"; }
node_service() { echo "${SERVICE_PREFIX}$1.service"; }

node_http_port() {
	case "$1" in
	1) echo 8545 ;;
	2) echo 8547 ;;
	3) echo 8549 ;;
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

	out="$(${GTOS_BIN} --datadir "${nodedir}" account new --signer "${SIGNER_TYPE}" --password "${PASSFILE}" 2>&1)"
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

	cat >"${BASE_DIR}/validator_accounts.txt" <<EOF_VALIDATORS
node1=${addr1}
node2=${addr2}
node3=${addr3}
EOF_VALIDATORS
	printf '%s\n%s\n%s\n' "${addr1}" "${addr2}" "${addr3}" | sort >"${BASE_DIR}/validators.sorted"
}

write_genesis() {
	local v1 v2 v3 h1 h2 h3 extra genesis ts_ms tos3_storage
	genesis="${BASE_DIR}/genesis_testnet_3vals.json"
	ts_ms="$(date +%s%3N)"
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

	# Generate TOS3 (ValidatorRegistryAddress) pre-seeded storage for DPoS epoch boundary.
	tos3_storage="$(cd "${REPO_ROOT}" && go run ./scripts/gen_genesis_slots/main.go "${v1}" "${v2}" "${v3}")"

	cat >"${genesis}" <<EOF_GENESIS
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
  "timestamp": "$(printf '0x%x' "${ts_ms}")",
  "extraData": "${extra}",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x1",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "alloc": {
    "${v1}": {"balance": "${FUNDED_BALANCE_HEX}"},
    "${v2}": {"balance": "${FUNDED_BALANCE_HEX}"},
    "${v3}": {"balance": "${FUNDED_BALANCE_HEX}"},
    "0x0000000000000000000000000000000000000000000000000000000000000003": {
      "balance": "0x0",
${tos3_storage}
    }
  },
  "number": "0x0",
  "gasUsed": "0x0",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
EOF_GENESIS
}

init_datadirs() {
	local genesis idx
	genesis="${BASE_DIR}/genesis_testnet_3vals.json"
	for idx in 1 2 3; do
		rm -rf "$(node_dir "${idx}")/gtos"
		"${GTOS_BIN}" --datadir "$(node_dir "${idx}")" init "${genesis}" >"$(node_init_log "${idx}")" 2>&1
	done
}

run_systemctl() {
	if [[ "${EUID}" -eq 0 ]]; then
		systemctl "$@"
	else
		sudo systemctl "$@"
	fi
}

service_exists() {
	local idx="$1"
	run_systemctl cat "$(node_service "${idx}")" >/dev/null 2>&1
}

assert_services_prepared() {
	local idx
	for idx in 1 2 3; do
		if ! service_exists "${idx}"; then
			echo "missing systemd service: $(node_service "${idx}")" >&2
			echo "create services first (see docs/LOCAL_TESTNET_3NODES_SYSTEMD.md)." >&2
			exit 1
		fi
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

wait_for_service_active() {
	local idx="$1" timeout_s="${2:-30}" elapsed=0
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		if run_systemctl is-active --quiet "$(node_service "${idx}")"; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
}

start_service_node() {
	local idx="$1"
	run_systemctl start "$(node_service "${idx}")"
	if ! wait_for_service_active "${idx}" 30; then
		echo "service failed to become active: $(node_service "${idx}")" >&2
		run_systemctl status --no-pager "$(node_service "${idx}")" || true
		exit 1
	fi
	if ! wait_for_ipc "${idx}" 30 || ! wait_for_attach "${idx}" 30; then
		echo "node${idx} attach not ready" >&2
		run_systemctl status --no-pager "$(node_service "${idx}")" || true
		exit 1
	fi
	echo "node${idx} started via $(node_service "${idx}")"
}

restart_service_node() {
	local idx="$1"
	run_systemctl restart "$(node_service "${idx}")"
	if ! wait_for_service_active "${idx}" 30; then
		echo "service failed after restart: $(node_service "${idx}")" >&2
		run_systemctl status --no-pager "$(node_service "${idx}")" || true
		exit 1
	fi
	if ! wait_for_ipc "${idx}" 30 || ! wait_for_attach "${idx}" 30; then
		echo "node${idx} attach not ready after restart" >&2
		run_systemctl status --no-pager "$(node_service "${idx}")" || true
		exit 1
	fi
	echo "node${idx} restarted via $(node_service "${idx}")"
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

	cat >"${ENODE_MAP_FILE}" <<EOF_ENODES
node1=${e1}
node2=${e2}
node3=${e3}
EOF_ENODES
	printf '%s,%s,%s\n' "${e1}" "${e2}" "${e3}" >"${BOOTNODES_FILE}"

	cat >"${n1}" <<EOF_STATIC1
[
  "${e2}",
  "${e3}"
]
EOF_STATIC1
	cat >"${n2}" <<EOF_STATIC2
[
  "${e1}",
  "${e3}"
]
EOF_STATIC2
	cat >"${n3}" <<EOF_STATIC3
[
  "${e1}",
  "${e2}"
]
EOF_STATIC3
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

refresh_mesh_artifacts() {
	local e1 e2 e3
	e1="$(get_node_enode 1 30 || true)"
	e2="$(get_node_enode 2 30 || true)"
	e3="$(get_node_enode 3 30 || true)"
	if [[ ! "${e1}" =~ ^enode:// || ! "${e2}" =~ ^enode:// || ! "${e3}" =~ ^enode:// ]]; then
		echo "failed to collect enodes after service start/restart" >&2
		echo "node1=${e1}" >&2
		echo "node2=${e2}" >&2
		echo "node3=${e3}" >&2
		exit 1
	fi
	connect_mesh "${e1}" "${e2}" "${e3}"
	write_peer_artifacts "${e1}" "${e2}" "${e3}"
	echo "mesh connected:"
	echo "  node1=${e1}"
	echo "  node2=${e2}"
	echo "  node3=${e3}"
}

start_nodes() {
	assert_services_prepared
	start_service_node 1
	if ! wait_for_block_growth 1 120 2; then
		echo "warning: node1 did not show solo block growth within timeout; continuing to start node2" >&2
	fi
	start_service_node 2
	start_service_node 3
	refresh_mesh_artifacts
}

restart_nodes() {
	assert_services_prepared
	restart_service_node 1
	restart_service_node 2
	restart_service_node 3
	refresh_mesh_artifacts
}

precollect_enodes() {
	assert_services_prepared
	stop_nodes
	start_nodes
	stop_nodes
	echo "precollect-enode done:"
	echo "  ${ENODE_MAP_FILE}"
	echo "  ${BOOTNODES_FILE}"
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
	local idx svc
	for idx in 1 2 3; do
		svc="$(node_service "${idx}")"
		if run_systemctl is-active --quiet "${svc}"; then
			run_systemctl stop "${svc}"
			echo "node${idx} stopped via ${svc}"
		else
			echo "node${idx} already stopped (${svc})"
		fi
	done
}

status_nodes() {
	local idx svc state port block peers pid
	echo "==> local testnet status (${BASE_DIR})"
	for idx in 1 2 3; do
		svc="$(node_service "${idx}")"
		port="$(node_http_port "${idx}")"
		if run_systemctl is-active --quiet "${svc}"; then
			pid="$(run_systemctl show -p MainPID --value "${svc}" | tr -d '\r')"
			state="running(service=${svc},pid=${pid})"
		else
			state="stopped(service=${svc})"
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
	rm -f "${BASE_DIR}/logs/node1.log" "${BASE_DIR}/logs/node2.log" "${BASE_DIR}/logs/node3.log"
	echo "clean done (keystore preserved)"
}

case "${action}" in
up)
	setup_network
	assert_network_prepared
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
restart)
	ensure_dirs
	ensure_gtos_bin
	assert_network_prepared
	restart_nodes
	;;
precollect-enode)
	ensure_dirs
	ensure_gtos_bin
	assert_network_prepared
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
