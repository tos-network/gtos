#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GTOS_BIN="${GTOS_BIN:-/usr/local/bin/gtos}"
TOSKEY_BIN="${TOSKEY_BIN:-${REPO_ROOT}/build/bin/toskey}"

BASE_DIR="${BASE_DIR:-/data/gtos}"
PASSFILE="${PASSFILE:-${BASE_DIR}/pass.txt}"
NETWORK_ID="${NETWORK_ID:-1666}"
SIGNER_TYPE="${SIGNER_TYPE:-ed25519}"
PERIOD_MS="${PERIOD_MS:-360}"
EPOCH="${EPOCH:-1664}"
TURN_LENGTH="${TURN_LENGTH:-16}"
MAX_VALIDATORS="${MAX_VALIDATORS:-15}"
CHECKPOINT_INTERVAL="${CHECKPOINT_INTERVAL:-50}"
CHECKPOINT_FINALITY_BLOCK="${CHECKPOINT_FINALITY_BLOCK:-}"
GC_MODE="${GC_MODE:-full}"
GENESIS_START_DELAY_MS="${GENESIS_START_DELAY_MS:-5000}"
VERIFY_SLEEP_SEC="${VERIFY_SLEEP_SEC:-3}"
SERVICE_PREFIX="${SERVICE_PREFIX:-gtos-validator@}"
LEGACY_SERVICE_PREFIX="${LEGACY_SERVICE_PREFIX:-gtos-node}"
SYSTEMD_TEMPLATE_SOURCE="${SYSTEMD_TEMPLATE_SOURCE:-${REPO_ROOT}/scripts/systemd/gtos-validator@.service}"
SYSTEMD_TEMPLATE_DEST="${SYSTEMD_TEMPLATE_DEST:-/etc/systemd/system/gtos-validator@.service}"
GUARD_SERVICE_SOURCE="${GUARD_SERVICE_SOURCE:-${REPO_ROOT}/scripts/systemd/gtos-validator-guard.service}"
GUARD_SERVICE_DEST="${GUARD_SERVICE_DEST:-/etc/systemd/system/gtos-validator-guard.service}"
GUARD_SERVICE_NAME="${GUARD_SERVICE_NAME:-gtos-validator-guard.service}"
REPORT_SERVICE_SOURCE="${REPORT_SERVICE_SOURCE:-${REPO_ROOT}/scripts/systemd/gtos-validator-report.service}"
REPORT_SERVICE_DEST="${REPORT_SERVICE_DEST:-/etc/systemd/system/gtos-validator-report.service}"
REPORT_SERVICE_NAME="${REPORT_SERVICE_NAME:-gtos-validator-report.service}"
REPORT_TIMER_SOURCE="${REPORT_TIMER_SOURCE:-${REPO_ROOT}/scripts/systemd/gtos-validator-report.timer}"
REPORT_TIMER_DEST="${REPORT_TIMER_DEST:-/etc/systemd/system/gtos-validator-report.timer}"
REPORT_TIMER_NAME="${REPORT_TIMER_NAME:-gtos-validator-report.timer}"
SHARED_CONFIG_FILE="${SHARED_CONFIG_FILE:-${BASE_DIR}/config.toml}"
RPC_SERVICE_PREFIX="${RPC_SERVICE_PREFIX:-gtos-rpc@}"
RPC_TEMPLATE_SOURCE="${RPC_TEMPLATE_SOURCE:-${REPO_ROOT}/scripts/systemd/gtos-rpc@.service}"
RPC_TEMPLATE_DEST="${RPC_TEMPLATE_DEST:-/etc/systemd/system/gtos-rpc@.service}"
SHARED_RPC_CONFIG_FILE="${SHARED_RPC_CONFIG_FILE:-${BASE_DIR}/config-rpc.toml}"
RPC_GC_MODE="${RPC_GC_MODE:-full}"
VERBOSITY="${VERBOSITY:-3}"

VANITY_HEX="0000000000000000000000000000000000000000000000000000000000000000"
FUNDED_BALANCE_HEX="0x33b2e3c9fd0803ce8000000"
VALIDATOR_REGISTER_VALUE_HEX="0x84595161401484a000000"
VALIDATOR_REGISTER_PAYLOAD_HEX="0x7b22616374696f6e223a2256414c494441544f525f5245474953544552227d"

action="up"
TARGET_NODE="${TARGET_NODE:-}"
ENODE_MAP_FILE="${BASE_DIR}/node_enodes.txt"
BOOTNODES_FILE="${BASE_DIR}/bootnodes.csv"

usage() {
	cat <<EOF_USAGE
Usage: scripts/validator_cluster.sh [action] [options]

Actions:
  up       setup + start + verify (default)
  setup    create accounts/genesis and run init for 3 validators + 1 rpc node
  precollect-enode
           start services, collect enodes, write peer artifacts, stop services
  start    start validator + rpc systemd services from prepared datadirs
  restart  restart validator + rpc systemd services
  enter-maintenance <node>
           submit VALIDATOR_ENTER_MAINTENANCE for node 1, 2, or 3
  exit-maintenance <node>
           submit VALIDATOR_EXIT_MAINTENANCE for node 1, 2, or 3
  drain <node>
           enter maintenance, wait until removed from active set, then stop service
  resume <node>
           start service, wait for connectivity, then exit maintenance
  report   generate a guard report immediately via systemd oneshot service
  chain-status
           render authoritative cluster status from validator/rpc/guard state
  verify   check peers, block growth, and miner rotation
  status   print node status summary
  stop     stop validator + rpc systemd services
  down     same as stop
  clean    stop services and remove chain db/log files (keystore kept)

Options:
  --base-dir <path>     data root (default: /data/gtos)
  --passfile <path>     password file for account unlock
  --network-id <id>     network id (default: 1666)
  --period-ms <n>       dpos periodMs in genesis (default: 360)
  --epoch <n>           dpos epoch in genesis (default: 1664)
  --turn-length <n>     dpos turnLength in genesis (default: 16)
  --max-validators <n>  dpos maxValidators in genesis (default: 15)
  --checkpoint-interval <n>
                        checkpoint interval in genesis (default: 50)
  --checkpoint-finality-block <n>
                        activation block for checkpoint finality (default: disabled)
  --gcmode <mode>       expected service gc mode: archive|full (default: full)
  --genesis-start-delay-ms <n>
                        delay genesis timestamp so nodes can peer before block 1
                        (default: 5000)
  --node <1|2|3>        target node for maintenance actions
  --signer <type>       signer type for account creation (default: ed25519)
  -h, --help            show this help

Environment overrides:
  GTOS_BIN, BASE_DIR, PASSFILE, NETWORK_ID, PERIOD_MS, EPOCH, MAX_VALIDATORS,
  TURN_LENGTH, CHECKPOINT_INTERVAL, CHECKPOINT_FINALITY_BLOCK, GC_MODE, RPC_GC_MODE,
  GENESIS_START_DELAY_MS, TOSKEY_BIN,
  SIGNER_TYPE, VERIFY_SLEEP_SEC, SERVICE_PREFIX, VERBOSITY
EOF_USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	up | setup | precollect-enode | start | restart | enter-maintenance | exit-maintenance | drain | resume | report | chain-status | verify | status | stop | down | clean)
		action="$1"
		shift
		if [[ $# -gt 0 && "$1" != --* ]] && [[ "${action}" == "enter-maintenance" || "${action}" == "exit-maintenance" || "${action}" == "drain" || "${action}" == "resume" ]]; then
			TARGET_NODE="$1"
			shift
		fi
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
	--turn-length)
		TURN_LENGTH="$2"
		shift 2
		;;
	--max-validators)
		MAX_VALIDATORS="$2"
		shift 2
		;;
	--checkpoint-interval)
		CHECKPOINT_INTERVAL="$2"
		shift 2
		;;
	--checkpoint-finality-block)
		CHECKPOINT_FINALITY_BLOCK="$2"
		shift 2
		;;
	--gcmode)
		GC_MODE="$2"
		shift 2
		;;
	--genesis-start-delay-ms)
		GENESIS_START_DELAY_MS="$2"
		shift 2
		;;
	--node)
		TARGET_NODE="$2"
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
node_env_file() { echo "$(node_dir "$1")/validator.env"; }
node_config_file() { echo "$(node_dir "$1")/validator.toml"; }
rpc_gc_mode_value() {
	case "${RPC_GC_MODE}" in
	archive) echo "archive" ;;
	full) echo "full" ;;
	*)
		echo "unsupported rpc gc mode: ${RPC_GC_MODE}" >&2
		exit 1
		;;
	esac
}
rpc_dir() { echo "${BASE_DIR}/rpc$1"; }
rpc_ipc() { echo "$(rpc_dir "$1")/gtos.ipc"; }
rpc_env_file() { echo "$(rpc_dir "$1")/rpc.env"; }
rpc_config_file() { echo "$(rpc_dir "$1")/rpc.toml"; }
rpc_service() { echo "${RPC_SERVICE_PREFIX}$1.service"; }
ops_dir() { echo "${BASE_DIR}/ops"; }
maintenance_state_dir() { echo "$(ops_dir)/maintenance"; }
maintenance_state_file() { echo "$(maintenance_state_dir)/node$1.env"; }
guard_env_file() { echo "$(ops_dir)/validator_guard.env"; }
incident_dir() { echo "$(ops_dir)/incidents"; }
report_env_file() { echo "$(ops_dir)/validator_report.env"; }
chain_status_script() { echo "${REPO_ROOT}/scripts/gtos_chain_status.sh"; }
node_account_log() { echo "$(node_dir "$1")/account_create.log"; }
node_init_log() { echo "${BASE_DIR}/logs/init_node$1.log"; }
node_service() { echo "${SERVICE_PREFIX}$1.service"; }
legacy_node_service() { echo "${LEGACY_SERVICE_PREFIX}$1.service"; }
normalize_local_enode() {
	local enode="$1"
	python3 -c '
import re, sys
enode = sys.argv[1].strip()
m = re.match(r"^(enode://[^@]+)@[^:]+:(\d+)$", enode)
if not m:
    raise SystemExit(enode)
print(f"{m.group(1)}@127.0.0.1:{m.group(2)}")
' "${enode}"
}
require_target_node() {
	if [[ -z "${TARGET_NODE}" ]]; then
		echo "this action requires a node index: 1, 2, or 3" >&2
		exit 1
	fi
	case "${TARGET_NODE}" in
	1 | 2 | 3) ;;
	*)
		echo "invalid node index: ${TARGET_NODE} (want 1, 2, or 3)" >&2
		exit 1
		;;
	esac
}

is_checkpoint_finality_enabled() {
	[[ -n "${CHECKPOINT_FINALITY_BLOCK}" ]]
}

first_checkpoint_at_or_after() {
	local base="$1" interval="$2" rem
	(( interval > 0 )) || {
		echo 0
		return
	}
	rem=$((base % interval))
	if (( rem == 0 )); then
		echo "${base}"
	else
		echo $((base + interval - rem))
	fi
}

checkpoint_first_eligible() {
	if ! is_checkpoint_finality_enabled; then
		echo 0
		return
	fi
	first_checkpoint_at_or_after "${CHECKPOINT_FINALITY_BLOCK}" "${CHECKPOINT_INTERVAL}"
}

checkpoint_config_json() {
	if ! is_checkpoint_finality_enabled; then
		return
	fi
	cat <<EOF_CHECKPOINT
      "checkpointInterval": ${CHECKPOINT_INTERVAL},
      "checkpointFinalityBlock": ${CHECKPOINT_FINALITY_BLOCK},
EOF_CHECKPOINT
}

expected_service_gc_flags() {
	case "${GC_MODE}" in
	archive)
		echo "archive"
		;;
	full)
		echo "full"
		;;
	*)
		echo ""
		;;
	esac
}

validate_local_checkpoint_config() {
	if (( TURN_LENGTH <= 0 )); then
		echo "turnLength must be > 0" >&2
		exit 1
	fi
	if (( TURN_LENGTH > EPOCH )); then
		echo "turnLength ${TURN_LENGTH} must be <= epoch ${EPOCH}" >&2
		exit 1
	fi
	if (( EPOCH % TURN_LENGTH != 0 )); then
		echo "epoch ${EPOCH} must be divisible by turnLength ${TURN_LENGTH}" >&2
		exit 1
	fi
	if ! is_checkpoint_finality_enabled; then
		if (( GENESIS_START_DELAY_MS < 0 )); then
			echo "genesis start delay must be >= 0" >&2
			exit 1
		fi
		return
	fi
	if (( CHECKPOINT_INTERVAL <= 0 )); then
		echo "checkpoint interval must be > 0" >&2
		exit 1
	fi
	# Local full-mode deployment rule: non-archive nodes only retain enough state
	# for the checkpoint finality window when 2*K <= 128, i.e. K <= 64.
	if [[ "${GC_MODE}" != "archive" ]] && (( CHECKPOINT_INTERVAL > 64 )); then
		echo "checkpoint interval ${CHECKPOINT_INTERVAL} is not full-mode safe; require <= 64 or use --gcmode archive" >&2
		exit 1
	fi
	if (( GENESIS_START_DELAY_MS < 0 )); then
		echo "genesis start delay must be >= 0" >&2
		exit 1
	fi
}

node_http_port() {
	case "$1" in
	1) echo 8545 ;;
	2) echo 8547 ;;
	3) echo 8549 ;;
	*) return 1 ;;
	esac
}

rpc_http_port() {
	case "$1" in
	1) echo 8555 ;;
	*) return 1 ;;
	esac
}

ensure_dirs() {
	mkdir -p "${BASE_DIR}/logs" "$(node_dir 1)" "$(node_dir 2)" "$(node_dir 3)" "$(rpc_dir 1)"
	mkdir -p "$(maintenance_state_dir)" "$(incident_dir)"
}

write_maintenance_state() {
	local idx="$1" state="$2" txhash="${3:-}" validator_addr="${4:-}"
	cat >"$(maintenance_state_file "${idx}")" <<EOF_STATE
STATE=${state}
UPDATED_AT=$(date -u +%s)
TX_HASH=${txhash}
VALIDATOR_ADDR=${validator_addr}
EOF_STATE
}

write_validator_guard_env() {
	cat >"$(guard_env_file)" <<EOF_ENV
NODES=http://127.0.0.1:8545,http://127.0.0.1:8547,http://127.0.0.1:8549
POLL_SEC=15
DURATION=0
JOURNAL_DIR=${BASE_DIR}/ops/validator_guard
INCIDENT_DIR=${BASE_DIR}/ops/incidents
MAINTENANCE_WARN_SEC=7200
MAINTENANCE_CRITICAL_SEC=21600
MAINTENANCE_EMERGENCY_SEC=86400
FINALITY_LAG_MAX_BLOCKS=512
HALT_TOLERANCE=4
PEER_MIN=1
GROUP_SAMPLE_FACTOR=2
BASE_DIR=${BASE_DIR}
ALERT_WEBHOOK_URL=
ALERT_WEBHOOK_TIMEOUT_SEC=5
ALERT_EMAIL_TO=
ALERT_EMAIL_FROM=
ALERT_EMAIL_SUBJECT_PREFIX=[GTOS Validator Guard]
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_TLS=true
EOF_ENV
}

write_validator_report_env() {
	cat >"$(report_env_file)" <<EOF_ENV
JOURNAL_DIR=${BASE_DIR}/ops/validator_guard
REPORT_DIR=${BASE_DIR}/ops/validator_guard/reports
INCIDENT_DIR=${BASE_DIR}/ops/incidents
BASE_DIR=${BASE_DIR}
LOOKBACK_HOURS=24
REPORT_FORMAT=both
EOF_ENV
}

write_shared_config_toml() {
	local no_pruning
	case "${GC_MODE}" in
	archive) no_pruning=true ;;
	full) no_pruning=false ;;
	*)
		echo "unsupported gc mode for config generation: ${GC_MODE}" >&2
		exit 1
		;;
	esac

	cat >"${SHARED_CONFIG_FILE}" <<EOF_CONFIG
[TOS]
NetworkId = ${NETWORK_ID}
SyncMode = "full"
NoPruning = ${no_pruning}
NoPrefetch = false
FilterLogCacheSize = 32
RPCGasCap = 50000000
RPCEVMTimeout = 5000000000
RPCTxFeeCap = 1.0

[TOS.Miner]
GasCeil = 30000000
Recommit = 3000000000
Noverify = false

[Node]
IPCPath = "gtos.ipc"
HTTPHost = "127.0.0.1"
HTTPVirtualHosts = ["localhost"]
HTTPModules = ["admin", "net", "web3", "tos", "dpos", "miner"]
AuthAddr = "127.0.0.1"
AuthVirtualHosts = ["localhost"]
WSHost = "127.0.0.1"
WSModules = ["net", "web3", "tos", "dpos"]
GraphQLVirtualHosts = ["localhost"]

[Node.P2P]
NoDiscovery = false
EOF_CONFIG
}

write_validator_config() {
	local idx="$1" addr p2p_port http_port ws_port authrpc_port no_pruning
	addr="$(node_validator_address "${idx}")"
	p2p_port=$((30310 + idx))
	http_port="$(node_http_port "${idx}")"
	ws_port=$((8643 + (idx * 2)))
	authrpc_port=$((9550 + idx))
	case "${GC_MODE}" in
	archive) no_pruning=true ;;
	full) no_pruning=false ;;
	*)
		echo "unsupported gc mode for validator config: ${GC_MODE}" >&2
		exit 1
		;;
	esac

	cat >"$(node_config_file "${idx}")" <<EOF_CONFIG
[TOS]
NetworkId = ${NETWORK_ID}
SyncMode = "full"
NoPruning = ${no_pruning}
NoPrefetch = false
FilterLogCacheSize = 32
RPCGasCap = 50000000
RPCEVMTimeout = 5000000000
RPCTxFeeCap = 1.0
MonitorDoubleSign = true
MonitorMaliciousVote = true
MonitorJournalDir = "${BASE_DIR}/ops/native_monitor/node${idx}"
VoteJournalPath = "${BASE_DIR}/ops/vote_journal/node${idx}"

[TOS.Miner]
GasCeil = 30000000
Recommit = 3000000000
Noverify = false

[Node]
DataDir = "$(node_dir "${idx}")"
IPCPath = "gtos.ipc"
HTTPHost = "127.0.0.1"
HTTPPort = ${http_port}
HTTPVirtualHosts = ["localhost"]
HTTPModules = ["admin", "net", "web3", "tos", "dpos", "miner"]
AuthAddr = "127.0.0.1"
AuthPort = ${authrpc_port}
AuthVirtualHosts = ["localhost"]
WSHost = "127.0.0.1"
WSPort = ${ws_port}
WSModules = ["net", "web3", "tos", "dpos"]
GraphQLVirtualHosts = ["localhost"]

[Node.P2P]
NoDiscovery = false
ListenAddr = ":${p2p_port}"
DiscAddr = ":${p2p_port}"
EOF_CONFIG
}

write_validator_configs() {
	local idx
	for idx in 1 2 3; do
		write_validator_config "${idx}"
	done
}

write_shared_rpc_config_toml() {
	local no_pruning
	case "${RPC_GC_MODE}" in
	archive) no_pruning=true ;;
	full) no_pruning=false ;;
	*)
		echo "unsupported rpc gc mode for config generation: ${RPC_GC_MODE}" >&2
		exit 1
		;;
	esac

	cat >"${SHARED_RPC_CONFIG_FILE}" <<EOF_CONFIG
[TOS]
NetworkId = ${NETWORK_ID}
SyncMode = "full"
NoPruning = ${no_pruning}
NoPrefetch = false
FilterLogCacheSize = 64
RPCGasCap = 50000000
RPCEVMTimeout = 5000000000
RPCTxFeeCap = 1.0

[Node]
IPCPath = "gtos.ipc"
HTTPHost = "127.0.0.1"
HTTPVirtualHosts = ["localhost"]
HTTPModules = ["admin", "net", "web3", "tos", "dpos", "txpool", "debug"]
AuthAddr = "127.0.0.1"
AuthVirtualHosts = ["localhost"]
WSHost = "127.0.0.1"
WSModules = ["net", "web3", "tos", "dpos", "txpool"]
GraphQLVirtualHosts = ["localhost"]

[Node.P2P]
NoDiscovery = false
EOF_CONFIG
}

write_rpc_config() {
	local idx="$1" p2p_port http_port ws_port authrpc_port no_pruning
	p2p_port=$((30400 + idx))
	http_port="$(rpc_http_port "${idx}")"
	ws_port=$((8654 + (idx * 2)))
	authrpc_port=$((9650 + idx))
	case "${RPC_GC_MODE}" in
	archive) no_pruning=true ;;
	full) no_pruning=false ;;
	*)
		echo "unsupported rpc gc mode for rpc config: ${RPC_GC_MODE}" >&2
		exit 1
		;;
	esac

	cat >"$(rpc_config_file "${idx}")" <<EOF_CONFIG
[TOS]
NetworkId = ${NETWORK_ID}
SyncMode = "full"
NoPruning = ${no_pruning}
NoPrefetch = false
FilterLogCacheSize = 64
RPCGasCap = 50000000
RPCEVMTimeout = 5000000000
RPCTxFeeCap = 1.0

[Node]
DataDir = "$(rpc_dir "${idx}")"
IPCPath = "gtos.ipc"
HTTPHost = "127.0.0.1"
HTTPPort = ${http_port}
HTTPVirtualHosts = ["localhost"]
HTTPModules = ["admin", "net", "web3", "tos", "dpos", "txpool", "debug"]
AuthAddr = "127.0.0.1"
AuthPort = ${authrpc_port}
AuthVirtualHosts = ["localhost"]
WSHost = "127.0.0.1"
WSPort = ${ws_port}
WSModules = ["net", "web3", "tos", "dpos", "txpool"]
GraphQLVirtualHosts = ["localhost"]

[Node.P2P]
NoDiscovery = false
ListenAddr = ":${p2p_port}"
DiscAddr = ":${p2p_port}"
EOF_CONFIG
}

write_rpc_configs() {
	write_rpc_config 1
}

bootnodes_csv_value() {
	if [[ -s "${BOOTNODES_FILE}" ]]; then
		tr -d '\n\r' <"${BOOTNODES_FILE}"
	fi
}

write_validator_env() {
	local idx="$1" addr bootnodes
	addr="$(node_validator_address "${idx}")"
	bootnodes="$(bootnodes_csv_value)"

	cat >"$(node_env_file "${idx}")" <<EOF_ENV
GTOS_CONFIG=$(node_config_file "${idx}")
GTOS_VALIDATOR_ADDR=${addr}
GTOS_PASSFILE=${PASSFILE}
GTOS_VERBOSITY=${VERBOSITY}
GTOS_BOOTNODES=${bootnodes}
GTOS_EXTRA_FLAGS=
EOF_ENV
}

write_validator_envs() {
	local idx
	for idx in 1 2 3; do
		write_validator_env "${idx}"
	done
}

write_rpc_env() {
	local idx="$1" bootnodes
	bootnodes="$(bootnodes_csv_value)"

	cat >"$(rpc_env_file "${idx}")" <<EOF_ENV
GTOS_CONFIG=$(rpc_config_file "${idx}")
GTOS_VERBOSITY=${VERBOSITY}
GTOS_BOOTNODES=${bootnodes}
GTOS_EXTRA_FLAGS=--gcmode $(rpc_gc_mode_value)
EOF_ENV
}

write_rpc_envs() {
	write_rpc_env 1
}

install_template_service() {
	if [[ ! -f "${SYSTEMD_TEMPLATE_SOURCE}" ]]; then
		echo "missing systemd template source: ${SYSTEMD_TEMPLATE_SOURCE}" >&2
		exit 1
	fi
	if [[ "${EUID}" -eq 0 ]]; then
		install -m 0644 "${SYSTEMD_TEMPLATE_SOURCE}" "${SYSTEMD_TEMPLATE_DEST}"
	else
		sudo install -m 0644 "${SYSTEMD_TEMPLATE_SOURCE}" "${SYSTEMD_TEMPLATE_DEST}"
	fi
	run_systemctl daemon-reload
}

install_rpc_service() {
	if [[ ! -f "${RPC_TEMPLATE_SOURCE}" ]]; then
		echo "missing rpc systemd template source: ${RPC_TEMPLATE_SOURCE}" >&2
		exit 1
	fi
	if [[ "${EUID}" -eq 0 ]]; then
		install -m 0644 "${RPC_TEMPLATE_SOURCE}" "${RPC_TEMPLATE_DEST}"
	else
		sudo install -m 0644 "${RPC_TEMPLATE_SOURCE}" "${RPC_TEMPLATE_DEST}"
	fi
	run_systemctl daemon-reload
}

prepare_runtime_assets() {
	write_shared_config_toml
	write_shared_rpc_config_toml
	write_validator_configs
	write_rpc_configs
	write_validator_envs
	write_rpc_envs
	write_validator_guard_env
	write_validator_report_env
	install_template_service
	install_rpc_service
	install_guard_service
	install_report_units
}

install_guard_service() {
	if [[ ! -f "${GUARD_SERVICE_SOURCE}" ]]; then
		echo "missing guard service source: ${GUARD_SERVICE_SOURCE}" >&2
		exit 1
	fi
	if [[ "${EUID}" -eq 0 ]]; then
		install -m 0644 "${GUARD_SERVICE_SOURCE}" "${GUARD_SERVICE_DEST}"
	else
		sudo install -m 0644 "${GUARD_SERVICE_SOURCE}" "${GUARD_SERVICE_DEST}"
	fi
	run_systemctl daemon-reload
}

install_report_units() {
	if [[ ! -f "${REPORT_SERVICE_SOURCE}" ]]; then
		echo "missing report service source: ${REPORT_SERVICE_SOURCE}" >&2
		exit 1
	fi
	if [[ ! -f "${REPORT_TIMER_SOURCE}" ]]; then
		echo "missing report timer source: ${REPORT_TIMER_SOURCE}" >&2
		exit 1
	fi
	if [[ "${EUID}" -eq 0 ]]; then
		install -m 0644 "${REPORT_SERVICE_SOURCE}" "${REPORT_SERVICE_DEST}"
		install -m 0644 "${REPORT_TIMER_SOURCE}" "${REPORT_TIMER_DEST}"
	else
		sudo install -m 0644 "${REPORT_SERVICE_SOURCE}" "${REPORT_SERVICE_DEST}"
		sudo install -m 0644 "${REPORT_TIMER_SOURCE}" "${REPORT_TIMER_DEST}"
	fi
	run_systemctl daemon-reload
}

ensure_gtos_bin() {
	if [[ -x "${GTOS_BIN}" ]]; then
		return
	fi
	echo "gtos binary not found at ${GTOS_BIN}, building..."
	(cd "${REPO_ROOT}" && go run build/ci.go install ./cmd/gtos)
}

ensure_toskey_bin() {
	if [[ -x "${TOSKEY_BIN}" ]]; then
		return
	fi
	echo "toskey binary not found at ${TOSKEY_BIN}, building..."
	(cd "${REPO_ROOT}" && go run build/ci.go install ./cmd/toskey)
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
	local v1 v2 v3 h1 h2 h3 extra genesis ts_ms tos3_storage checkpoint_json
	genesis="${BASE_DIR}/genesis_testnet_3vals.json"
	ts_ms=$(( $(date +%s%3N) + GENESIS_START_DELAY_MS ))
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
	checkpoint_json="$(checkpoint_config_json)"

	cat >"${genesis}" <<EOF_GENESIS
{
  "config": {
    "chainId": ${NETWORK_ID},
    "dpos": {
      "periodMs": ${PERIOD_MS},
      "epoch": ${EPOCH},
      "turnLength": ${TURN_LENGTH},
      "maxValidators": ${MAX_VALIDATORS},
${checkpoint_json}      "sealSignerType": "ed25519"
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
		# Wipe chain state only; preserve nodekey so enode IDs stay stable.
		rm -rf "$(node_dir "${idx}")/gtos/chaindata" \
		       "$(node_dir "${idx}")/gtos/lightchaindata" \
		       "$(node_dir "${idx}")/gtos/triecache" \
		       "$(node_dir "${idx}")/gtos/nodes"
		rm -f  "$(node_dir "${idx}")/gtos/transactions.rlp"
		"${GTOS_BIN}" --datadir "$(node_dir "${idx}")" init "${genesis}" >"$(node_init_log "${idx}")" 2>&1
	done
	rm -rf "$(rpc_dir 1)/gtos/chaindata" \
	       "$(rpc_dir 1)/gtos/lightchaindata" \
	       "$(rpc_dir 1)/gtos/triecache" \
	       "$(rpc_dir 1)/gtos/nodes"
	rm -f  "$(rpc_dir 1)/gtos/transactions.rlp"
	"${GTOS_BIN}" --datadir "$(rpc_dir 1)" init "${genesis}" >"${BASE_DIR}/logs/init_rpc1.log" 2>&1
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

legacy_service_exists() {
	local idx="$1"
	run_systemctl cat "$(legacy_node_service "${idx}")" >/dev/null 2>&1
}

assert_services_prepared() {
	local idx
	for idx in 1 2 3; do
		if ! service_exists "${idx}"; then
			echo "missing systemd service: $(node_service "${idx}")" >&2
			echo "run setup first so validator_cluster.sh installs template units and env files." >&2
			exit 1
		fi
	done
}

assert_rpc_service_prepared() {
	if ! run_systemctl cat "$(rpc_service 1)" >/dev/null 2>&1; then
		echo "missing rpc systemd service: $(rpc_service 1)" >&2
		echo "run setup first so validator_cluster.sh installs rpc template units and env files." >&2
		exit 1
	fi
}

stop_legacy_nodes() {
	local idx svc
	for idx in 1 2 3; do
		svc="$(legacy_node_service "${idx}")"
		if run_systemctl is-active --quiet "${svc}"; then
			run_systemctl stop "${svc}"
			echo "stopped legacy service ${svc}"
		fi
	done
}

retire_legacy_units() {
	local idx svc
	for idx in 1 2 3; do
		if ! legacy_service_exists "${idx}"; then
			continue
		fi
		svc="$(legacy_node_service "${idx}")"
		run_systemctl disable --now "${svc}" >/dev/null 2>&1 || true
		echo "retired legacy unit ${svc}"
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

wait_for_named_service_active() {
	local svc="$1" timeout_s="${2:-30}" elapsed=0
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		if run_systemctl is-active --quiet "${svc}"; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
}

wait_for_rpc_ipc() {
	local idx="$1" timeout_s="${2:-30}" ipc elapsed=0
	ipc="$(rpc_ipc "${idx}")"
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		if [[ -S "${ipc}" ]]; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
}

wait_for_rpc_attach() {
	local idx="$1" timeout_s="${2:-30}" elapsed=0
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		if "${GTOS_BIN}" --exec 'admin.nodeInfo.id' attach "$(rpc_ipc "${idx}")" >/dev/null 2>&1; then
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

start_rpc_service() {
	local idx="$1" svc
	svc="$(rpc_service "${idx}")"
	run_systemctl start "${svc}"
	if ! wait_for_named_service_active "${svc}" 30; then
		echo "rpc service failed to become active: ${svc}" >&2
		run_systemctl status --no-pager "${svc}" || true
		exit 1
	fi
	if ! wait_for_rpc_ipc "${idx}" 30 || ! wait_for_rpc_attach "${idx}" 30; then
		echo "rpc${idx} attach not ready" >&2
		run_systemctl status --no-pager "${svc}" || true
		exit 1
	fi
	echo "rpc${idx} started via ${svc}"
}

start_guard_service() {
	run_systemctl enable "${GUARD_SERVICE_NAME}" >/dev/null 2>&1 || true
	run_systemctl restart "${GUARD_SERVICE_NAME}"
	if ! wait_for_named_service_active "${GUARD_SERVICE_NAME}" 15; then
		echo "guard service failed to become active: ${GUARD_SERVICE_NAME}" >&2
		run_systemctl status --no-pager "${GUARD_SERVICE_NAME}" || true
		exit 1
	fi
	echo "guard started via ${GUARD_SERVICE_NAME}"
}

start_report_timer() {
	run_systemctl enable "${REPORT_TIMER_NAME}" >/dev/null 2>&1 || true
	run_systemctl restart "${REPORT_TIMER_NAME}"
	if ! wait_for_named_service_active "${REPORT_TIMER_NAME}" 15; then
		echo "report timer failed to become active: ${REPORT_TIMER_NAME}" >&2
		run_systemctl status --no-pager "${REPORT_TIMER_NAME}" || true
		exit 1
	fi
	echo "report timer started via ${REPORT_TIMER_NAME}"
}

stop_guard_service() {
	if run_systemctl is-active --quiet "${GUARD_SERVICE_NAME}"; then
		run_systemctl stop "${GUARD_SERVICE_NAME}"
		echo "guard stopped via ${GUARD_SERVICE_NAME}"
	fi
}

stop_report_timer() {
	if run_systemctl is-active --quiet "${REPORT_TIMER_NAME}"; then
		run_systemctl stop "${REPORT_TIMER_NAME}"
		echo "report timer stopped via ${REPORT_TIMER_NAME}"
	fi
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

restart_rpc_service() {
	local idx="$1" svc
	svc="$(rpc_service "${idx}")"
	run_systemctl restart "${svc}"
	if ! wait_for_named_service_active "${svc}" 30; then
		echo "rpc service failed after restart: ${svc}" >&2
		run_systemctl status --no-pager "${svc}" || true
		exit 1
	fi
	if ! wait_for_rpc_ipc "${idx}" 30 || ! wait_for_rpc_attach "${idx}" 30; then
		echo "rpc${idx} attach not ready after restart" >&2
		run_systemctl status --no-pager "${svc}" || true
		exit 1
	fi
	echo "rpc${idx} restarted via ${svc}"
}

get_node_enode() {
	local idx="$1" timeout_s="${2:-30}" elapsed=0 enode=""
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		enode="$("${GTOS_BIN}" --exec 'admin.nodeInfo.enode' attach "$(node_ipc "${idx}")" 2>/dev/null | tr -d '"\r\n[:space:]')"
		if [[ "${enode}" =~ ^enode:// ]]; then
			echo "$(normalize_local_enode "${enode}")"
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

rpc_json() {
	rpc_call "$1" "$2" "$3"
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

wait_for_rpc_catchup() {
	local timeout_s="${1:-30}" max_lag="${2:-4}" elapsed=0 validator_head rpc_head
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		validator_head="$(hex_to_dec "$(rpc_hex_result "$(node_http_port 1)" "tos_blockNumber" "[]" || echo 0x0)")"
		rpc_head="$(hex_to_dec "$(rpc_hex_result "$(rpc_http_port 1)" "tos_blockNumber" "[]" || echo 0x0)")"
		if (( rpc_head + max_lag >= validator_head )); then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
}

node_validator_address() {
	local idx="$1" addr
	addr="$(tr -d '\n\r\t ' <"$(node_addr_file "${idx}")" 2>/dev/null || true)"
	if ! valid_addr "${addr}"; then
		echo "node${idx} validator address missing or invalid" >&2
		exit 1
	fi
	normalize_addr "${addr}"
}

node_keyfile_for_validator() {
	local idx="$1" addr addrhex keyfile
	addr="$(node_validator_address "${idx}")"
	addrhex="${addr#0x}"
	keyfile="$(find "$(node_dir "${idx}")/keystore" -maxdepth 1 -type f -print | sort | while read -r path; do
		if grep -q "\"address\":\"${addrhex}\"" "${path}"; then
			echo "${path}"
			break
		fi
	done)"
	if [[ -z "${keyfile}" ]]; then
		echo "failed to locate keyfile for node${idx} validator ${addr}" >&2
		exit 1
	fi
	echo "${keyfile}"
}

node_signer_value_from_keyfile() {
	local idx="$1" keyfile out
	ensure_toskey_bin
	keyfile="$(node_keyfile_for_validator "${idx}")"
	out="$("${TOSKEY_BIN}" inspect --json --passwordfile "${PASSFILE}" "${keyfile}")"
	python3 -c '
import json, sys
body = json.load(sys.stdin)
signer_type = str(body.get("SignerType") or "").strip().lower()
pub = str(body.get("PublicKey") or "").strip().lower()
if signer_type != "ed25519":
    raise SystemExit(f"validator key is {signer_type or 'unknown'}, want ed25519")
if len(pub) != 64:
    raise SystemExit("invalid ed25519 public key length from toskey inspect")
print("0x" + pub)
' <<<"${out}"
}

get_signer_profile_json() {
	local query_idx="$1" validator_addr="$2" port
	port="$(node_http_port "${query_idx}")"
	rpc_json "${port}" "tos_getSigner" "[\"${validator_addr}\",\"latest\"]"
}

validator_status_slot() {
	local validator_addr="$1"
	(cd "${REPO_ROOT}" && go run ./scripts/validator_slot/main.go "${validator_addr}" status)
}

validator_status_on_node() {
	local query_idx="$1" validator_addr="$2" slot raw
	slot="$(validator_status_slot "${validator_addr}")"
	raw="$(rpc_json "$(node_http_port "${query_idx}")" "tos_getStorageAt" "[\"0x0000000000000000000000000000000000000000000000000000000000000003\",\"${slot}\",\"latest\"]")"
	python3 -c '
import json, sys
body = json.load(sys.stdin)
value = str(body.get("result") or "0x0")
if not value.startswith("0x"):
    raise SystemExit("invalid storage result")
raw = bytes.fromhex(value[2:].rjust(64, "0"))
print(raw[-1])
' <<<"${raw}"
}

get_epoch_info_json() {
	local query_idx="$1" port
	port="$(node_http_port "${query_idx}")"
	rpc_json "${port}" "dpos_getEpochInfo" "[\"latest\"]"
}

wait_for_tx_receipt() {
	local idx="$1" txhash="$2" timeout_s="${3:-60}" elapsed=0 port out
	port="$(node_http_port "${idx}")"
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		out="$(rpc_json "${port}" "tos_getTransactionReceipt" "[\"${txhash}\"]")"
		if ! echo "${out}" | grep -q '"error"'; then
			if python3 -c '
import json, sys
body = json.load(sys.stdin)
receipt = body.get("result")
if not receipt:
    raise SystemExit(1)
status = str(receipt.get("status") or "")
if status in ("0x1", "0x01", "1"):
    raise SystemExit(0)
raise SystemExit(2)
' <<<"${out}"; then
				return 0
			else
				case "$?" in
				2) return 2 ;;
				esac
			fi
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
}

wait_for_validator_status() {
	local query_idx="$1" validator_addr="$2" want_status="$3" timeout_s="${4:-60}" elapsed=0 have
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		have="$(validator_status_on_node "${query_idx}" "${validator_addr}")"
		if [[ "${have}" == "${want_status}" ]]; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
}

describe_next_epoch() {
	local query_idx="$1" info
	info="$(get_epoch_info_json "${query_idx}")"
	python3 -c '
import json, sys
body = json.load(sys.stdin)
result = body.get("result") or {}
def dec(key):
    value = str(result.get(key) or "0x0")
    return int(value, 16) if value.startswith("0x") else int(value or "0")
next_epoch = dec("nextEpochStart")
blocks = dec("blocksUntilEpoch")
period_ms = dec("targetBlockPeriodMs")
print(f"next epoch at block {next_epoch} ({blocks} blocks, period {period_ms}ms)")
' <<<"${info}"
}

epoch_transition_timeout_seconds() {
	local query_idx="$1" info
	info="$(get_epoch_info_json "${query_idx}")"
	python3 -c '
import json, sys, math
body = json.load(sys.stdin)
result = body.get("result") or {}
def dec(key):
    value = str(result.get(key) or "0x0")
    return int(value, 16) if value.startswith("0x") else int(value or "0")
blocks = dec("blocksUntilEpoch")
period_ms = dec("targetBlockPeriodMs")
secs = math.ceil((blocks * period_ms) / 1000.0) + 30
print(max(secs, 60))
' <<<"${info}"
}

ensure_validator_signer_registered() {
	local idx="$1" addr query_idx signer_value profile txresp status=0
	addr="$(node_validator_address "${idx}")"
	query_idx="$(first_running_node || true)"
	if [[ -z "${query_idx}" ]]; then
		echo "no running node available to inspect signer metadata for ${addr}" >&2
		exit 1
	fi
	signer_value="$(node_signer_value_from_keyfile "${idx}")"
	profile="$(get_signer_profile_json "${query_idx}" "${addr}")"
	if python3 -c '
import json, sys
addr = sys.argv[1].lower()
want = sys.argv[2].lower()
body = json.load(sys.stdin)
signer = (body.get("result") or {}).get("signer") or {}
stype = str(signer.get("type") or "").strip().lower()
svalue = str(signer.get("value") or "").strip().lower()
defaulted = bool(signer.get("defaulted"))
if defaulted or stype == "address":
    raise SystemExit(10)
if stype != "ed25519":
    raise SystemExit(f"on-chain signer for {addr} is {stype or 'unknown'}, want ed25519")
if svalue != want:
    raise SystemExit(f"on-chain signer value for {addr} does not match local key")
' "${addr}" "${signer_value}" <<<"${profile}"
	then
		status=0
	else
		status=$?
	fi
	case "${status}" in
	0)
		return 0
		;;
	10)
		;;
	*)
		echo "signer metadata check failed for node${idx}" >&2
		exit 1
		;;
	esac
	echo "node${idx} has no on-chain signer metadata; bootstrapping ed25519 signer"
	txresp="$(rpc_json "$(node_http_port "${idx}")" "tos_setSigner" "[{\"from\":\"${addr}\",\"signerType\":\"ed25519\",\"signerValue\":\"${signer_value}\"}]")"
	if echo "${txresp}" | grep -q '"error"'; then
		echo "RPC tos_setSigner failed for node${idx}: ${txresp}" >&2
		exit 1
	fi
	if ! wait_for_signer_state "${query_idx}" "${addr}" "${signer_value}" 60; then
		echo "signer bootstrap tx submitted for node${idx} but signer metadata did not become visible in time" >&2
		exit 1
	fi
}

submit_validator_register() {
	local idx="$1" addr port out txhash
	addr="$(node_validator_address "${idx}")"
	port="$(node_http_port "${idx}")"
	out="$(rpc_json "${port}" "tos_sendTransaction" "[{\"from\":\"${addr}\",\"to\":\"0x0000000000000000000000000000000000000000000000000000000000000001\",\"value\":\"${VALIDATOR_REGISTER_VALUE_HEX}\",\"input\":\"${VALIDATOR_REGISTER_PAYLOAD_HEX}\",\"signerType\":\"ed25519\"}]")"
	if echo "${out}" | grep -q '"error"'; then
		echo "RPC tos_sendTransaction validator register failed for node${idx}: ${out}" >&2
		exit 1
	fi
	txhash="$(echo "${out}" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')"
	if [[ -z "${txhash}" ]]; then
		echo "validator register returned no transaction hash for node${idx}: ${out}" >&2
		exit 1
	fi
	echo "${txhash}"
}

ensure_validator_registered() {
	local idx="$1" addr query_idx status txhash
	addr="$(node_validator_address "${idx}")"
	query_idx="$(first_running_node || true)"
	if [[ -z "${query_idx}" ]]; then
		echo "no running node available to inspect validator registry state for ${addr}" >&2
		exit 1
	fi
	status="$(validator_status_on_node "${query_idx}" "${addr}")"
	case "${status}" in
	1|2)
		return 0
		;;
	0)
		;;
	*)
		echo "unexpected validator status ${status} for ${addr}" >&2
		exit 1
		;;
	esac
	echo "node${idx} is not registered in validator registry; submitting validator register"
	txhash="$(submit_validator_register "${idx}")"
	if wait_for_tx_receipt "${idx}" "${txhash}" 60; then
		:
	else
		case "$?" in
		2)
			echo "validator register tx=${txhash} for node${idx} reverted" >&2
			exit 1
			;;
		*)
			echo "validator register tx=${txhash} for node${idx} not mined within timeout" >&2
			exit 1
			;;
		esac
	fi
	if ! wait_for_validator_status "${query_idx}" "${addr}" 1 60; then
		echo "validator register tx=${txhash} for node${idx} mined but validator status did not become Active" >&2
		exit 1
	fi
}

wait_for_signer_state() {
	local query_idx="$1" validator_addr="$2" signer_value="$3" timeout_s="${4:-60}" elapsed=0 profile
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		profile="$(get_signer_profile_json "${query_idx}" "${validator_addr}")"
		if python3 -c '
import json, sys
want = sys.argv[1].lower()
body = json.load(sys.stdin)
signer = (body.get("result") or {}).get("signer") or {}
stype = str(signer.get("type") or "").strip().lower()
svalue = str(signer.get("value") or "").strip().lower()
defaulted = bool(signer.get("defaulted"))
sys.exit(0 if (not defaulted and stype == "ed25519" and svalue == want) else 1)
' "${signer_value}" <<<"${profile}"
		then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
}

first_running_node() {
	local idx
	for idx in 1 2 3; do
		if run_systemctl is-active --quiet "$(node_service "${idx}")"; then
			echo "${idx}"
			return 0
		fi
	done
	return 1
}

first_running_node_except() {
	local skip="$1" idx
	for idx in 1 2 3; do
		if [[ "${idx}" == "${skip}" ]]; then
			continue
		fi
		if run_systemctl is-active --quiet "$(node_service "${idx}")"; then
			echo "${idx}"
			return 0
		fi
	done
	return 1
}

validator_active_on_node() {
	local query_idx="$1" validator_addr="$2"
	local port out
	port="$(node_http_port "${query_idx}")"
	out="$(rpc_json "${port}" "dpos_getValidators" "[\"latest\"]")"
	python3 -c '
import json, sys
validator = sys.argv[1].lower()
body = json.load(sys.stdin)
result = body.get("result") or []
values = [str(v).lower() for v in result]
sys.exit(0 if validator in values else 1)
' "${validator_addr}" <<<"${out}"
}

wait_for_validator_active_state() {
	local query_idx="$1" validator_addr="$2" want_present="$3" timeout_s="${4:-60}" elapsed=0
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		if validator_active_on_node "${query_idx}" "${validator_addr}"; then
			if [[ "${want_present}" == "present" ]]; then
				return 0
			fi
		else
			if [[ "${want_present}" == "absent" ]]; then
				return 0
			fi
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	return 1
}

submit_validator_maintenance_action() {
	local idx="$1" method="$2" port addr params out txhash
	if ! run_systemctl is-active --quiet "$(node_service "${idx}")"; then
		echo "node${idx} service is not running; cannot submit ${method}" >&2
		exit 1
	fi
	ensure_validator_signer_registered "${idx}"
	addr="$(node_validator_address "${idx}")"
	port="$(node_http_port "${idx}")"
	params="[{\"from\":\"${addr}\"}]"
	out="$(rpc_json "${port}" "${method}" "${params}")"
	if echo "${out}" | grep -q '"error"'; then
		echo "RPC ${method} failed for node${idx}: ${out}" >&2
		exit 1
	fi
	txhash="$(echo "${out}" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')"
	if [[ -z "${txhash}" ]]; then
		echo "RPC ${method} returned no transaction hash for node${idx}: ${out}" >&2
		exit 1
	fi
	echo "${txhash}"
}

wait_for_peer_mesh() {
	local timeout_s="${1:-30}" elapsed=0
	local n peer_hex peer_dec
	while [[ "${elapsed}" -lt "${timeout_s}" ]]; do
		for n in 1 2 3; do
			peer_hex="$(rpc_hex_result "$(node_http_port "${n}")" "net_peerCount" "[]" || echo 0x0)"
			peer_dec="$(hex_to_dec "${peer_hex}")"
			if (( peer_dec < 2 )); then
				sleep 1
				elapsed=$((elapsed + 1))
				continue 2
			fi
		done
		return 0
	done
	return 1
}

assert_accounts_prepared() {
	local idx addr
	for idx in 1 2 3; do
		addr="$(tr -d '\n\r\t ' <"$(node_addr_file "${idx}")" 2>/dev/null || true)"
		if ! valid_addr "${addr}"; then
			echo "node${idx} validator address missing. run: scripts/validator_cluster.sh setup" >&2
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
	write_validator_envs
	write_rpc_envs
	echo "mesh connected:"
	echo "  node1=${e1}"
	echo "  node2=${e2}"
	echo "  node3=${e3}"
}

start_nodes() {
	assert_services_prepared
	assert_rpc_service_prepared
	assert_accounts_prepared
	stop_guard_service
	stop_legacy_nodes
	start_service_node 1
	start_service_node 2
	start_service_node 3
	refresh_mesh_artifacts
	if ! wait_for_peer_mesh 30; then
		echo "warning: peer mesh did not converge to 2 peers per node within timeout" >&2
	fi
	start_rpc_service 1
	if ! wait_for_rpc_catchup 30 4; then
		echo "warning: rpc1 did not catch up within 4 blocks of validator head" >&2
	fi
	start_guard_service
	start_report_timer
}

restart_nodes() {
	assert_services_prepared
	assert_rpc_service_prepared
	stop_guard_service
	stop_legacy_nodes
	restart_service_node 1
	restart_service_node 2
	restart_service_node 3
	refresh_mesh_artifacts
	restart_rpc_service 1
	if ! wait_for_rpc_catchup 30 4; then
		echo "warning: rpc1 did not catch up within 4 blocks of validator head after restart" >&2
	fi
	start_guard_service
	start_report_timer
}

run_report_now() {
	run_systemctl start "${REPORT_SERVICE_NAME}"
	run_systemctl --no-pager --lines=20 status "${REPORT_SERVICE_NAME}" || true
}

run_chain_status() {
	if [[ ! -x "$(chain_status_script)" ]]; then
		echo "missing chain status script: $(chain_status_script)" >&2
		exit 1
	fi
	"$(chain_status_script)" \
		--base-dir "${BASE_DIR}" \
		--nodes "http://127.0.0.1:8545,http://127.0.0.1:8547,http://127.0.0.1:8549" \
		--rpcs "http://127.0.0.1:8555" \
		--guard-dir "${BASE_DIR}/ops/validator_guard" \
		--incident-dir "${BASE_DIR}/ops/incidents" \
		--format both
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

enter_maintenance() {
	local idx="$1" txhash query_idx addr rc=0 status
	ensure_validator_signer_registered "${idx}"
	ensure_validator_registered "${idx}"
	addr="$(node_validator_address "${idx}")"
	query_idx="$(first_running_node || true)"
	status="$(validator_status_on_node "${query_idx}" "${addr}")"
	if [[ "${status}" == "2" ]]; then
		write_maintenance_state "${idx}" "maintenance" "" "${addr}"
		echo "node${idx} is already in maintenance; proposer-set removal takes effect at the next epoch: $(describe_next_epoch "${query_idx}")"
		return 0
	fi
	txhash="$(submit_validator_maintenance_action "${idx}" "tos_enterMaintenance")"
	if wait_for_tx_receipt "${idx}" "${txhash}" 60; then
		:
	else
		rc=$?
		case "${rc}" in
		2)
			echo "enter maintenance tx=${txhash} for node${idx} reverted" >&2
			exit 1
			;;
		esac
		echo "warning: enter maintenance tx=${txhash} for node${idx} not mined within timeout" >&2
	fi
	query_idx="$(first_running_node_except "${idx}" || first_running_node || true)"
	if [[ -z "${query_idx}" ]]; then
		write_maintenance_state "${idx}" "maintenance" "${txhash}" "${addr}"
		echo "submitted enter maintenance for node${idx}, tx=${txhash}"
		return 0
	fi
	write_maintenance_state "${idx}" "maintenance" "${txhash}" "${addr}"
	if validator_active_on_node "${query_idx}" "${addr}"; then
		echo "node${idx} entered maintenance, tx=${txhash}; removal from proposer set takes effect at the next epoch: $(describe_next_epoch "${query_idx}")"
	else
		echo "node${idx} entered maintenance, tx=${txhash}"
	fi
}

exit_maintenance() {
	local idx="$1" txhash query_idx addr rc=0 status
	ensure_validator_signer_registered "${idx}"
	addr="$(node_validator_address "${idx}")"
	query_idx="$(first_running_node || true)"
	if [[ -z "${query_idx}" ]]; then
		echo "no running node available to inspect validator status for node${idx}" >&2
		exit 1
	fi
	status="$(validator_status_on_node "${query_idx}" "${addr}")"
	case "${status}" in
	2)
		;;
	1)
		write_maintenance_state "${idx}" "active" "" "${addr}"
		echo "node${idx} is already active; no exit-maintenance transaction needed"
		return 0
		;;
	0)
		echo "node${idx} is not registered in validator registry; cannot exit maintenance" >&2
		exit 1
		;;
	esac
	txhash="$(submit_validator_maintenance_action "${idx}" "tos_exitMaintenance")"
	if wait_for_tx_receipt "${idx}" "${txhash}" 60; then
		:
	else
		rc=$?
		case "${rc}" in
		2)
			echo "exit maintenance tx=${txhash} for node${idx} reverted" >&2
			exit 1
			;;
		esac
		echo "warning: exit maintenance tx=${txhash} for node${idx} not mined within timeout" >&2
	fi
	write_maintenance_state "${idx}" "active" "${txhash}" "${addr}"
	if validator_active_on_node "${query_idx}" "${addr}"; then
		echo "node${idx} exited maintenance, tx=${txhash}"
	else
		echo "node${idx} exited maintenance, tx=${txhash}; proposer-set rejoin takes effect at the next epoch: $(describe_next_epoch "${query_idx}")"
	fi
}

drain_node() {
	local idx="$1" addr query_idx timeout_s
	enter_maintenance "${idx}"
	addr="$(node_validator_address "${idx}")"
	query_idx="$(first_running_node_except "${idx}" || first_running_node || true)"
	if [[ -n "${query_idx}" ]]; then
		timeout_s="$(epoch_transition_timeout_seconds "${query_idx}")"
		if ! wait_for_validator_active_state "${query_idx}" "${addr}" absent "${timeout_s}"; then
			echo "node${idx} did not leave the active validator set before timeout; next epoch status: $(describe_next_epoch "${query_idx}")" >&2
			exit 1
		fi
	fi
	stop_service_node "${idx}"
	echo "node${idx} drained"
}

resume_node() {
	local idx="$1"
	start_service_node "${idx}"
	if run_systemctl is-active --quiet "$(node_service 1)" && run_systemctl is-active --quiet "$(node_service 2)" && run_systemctl is-active --quiet "$(node_service 3)"; then
		refresh_mesh_artifacts
	fi
	if ! wait_for_peer_mesh 30; then
		echo "warning: peer mesh did not fully converge before exit maintenance for node${idx}" >&2
	fi
	exit_maintenance "${idx}"
	echo "node${idx} resumed"
}

verify_nodes() {
	local n phex b1hex b2hex pdec b1dec b2dec
	local rpc_before_hex rpc_after_hex rpc_peer_hex
	local -A peer_count_hex block_before_hex block_after_hex

	for n in 1 2 3; do
		peer_count_hex["${n}"]="$(rpc_hex_result "$(node_http_port "${n}")" "net_peerCount" "[]")"
		block_before_hex["${n}"]="$(rpc_hex_result "$(node_http_port "${n}")" "tos_blockNumber" "[]")"
	done
	rpc_peer_hex="$(rpc_hex_result "$(rpc_http_port 1)" "net_peerCount" "[]" || echo 0x0)"
	rpc_before_hex="$(rpc_hex_result "$(rpc_http_port 1)" "tos_blockNumber" "[]" || echo 0x0)"

	sleep "${VERIFY_SLEEP_SEC}"

	for n in 1 2 3; do
		block_after_hex["${n}"]="$(rpc_hex_result "$(node_http_port "${n}")" "tos_blockNumber" "[]")"
	done
	rpc_after_hex="$(rpc_hex_result "$(rpc_http_port 1)" "tos_blockNumber" "[]" || echo 0x0)"

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
	echo "rpc1: peerCount=$(hex_to_dec "${rpc_peer_hex}") block=$(hex_to_dec "${rpc_before_hex}")->$(hex_to_dec "${rpc_after_hex}")"

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
			if ! wait_for_block_growth "${n}" 15 1; then
				echo "verify failed: node${n} block number did not grow" >&2
				exit 1
			fi
		fi
	done
	if (( "$(hex_to_dec "${rpc_peer_hex}")" < 1 )); then
		echo "verify failed: rpc1 peerCount < 1" >&2
		exit 1
	fi
	if (( "$(hex_to_dec "${rpc_after_hex}")" + 4 < "$(hex_to_dec "${block_after_hex[1]}")" )); then
		echo "verify failed: rpc1 lag exceeds 4 blocks behind validator head" >&2
		exit 1
	fi

	python3 - <<'PY'
import json, urllib.request, sys
url = "http://127.0.0.1:8545"
def rpc(method, params):
    data = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        body = json.loads(r.read())
    if "error" in body:
        raise SystemExit(f'{method} error: {body["error"]}')
    return body["result"]

def dec(value):
    if isinstance(value, str) and value.startswith("0x"):
        return int(value, 16)
    return int(value)

latest = dec(rpc("tos_blockNumber", []))
genesis = rpc("tos_getBlockByNumber", ["0x0", False])
epoch_info = rpc("dpos_getEpochInfo", ["latest"])
validators = [str(v).lower() for v in (rpc("dpos_getValidators", ["latest"]) or [])]
period_ms = dec(epoch_info.get("targetBlockPeriodMs") or "0x0")
turn_length = dec(epoch_info.get("turnLength") or "0x0")
if period_ms <= 0 or turn_length <= 0 or not validators:
    print("verify failed: invalid DPoS epoch info for grouped-turn validation", file=sys.stderr)
    sys.exit(1)

sample_len = min(latest, max(turn_length * 2, 16))
start = max(1, latest - sample_len + 1)
records = []
for num in range(start, latest + 1):
    block = rpc("tos_getBlockByNumber", [hex(num), False])
    miner = block["miner"].lower()
    ts = dec(block["timestamp"])
    slot = (ts - dec(genesis["timestamp"])) // period_ms
    if slot < 1:
        print(f"verify failed: block {num} has invalid slot {slot}", file=sys.stderr)
        sys.exit(1)
    group = (slot - 1) // turn_length
    records.append((num, miner, slot, group))

print("grouped-turn sample:", len(records), "blocks,", "turnLength=", turn_length)
for num, miner, slot, group in records:
    print(f"  block={num} slot={slot} group={group} miner={miner}")

group_counts = {}
group_order = []
group_totals = {}
for _, miner, _, group in records:
    counts = group_counts.get(group)
    if counts is None:
        counts = {}
        group_counts[group] = counts
        group_order.append(group)
    counts[miner] = counts.get(miner, 0) + 1
    group_totals[group] = group_totals.get(group, 0) + 1

if len(group_order) >= 1:
    dominant = {}
    out_of_turn = 0
    strict_groups = group_order[1:-1] if len(group_order) > 2 else group_order
    for group in group_order:
        counts = group_counts[group]
        miner, count = max(counts.items(), key=lambda item: item[1])
        dominant[group] = miner
        out_of_turn += group_totals[group] - count
        if group in strict_groups and count * 2 <= group_totals[group]:
            print(f"verify failed: group {group} has no dominant proposer: {counts}", file=sys.stderr)
            sys.exit(1)
        if group in strict_groups:
            expected = validators[group % len(validators)]
            if miner != expected:
                print(
                    f"verify failed: group {group} dominant proposer {miner} != expected {expected}",
                    file=sys.stderr,
                )
                sys.exit(1)
    print("grouped-turn rotation observed across", len(group_order), "groups;", "out-of-turn blocks=", out_of_turn)
else:
    print("grouped-turn sample covers one group only; proposer continuity is expected")
PY

	echo "verify passed"
}

stop_nodes() {
	local idx
	stop_guard_service
	stop_report_timer
	stop_rpc_service 1
	for idx in 1 2 3; do
		stop_service_node "${idx}"
	done
}

stop_rpc_service() {
	local idx="$1" svc
	svc="$(rpc_service "${idx}")"
	if ! run_systemctl cat "${svc}" >/dev/null 2>&1; then
		echo "rpc${idx} service not installed (${svc})"
		return 0
	fi
	if run_systemctl is-active --quiet "${svc}"; then
		run_systemctl stop "${svc}"
		echo "rpc${idx} stopped via ${svc}"
	else
		echo "rpc${idx} already stopped (${svc})"
	fi
}

stop_service_node() {
	local idx="$1" svc
	svc="$(node_service "${idx}")"
	if run_systemctl is-active --quiet "${svc}"; then
		run_systemctl stop "${svc}"
		echo "node${idx} stopped via ${svc}"
	else
		echo "node${idx} already stopped (${svc})"
	fi
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
	svc="$(rpc_service 1)"
	port="$(rpc_http_port 1)"
	if ! run_systemctl cat "${svc}" >/dev/null 2>&1; then
		echo "rpc1: not installed(service=${svc})"
	elif run_systemctl is-active --quiet "${svc}"; then
		pid="$(run_systemctl show -p MainPID --value "${svc}" | tr -d '\r')"
		state="running(service=${svc},pid=${pid})"
		block="$(rpc_hex_result "${port}" "tos_blockNumber" "[]" || true)"
		peers="$(rpc_hex_result "${port}" "net_peerCount" "[]" || true)"
		if [[ -n "${block}" ]]; then
			block="$(hex_to_dec "${block}")"
		fi
		if [[ -n "${peers}" ]]; then
			peers="$(hex_to_dec "${peers}")"
		fi
	else
		state="stopped(service=${svc})"
		block="-"
		peers="-"
	fi
	echo "rpc1: ${state}, http=127.0.0.1:${port}, block=${block}, peers=${peers}"
	for idx in 1 2 3; do
		if [[ -f "$(maintenance_state_file "${idx}")" ]]; then
			# shellcheck disable=SC1090
			source "$(maintenance_state_file "${idx}")"
			age="-"
			severity=""
			if [[ -n "${UPDATED_AT:-}" ]]; then
				age="$(( $(date -u +%s) - UPDATED_AT ))"
				if (( age >= 86400 )); then
					severity="CRITICAL"
				elif (( age >= 21600 )); then
					severity="ERROR"
				elif (( age >= 7200 )); then
					severity="WARN"
				fi
			fi
			echo "node${idx}-maintenance: state=${STATE:-unknown}, ageSec=${age}, severity=${severity:-none}, tx=${TX_HASH:-}"
		else
			echo "node${idx}-maintenance: state=unknown"
		fi
	done
	if run_systemctl is-active --quiet "${GUARD_SERVICE_NAME}"; then
		echo "guard: running(service=${GUARD_SERVICE_NAME})"
	else
		echo "guard: stopped(service=${GUARD_SERVICE_NAME})"
	fi
	if run_systemctl is-active --quiet "${REPORT_TIMER_NAME}"; then
		echo "report-timer: running(service=${REPORT_TIMER_NAME})"
	else
		echo "report-timer: stopped(service=${REPORT_TIMER_NAME})"
	fi
	echo
	run_chain_status || true
}

setup_network() {
	ensure_dirs
	ensure_gtos_bin
	ensure_passfile
	validate_local_checkpoint_config
	stop_nodes
	stop_legacy_nodes
	retire_legacy_units
	write_validators_files
	prepare_runtime_assets
	write_genesis
	init_datadirs
	echo "setup done (accounts/config/genesis initialized):"
	echo "  validators: ${BASE_DIR}/validator_accounts.txt"
	echo "  validator config example: $(node_config_file 1)"
	echo "  rpc config example: $(rpc_config_file 1)"
	echo "  systemd template: ${SYSTEMD_TEMPLATE_DEST}"
	echo "  rpc systemd template: ${RPC_TEMPLATE_DEST}"
	echo "  turn length: ${TURN_LENGTH}"
	echo "  turn group duration (ms): $((TURN_LENGTH * PERIOD_MS))"
	if is_checkpoint_finality_enabled; then
		echo "  checkpoint interval: ${CHECKPOINT_INTERVAL}"
		echo "  checkpoint finality block: ${CHECKPOINT_FINALITY_BLOCK}"
		echo "  first eligible checkpoint: $(checkpoint_first_eligible)"
		echo "  gc mode: $(expected_service_gc_flags)"
	else
		echo "  checkpoint finality: disabled"
	fi
	echo "  genesis start delay (ms): ${GENESIS_START_DELAY_MS}"
}

clean_network() {
	stop_nodes
	stop_legacy_nodes
	rm -rf "$(node_dir 1)/gtos" "$(node_dir 2)/gtos" "$(node_dir 3)/gtos" "$(rpc_dir 1)/gtos"
	rm -f "${BASE_DIR}/logs/node1.log" "${BASE_DIR}/logs/node2.log" "${BASE_DIR}/logs/node3.log" "${BASE_DIR}/logs/rpc1.log"
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
	validate_local_checkpoint_config
	prepare_runtime_assets
	assert_accounts_prepared
	start_nodes
	;;
restart)
	ensure_dirs
	ensure_gtos_bin
	ensure_passfile
	validate_local_checkpoint_config
	prepare_runtime_assets
	assert_accounts_prepared
	restart_nodes
	;;
enter-maintenance)
	require_target_node
	assert_accounts_prepared
	enter_maintenance "${TARGET_NODE}"
	;;
exit-maintenance)
	require_target_node
	assert_accounts_prepared
	exit_maintenance "${TARGET_NODE}"
	;;
drain)
	require_target_node
	assert_accounts_prepared
	drain_node "${TARGET_NODE}"
	;;
resume)
	require_target_node
	assert_accounts_prepared
	resume_node "${TARGET_NODE}"
	;;
report)
	ensure_dirs
	prepare_runtime_assets
	run_report_now
	;;
chain-status)
	run_chain_status
	;;
precollect-enode)
	ensure_dirs
	ensure_gtos_bin
	ensure_passfile
	validate_local_checkpoint_config
	prepare_runtime_assets
	assert_accounts_prepared
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
