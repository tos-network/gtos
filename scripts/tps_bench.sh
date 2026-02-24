#!/usr/bin/env bash
set -euo pipefail

# GTOS TPS benchmark helper.
# It starts a local private dev chain, generates transfer load, then reports tx/s per block.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GTOS_BIN="${GTOS_BIN:-$ROOT_DIR/build/bin/gtos}"

DURATION=30
WORKERS=4
BATCH_SIZE=200
DEV_PERIOD=1
DEV_GAS_LIMIT=30000000
COOLDOWN=5
HTTP_PORT=18545
KEEP_DATA=0
DATADIR=""
TEMP_DATADIR=0

NODE_LOG=""
NODE_PID=""
RPC_URL=""
FROM_ADDR=""
TO_ADDR="0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
SEND_BATCH_PAYLOAD=""

WORKER_PIDS=()

usage() {
	cat <<'EOF'
Usage: scripts/tps_bench.sh [options]

Options:
  --duration <sec>       Load generation duration in seconds (default: 30)
  --workers <n>          Number of concurrent load workers (default: 4)
  --batch-size <n>       Transactions per RPC batch call (default: 200)
  --dev-period <sec>     Block period in --dev mode (default: 1)
  --dev-gaslimit <gas>   Initial gas limit in --dev mode (default: 30000000)
  --cooldown <sec>       Extra wait after load (default: 5)
  --http-port <port>     JSON-RPC HTTP port (default: 18545)
  --datadir <path>       Datadir for the benchmark node (default: temp dir)
  --gtos-bin <path>      Path to gtos binary (default: build/bin/gtos)
  --keep-data            Keep datadir and logs after run
  -h, --help             Show this help message
EOF
}

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Missing required command: $1"
		exit 1
	fi
}

to_dec() {
	local value
	value="$(echo "$1" | tr -d '"[:space:]')"
	if [[ "$value" =~ ^0[xX][0-9a-fA-F]+$ ]]; then
		echo $((16#${value:2}))
		return 0
	fi
	if [[ "$value" =~ ^[0-9]+$ ]]; then
		echo "$value"
		return 0
	fi
	return 1
}

to_hex() {
	printf '0x%x' "$1"
}

rpc_call() {
	local method="$1"
	local params="$2"
	curl -sS --max-time 8 \
		-H 'Content-Type: application/json' \
		--data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}" \
		"$RPC_URL"
}

rpc_result() {
	local method="$1"
	local params="$2"
	local response
	response="$(rpc_call "$method" "$params")"
	local has_error
	has_error="$(echo "$response" | jq -r 'has("error")')"
	if [[ "$has_error" == "true" ]]; then
		echo "$response" | jq -r '.error.message // "unknown RPC error"' >&2
		return 1
	fi
	echo "$response" | jq -c '.result'
}

get_block_number() {
	local raw
	raw="$(rpc_result "tos_blockNumber" "[]")"
	to_dec "$raw"
}

get_pending_count() {
	local raw
	raw="$(rpc_result "txpool_status" "[]")"
	to_dec "$(echo "$raw" | jq -r '.pending')"
}

get_block_meta() {
	local number="$1"
	local number_hex
	number_hex="$(to_hex "$number")"
	local result
	result="$(rpc_result "tos_getBlockByNumber" "[\"${number_hex}\", false]")"
	if [[ "$result" == "null" ]]; then
		echo "MISSING"
		return 0
	fi
	local ts_raw tx_count ts
	ts_raw="$(echo "$result" | jq -r '.timestamp')"
	tx_count="$(echo "$result" | jq -r '.transactions | length')"
	ts="$(to_dec "$ts_raw")"
	echo "${number} ${ts} ${tx_count}"
}

build_send_batch_payload() {
	local i
	printf '['
	for ((i = 0; i < BATCH_SIZE; i++)); do
		printf '{"jsonrpc":"2.0","id":%d,"method":"tos_sendTransaction","params":[{"from":"%s","to":"%s","value":"0x1","gas":"0x5208"}]}' \
			"$i" "$FROM_ADDR" "$TO_ADDR"
		if (( i + 1 < BATCH_SIZE )); then
			printf ','
		fi
	done
	printf ']'
}

send_worker() {
	local deadline="$1"
	while (( "$(date +%s)" < deadline )); do
		curl -sS --max-time 8 \
			-H 'Content-Type: application/json' \
			--data "$SEND_BATCH_PAYLOAD" \
			"$RPC_URL" >/dev/null || true
	done
}

wait_for_node() {
	local retries=120
	for ((i = 0; i < retries; i++)); do
		if get_block_number >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.25
	done
	return 1
}

cleanup() {
	set +e
	for pid in "${WORKER_PIDS[@]:-}"; do
		if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
			kill "$pid" 2>/dev/null || true
		fi
	done

	if [[ -n "$NODE_PID" ]] && kill -0 "$NODE_PID" 2>/dev/null; then
		kill "$NODE_PID" 2>/dev/null || true
		wait "$NODE_PID" 2>/dev/null || true
	fi

	if [[ "$KEEP_DATA" -eq 0 && "$TEMP_DATADIR" -eq 1 && -n "$DATADIR" ]]; then
		rm -rf "$DATADIR"
	fi
}
trap cleanup EXIT INT TERM

print_summary() {
	local start_block="$1"
	local end_block="$2"

	if (( end_block <= start_block )); then
		echo "No new blocks produced in benchmark window."
		return 0
	fi

	local start_meta
	start_meta="$(get_block_meta "$start_block")"
	if [[ "$start_meta" == "MISSING" ]]; then
		echo "Failed to read start block metadata."
		return 1
	fi

	local _bn prev_ts _tx
	read -r _bn prev_ts _tx <<<"$start_meta"

	local total_txs=0
	local first_ts="$prev_ts"
	local last_ts="$prev_ts"
	local line bn ts tx_count delta tps

	printf "\n%-8s %-12s %-10s %-9s %-10s\n" "Block" "Timestamp" "TxCount" "Delta(s)" "TPS"
	printf "%-8s %-12s %-10s %-9s %-10s\n" "-----" "---------" "-------" "--------" "---"

	for ((bn = start_block + 1; bn <= end_block; bn++)); do
		line="$(get_block_meta "$bn")"
		if [[ "$line" == "MISSING" ]]; then
			continue
		fi
		read -r bn ts tx_count <<<"$line"
		delta=$((ts - prev_ts))
		if (( delta <= 0 )); then
			delta=1
		fi
		tps="$(awk -v tx="$tx_count" -v dt="$delta" 'BEGIN { printf "%.2f", tx / dt }')"
		printf "%-8d %-12d %-10d %-9d %-10s\n" "$bn" "$ts" "$tx_count" "$delta" "$tps"
		total_txs=$((total_txs + tx_count))
		prev_ts="$ts"
		last_ts="$ts"
	done

	local span=$((last_ts - first_ts))
	if (( span <= 0 )); then
		span=1
	fi
	local avg_tps
	avg_tps="$(awk -v tx="$total_txs" -v dt="$span" 'BEGIN { printf "%.2f", tx / dt }')"

	printf "\nBlocks analyzed : %d\n" "$((end_block - start_block))"
	printf "Total txs       : %d\n" "$total_txs"
	printf "Time span (sec) : %d\n" "$span"
	printf "Average TPS     : %s\n" "$avg_tps"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--duration)
		DURATION="$2"
		shift 2
		;;
	--workers)
		WORKERS="$2"
		shift 2
		;;
	--batch-size)
		BATCH_SIZE="$2"
		shift 2
		;;
	--dev-period)
		DEV_PERIOD="$2"
		shift 2
		;;
	--dev-gaslimit)
		DEV_GAS_LIMIT="$2"
		shift 2
		;;
	--cooldown)
		COOLDOWN="$2"
		shift 2
		;;
	--http-port)
		HTTP_PORT="$2"
		shift 2
		;;
	--datadir)
		DATADIR="$2"
		shift 2
		;;
	--gtos-bin)
		GTOS_BIN="$2"
		shift 2
		;;
	--keep-data)
		KEEP_DATA=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "Unknown argument: $1"
		usage
		exit 1
		;;
	esac
done

if [[ ! "$DURATION" =~ ^[0-9]+$ ]] || (( DURATION <= 0 )); then
	echo "Invalid --duration: $DURATION"
	exit 1
fi
if [[ ! "$WORKERS" =~ ^[0-9]+$ ]] || (( WORKERS <= 0 )); then
	echo "Invalid --workers: $WORKERS"
	exit 1
fi
if [[ ! "$BATCH_SIZE" =~ ^[0-9]+$ ]] || (( BATCH_SIZE <= 0 )); then
	echo "Invalid --batch-size: $BATCH_SIZE"
	exit 1
fi
if [[ ! "$HTTP_PORT" =~ ^[0-9]+$ ]] || (( HTTP_PORT <= 0 || HTTP_PORT > 65535 )); then
	echo "Invalid --http-port: $HTTP_PORT"
	exit 1
fi

require_cmd curl
require_cmd jq

if [[ ! -x "$GTOS_BIN" ]]; then
	echo "gtos binary not found at $GTOS_BIN, building..."
	(
		cd "$ROOT_DIR"
		make gtos
	)
fi

if [[ -z "$DATADIR" ]]; then
	DATADIR="$(mktemp -d /tmp/gtos-tps-XXXXXX)"
	TEMP_DATADIR=1
else
	mkdir -p "$DATADIR"
fi

RPC_URL="http://127.0.0.1:${HTTP_PORT}"
NODE_LOG="${DATADIR}/node.log"

echo "Starting benchmark node..."
"$GTOS_BIN" \
	--dev \
	--dev.period "$DEV_PERIOD" \
	--dev.gaslimit "$DEV_GAS_LIMIT" \
	--datadir "$DATADIR" \
	--port 0 \
	--authrpc.port 0 \
	--http \
	--http.addr 127.0.0.1 \
	--http.port "$HTTP_PORT" \
	--http.vhosts "*" \
	--http.api "tos,txpool,miner,personal,net,web3" \
	--verbosity 3 \
	>"$NODE_LOG" 2>&1 &
NODE_PID="$!"

if ! wait_for_node; then
	echo "Failed to start node. See log: $NODE_LOG"
	exit 1
fi

FROM_ADDR="$(rpc_result "tos_accounts" "[]" | jq -r '.[0]')"
if [[ -z "$FROM_ADDR" || "$FROM_ADDR" == "null" ]]; then
	echo "Failed to find dev account."
	exit 1
fi

echo "Using account: $FROM_ADDR"
echo "Datadir      : $DATADIR"
echo "Node log     : $NODE_LOG"

rpc_call "miner_start" "[1]" >/dev/null || true

START_BLOCK="$(get_block_number)"
echo "Start block  : $START_BLOCK"
echo "Load         : ${WORKERS} workers, batch size ${BATCH_SIZE}, duration ${DURATION}s"

SEND_BATCH_PAYLOAD="$(build_send_batch_payload)"
deadline=$(( $(date +%s) + DURATION ))

for ((w = 0; w < WORKERS; w++)); do
	send_worker "$deadline" &
	WORKER_PIDS+=("$!")
done

for pid in "${WORKER_PIDS[@]}"; do
	wait "$pid"
done

echo "Load finished, waiting for pending txs to be mined..."
stop_wait=$(( $(date +%s) + COOLDOWN ))
while (( "$(date +%s)" < stop_wait )); do
	pending="$(get_pending_count || echo 0)"
	if [[ "$pending" =~ ^[0-9]+$ ]] && (( pending == 0 )); then
		break
	fi
	sleep 1
done

END_BLOCK="$(get_block_number)"
echo "End block    : $END_BLOCK"

print_summary "$START_BLOCK" "$END_BLOCK"
