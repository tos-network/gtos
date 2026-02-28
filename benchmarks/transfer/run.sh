#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/benchmarks/transfer/results"
STAMP="$(date +%Y%m%d-%H%M%S)"

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
DURATION="${DURATION:-90}"
WALLETS="${WALLETS:-8}"
FUNDER="${FUNDER:-0x25e8750786adb41f9725d7bfc8dec9de30521661c53750b142a8ebfa68b85bbe}"
FUNDER_SIGNER="${FUNDER_SIGNER:-elgamal}"
FUND_WEI="${FUND_WEI:-1000000000000000}"
TX_VALUE_WEI="${TX_VALUE_WEI:-1}"

mkdir -p "${OUT_DIR}"
SUMMARY="${OUT_DIR}/${STAMP}-summary.tsv"
echo -e "profile\tduration_s\twallets\tworkers\taccepted\tfailed\tsoft_failed\taccepted_tps\toutput" >"${SUMMARY}"

run_profile() {
	local profile="$1"
	local workers="$2"
	local run_dir="${OUT_DIR}/${STAMP}-${profile}"
	local out_file="${run_dir}.txt"

	echo "[${profile}] wallets=${WALLETS} workers=${workers} duration=${DURATION}s"
	(
		cd "${ROOT_DIR}"
		./scripts/plain_transfer_soak.sh \
			--rpc "${RPC_URL}" \
			--duration "${DURATION}s" \
			--wallets "${WALLETS}" \
			--workers "${workers}" \
			--fund-wei "${FUND_WEI}" \
			--funding-receipt-timeout 0 \
			--tx-value-wei "${TX_VALUE_WEI}" \
			--funder "${FUNDER}" \
			--funder-signer "${FUNDER_SIGNER}" \
			--skip-dpos-monitor \
			--out-dir "${run_dir}" \
			| tee "${out_file}"
	)

	local accepted failed soft_failed duration_s accepted_tps
	read -r accepted failed soft_failed duration_s < <(python3 - "${run_dir}/plain_transfer_report.json" <<'PY'
import json,sys
with open(sys.argv[1], "r") as f:
    d=json.load(f)
print(d.get("accepted", 0), d.get("failed", 0), d.get("soft_failed", 0), d.get("duration_sec", 1))
PY
)
	accepted_tps="$(python3 - <<PY
a=${accepted}
d=${duration_s}
print(f"{(a/d) if d else 0:.2f}")
PY
)"

	echo -e "${profile}\t${duration_s}\t${WALLETS}\t${workers}\t${accepted}\t${failed}\t${soft_failed}\t${accepted_tps}\t${run_dir}" >>"${SUMMARY}"
}

run_profile "w2" 2
run_profile "w4" 4
run_profile "w8" 8

echo
echo "Saved results:"
ls -1 "${OUT_DIR}/${STAMP}-"*
echo
echo "Summary:"
column -t -s $'\t' "${SUMMARY}"
