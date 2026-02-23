#!/usr/bin/env bash
set -euo pipefail

DURATION="${DURATION:-24h}"
MAXRUNS="${MAXRUNS:-0}"
TEST_TIMEOUT="${TEST_TIMEOUT:-20m}"
RUN_REGEX="${RUN_REGEX:-^TestDPoSThreeValidatorStabilityGate$}"
PKG="${PKG:-./consensus/dpos}"

usage() {
	cat <<'EOF'
Usage: scripts/dpos_stability_soak.sh [options]

Runs DPoS stability soak loop by repeatedly executing the deterministic
three-validator stability gate test.

Options:
  --duration <value>      total soak duration (default: 24h)
  --max-runs <n>          max runs (0 = no cap, default: 0)
  --test-timeout <value>  per-run go test timeout (default: 20m)
  --run <regex>           go test -run regex (default: ^TestDPoSThreeValidatorStabilityGate$)
  --pkg <path>            package path (default: ./consensus/dpos)
  -h, --help              show help

Examples:
  scripts/dpos_stability_soak.sh --duration 2h --max-runs 8
  DURATION=30m MAXRUNS=2 scripts/dpos_stability_soak.sh
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--duration)
		DURATION="$2"
		shift 2
		;;
	--max-runs)
		MAXRUNS="$2"
		shift 2
		;;
	--test-timeout)
		TEST_TIMEOUT="$2"
		shift 2
		;;
	--run)
		RUN_REGEX="$2"
		shift 2
		;;
	--pkg)
		PKG="$2"
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

CMD=(
	go run build/ci.go soak-dpos
	-duration "${DURATION}"
	-maxruns "${MAXRUNS}"
	-testtimeout "${TEST_TIMEOUT}"
	-run "${RUN_REGEX}"
	-pkg "${PKG}"
)

echo "==> DPoS stability soak"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "go: $(go version)"
echo "cmd: ${CMD[*]}"

"${CMD[@]}"
