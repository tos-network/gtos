#!/usr/bin/env bash
set -euo pipefail

BENCHTIME="${BENCHTIME:-1x}"
COUNT="${COUNT:-1}"
OUTFILE=""

usage() {
	cat <<'EOF'
Usage: scripts/ttl_prune_bench_smoke.sh [--benchtime <value>] [--count <n>] [--out <file>]

Runs TTL prune benchmark smoke suite:
  go test ./core -run '^$' -bench 'BenchmarkPruneExpired(Code|KV)At' -benchmem

Options:
  --benchtime <value>  go test benchtime (default: 1x)
  --count <n>          go test count (default: 1)
  --out <file>         write output to file
  -h, --help           show help
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--benchtime)
		BENCHTIME="$2"
		shift 2
		;;
	--count)
		COUNT="$2"
		shift 2
		;;
	--out)
		OUTFILE="$2"
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
	go test ./core
	-run '^$'
	-bench 'BenchmarkPruneExpired(Code|KV)At'
	-benchmem
	-benchtime "${BENCHTIME}"
	-count "${COUNT}"
)

echo "==> TTL prune benchmark smoke"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "go: $(go version)"
echo "cmd: ${CMD[*]}"

if [[ -n "${OUTFILE}" ]]; then
	mkdir -p "$(dirname "${OUTFILE}")"
	"${CMD[@]}" | tee "${OUTFILE}"
else
	"${CMD[@]}"
fi
