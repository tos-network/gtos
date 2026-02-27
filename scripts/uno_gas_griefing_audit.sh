#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

MAX_VERIFY_NS="${UNO_MAX_VERIFY_NS:-1500000}"
MAX_VERIFY_BOP="${UNO_MAX_VERIFY_BOP:-65536}"
MAX_VERIFY_RATIO="${UNO_MAX_VERIFY_RATIO:-64}"

tmp_out="$(mktemp)"
trap 'rm -f "${tmp_out}"' EXIT

echo "==> UNO gas-griefing audit benchmarks (cgo+ed25519c)"
CGO_ENABLED=1 go test -tags ed25519c ./core -run '^$' \
  -bench 'BenchmarkUNOShieldInvalidProof(Shape|VerifyPath)$' \
  -benchtime=300x -count=1 | tee "${tmp_out}"

shape_ns="$(awk '/BenchmarkUNOShieldInvalidProofShape/ {print $3}' "${tmp_out}" | tail -n1)"
shape_bop="$(awk '/BenchmarkUNOShieldInvalidProofShape/ {print $5}' "${tmp_out}" | tail -n1)"
verify_ns="$(awk '/BenchmarkUNOShieldInvalidProofVerifyPath/ {print $3}' "${tmp_out}" | tail -n1)"
verify_bop="$(awk '/BenchmarkUNOShieldInvalidProofVerifyPath/ {print $5}' "${tmp_out}" | tail -n1)"

if [[ -z "${shape_ns}" || -z "${verify_ns}" || -z "${shape_bop}" || -z "${verify_bop}" ]]; then
  echo "failed to parse benchmark output" >&2
  exit 1
fi

ratio=$(( verify_ns / (shape_ns == 0 ? 1 : shape_ns) ))

echo "==> Parsed:"
echo "    shape:  ${shape_ns} ns/op, ${shape_bop} B/op"
echo "    verify: ${verify_ns} ns/op, ${verify_bop} B/op"
echo "    ratio:  ${ratio}x"

if (( verify_ns > MAX_VERIFY_NS )); then
  echo "verify path too slow: ${verify_ns} ns/op > ${MAX_VERIFY_NS} ns/op" >&2
  exit 1
fi
if (( verify_bop > MAX_VERIFY_BOP )); then
  echo "verify path too memory-heavy: ${verify_bop} B/op > ${MAX_VERIFY_BOP} B/op" >&2
  exit 1
fi
if (( ratio > MAX_VERIFY_RATIO )); then
  echo "verify/shape ratio too high: ${ratio}x > ${MAX_VERIFY_RATIO}x" >&2
  exit 1
fi

echo "==> audit complete (thresholds satisfied)"
