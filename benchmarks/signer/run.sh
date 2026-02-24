#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/benchmarks/signer/results"
STAMP="$(date +%Y%m%d-%H%M%S)"

SIGN_OPS="${SIGN_OPS:-5000}"
VERIFY_OPS="${VERIFY_OPS:-5000}"

mkdir -p "${OUT_DIR}"

echo "[1/2] benchmark default build"
(
  cd "${ROOT_DIR}"
  go run ./benchmarks/signer -sign-ops "${SIGN_OPS}" -verify-ops "${VERIFY_OPS}" \
    | tee "${OUT_DIR}/${STAMP}-default.txt"
)

echo "[2/2] benchmark CGO + ed25519native build"
(
  cd "${ROOT_DIR}"
  CGO_ENABLED=1 go run -tags 'ed25519c ed25519native' ./benchmarks/signer \
    -sign-ops "${SIGN_OPS}" -verify-ops "${VERIFY_OPS}" \
    | tee "${OUT_DIR}/${STAMP}-ed25519native.txt"
)

echo
echo "Saved:"
echo "  ${OUT_DIR}/${STAMP}-default.txt"
echo "  ${OUT_DIR}/${STAMP}-ed25519native.txt"
