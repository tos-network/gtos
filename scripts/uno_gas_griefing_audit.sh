#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "==> UNO gas-griefing audit benchmarks (cgo+ed25519c)"
CGO_ENABLED=1 go test -tags ed25519c ./core -run '^$' \
  -bench 'BenchmarkUNOShieldInvalidProof(Shape|VerifyPath)$' \
  -benchtime=300x -count=1

echo "==> audit complete"
