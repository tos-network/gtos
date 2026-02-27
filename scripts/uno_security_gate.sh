#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "==> UNO security gate: crypto/uno baseline"
go test ./crypto/uno

echo "==> UNO security gate: txpool/execution parity matrix (core)"
go test ./core -run '^TestUNOTxPoolExecutionRejectParity' -count=1

echo "==> UNO security gate: replay/reorg determinism"
go test ./core -run 'TestUNONonceReplayRejectedAcrossActions|TestUNOReorgReimportVersionConsistency' -count=1

echo "==> UNO security gate: parallel determinism with UNO"
go test ./core/parallel -run 'TestAnalyzeTxUNO|TestAnalyzeTxUNOSerializedAcrossSenders' -count=1
go test ./core -run 'TestExecuteTransactionsBatchVsPerTxParityWithUNO|TestExecuteTransactionsBatchVsPerTxParityMixedSystemAndUNO|TestExecuteTransactionsBatchVsPerTxParityUNORandomizedStress' -count=1

echo "==> UNO security gate: cgo+ed25519c differential vectors"
CGO_ENABLED=1 go test -tags ed25519c ./crypto/uno -run 'TestDeterministicVectorsWithOpening|TestDeterministicCiphertextOpsVectors|TestXelisDifferentialCiphertextOpsVectors' -count=1

echo "==> UNO security gate: PASS"
