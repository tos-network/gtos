#!/usr/bin/env bash
# Run all 2046 architecture tests across all three repos
set -e

echo "=== GTOS Boundary Tests ==="
cd ~/gtos && go test ./boundary/... ./policywallet/... ./auditreceipt/... ./gateway/... ./settlement/... ./e2e/...

echo "=== OpenFox 2046 Tests ==="
cd ~/openfox && npx vitest run src/__tests__/intent.test.ts src/__tests__/terminal.test.ts src/__tests__/intent-explain.test.ts src/__tests__/routing.test.ts src/__tests__/pipeline.test.ts

echo "=== TOL Metadata & E2E Tests ==="
cd ~/tolang && go test ./metadata/... ./e2e/...

echo "=== Schema Version Check ==="
GTOS_VER=$(grep 'SchemaVersion' ~/gtos/boundary/types.go | grep -o '"[^"]*"' | tr -d '"')
OPENFOX_VER=$(grep 'BOUNDARY_SCHEMA_VERSION' ~/openfox/src/intent/types.ts | grep -o '"[^"]*"' | tr -d '"')
TOL_VER=$(grep 'SchemaVersion' ~/tolang/metadata/metadata.go | grep -o '"[^"]*"' | head -1 | tr -d '"')

echo "GTOS:    $GTOS_VER"
echo "OpenFox: $OPENFOX_VER"
echo "TOL:     $TOL_VER"

if [ "$GTOS_VER" = "$OPENFOX_VER" ] && [ "$OPENFOX_VER" = "$TOL_VER" ]; then
  echo "All schema versions match: $GTOS_VER"
else
  echo "Schema version mismatch!"
  exit 1
fi

echo "=== All 2046 Compatibility Checks Passed ==="
