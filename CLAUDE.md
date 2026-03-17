# gtos — Claude Code Instructions

## Paths

Do not hardcode user-specific absolute home directories such as `/home/<user>`
in repository files, scripts, docs, or systemd templates.

Use one of these instead:

- `$HOME/...` in shell examples and scripts
- `~/...` in human-facing documentation when expansion is only illustrative
- relative repository paths where possible
- runtime-provided environment variables

For systemd units, do not rely on a hardcoded home path. Prefer invoking a
shell that expands `$HOME` for the target user, for example:

```ini
ExecStart=/bin/bash -lc 'exec "$HOME/gtos/scripts/validator_guard.sh"'
```

## Testing

Use `-p` to run package tests in parallel and speed up the suite significantly:

```bash
go test -p 96 ./...
go test -p 96 ./core/... -timeout 300s
go test -p 96 ./core/... ./tos/... ./params/... -count=1 -timeout 300s
```

`-p N` sets the number of packages that can be tested in parallel (default is GOMAXPROCS). On machines with many cores, `-p 96` (or match your CPU count) cuts total wall-clock time drastically.

Single-package runs don't benefit from `-p`; use `-parallel` instead to parallelise test cases within a package:

```bash
go test -parallel 16 ./core -timeout 120s
```

## 2046 Architecture Packages

The 2046 architecture is defined in `docs/2046.md`. The following packages
implement its core components:

- `boundary/` — Shared boundary schemas (IntentEnvelope, PlanRecord,
  ApprovalRecord, ExecutionReceipt, terminal classes, trust tiers, agent roles)
- `policywallet/` — On-chain policy wallet primitives (spend caps, allowlists,
  terminal restrictions, delegation, guardian recovery, suspension) at
  `PolicyWalletRegistryAddress` (0x...010C)
- `auditreceipt/` — Audit receipt surface (AuditReceipt, ProofReference,
  PolicyDecisionRecord, SponsorAttribution, SettlementTrace, SessionProof) at
  `AuditReceiptRegistryAddress` (0x...010D)
- `gateway/` — Gateway relay as first-class capability at
  `GatewayRegistryAddress` (0x...010E)
- `settlement/` — Settlement callbacks and async fulfillment at
  `SettlementRegistryAddress` (0x...010F)
- `deploy/` — Contract compilation and deployment tooling for TOL contracts
- `e2e/` — Cross-package integration tests

All system contract addresses use full 32-byte (64 hex character) format in
`params/tos_params.go`. The shared boundary schema version is `0.1.0`.

Run `scripts/check-2046-compat.sh` to verify cross-repo compatibility.
