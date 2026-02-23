# GTOS DPoS Stability Soak

Status: `IN_PROGRESS`
Last Updated: `2026-02-23`

This document defines the runnable automation path for long-window DPoS stability validation.

## Target

- Primary gate: no consensus halt while repeatedly running deterministic 3-validator stability insertion checks.
- Default soak window: `24h`.

## Commands

CI entry:

```bash
go run build/ci.go soak-dpos -duration 24h
```

Make wrapper:

```bash
make dpos-soak-ci
make dpos-soak-ci SOAK_ARGS='-duration 30m -maxruns 2'
```

Script wrapper:

```bash
scripts/dpos_stability_soak.sh --duration 24h
```

Fast smoke examples:

```bash
go run build/ci.go soak-dpos -duration 5m -maxruns 1 -testtimeout 20m
scripts/dpos_stability_soak.sh --duration 10m --max-runs 2
```

## Default Test Core

- Package: `./consensus/dpos`
- Test regex: `^TestDPoSThreeValidatorStabilityGate$`
- Per-run timeout: `20m`

## Acceptance Evidence (24h Gate)

- Soak command start/end timestamps.
- Run count and total elapsed time from soak summary log.
- Zero non-zero exit runs during the 24h window.
- At least one archived log artifact with command line and environment snapshot.
