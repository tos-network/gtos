# UNO Gas-Griefing SLO (Shield Verify Path)

This defines the executable threshold gate for UNO proof-verify cost in CI/local audits.

## Benchmark targets

Runner:
- `scripts/uno_gas_griefing_audit.sh`

Benchmarks:
- `BenchmarkUNOShieldInvalidProofShape`
- `BenchmarkUNOShieldInvalidProofVerifyPath`

## Default thresholds

- `UNO_MAX_VERIFY_NS = 1_500_000` ns/op
- `UNO_MAX_VERIFY_BOP = 65_536` B/op
- `UNO_MAX_VERIFY_RATIO = 64` (verify path ns/op divided by shape-reject ns/op)

These are conservative limits for current dev hardware classes and can be tightened over time.

## Override knobs

The runner accepts environment overrides:
- `UNO_MAX_VERIFY_NS`
- `UNO_MAX_VERIFY_BOP`
- `UNO_MAX_VERIFY_RATIO`

Example:

```bash
UNO_MAX_VERIFY_NS=1200000 UNO_MAX_VERIFY_RATIO=48 scripts/uno_gas_griefing_audit.sh
```
