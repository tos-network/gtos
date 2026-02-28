# Transfer TPS Benchmark Results

## Formal Matrix Run (Submit / Committed / Finalized)

- Run id: `20260228-060041`
- Date (UTC): `2026-02-28`
- Command:

```bash
./scripts/tps_matrix.sh \
  --rpc http://127.0.0.1:8545 \
  --duration 90 \
  --wallets 12 \
  --profiles 2,4,8 \
  --finality-depth 12 \
  --period-ms 360
```

| profile | workers | submitted | submit_tps | committed | committed_tps | finalized | finalized_tps |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| w2 | 2 | 1894 | 21.04 | 1905 | 21.17 | 1905 | 21.17 |
| w4 | 4 | 3738 | 41.53 | 3749 | 41.66 | 3749 | 41.66 |
| w8 | 8 | 7401 | 82.23 | 7412 | 82.36 | 7412 | 82.36 |

Artifacts:

- `benchmarks/transfer/matrix/20260228-060041/summary.tsv`
- `benchmarks/transfer/matrix/20260228-060041/summary.md`

## Legacy Runner Note

The old `benchmarks/transfer/run.sh` path reports accepted send-side TPS only.
Use the matrix runner for formal 3-metric TPS.
