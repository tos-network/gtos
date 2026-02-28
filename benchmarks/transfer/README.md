# Transfer TPS Benchmarks

This benchmark suite measures plain transfer throughput (TPS) using the in-repo
helper `scripts/plain_transfer_soak.sh`.

The runner executes multiple worker profiles against a running local network
(default: `http://127.0.0.1:8545`) and reports accepted transfer TPS.

## Run Benchmark Profiles

```bash
./benchmarks/transfer/run.sh
```

Optional environment overrides:

```bash
DURATION=30 WALLETS=12 ./benchmarks/transfer/run.sh
```

Available knobs:

- `RPC_URL` (default: `http://127.0.0.1:8545`)
- `DURATION` seconds per profile (default: `90`)
- `WALLETS` (default: `8`)
- `FUNDER` (default: local funded ElGamal account)
- `FUNDER_SIGNER` (default: `elgamal`)
- `FUND_WEI` (default: `1000000000000000`)
- `TX_VALUE_WEI` (default: `1`)

## Outputs

Artifacts are stored in:

- `benchmarks/transfer/results/<timestamp>-<profile>/` (raw soak artifacts)
- `benchmarks/transfer/results/<timestamp>-<profile>.txt` (runner stdout)
- `benchmarks/transfer/results/<timestamp>-summary.tsv`

Current curated results are tracked in:

- `benchmarks/transfer/RESULTS.md`

## Formal 3-Metric Matrix

For standard benchmarking on a running 3-node network, use:

```bash
./scripts/tps_matrix.sh \
  --rpc http://127.0.0.1:8545 \
  --duration 90 \
  --wallets 12 \
  --profiles 2,4,8 \
  --finality-depth 12
```

Outputs:

- `benchmarks/transfer/matrix/<run_id>/summary.tsv`
- `benchmarks/transfer/matrix/<run_id>/summary.md`
