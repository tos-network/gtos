# Signer Benchmarks

This directory keeps the signer benchmark tool in-repo (migrated from a temporary `/tmp` script) and adds `ed25519native` comparison.

## Run Once

```bash
go run ./benchmarks/signer
```

Optional flags:

```bash
go run ./benchmarks/signer -sign-ops 10000 -verify-ops 10000
```

## Compare Default vs `ed25519native`

```bash
./benchmarks/signer/run.sh
```

The script runs:

1. default build (`go run ./benchmarks/signer`)
2. native build (`CGO_ENABLED=1 go run -tags 'ed25519c ed25519native' ./benchmarks/signer`)

Outputs are saved to `benchmarks/signer/results/`.

Notes:

- `ed25519std` is Go stdlib `crypto/ed25519`.
- `ed25519gtos` is GTOS `crypto/ed25519` backend without `ed25519native`.
- `ed25519native` label appears when built with `ed25519c ed25519native`.
