# Signer Benchmark Results

Date: 2026-02-24
Workdir: `/home/tomi/gtos`
Workload: `sign-ops=5000`, `verify-ops=5000`

Source files:

- `benchmarks/signer/results/20260224-195149-default.txt`
- `benchmarks/signer/results/20260224-195149-ed25519native.txt`

## Default Build

Command:

```bash
go run ./benchmarks/signer -sign-ops 5000 -verify-ops 5000
```

| Algorithm | sign us | sign ops/s | verify us | verify ops/s |
| --- | ---: | ---: | ---: | ---: |
| secp256k1 | 68.16 | 14671 | 72.99 | 13701 |
| secp256r1 | 40.48 | 24706 | 119.31 | 8382 |
| ed25519std | 17.34 | 57682 | 38.19 | 26187 |
| ed25519gtos | 17.33 | 57719 | 38.10 | 26244 |
| bls12-381 | 333.40 | 2999 | 1108.86 | 902 |
| elgamal | 104.02 | 9613 | 124.96 | 8003 |

Sign rank: `ed25519gtos > ed25519std > secp256r1 > secp256k1 > elgamal > bls12-381`
Verify rank: `ed25519gtos > ed25519std > secp256k1 > secp256r1 > elgamal > bls12-381`

## Native Build (`ed25519c ed25519native`)

Command:

```bash
CGO_ENABLED=1 go run -tags 'ed25519c ed25519native' ./benchmarks/signer -sign-ops 5000 -verify-ops 5000
```

| Algorithm | sign us | sign ops/s | verify us | verify ops/s |
| --- | ---: | ---: | ---: | ---: |
| secp256k1 | 68.06 | 14692 | 72.91 | 13715 |
| secp256r1 | 43.49 | 22991 | 101.90 | 9814 |
| ed25519std | 33.13 | 30184 | 72.57 | 13779 |
| ed25519native | 53.70 | 18621 | 116.21 | 8605 |
| bls12-381 | 408.49 | 2448 | 1054.99 | 948 |
| elgamal | 111.10 | 9001 | 86.26 | 11593 |

Sign rank: `ed25519std > secp256r1 > ed25519native > secp256k1 > elgamal > bls12-381`
Verify rank: `ed25519std > secp256k1 > elgamal > secp256r1 > ed25519native > bls12-381`
