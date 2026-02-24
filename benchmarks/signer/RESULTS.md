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

## High-Sample Validation (`sign-ops=20000`, `verify-ops=20000`)

This section was added to verify whether `ed25519native` is faster than default `ed25519gtos` on this machine.

### Run A: Default Build

Command:

```bash
go run ./benchmarks/signer -sign-ops 20000 -verify-ops 20000
```

| Algorithm | sign us | sign ops/s | verify us | verify ops/s |
| --- | ---: | ---: | ---: | ---: |
| secp256k1 | 59.42 | 16828 | 37.65 | 26560 |
| secp256r1 | 39.07 | 25598 | 121.13 | 8256 |
| ed25519std | 19.75 | 50631 | 38.50 | 25972 |
| ed25519gtos | 17.32 | 57728 | 37.70 | 26526 |
| bls12-381 | 397.58 | 2515 | 1071.69 | 933 |
| elgamal | 112.06 | 8924 | 119.42 | 8374 |

### Run B: CGO Build (`ed25519c`)

Command:

```bash
CGO_ENABLED=1 go run -tags 'ed25519c' ./benchmarks/signer -sign-ops 20000 -verify-ops 20000
```

| Algorithm | sign us | sign ops/s | verify us | verify ops/s |
| --- | ---: | ---: | ---: | ---: |
| secp256k1 | 36.09 | 27707 | 37.49 | 26676 |
| secp256r1 | 40.71 | 24564 | 115.86 | 8631 |
| ed25519std | 21.46 | 46603 | 38.25 | 26144 |
| ed25519gtos | 52.59 | 19017 | 97.75 | 10230 |
| bls12-381 | 347.90 | 2874 | 985.29 | 1015 |
| elgamal | 98.31 | 10172 | 121.57 | 8226 |

### Run C: Native Build (`ed25519c ed25519native`)

Command:

```bash
CGO_ENABLED=1 go run -tags 'ed25519c ed25519native' ./benchmarks/signer -sign-ops 20000 -verify-ops 20000
```

| Algorithm | sign us | sign ops/s | verify us | verify ops/s |
| --- | ---: | ---: | ---: | ---: |
| secp256k1 | 47.97 | 20846 | 49.13 | 20355 |
| secp256r1 | 37.48 | 26683 | 115.91 | 8627 |
| ed25519std | 17.65 | 56654 | 38.12 | 26233 |
| ed25519native | 28.72 | 34820 | 61.53 | 16252 |
| bls12-381 | 406.75 | 2459 | 972.24 | 1029 |
| elgamal | 130.22 | 7679 | 126.43 | 7909 |

### Conclusion (This Machine)

- `ed25519native` is faster than `ed25519c` baseline.
- `ed25519native` is still slower than default `ed25519gtos` in this benchmark shape (32-byte hash sign/verify loop).
