# Licensing By Directory

This repository is a mixed-license codebase.

## Default

- Unless otherwise stated by a file header or a local license file,
  source code is distributed under **LGPL-3.0**.
- See: `LICENSE` and `COPYING.LESSER`.

## Directory-level declarations

- `cmd/`:
  - **GPL-3.0** applies to CLI/application command code derived from geth cmd
    components.
  - See: `COPYING`.

## Embedded third-party components (own license files)

- `crypto/blake3/` -> CC0-1.0 (`crypto/blake3/LICENSE`)
- `crypto/ecies/` -> BSD-style (`crypto/ecies/LICENSE`)
- `crypto/edwards25519/` -> BSD-style (`crypto/edwards25519/LICENSE`)
- `crypto/ristretto255/` -> BSD-style (`crypto/ristretto255/LICENSE`)
- `crypto/secp256k1/` -> BSD-style (`crypto/secp256k1/LICENSE`)
- `crypto/secp256k1/libsecp256k1/` -> MIT (`crypto/secp256k1/libsecp256k1/COPYING`)
- `log/` -> Apache-2.0 (`log/LICENSE`)
- `metrics/` -> BSD-2-Clause (`metrics/LICENSE`)
- `metrics/influxdb/` -> MIT (`metrics/influxdb/LICENSE`)

## Precedence rule

If there is any conflict:
1. File header license notice (if present)
2. Subdirectory license file
3. Repository default in `LICENSE`
