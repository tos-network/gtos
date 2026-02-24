# libed25519 (GTOS Snapshot)

This directory vendors the Avatar ed25519 C implementation used by GTOS.

Source of imported materials:

- `/home/tomi/avatar/src/crypto/ed25519/`
- `/home/tomi/avatar/include/at/crypto/`
- `/home/tomi/avatar/include/at/infra/`
- `/home/tomi/avatar/src/crypto/sha512/at_sha512.c`

How GTOS uses it:

- Build tag `ed25519c` + `cgo` enables the C backend in `crypto/ed25519/ed25519_cgo.go`.
- Without `ed25519c`, GTOS uses the pure Go/std-compatible fallback (`ed25519_nocgo.go`).
- Public API remains `crypto/ed25519` and keeps stdlib-compatible key/signature formats.
- Build tag `ed25519native` (with `ed25519c`) enables `-march=native -mtune=native`.
  - This activates Avatar-style capability switches (`AT_HAS_AVX`, `AT_HAS_AVX512`, `AT_HAS_AVX512_IFMA`) from compiler builtins.
  - On IFMA-capable hosts, ed25519 field arithmetic uses the vendored AVX-512 IFMA backend.
