# GTOS UNO v1 Protocol Freeze

This document freezes the consensus-relevant UNO v1 protocol surface.
Any change below is a protocol upgrade and must be handled explicitly.

## 1. Envelope and Action IDs

- Payload prefix: `GTOSUNO1`
- Action IDs:
  - `UNO_SHIELD`: `0x02`
  - `UNO_TRANSFER`: `0x03`
  - `UNO_UNSHIELD`: `0x04`

## 2. Payload Field Ordering (Canonical)

- `UNO_SHIELD`:
  - `amount`
  - `new_sender_ciphertext`
  - `proof_bundle`
  - `encrypted_memo`
- `UNO_TRANSFER`:
  - `to`
  - `new_sender_ciphertext`
  - `receiver_delta_ciphertext`
  - `proof_bundle`
  - `encrypted_memo`
- `UNO_UNSHIELD`:
  - `to`
  - `amount`
  - `new_sender_ciphertext`
  - `proof_bundle`
  - `encrypted_memo`

These are frozen in code via `core/uno/FrozenPayloadFieldOrder` and by wire golden tests in `core/uno/protocol_constants_test.go`.

## 3. Transcript Domains and Tags

- Context version: `1`
- Native asset tag: `0`
- Context label: `chain-ctx`
- Domain tags:
  - `uno-shield-v1`
  - `uno-transfer-v1`
  - `uno-unshield-v1`
- Domain separator: `|`

These constants are centralized in `core/uno/protocol_constants.go`.

## 4. GTOS/XELIS Semantic Mapping (v1)

| GTOS UNO | XELIS-style semantic equivalent | Notes |
|---|---|---|
| `UNO_SHIELD` | Public balance -> encrypted balance credit | GTOS debits public TOS and updates sender encrypted state. |
| `UNO_TRANSFER` | Encrypted balance transfer | Sender encrypted state decreases; receiver encrypted state increases. |
| `UNO_UNSHIELD` | Encrypted balance -> public balance release | Sender encrypted state decreases; receiver public TOS increases. |
| `uno_version` | Monotonic account encrypted-state version | Used for deterministic progression and replay/reorg safety. |
| Transcript chain context (`chainId/action/from/to/nonce/...`) | Domain-separated proof context | Prevents cross-chain/cross-action/cross-context replay. |

This mapping freezes semantics, not wire-level compatibility.
