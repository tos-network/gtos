# GTOS Privacy Enhancement Plan: Closing the Gap to "Privacy as a First-Class Property"

## Context

GTOS states "privacy as a first-class property" as a core design goal, but current implementation covers only encrypted balances (Priv protocol) — approximately 30-35% of that vision. Five privacy dimensions remain uncovered: transaction graph privacy, agent/identity privacy, network-layer privacy, metadata privacy, and contract/call privacy. This plan addresses each dimension through six incremental phases, respecting frozen protocol constants and preserving agent economy functionality.

### Confirmed Decisions
- **Phase 0**: Front-loaded as a prerequisite (C library exists, CGO build chain needs fixing)
- **Phase 3**: Validator-transparent decoys (simpler, lower gas, no new proof types)
- **Phase 5 Reputation**: Bucketed ranges (Low/Medium/High/Elite) for Private/Stealth agents
- **Sequencing**: Phase 0→1→2→3→4→5→6 in order, with Phase 4 parallelizable alongside Phase 3

---

## Phase 0: Critical Blocker — C Backend Proof Verification

**Problem**: All ZK proof verification dispatches to the C backend (`ed25519c`) via CGO FFI. Without it, every call returns `ErrPrivBackendUnavailable`. Priv is architecturally present but operationally inert.

**Scope**: Ensure the C backend (`libed25519`) compiles and links correctly, so `BackendEnabled()` returns `true` and all six verification functions work end-to-end.

**Files**:
- `crypto/ed25519/priv_proofs_cgo.go` — C glue (58.5KB), verify CGO build tags and library linking
- `crypto/ed25519/priv_backend_cgo.go` — Feature flag
- `core/priv/verify.go` — Remove expectation of `ErrPrivBackendUnavailable` in production paths
- Tests: Update `core/priv/verify_test.go` and `core/priv_state_transition_test.go` to expect successful verification

**Outcome**: Priv transactions are fully validated on-chain. No consensus change needed — this is a build/toolchain fix.

---

## Phase 1: Metadata Privacy — Uniform Transaction Envelopes

**Dimension**: Metadata privacy (gas-based action type inference, payload size leakage)

### 1a. Uniform Gas Charging
All three Priv actions charge `PrivUniformGas = 650,000` (= PrivBaseGas + PrivTransferGas). Shield and Unshield callers pay Transfer-level gas.

- `params/tos_params.go` — Add `PrivUniformGas` constant
- `core/state_transition.go` (lines ~718, ~774, ~833) — Replace per-action gas with `PrivUniformGas` in all `applyPriv()` branches

### 1b. Fixed-Size Padded Envelope
Pad `Envelope.Body` to `PrivPaddedEnvelopeSize` (max RLP-encoded Transfer body size) so all actions produce identical on-chain data sizes.

- `core/priv/types.go` — Add `PrivPaddedEnvelopeSize` constant
- `core/priv/codec.go` — Add zero-padding in `EncodeEnvelope()`, strip on `DecodeEnvelope()`

**Gas impact**: Shield/Unshield cost rises from 450k to 650k (privacy premium).
**Consensus**: Hard fork required.
**Dependencies**: None.

---

## Phase 2: Transaction Graph Privacy — Stealth Addresses (DKSAP)

**Dimension**: Transaction graph privacy (receiver linkability)

**Scheme**: Dual-Key Stealth Address Protocol over Ristretto255. Receiver publishes meta-address `(S, V)` (spend + view keys). Sender generates ephemeral `(r, R)`, derives stealth address `P = S + H(r·V)·G`. Only the receiver (holding view key `v`) can scan for payments via `H(v·R)`.

### 2a. Stealth Key Registration
New storage slots on Priv accounts for stealth meta-address `(S, V)`.

- `core/priv/state.go` — Add `StealthSpendKeySlot`, `StealthViewKeySlot` via `keccak256("gtos.priv.stealthSpend")` etc. Add `Get/SetStealthKeys()`.

### 2b. New Action: StealthTransfer (ActionID 0x05)
Adds to existing actions (frozen IDs 0x02-0x04 untouched).

`StealthTransferPayload`:
- `EphemeralPubkey [32]byte` — sender's ephemeral R
- `StealthAddress common.Address` — derived one-time address P
- `NewSender Ciphertext` — sender's updated encrypted balance
- `ReceiverDelta Ciphertext` — encrypted delta under stealth pubkey
- `ProofBundle []byte` — same structure as Transfer (CTValidity 160B + Balance 200B + Range 672B = 1032B)
- `EncryptedMemo []byte`

New files:
- `core/priv/stealth.go` — `DeriveStealthAddress()`, `ScanStealthPayment()` using `crypto/ristretto255`
- `core/priv/stealth_test.go` — Round-trip DKSAP tests

Modified files:
- `core/priv/types.go` — Add `ActionStealthTransfer = 0x05`, `StealthTransferPayload` struct
- `core/priv/codec.go` — Encode/decode for stealth payload
- `core/priv/context.go` — `BuildPrivStealthTransferTranscriptContext()` including ephemeral pubkey
- `core/priv/verify.go` — `VerifyStealthTransferProofBundleWithContext()` (reuses existing proof primitives)
- `core/state_transition.go` — Add `case priv.ActionStealthTransfer` in `applyPriv()`
- `core/parallel/analyze.go` — Add stealth address to write set
- `params/tos_params.go` — `PrivStealthTransferGas = 650,000`

### 2c. Stealth Scanner RPC
New RPC: `priv_scanStealthPayments(viewKey, spendPubKey, fromBlock, toBlock)` — scans blocks for ephemeral pubkeys matching the caller's view key.

- New file: `core/priv/scanner.go`
- RPC handler registration in existing RPC infrastructure

**Gas impact**: Same as Transfer (650k with uniform gas).
**Consensus**: Hard fork (new action ID).
**Dependencies**: Phase 1 (uniform envelope).

---

## Phase 3: Transaction Graph Privacy — Decoy Outputs

**Dimension**: Transaction graph privacy (deepening anonymity set)

Extend StealthTransfer to include N decoy `(stealthAddress, ciphertextDelta)` pairs using **validator-transparent decoys**: decoys encrypt zero (identity ciphertext). Validators can distinguish real from decoy, but chain observers scanning raw data cannot. This avoids new proof types and keeps gas costs low.

Modified files:
- `core/priv/types.go` — Add `Decoys []DecoyOutput` to `StealthTransferPayload`
- `core/priv/codec.go` — Encode/decode decoy array
- `core/state_transition.go` — Apply decoy deltas in StealthTransfer case
- `params/tos_params.go` — `PrivDecoyGas = 50,000` per decoy, `PrivMaxDecoys = 7`

**Gas impact**: +50k per decoy (~850k total with 4 decoys).
**Consensus**: Hard fork (payload format extension).
**Dependencies**: Phase 2.

---

## Phase 4: Network-Layer Privacy — Dandelion++

**Dimension**: Network-layer privacy (IP correlation)

Transactions enter a "stem" phase (forwarded 1-to-1 along a random path) before "fluffing" into normal gossip. Prevents originator IP correlation.

New package: `p2p/dandelion/`
- `dandelion.go` — Stem/fluff state machine, epoch-based stem graph
- `stem.go` — Stem relay (forward with probability 0.9, fluff with 0.1)
- `config.go` — Stem probability, epoch duration, timeout

Modified files:
- `p2p/` — Intercept `BroadcastTransaction` for Priv transactions, route through stem phase
- `cmd/gtos/` — CLI flag `--privacy.dandelion`

**Gas impact**: None (network-layer only).
**Consensus**: None (P2P protocol change, backward-compatible).
**Dependencies**: None (can parallelize with Phase 3).

---

## Phase 5: Agent/Identity Privacy — Privacy Tiers with ZK Capability Proofs

**Dimension**: Agent/identity privacy

### Three Agent Privacy Tiers

| Tier | Stake | Capabilities | Reputation | Discovery |
|------|-------|-------------|------------|-----------|
| **Public** (default) | Visible | Bloom filter | Exact score | Full ENR |
| **Private** | Encrypted (ElGamal + range proof ≥ MinStake) | ZK capability proof (Pedersen commitment) | Bucketed (Low/Medium/High/Elite) | Commitment in ENR |
| **Stealth** | Encrypted | ZK proof | Bucketed (Low/Medium/High/Elite) | Stealth meta-address in ENR |

### 5a. Privacy Mode Storage
- `agent/state.go` — Add `privacyModeSlot`. Values: 0=Public, 1=Private, 2=Stealth.
- `agent/handler.go` — New system action `ActionAgentSetPrivacy`

### 5b. ZK Capability Proofs
Agent commits to capability set as `C = Pedersen(capBits, r)`, stores C on-chain. During discovery, provides sigma-protocol proof that a specific bit is set.

New files:
- `crypto/priv/capability_proof.go` — `ProveCapabilityOwnership()`, `VerifyCapabilityOwnership()`
- `agent/privacy.go` — Privacy tier logic, committed capability management

### 5c. Private Agent Discovery
- `agentdiscovery/types.go` — Add ENR key `"agp"` for privacy mode, `capabilityCommitmentEntry`
- `agentdiscovery/service.go` — Handle Private agents: verify ZK proofs instead of bloom filter matching

### 5d. Encrypted Stake
- `agent/state.go` — Add `encryptedStakeSlot` (commitment + handle). Private agents store ElGamal ciphertext + range proof ≥ `AgentMinStake`.

**Gas impact**: +100k (ZK capability proof) + 200k (encrypted stake range proof) at registration.
**Consensus**: Hard fork (new agent state fields, new system action, discovery protocol v2).
**Dependencies**: Phase 2 (stealth addresses for Stealth tier).

---

## Phase 6: Contract/Call Privacy — Private LVM State (Future/Aspirational)

**Dimension**: Contract/call privacy

**Practical first step**: A "private token" precompile at a new system address extending Priv ciphertext arithmetic to arbitrary tokens (not just native TOS). Full FHE/MPC for general-purpose encrypted computation is out of current scope.

- `core/priv/private_token.go` — Private token registry using Priv infrastructure
- New system address in `params/tos_params.go`

**Dependencies**: Phases 1-2.

---

## Progress Projection

| Phase | Dimension | Privacy Gain | Cumulative |
|-------|-----------|-------------|------------|
| Baseline (Priv) | Amount privacy | ~30-35% | ~30-35% |
| Phase 0: C backend | (unblocks Priv) | +0% (enabler) | ~30-35% |
| Phase 1: Uniform envelopes | Metadata | +8% | ~40% |
| Phase 2: Stealth addresses | Tx graph | +15% | ~55% |
| Phase 3: Decoy outputs | Tx graph (depth) | +8% | ~63% |
| Phase 4: Dandelion++ | Network | +7% | ~70% |
| Phase 5: Agent privacy tiers | Identity | +10% | ~80% |
| Phase 6: Private contracts | Contract | +5-10% | ~85-90% |

## Implementation Sequencing

```
Phase 0 (C backend fix)          ← must come first
    │
Phase 1 (Uniform envelopes)      Phase 4 (Dandelion++)
    │                                │
Phase 2 (Stealth addresses)      ← can parallelize ─┘
    │
Phase 3 (Decoy outputs)
    │
Phase 5 (Agent privacy tiers)
    │
Phase 6 (Private contracts)      ← aspirational
```

## Verification Strategy

- **Phase 0**: Run `core/priv/verify_test.go` with CGO+ed25519c enabled; all proofs must pass
- **Phase 1**: Verify gas charged is identical for all three Priv actions; verify encoded envelope sizes are equal
- **Phase 2**: Round-trip DKSAP test: derive stealth address → send StealthTransfer → scan → spend. Integration test in `core/priv_state_transition_test.go`
- **Phase 3**: Verify decoy ciphertexts are applied without changing recipient balances; verify anonymity set size
- **Phase 4**: Network simulation: verify transaction origin cannot be traced within N hops
- **Phase 5**: Register Private agent → verify bloom filter absent → verify ZK capability proof accepted by discovery
