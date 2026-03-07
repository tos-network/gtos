# GTOS Checkpoint Finality Runbook

This runbook is the operator checklist for enabling and running GTOS checkpoint finality safely.

It is written for validators, full-node operators, bridge operators, and release engineers.

## 1. Chain Config Consistency

All validator and full-node instances must run the exact same consensus-relevant configuration.

Verify that every node uses the same values for:

- `CheckpointFinalityBlock`
- `CheckpointInterval`
- `Epoch`
- `PeriodMs`
- `MaxValidators`
- `SealSignerType = ed25519`

If any node starts with a different checkpoint finality configuration, startup must fail. Do not bypass that failure.

## 2. Validator Count Limit

Checkpoint finality v1 uses a `uint64` bitmap in the QC wire format.

Required invariant:

- `MaxValidators <= 64`

Do not activate checkpoint finality on a network with a larger validator set.

## 3. Validator Signer Metadata

Before `FirstEligibleCheckpoint`, every active validator must already have valid canonical `ed25519` signer metadata on-chain.

Each validator must satisfy all of the following:

- signer metadata exists
- signer type is `ed25519`
- signer public key is well-formed
- signer public key derives to the validator address

If even one active validator is missing or malformed, QC verification will fail.

## 4. State Retention Requirement

Checkpoint finality requires access to checkpoint pre-state signer metadata.

Protocol requirement:

- nodes participating in checkpoint finality must retain enough state to verify QCs for at least `2 * CheckpointInterval` blocks behind head

Current implementation behavior:

- archive nodes are always acceptable
- non-archive nodes are rejected at startup if their retention window is too short

Operational rule:

- if checkpoint finality is enabled, prefer archive mode for validators unless you have explicitly verified the retention requirement

## 5. Validator Key Type

DPoS sealing is `ed25519-only`.

Verify for every validator:

- the unlocked validator account is `ed25519`
- the keystore entry is `ed25519`
- the configured `coinbase` / validator address matches that key

Do not use a `secp256k1` validator account for DPoS sealing.

## 6. Activation Height

Checkpoint finality does not begin at every height after `CheckpointFinalityBlock`.

Compute:

```text
FirstEligibleCheckpoint = first h such that
  h >= CheckpointFinalityBlock
  and h % CheckpointInterval == 0
```

Validators begin signing checkpoint votes starting from `FirstEligibleCheckpoint`.

Before activation, publish the exact value of:

- `CheckpointFinalityBlock`
- `CheckpointInterval`
- `FirstEligibleCheckpoint`

## 7. RPC Integration

External systems must treat checkpoint finality as the source of truth for irreversible confirmation.

Use:

```text
tos_getFinalizedBlock
```

Bridge, withdrawal, and settlement systems should rely on this RPC, not on raw head depth.

Expected returned fields:

- `number`
- `hash`
- `timestamp`
- `validatorSetHash`

## 8. Restart Recovery Drill

Before production activation, run at least one validator restart drill.

Expected behavior after restart:

- validator resumes block production normally
- previously signed but not yet finalized checkpoint votes are re-gossiped
- `tos_getFinalizedBlock` remains correct across restart

Do not activate checkpoint finality on a network that has not passed a restart drill.

## 9. Reorg / Finality Enforcement Drill

Before production activation, run a fork-choice drill.

Expected behavior:

- a checkpoint finalized on the canonical chain remains finalized after restart
- a side branch carrying a QC does not update finalized state before canonical adoption
- a longer side branch that does not contain the finalized checkpoint is rejected

This is the main consensus-hard safety property. Verify it explicitly.

## 10. Monitoring

At minimum, monitor:

- current head block number
- current finalized block number
- finalized lag: `head - finalized`
- validator liveness
- checkpoint vote activity
- QC verification failures
- signer metadata errors
- restart recovery events

Recommended alerts:

- finalized block stops advancing for too long
- finalized lag exceeds expected bounds
- repeated checkpoint QC verification errors
- repeated missing signer metadata errors

## 11. Recommended Rollout Procedure

Use this rollout order:

1. Deploy code to all nodes with `CheckpointFinalityBlock = nil`
2. Verify all validators have valid `ed25519` signer metadata
3. Verify archive/retention settings on validator and critical full nodes
4. Compute and announce `FirstEligibleCheckpoint`
5. Activate `CheckpointFinalityBlock`
6. Observe that checkpoint votes are produced and propagated
7. Confirm `tos_getFinalizedBlock` starts advancing as expected
8. Only then allow bridges or withdrawal systems to trust checkpoint finality

## 12. Do Not Ignore

Do not proceed if any of the following is true:

- validator configs differ
- validator signer metadata is incomplete
- a validator still uses a non-`ed25519` DPoS key
- non-archive validators fail the retention requirement
- restart recovery has not been tested
- finalized reorg protection has not been tested

Checkpoint finality is consensus-hard. Treat activation like a consensus upgrade, not like a normal feature toggle.
