# GTOS Oracle v1 Design

**Status:** Proposed  
**Target repository:** `gtos`  
**Scope:** Native on-chain oracle module that is implementable with the current GTOS architecture.

## 1. Purpose

This document turns the broader OracleHub, incentive, and result-ABI drafts into a version that can be implemented in the current `gtos` codebase without new cryptographic verifiers, new databases, or a new execution environment.

The design target is a native oracle module for:

- prediction-market settlement
- agent-native task settlement
- bounded event and statistic resolution

The implementation model must fit the current GTOS pattern:

- system actions routed through `params.SystemActionAddress`
- a native Go package with `init()` registration
- state stored in a fixed system account via keccak256-derived slots
- optional LVM read helpers in `core/vm/lvm.go`

## 2. Design Principles

1. Ship a useful oracle before shipping a maximal oracle.
2. Keep the consensus object bounded and machine-comparable.
3. Accept evidence commitments in v1, not full proof verification.
4. Reuse existing GTOS agent and reputation infrastructure where it is already real.
5. Do not depend on delegation, zkTLS verification, SNARK verification, TEE attestation, or zkML for the first implementation.

## 3. What Ships in v1

Version 1 includes:

- native `oracle/` module with fixed protocol address
- oracle operator registration with separate slashable bond
- requirement that an oracle operator is an active registered agent
- single-query, single-round commit/reveal resolution
- bounded result types: `BINARY`, `ENUM`, `SCALAR`, `RANGE`, `STATUS`
- query-funded reward pool
- count-weighted `M-of-N` threshold consensus
- evidence commitments:
  - `policy_hash`
  - `evidence_root`
  - `source_proofs_root`
  - `model_set_id`
- automatic handling of objective faults:
  - commit without reveal
  - malformed reveal
  - policy mismatch
  - missing required evidence commitment fields
- simple reward split among winning revealers
- simple slash model for objectively checkable faults
- reputation updates through the existing `reputation/` package
- LVM read helper for finalized oracle results

## 4. Explicit Non-Goals for v1

The following items are intentionally cut from the initial implementation:

- multi-round dispute and appeal trees
- on-chain zkTLS or TLSNotary verification
- on-chain SNARK verification
- on-chain TEE attestation verification
- on-chain zkML verification
- delegated oracle stake and delegator reward accounting
- proof-provider markets and proof premiums
- stake-weighted or reputation-weighted consensus
- arbitrary free-form text settlement
- generic price-feed mode
- recurring query automation via `task/`
- separate `OracleMarketAddress` and `OracleEvidenceAddress`
- full challenge game with subjective evidence adjudication

These are not rejected forever. They are postponed until the base oracle is live and stable.

## 5. High-Level Model

GTOS Oracle v1 is a native commit/reveal oracle with evidence commitments.

The trust model is:

- operators are economically bonded
- operators must already exist as GTOS agents
- operators commit first, reveal second
- the chain aggregates only bounded result bodies
- evidence and source-proof data are committed by hash, not verified on-chain
- the chain finalizes only when a threshold of matching bounded results is reached

This makes v1 an evidence-aware oracle, not yet a fully verifiable oracle.

## 6. Result Model

GTOS Oracle v1 reuses the bounded result families from `docs/GTOS_AI_Oracle_Result_ABI_Spec.md`, but simplifies aggregation by separating:

- the **consensus object**
- the **final stored result header**

### 6.1 Consensus object

Reports are grouped by `outcome_hash`, not by the full final header.

`outcome_hash` is computed from the normalized bounded body only:

```text
outcome_hash =
  H(
    result_type ||
    outcome_u32 ||
    scalar_value_i128 ||
    raw_value_i128 ||
    decimals_u8 ||
    invalid_u8 ||
    status_code_u8 ||
    reason_code_u32
  )
```

This avoids false disagreement caused by different evidence bundles that lead to the same resolved outcome.

### 6.2 Final stored result

After finalization, the module stores a final result object compatible with the Oracle ABI direction:

```text
OracleFinalResult {
  version
  query_id
  market_id
  result_type
  status
  proof_mode
  finalized_at_block
  confidence_bps
  policy_hash
  evidence_root
  source_proofs_root

  outcome_u32
  scalar_value_i128
  raw_value_i128
  decimals_u8
  invalid_u8
  status_code_u8
  reason_code_u32
}
```

Notes:

- `finalized_at_block` uses block number, not wall-clock timestamp.
- `evidence_root` is an aggregate hash over accepted reports' evidence roots.
- `source_proofs_root` is an aggregate hash over accepted reports' source proof roots.
- `proof_mode` is stored as a query requirement and final-result attribute, even though v1 does not verify proofs on-chain.

### 6.3 Supported result types

`result_type` values:

```text
1 = BINARY
2 = ENUM
3 = SCALAR
4 = RANGE
5 = STATUS
```

Normalized field usage:

- `BINARY`: use `outcome_u32` as `0` or `1`, plus `invalid_u8`
- `ENUM`: use `outcome_u32` as enum index, plus `invalid_u8`
- `SCALAR`: use `scalar_value_i128` and `decimals_u8`
- `RANGE`: use `outcome_u32` as bucket index, plus `raw_value_i128` and `decimals_u8`
- `STATUS`: use `status_code_u8` and `reason_code_u32`

## 7. Proof Modes

Keep the ABI enum values, but only a subset is accepted in v1:

```text
0 = PROOF_NONE
1 = PROOF_EVIDENCE_DIGEST
2 = PROOF_EVIDENCE_AUTH
3 = PROOF_TEE_ATTESTED
4 = PROOF_ZK_AGGREGATED
5 = PROOF_ZKML_CLASSIFIED
```

Accepted in v1:

- `0`
- `1`
- `2`

Rejected in v1:

- `3`
- `4`
- `5`

Interpretation in v1:

- `PROOF_EVIDENCE_DIGEST` means evidence hashes are required
- `PROOF_EVIDENCE_AUTH` means evidence hashes and source-proof hashes are required
- neither mode means the chain has verified the proof bundle cryptographically

## 8. Native Module Architecture

Create a new native package:

```text
oracle/
  types.go
  state.go
  hash.go
  handler.go
  oracle_test.go
```

Modify:

- `params/tos_params.go`
- `sysaction/types.go`
- `tos/backend.go`
- `core/vm/lvm.go`

## 9. Fixed Address and Constants

Add a new system address in `params/tos_params.go`:

```go
OracleHubAddress = common.HexToAddress("0x0000000000000000000000000000000000000110")
```

Rationale:

- `0x...0109` is already occupied by `CheckpointSlashIndicatorAddress`
- `0x...0110` is currently free in the codebase

Recommended constants:

```go
var (
    OracleMinSelfStake = new(big.Int).Set(params.AgentMinStake)
)

const (
    OracleResultLoadGas        uint64 = 200

    OracleMaxOperatorsPerQuery uint64 = 15
    OracleMinCommitBlocks      uint64 = 20
    OracleMinRevealBlocks      uint64 = 20
    OracleUnstakeDelayBlocks   uint64 = 10_000

    OracleLightSlashBps  uint64 = 50   // 0.50%
    OracleMediumSlashBps uint64 = 300  // 3.00%
)
```

Implementation note:

- system actions still use the existing fixed `params.SysActionGas`
- only `OracleResultLoadGas` needs a new dedicated LVM gas constant in v1

## 10. Operator Model

### 10.1 Requirements

An oracle operator must:

- be a registered GTOS agent
- be in `AgentActive` status
- not be suspended
- lock a separate oracle bond in `OracleHubAddress`

The agent stake and the oracle bond are distinct:

- agent stake proves agent presence in GTOS
- oracle bond is slashable by the oracle module

### 10.2 Operator state

```text
OperatorStatus:
  0 = INACTIVE
  1 = ACTIVE
  2 = EXIT_PENDING
  3 = JAILED
```

Store:

- `status`
- `self_stake`
- `slashable_stake`
- `metadata_uri_hash`
- `pending_unstake`
- `exit_ready_block`
- `active_commitments`
- `rounds_participated`
- `rounds_won`
- `rounds_missed`
- `rounds_slashed`
- `last_active_block`

### 10.3 Unstake rule

Unstake is two-step:

1. `ORACLE_UNSTAKE_REQUEST`
2. `ORACLE_UNSTAKE_FINALIZE`

Finalize is allowed only if:

- current block >= `exit_ready_block`
- `active_commitments == 0`
- remaining stake is either `0` or `>= OracleMinSelfStake`

## 11. Query Model

Version 1 deliberately uses **one query = one commit/reveal round**.

There is no `ORACLE_OPEN_ROUND` in v1.

### 11.1 Query state

```text
QueryStatus:
  0 = COMMIT_OPEN
  1 = REVEAL_OPEN
  2 = FINALIZED
  3 = FAILED
  4 = CANCELLED
```

The phase is block-driven:

- from creation through `commit_end_block`: `COMMIT_OPEN`
- from `commit_end_block + 1` through `reveal_end_block`: `REVEAL_OPEN`
- after that: only terminal transitions are allowed

Handlers may update the stored status lazily when a query is touched after the phase boundary.

### 11.2 Query payload

`ORACLE_CREATE_QUERY` payload:

```json
{
  "market_id": "0x...",
  "spec_hash": "0x...",
  "result_type": 1,
  "proof_mode": 0,
  "policy_hash": "0x...",
  "min_responses": 3,
  "threshold_m": 2,
  "max_operators": 7,
  "commit_duration_blocks": 120,
  "reveal_duration_blocks": 120
}
```

Funding rule:

- `tx.Value` is the query reward pool
- `tx.Value` must be positive

Validation rules:

- `1 <= threshold_m <= min_responses <= max_operators <= OracleMaxOperatorsPerQuery`
- `commit_duration_blocks >= OracleMinCommitBlocks`
- `reveal_duration_blocks >= OracleMinRevealBlocks`
- `proof_mode <= PROOF_EVIDENCE_AUTH` in v1

### 11.3 Query ID

Use a per-creator nonce:

```text
query_id = keccak256(creator[20] || nonce[8] || block_number[8])
```

This requires:

- `oracleCreatorNonceSlot(creator)` in state
- append-only query list for enumeration

## 12. System Actions

Add these `ActionKind` values to `sysaction/types.go`:

```go
ActionOracleRegisterOperator ActionKind = "ORACLE_REGISTER_OPERATOR"
ActionOracleUpdateOperator   ActionKind = "ORACLE_UPDATE_OPERATOR"
ActionOracleStake            ActionKind = "ORACLE_STAKE"
ActionOracleUnstakeRequest   ActionKind = "ORACLE_UNSTAKE_REQUEST"
ActionOracleUnstakeFinalize  ActionKind = "ORACLE_UNSTAKE_FINALIZE"

ActionOracleCreateQuery      ActionKind = "ORACLE_CREATE_QUERY"
ActionOracleCancelQuery      ActionKind = "ORACLE_CANCEL_QUERY"
ActionOracleCommit           ActionKind = "ORACLE_COMMIT"
ActionOracleReveal           ActionKind = "ORACLE_REVEAL"
ActionOracleFinalize         ActionKind = "ORACLE_FINALIZE"
```

### 12.1 Operator actions

`ORACLE_REGISTER_OPERATOR`

```json
{
  "metadata_uri_hash": "0x..."
}
```

Rules:

- sender must be an active, unsuspended registered agent
- `tx.Value >= OracleMinSelfStake`
- sender must not already be an active oracle operator

`ORACLE_UPDATE_OPERATOR`

```json
{
  "metadata_uri_hash": "0x..."
}
```

`ORACLE_STAKE`

- no payload
- additional stake comes from `tx.Value`

`ORACLE_UNSTAKE_REQUEST`

```json
{
  "amount": "1000000000000000000"
}
```

`ORACLE_UNSTAKE_FINALIZE`

```json
{
  "amount": "1000000000000000000"
}
```

### 12.2 Query actions

`ORACLE_CREATE_QUERY`

- payload defined above
- reward pool comes from `tx.Value`

`ORACLE_CANCEL_QUERY`

```json
{
  "query_id": "0x..."
}
```

Allowed only if:

- sender is query creator
- query is still `COMMIT_OPEN`
- `commit_count == 0`

Refund:

- full reward pool back to creator

### 12.3 Reporting actions

`ORACLE_COMMIT`

```json
{
  "query_id": "0x...",
  "commitment_hash": "0x..."
}
```

Rules:

- operator must be `ACTIVE`
- query must be `COMMIT_OPEN`
- current block <= `commit_end_block`
- operator must not have committed already
- `commit_count < max_operators`

`ORACLE_REVEAL`

```json
{
  "query_id": "0x...",
  "result_type": 1,
  "outcome_u32": 1,
  "scalar_value": "0",
  "raw_value": "0",
  "decimals": 0,
  "invalid": false,
  "status_code": 0,
  "reason_code": 0,
  "confidence_bps": 8700,
  "evidence_root": "0x...",
  "source_proofs_root": "0x...",
  "policy_hash": "0x...",
  "model_set_id": "0x...",
  "salt": "0x..."
}
```

Rules:

- operator must have committed
- operator must not have revealed already
- query must be in reveal phase
- reveal phase means `current block > commit_end_block && current block <= reveal_end_block`
- current block <= `reveal_end_block`
- `result_type` must equal query `result_type`
- `policy_hash` must equal query `policy_hash`
- `confidence_bps <= 10000`
- if `proof_mode >= PROOF_EVIDENCE_DIGEST`, `evidence_root != 0`
- if `proof_mode >= PROOF_EVIDENCE_AUTH`, `source_proofs_root != 0`

Commitment formula:

```text
commitment_hash =
  H(
    query_id ||
    outcome_hash ||
    confidence_bps ||
    evidence_root ||
    source_proofs_root ||
    policy_hash ||
    model_set_id ||
    salt
  )
```

`ORACLE_FINALIZE`

```json
{
  "query_id": "0x..."
}
```

Rules:

- query must not already be terminal
- current block > `reveal_end_block`

## 13. Aggregation and Finalization

### 13.1 Equality rule

Two accepted reveals are equal if their `outcome_hash` matches.

### 13.2 Winning outcome

After reveal close:

- gather all accepted reveals
- count reports per `outcome_hash`
- choose the unique highest count

Finalize success if all are true:

- accepted reveal count >= `min_responses`
- winning count >= `threshold_m`
- no tie at winning count

Otherwise:

- query becomes `FAILED`

### 13.3 Final confidence

For the winning set:

```text
final_confidence_bps = floor(sum(confidence_bps) / winner_count)
```

### 13.4 Final evidence roots

Aggregate from winning reports only:

```text
final_evidence_root =
  H(sorted_concat(operator || evidence_root))

final_source_proofs_root =
  H(sorted_concat(operator || source_proofs_root))
```

Sort by operator address ascending.

## 14. Rewards, Refunds, and Slashing

### 14.1 Reward split

If query finalizes successfully:

- winning revealers split the query reward pool equally
- losing revealers get no reward

Formula:

```text
reward_per_winner = reward_pool / winner_count
remainder         = reward_pool % winner_count
```

Remainder policy:

- leave remainder in `OracleHubAddress` as protocol dust

### 14.2 Failed query refund

If query fails:

- reward pool is refunded to query creator

### 14.3 Slash classes in v1

Only objective, chain-checkable slashes are included.

Light slash:

- committed but never revealed
- malformed reveal payload
- reveal commitment mismatch

Medium slash:

- policy hash mismatch
- missing required evidence fields for declared proof mode
- attempting duplicate reveal after accepted commit

No heavy slash is included in v1 because no cryptographic evidence verifier exists yet.

### 14.4 Slash formula

```text
light_slash  = slashable_stake * OracleLightSlashBps  / 10_000
medium_slash = slashable_stake * OracleMediumSlashBps / 10_000
```

Slashed funds stay in `OracleHubAddress` in v1.

### 14.5 Reputation updates

After successful finalize:

- winning revealers: `+1`
- non-reveal committers: `-1`
- malformed or medium-slashed reporters: `-1`

After failed finalize:

- non-reveal committers: `-1`
- malformed or medium-slashed reporters: `-1`
- valid revealers with losing outcomes: `0`

Implementation note:

- call `reputation.RecordScore(ctx.StateDB, addr, delta)` directly from `oracle/handler.go`

## 15. Storage Layout

All oracle state is stored under `params.OracleHubAddress`.

### 15.1 Slot helpers

Use field-per-slot layout, following `validator/` and `task/`.

Prefixes:

```text
"oracle\x00operator\x00"
"oracle\x00query\x00"
"oracle\x00commit\x00"
"oracle\x00reveal\x00"
"oracle\x00final\x00"
"oracle\x00opcount"
"oracle\x00oplist\x00"
"oracle\x00qcount"
"oracle\x00qlist\x00"
"oracle\x00nonce\x00"
```

Derived slot rule:

```text
slot = keccak256(prefix || key_bytes || field_name)
```

### 15.2 Operator slots

Keyed by `operator address`.

Fields:

- `status`
- `selfStake`
- `slashableStake`
- `metadataHash`
- `pendingUnstake`
- `exitReadyBlock`
- `activeCommitments`
- `roundsParticipated`
- `roundsWon`
- `roundsMissed`
- `roundsSlashed`
- `lastActiveBlock`
- `registered`

### 15.3 Query slots

Keyed by `query_id`.

Fields:

- `creator`
- `marketId`
- `specHash`
- `resultType`
- `proofMode`
- `policyHash`
- `rewardPool`
- `minResponses`
- `thresholdM`
- `maxOperators`
- `commitEndBlock`
- `revealEndBlock`
- `commitCount`
- `revealCount`
- `status`
- `finalizedAtBlock`
- `finalResultHash`

### 15.4 Commit slots

Keyed by `(query_id, operator)`.

Fields:

- `commitmentHash`
- `committed`
- `revealed`
- `countedMiss`

`countedMiss` prevents double-slashing or double-decrement during finalize.

### 15.5 Reveal slots

Keyed by `(query_id, operator)`.

Fields:

- `accepted`
- `outcomeHash`
- `confidenceBps`
- `evidenceRoot`
- `sourceProofsRoot`
- `policyHash`
- `modelSetId`
- `resultType`
- `outcomeU32`
- `scalarValue`
- `rawValue`
- `decimals`
- `invalid`
- `statusCode`
- `reasonCode`
- `slashClass`

### 15.6 Final result slots

Keyed by `query_id`.

Fields:

- `version`
- `marketId`
- `resultType`
- `status`
- `proofMode`
- `finalizedAtBlock`
- `confidenceBps`
- `policyHash`
- `evidenceRoot`
- `sourceProofsRoot`
- `outcomeU32`
- `scalarValue`
- `rawValue`
- `decimals`
- `invalid`
- `statusCode`
- `reasonCode`
- `resultHash`

## 16. Handler Behavior

`oracle/handler.go` should follow the same pattern as other native modules:

- `init()` registers the handler
- `CanHandle()` switches over `ActionOracle*`
- `Handle()` dispatches to small action-specific functions

Recommended internal helper flow:

1. validate payload and state preconditions
2. perform balance checks
3. mutate state
4. adjust operator counters
5. update reputation if needed

Important invariants:

- `OracleHubAddress` balance must always cover total locked operator stake plus active query reward pools
- `active_commitments` must return to zero once a query reaches a terminal state
- no query may finalize twice
- only one commit and one reveal per operator per query

## 17. LVM Read API

Add a minimal host read primitive:

```text
tos.oracleresult(queryIdHex, field) -> value | nil
```

Supported fields:

- `status`
- `market_id`
- `result_type`
- `proof_mode`
- `finalized_at_block`
- `confidence_bps`
- `policy_hash`
- `evidence_root`
- `source_proofs_root`
- `outcome`
- `scalar_value`
- `raw_value`
- `decimals`
- `invalid`
- `status_code`
- `reason_code`

This is enough for on-chain consumers to settle against finalized oracle outputs.

Do not add a write primitive in v1. Oracle state changes happen only through system actions.

## 18. Tests Required

Create `oracle/oracle_test.go` covering at least:

- operator register happy path
- register fails if sender is not an active agent
- stake increase and two-step unstake
- create query happy path
- create query rejects unsupported proof modes
- commit then reveal happy path
- reveal rejects bad commitment
- reveal rejects policy mismatch
- finalize success with `M-of-N` threshold
- finalize failure with insufficient reveals
- finalize failure on tie
- non-reveal slash on finalize
- reward payout to winners
- refund on failed query
- operator `active_commitments` accounting
- LVM `tos.oracleresult()` reads finalized values correctly

Use `go test -p 96 ./oracle ./core/vm -count=1`.

## 19. Deferred v2 Work

After v1 is merged and stable, the next meaningful upgrades are:

1. objective challenge actions for narrow fraud classes
2. task-scheduler integration for recurring queries
3. proof mode `3/4/5` with real verifier hooks
4. stake-weighted or reputation-weighted aggregation
5. delegated oracle stake once delegation becomes more than nonce tracking
6. richer result-envelope hashing utilities for `.abi` consumers

## 20. Summary

This design intentionally narrows OracleHub into something GTOS can actually ship:

- one native module
- one slashable operator bond
- one query, one round
- one bounded result language
- one threshold finalization rule
- evidence commitments now
- cryptographic evidence verification later

That is enough to make GTOS oracle settlement real, testable, and incrementally extensible.
