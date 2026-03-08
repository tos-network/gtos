# GTOS Oracle Design

**Status:** Proposed  
**Target repository:** `gtos`  
**Scope:** Dual-layer oracle design for GTOS:

- Layer A: implementable native oracle MVP in the current GTOS architecture
- Layer B: verifiable AI consensus path for later releases

## 1. Purpose

This document turns the broader OracleHub, incentive, and result-ABI drafts into a design that serves two purposes at once:

- specify a version that can be implemented in the current `gtos` codebase without new cryptographic verifiers, new databases, or a new execution environment
- preserve a clean upgrade path toward an agent-native oracle in which `LLM + zkTLS + SNARK` can become a first-class protocol path

The design target is a native oracle module for:

- prediction-market settlement
- agent-native task settlement
- bounded event and statistic resolution

The implementation model must fit the current GTOS pattern:

- system actions routed through `params.SystemActionAddress`
- a native Go package with `init()` registration
- state stored in a fixed system account via keccak256-derived slots
- optional LVM read helpers in `core/vm/lvm.go`

This document is intentionally split into two layers:

- **Layer A**: what GTOS can encode and ship now
- **Layer B**: what GTOS should converge to for verifiable AI consensus

## 2. Design Principles

1. Ship a useful oracle before shipping a maximal oracle.
2. Keep the consensus object bounded and machine-comparable.
3. Accept evidence commitments in v1, not full proof verification.
4. Reuse existing GTOS agent and reputation infrastructure where it is already real.
5. Do not depend on delegation, zkTLS verification, SNARK verification, TEE attestation, or zkML for the first implementation.
6. Still define the Layer B end-state precisely enough that Layer A does not paint the protocol into a corner.

## 3. Layer A — What Ships in v1

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

## 4. Layer A — Explicit Non-Goals for v1

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

These are not rejected forever. They are postponed into Layer B so the base oracle can go live first.

## 5. Layer A — High-Level Model

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

### 6.4 Canonical encoding and hash rules

All Layer A formulas that use `H(...)` must use the same byte-level encoding.

Define:

```text
H(x) = keccak256(x)
```

Field encoding rules:

- `uint8`: 1 byte
- `uint16`: 2 bytes, big-endian
- `uint32`: 4 bytes, big-endian
- `uint64`: 8 bytes, big-endian
- `int128`: 16 bytes, two's-complement, big-endian
- `bool`: 1 byte, `0x00` or `0x01`
- `bytes32` / `common.Hash`: raw 32 bytes
- `address`: raw 20 bytes

Concatenation rule:

- fixed-width fields are concatenated directly
- there are no length prefixes in Layer A hashing formulas
- fields that are not used by a given `result_type` must be encoded as all-zero fixed-width values

Normalized Layer A `outcome_hash` layout:

```text
outcome_hash =
  H(
    result_type:u8 ||
    outcome_u32:u32 ||
    scalar_value_i128:i128 ||
    raw_value_i128:i128 ||
    decimals_u8:u8 ||
    invalid_u8:u8 ||
    status_code_u8:u8 ||
    reason_code_u32:u32
  )
```

Normalized Layer A `commitment_hash` layout:

```text
commitment_hash =
  H(
    query_id:bytes32 ||
    outcome_hash:bytes32 ||
    confidence_bps:u16 ||
    evidence_root:bytes32 ||
    source_proofs_root:bytes32 ||
    policy_hash:bytes32 ||
    model_set_id:bytes32 ||
    salt:bytes32
  )
```

Implementation notes:

- `confidence_bps` is encoded as `uint16`
- `model_set_id` and `salt` are fixed as `bytes32` in Layer A payloads
- `metadata_uri_hash`, `spec_hash`, and other committed hashes in Layer A should also be represented as `bytes32`

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

### 11.4 Layer A semantics for `model_set_id`

Layer A stores `model_set_id` in reveal records and includes it in `commitment_hash`, but does not yet enforce a query-level model-set requirement.

This means:

- `model_set_id` is reporter-declared metadata in Layer A
- it is useful for audit logs, off-chain analysis, and later migration to Layer B
- it is not, by itself, a chain-enforced guarantee that all operators used the same model family or version

If a market requires hard model-set constraints, it must use the Layer B fields:

- `model_policy_hash`
- query-level `model_set_id`
- `committee_root`
- proof-bearing verification rules

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

### 12.4 Reveal fault semantics under `sysaction`

Because GTOS system actions revert all writes when the handler returns an error, Layer A must distinguish between:

- **hard rejection errors**
- **fault-bearing reveals**

Hard rejection errors return `error` and must not mutate oracle state.

Use hard rejection only for:

- payload JSON cannot be decoded
- `query_id` does not exist
- operator is not registered as an active oracle operator
- query is already terminal
- query is not in reveal phase
- operator never committed for this query
- operator already revealed for this query

Fault-bearing reveals return `nil`, write state, and may slash.

Use fault-bearing reveal handling for decodable, attributable submissions where the operator had a valid commit but the revealed content is objectively invalid.

Fault-bearing classes in Layer A:

- `FAULT_RESULT_MALFORMED`
  - result body is semantically invalid for its `result_type`
  - examples: out-of-range boolean outcome, impossible enum/body combination, invalid field combination
- `FAULT_COMMITMENT_MISMATCH`
  - recomputed `commitment_hash` does not match the stored commit
- `FAULT_POLICY_MISMATCH`
  - reveal `policy_hash` does not match the query
- `FAULT_EVIDENCE_REQUIREMENT_MISSING`
  - required `evidence_root` or `source_proofs_root` is zero for the query proof mode

When a fault-bearing reveal is processed, the handler must:

1. set `commit.revealed = true`
2. write a reveal record with:
   - `accepted = false`
   - `faultCode`
   - `slashClass`
3. apply the corresponding slash immediately
4. decrement `active_commitments`
5. return `nil`

This ensures:

- the operator is not double-slashed later as a non-revealer
- objectively faulty reveals become visible on-chain
- finalize logic can ignore `accepted = false` reveals during threshold aggregation

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
- semantically malformed reveal
- reveal commitment mismatch

Medium slash:

- policy hash mismatch
- missing required evidence fields for declared proof mode

Clarification:

- raw JSON decode failure is a hard rejection error, not a slashable reveal
- duplicate reveal after a stored reveal is a hard rejection error, not a separate slash class

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

Layer A storage is intentionally split into two classes:

- **persistent state**
  - long-lived state required after a query reaches terminal status
  - operator state, query summary state, and finalized result state belong here
- **ephemeral state**
  - active-round working state needed only until query finalization
  - commit and reveal records belong here
  - ephemeral state must be deleted when a query reaches `FINALIZED`, `FAILED`, or `CANCELLED`

Design rule:

- if a field is only needed to evaluate one in-flight query, it should not survive query finalization
- if a field can be reconstructed from tx history or from the finalized result object, it should not be kept in persistent state

### 15.1 Slot helpers

Use field-per-slot layout, following `validator/` and `task/`.

Prefixes:

```text
"oracle\x00p\x00operator\x00"
"oracle\x00p\x00query\x00"
"oracle\x00e\x00commit\x00"
"oracle\x00e\x00reveal\x00"
"oracle\x00p\x00final\x00"
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

Recommended naming:

- `p` = persistent
- `e` = ephemeral

### 15.2 Persistent operator state

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

Rationale:

- all fields here are required across many queries and across terminal query boundaries

### 15.3 Persistent query state

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

Rationale:

- this is the compact summary of the query itself
- it remains useful after commit/reveal working state has been cleared

### 15.4 Ephemeral commit state

Keyed by `(query_id, operator)`.

Fields:

- `commitmentHash`
- `revealed`

Encoding rule:

- `commitmentHash == 0` means "no commit exists"
- `revealed == 1` means the operator has consumed their commit by either:
  - accepted reveal
  - fault-bearing reveal
  - non-reveal processing during finalize

Rationale:

- `committed` is derivable from `commitmentHash != 0`
- `countedMiss` is unnecessary if finalize performs a single terminal cleanup pass and then deletes the ephemeral record

### 15.5 Ephemeral reveal state

Keyed by `(query_id, operator)`.

Fields:

- `accepted`
- `faultCode`
- `outcomeHash`
- `confidenceBps`
- `evidenceRoot`
- `sourceProofsRoot`
- `outcomeU32`
- `scalarValue`
- `rawValue`
- `decimals`
- `invalid`
- `statusCode`
- `reasonCode`

Rationale:

- `policyHash` and `resultType` are already stored on the query
- `modelSetId` is Layer A audit metadata and should remain in tx payload / history rather than persistent or ephemeral state
- `slashClass` is derivable from `faultCode`

### 15.6 Persistent finalized result state

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

Rationale:

- this is the only per-query result object that on-chain consumers should need after terminalization

### 15.7 Ephemeral cleanup rule

When a query reaches `FINALIZED`, `FAILED`, or `CANCELLED`, the handler must clear all ephemeral state for that query:

- all `oracle\x00e\x00commit\x00(query_id, operator, *)` slots
- all `oracle\x00e\x00reveal\x00(query_id, operator, *)` slots

Cleanup procedure:

1. iterate over operators that committed or revealed for the query
2. finalize rewards, refunds, and slashes
3. decrement any remaining `activeCommitments`
4. zero the ephemeral commit/reveal slots
5. leave only persistent query/operator/final state behind

Because `max_operators` is capped at a small number in Layer A, this terminal cleanup pass is acceptable.

### 15.8 Auditing model

After cleanup, auditability comes from:

- persistent query summary state
- persistent final result state
- operator counters and reputation changes
- the original commit/reveal transactions in chain history

Layer A does not aim to keep a permanently queryable per-reveal archive in protocol state.

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
- ephemeral commit/reveal state must be zeroed when the query becomes terminal

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
- malformed JSON reveal is hard-rejected with no oracle state mutation
- decodable faulty reveal records `accepted = false`, stores `faultCode`, and applies slash
- finalize success with `M-of-N` threshold
- finalize failure with insufficient reveals
- finalize failure on tie
- non-reveal slash on finalize
- reward payout to winners
- refund on failed query
- operator `active_commitments` accounting
- terminal finalize clears ephemeral commit/reveal state
- LVM `tos.oracleresult()` reads finalized values correctly

Use `go test -p 96 ./oracle ./core/vm -count=1`.

## 19. Layer B — Verifiable AI Consensus Path

Layer B is the protocol path that addresses the full agent-native oracle vision:

- `M-of-N` oracle agents
- each operator may run a small, bounded LLM-based extraction pipeline
- operators consume authenticated source evidence such as zkTLS or TLSNotary transcripts
- the committee reduces evidence into a canonical bounded result
- a succinct proof may attest to the aggregation and result-binding process

This is the layer in which the oracle stops looking like "people reporting answers" and starts looking like **verifiable AI consensus**.

### 19.1 What Layer B is for

Layer B is specifically for query classes where agents need more than a human-style reporter network:

- news facts
- market state snapshots
- external event resolution
- multi-source composite judgments

In these classes, the protocol must eventually express three distinct roles:

- `LLM`: interpret authenticated evidence under a fixed extraction policy
- `zkTLS`: authenticate where the evidence came from
- `SNARK`: compress committee agreement and pipeline correctness into an efficiently verifiable proof

### 19.2 Layer B pipeline

The target pipeline is:

```text
authenticated source sessions
  -> source proofs root
  -> extraction / normalization policy
  -> model-set constrained oracle committee
  -> canonical result hash
  -> committee agreement root
  -> succinct proof
  -> native verification
  -> finalized verified result
```

Important boundary:

- AI is not the root source of truth
- authenticated source bytes are the root evidence
- AI is the constrained interpreter that maps evidence into a bounded settlement object

### 19.3 Layer B query-level commitments

Layer A already commits to `policy_hash`, `evidence_root`, `source_proofs_root`, and `model_set_id`.
Layer B extends this into explicit query-level constraints so the committee is not free to improvise its own evidence or model stack.

Add these query fields for proof-bearing modes:

- `source_set_root`
  - Merkle root of allowed source descriptors
  - can encode domains, endpoint classes, publisher IDs, or source schemas
- `source_policy_hash`
  - minimum distinct sources
  - minimum distinct domains
  - freshness window
  - publication-time rules
  - source conflict handling rules
- `model_policy_hash`
  - exact extraction / normalization / prompt policy commitment
- `model_set_id`
  - fixed model family / version set allowed for the committee
- `committee_root`
  - Merkle root of the operator set eligible for the proof-bearing round
- `verifier_key_id`
  - selects the verifier and key material used by the chain
- `proof_requirement`
  - threshold-only
  - evidence-authenticated
  - zk-aggregated
  - zkml-classified

For news-fact style queries, `source_set_root` and `source_policy_hash` are what let GTOS express "a few mainstream news sites" as a protocol rule rather than a social expectation.

Recommended `source_set_root` templates by market class:

| Market class | Primary settlement sources | Secondary corroboration sources | Notes |
|---|---|---|---|
| Polymarket-style election event | official election authority pages; certified result feeds; state or national election APIs | AP Elections API; Reuters; AP wire | Final settlement should prefer official election authorities. Media confirms freshness and conflict handling, but should not override certified results. |
| Polymarket-style company / product event | company IR / newsroom pages; exchange filings; SEC / regulator filings | Reuters; AP; selected mainstream business press | Use official issuer or regulator disclosures as the strongest source. News can corroborate timing or summarize event interpretation. |
| Polymarket-style legal / regulatory event | court docket pages; regulator announcement pages; government gazettes | Reuters; AP; selected legal or financial press | Prefer docketed or officially published actions over narrative coverage. |
| Polymarket-style generic news fact | designated official pages if they exist; otherwise a configured multi-source news set | Reuters; AP; The Guardian; other explicitly allowed outlets | This is the main class where "a few mainstream news sites" is appropriate. Query policy should require multiple distinct domains and explicit conflict rules. |
| Kalshi-style macro statistic | official statistics agency release pages and machine-readable feeds | Reuters; AP; specialized economic data vendors if explicitly allowed | Settlement should follow the official published statistic, including revision policy defined in `source_policy_hash`. |
| Kalshi-style weather / climate scalar | national weather agency or official meteorological service feeds; station datasets | Reuters; AP; local official weather bulletins | Prefer the designated official station or official aggregate dataset. Media should not be the settlement source. |
| Kalshi-style market reference value | designated exchange, benchmark administrator, or official reference publisher | Reuters; official market data redistributors if explicitly allowed | Query policy must pin the exact benchmark and publication timestamp semantics. |
| Agent task settlement with external event dependency | the task-specific official system of record | Reuters; AP; task-specific backup source set | For agent tasks, `source_set_root` should be narrow and task-specific, not a generic news bundle. |

Operational rule:

- default to official system-of-record sources whenever such a source exists
- only use mainstream news outlets as primary settlement sources for event classes where no single official publisher fully determines the outcome
- require all domains in the source set to be explicitly allowlisted by the query creator or protocol policy

### 19.4 Layer B agreement object

Layer A groups reports by `outcome_hash`.
That is sufficient for an MVP, but it is not sufficient for verifiable AI consensus.

In Layer B, the committee must agree on a **bound result context**, not just the final answer.

Define:

```text
consensus_context_hash =
  H(
    query_id ||
    source_set_root ||
    source_policy_hash ||
    model_policy_hash ||
    model_set_id ||
    proof_mode
  )

binding_hash =
  H(
    canonical_result_hash ||
    evidence_root ||
    source_proofs_root ||
    consensus_context_hash
  )
```

Layer B threshold consensus is over `binding_hash`, not merely over `outcome_hash`.

This means `M-of-N` agreement now covers:

- the result
- the evidence commitments
- the allowed sources
- the interpretation policy
- the model set

That is the protocol-level meaning of verifiable AI consensus.

### 19.5 Layer B proof modes

Layer B keeps the existing proof mode enum but changes which modes are first-class:

- `PROOF_EVIDENCE_AUTH`
  - authenticated source proofs are required
  - suitable when source authenticity is provable but the inference path is not yet fully proved
- `PROOF_ZK_AGGREGATED`
  - a succinct proof shows at least `M` of `N` valid committee members agreed on the same `binding_hash`
- `PROOF_ZKML_CLASSIFIED`
  - only for narrow bounded tasks
  - not required for general news/event interpretation
- `PROOF_TEE_ATTESTED`
  - optional intermediate path
  - not the primary architectural direction for open verifiable consensus

For the specific vision of `LLM + zkTLS + SNARK`, the canonical Layer B path is:

```text
LLM-constrained committee
  + zkTLS-authenticated evidence
  + ZK-aggregated committee proof
```

### 19.6 Layer B system actions

Layer B adds proof lifecycle actions:

```go
ActionOracleSubmitPhase3Proof ActionKind = "ORACLE_SUBMIT_PHASE3_PROOF"
ActionOracleVerifyPhase3Proof ActionKind = "ORACLE_VERIFY_PHASE3_PROOF"
ActionOracleChallengeProof    ActionKind = "ORACLE_CHALLENGE_PROOF"
```

`ORACLE_SUBMIT_PHASE3_PROOF` payload:

```json
{
  "query_id": "0x...",
  "canonical_result_hash": "0x...",
  "binding_hash": "0x...",
  "evidence_root": "0x...",
  "source_proofs_root": "0x...",
  "source_set_root": "0x...",
  "source_policy_hash": "0x...",
  "model_policy_hash": "0x...",
  "model_set_id": "0x...",
  "committee_root": "0x...",
  "verifier_key_id": "0x...",
  "proof_blob_hash": "0x..."
}
```

`ORACLE_VERIFY_PHASE3_PROOF` payload:

```json
{
  "query_id": "0x..."
}
```

`ORACLE_CHALLENGE_PROOF` payload:

```json
{
  "query_id": "0x...",
  "challenge_type": 1,
  "expected_hash": "0x...",
  "observed_hash": "0x..."
}
```

Objective proof challenge classes:

- `1 = SOURCE_SET_MISMATCH`
- `2 = SOURCE_PROOFS_ROOT_MISMATCH`
- `3 = MODEL_SET_MISMATCH`
- `4 = POLICY_HASH_MISMATCH`
- `5 = PUBLIC_INPUTS_MISMATCH`
- `6 = INVALID_PROOF`

### 19.7 Layer B proof public inputs

At minimum, a Layer B proof should bind the following public inputs:

- `query_id`
- `canonical_result_hash`
- `binding_hash`
- `evidence_root`
- `source_proofs_root`
- `source_set_root`
- `source_policy_hash`
- `model_policy_hash`
- `model_set_id`
- `committee_root`
- `threshold_m`
- `verifier_key_id`

This is the minimum set that makes the proof about the whole bounded pipeline rather than only about an output blob.

### 19.8 Layer B verification rule

For queries with proof-bearing modes, finalization must change from:

```text
threshold met -> finalize
```

to:

```text
threshold on binding_hash met
  -> proof submitted
  -> public inputs match stored commitments
  -> native verifier accepts proof
  -> no unresolved objective proof challenge
  -> finalize verified result
```

This is the critical rule that turns the module from evidence-aware into verifiable.

### 19.9 Layer B storage additions

Layer B extends query and final-result storage with:

- `sourceSetRoot`
- `sourcePolicyHash`
- `modelPolicyHash`
- `committeeRoot`
- `verifierKeyId`
- `phase3Required`
- `phase3ProofHash`
- `phase3PublicInputsHash`
- `phase3Verified`
- `verificationStatus`

`verificationStatus` values:

- `0 = UNVERIFIED`
- `1 = VERIFIED`
- `2 = CHALLENGED`

### 19.10 Layer B implementation note

Layer B is not immediately implementable in the current repository without new verifier code and proof plumbing.
Its purpose in this document is to:

- make the end-state explicit
- force Layer A data structures to remain upgrade-friendly
- ensure GTOS can grow from commit/reveal oracle into an AI-native oracle without redesigning the protocol from scratch

## 20. Layer B Rollout Order

After Layer A is live, the recommended rollout order is:

1. extend `ORACLE_CREATE_QUERY` with `source_set_root`, `source_policy_hash`, `model_policy_hash`, `committee_root`, and `verifier_key_id`
2. switch proof-bearing queries from `outcome_hash` aggregation to `binding_hash` aggregation
3. add proof submission and verification storage paths
4. implement native verifier hooks for `PROOF_EVIDENCE_AUTH` and `PROOF_ZK_AGGREGATED`
5. add objective proof challenges
6. add `phase3_verified` / `verification_status` reads to LVM
7. only after that, consider narrow `PROOF_ZKML_CLASSIFIED`

## 21. Summary

This design is now intentionally dual-layer:

- **Layer A** makes GTOS oracle settlement real, testable, and shippable now
- **Layer B** captures the actual AI-native oracle destination

Layer A gives GTOS:

- one native module
- one slashable operator bond
- one query, one round
- one bounded result language
- one threshold finalization rule
- evidence commitments now

Layer B adds what the stronger vision requires:

- query-level source and model constraints
- committee agreement on a bound evidence-processing context
- zkTLS-authenticated source evidence
- succinct proof verification for `M-of-N` committee agreement

That is the bridge from a practical MVP to a future oracle that can reasonably be described as **verifiable AI consensus**.
