# GTOS OracleHub for Prediction Markets
## System Design Draft
### Anchored on Polymarket-style Event Markets and Kalshi-style Scalar Markets

**Status:** Draft  
**Target chain:** GTOS  
**Language:** English  
**Scope:** OracleHub core protocol, on-chain state, action enum, transaction flow, state machines, and phased roadmap up to Phase III: Verifiable AI Oracle.

---

## 1. Overview

GTOS OracleHub is a native oracle protocol for prediction markets and agent-native applications.  
This design is anchored on two representative market classes:

- **Polymarket-style markets**: binary and categorical event-resolution markets
- **Kalshi-style markets**: scalar and range/bucket markets based on official statistics or reference values

OracleHub is designed as an **AI-native oracle**. Off-chain AI systems may retrieve evidence, summarize sources, classify outcomes, normalize noisy real-world data, and produce candidate verdicts. On-chain logic accepts only bounded, canonical, slashable outputs.

OracleHub therefore treats AI as an interpreter, not as the root source of truth. The trust root is the combination of authenticated evidence, fixed interpretation policy, canonical result encoding, accountable operators, and optional proof-backed aggregation. A target Phase III shape is an `M-of-N` oracle committee that consumes authenticated evidence such as zkTLS or TLSNotary proofs, reduces it to a canonical result under a committed policy, and optionally attaches succinct proofs that aggregation and result binding were executed correctly.

The chain settles:

- who submitted
- what was committed
- what was revealed
- whether reveal matched commitment
- whether evidence and policy requirements were met
- whether threshold consensus was achieved
- whether a challenge or proof requirement blocks finalization
- how rewards, slashing, and reputation updates should be applied

---

## 2. Design Goals

### 2.1 Primary goals

OracleHub must provide:

1. deterministic final settlement
2. bounded structured outputs for market resolution
3. economic accountability through staking and slashing
4. AI-friendly off-chain evidence gathering with on-chain canonicalization
5. direct support for binary, enum, scalar, and range markets
6. upgrade path to proof-carrying oracle results in Phase III

### 2.2 Non-goals

OracleHub does not aim to:

- run full LLM inference on-chain
- store raw webpages, PDFs, or full model transcripts on-chain
- resolve free-form text disputes directly on-chain
- treat unconstrained LLM output as self-authenticating truth
- support unbounded reporter sets
- force zkML on every market

---

## 3. Market Design Anchors

## 3.1 Polymarket-style markets

These require mainly:

- binary event resolution
- enum winner selection
- invalid / ambiguous market handling
- evidence from official announcements, trusted news, or public records

Examples:

- Will X happen before date D?
- Will candidate A win election E?
- Which company launches product P first?
- Did event Y occur under the stated rules?

## 3.2 Kalshi-style markets

These require mainly:

- scalar reference value resolution
- range / bucket resolution
- official statistic source tracking
- timestamped publication and revision handling

Examples:

- What is the CPI release value for month M?
- Will rainfall exceed threshold T?
- Which temperature bucket contains the official reading?
- What is the final reported value at time T?

---

## 4. GTOS Positioning

GTOS already reserves fixed protocol-level addresses for native infrastructure such as AgentRegistry, CapabilityRegistry, DelegationRegistry, ReputationHub, and TaskScheduler. OracleHub should be introduced as another protocol-level native module.

### 4.1 Proposed addresses

```go
OracleHubAddress = common.HexToAddress("0x0000000000000000000000000000000000000110")
```

Notes:

- `0x...0109` is already occupied by `CheckpointSlashIndicatorAddress` in the current GTOS codebase.
- Version 1 should not reserve separate `OracleMarketAddress` or `OracleEvidenceAddress`; those can be introduced later if the module is split.

### 4.2 Execution model

For the current GTOS implementation, use **SystemAction style**:

- send transactions to `SystemActionAddress`
- encode `ORACLE_*` actions in the system-action payload
- store oracle state under `OracleHubAddress`

### 4.3 Recommendation

Use native execution rather than a general LVM contract for the first release, because OracleHub needs:

- explicit gas control
- stable state slot layout
- direct slash/reward handling
- tight integration with reputation and scheduler modules

---

## 5. Supported Query and Market Types

OracleHub should support only bounded market result classes.

### 5.1 Query types

```text
BINARY
ENUM
SCALAR
RANGE
STATUS
```

### 5.2 Canonical outputs

- **BINARY**: `YES`, `NO`, optionally `INVALID`
- **ENUM**: winning index
- **SCALAR**: integer value plus decimals
- **RANGE**: bucket index, optionally the raw scalar value
- **STATUS**: pending / final / invalid / unresolvable / disputed

---

## 6. Roles

### 6.1 Query creator
Creates a market query and funds the reward pool.

### 6.2 Oracle operator
A staked participant that may act as reporter, validator, challenger, proof submitter, or aggregator.

### 6.3 Delegator
Delegates stake to an operator.

### 6.4 Consumer
A prediction market or application that reads final results.

### 6.5 Challenger
Submits a challenge during the dispute window.

### 6.6 Resolver
Finalizes the market through threshold consensus and, in higher phases, proof-aware verification.

---

## 7. Phases

## 7.1 Phase I — Commit/Reveal Oracle Network

Features:

- staked operators
- commit/reveal
- threshold consensus
- reward and slash
- reputation updates

No cryptographic proof of source authenticity is required.

## 7.2 Phase II — Evidence-Aware AI Oracle

Adds:

- evidence roots
- source proof roots
- prompt hash
- policy hash
- model set ID
- source policy enforcement
- evidence-based challenge types

Phase II binds candidate results to evidence and interpretation commitments, but it does not yet prove the full off-chain reasoning path. It establishes the boundary conditions for later verification by committing to authenticated evidence roots, source-proof roots, prompt or policy commitments, and model-set commitments so challenges can target mismatches between source bytes, interpretation policy, and canonical output.

## 7.3 Phase III — Verifiable AI Oracle

Adds one or more proof modes:

- evidence-authenticated mode
- TEE-attested mode
- zk-aggregated committee mode
- zkML classifier mode for narrow bounded tasks

The target object of verification is not arbitrary free-form LLM reasoning. It is a bounded oracle pipeline:

```text
authenticated evidence
  -> constrained interpretation
  -> canonical result
  -> M-of-N committee threshold
  -> optional succinct proof
```

Phase III does not require all markets to use zkML. Proof mode is selected per market.

---

## 8. Action Enum

```text
ORACLE_REGISTER_OPERATOR         = 0x01
ORACLE_UPDATE_OPERATOR           = 0x02
ORACLE_SET_CAPABILITY            = 0x03
ORACLE_STAKE                     = 0x04
ORACLE_UNSTAKE_REQUEST           = 0x05
ORACLE_UNSTAKE_FINALIZE          = 0x06
ORACLE_DELEGATE                  = 0x07
ORACLE_UNDELEGATE                = 0x08

ORACLE_CREATE_QUERY              = 0x20
ORACLE_CANCEL_QUERY              = 0x21
ORACLE_TOPUP_REWARD              = 0x22

ORACLE_OPEN_ROUND                = 0x30
ORACLE_COMMIT                    = 0x31
ORACLE_REVEAL                    = 0x32
ORACLE_FINALIZE                  = 0x33
ORACLE_TIMEOUT                   = 0x34

ORACLE_CHALLENGE                 = 0x40
ORACLE_RESPOND_CHALLENGE         = 0x41
ORACLE_RESOLVE_CHALLENGE         = 0x42

ORACLE_SUBMIT_PHASE3_PROOF       = 0x50
ORACLE_VERIFY_PHASE3_PROOF       = 0x51

ORACLE_REWARD_AND_SLASH          = 0x60
ORACLE_UPDATE_REPUTATION         = 0x61

ORACLE_READ_QUERY                = 0x80
ORACLE_READ_ROUND                = 0x81
ORACLE_READ_RESULT               = 0x82
ORACLE_READ_OPERATOR             = 0x83
```

---

## 9. Payload Schemas

## 9.1 Register operator

```text
ORACLE_REGISTER_OPERATOR {
  operator_address
  role_flags
  metadata_uri_hash
  capability_root
  min_proof_mode
  bond_amount
}
```

## 9.2 Create query

```text
ORACLE_CREATE_QUERY {
  query_type
  query_class
  spec_hash
  reward_amount
  min_responses
  threshold_m
  max_reporters_n
  commit_deadline_block
  reveal_deadline_block
  dispute_deadline_block
  proof_mode
  source_policy_hash
  normalizer_hash
}
```

### proof_mode

```text
0 = NONE
1 = EVIDENCE_DIGEST
2 = EVIDENCE_AUTH
3 = TEE_ATTESTED
4 = ZK_AGGREGATED
5 = ZKML_CLASSIFIED
```

## 9.3 Commit

```text
ORACLE_COMMIT {
  query_id
  round_id
  commitment_hash
}
```

Where:

```text
commitment_hash = H(
  canonical_result_hash ||
  evidence_root ||
  proof_mode ||
  aux_hash ||
  salt
)
```

## 9.4 Reveal

```text
ORACLE_REVEAL {
  query_id
  round_id
  canonical_result
  confidence_bps
  evidence_root
  source_proofs_root
  prompt_hash
  policy_hash
  model_set_id
  aux_hash
  salt
  reporter_signature
}
```

## 9.5 Challenge

```text
ORACLE_CHALLENGE {
  query_id
  round_id
  target_operator
  challenge_type
  challenge_evidence_hash
  bond_amount
}
```

### challenge types

```text
1 = INVALID_FORMAT
2 = COMMIT_REVEAL_MISMATCH
3 = EVIDENCE_POLICY_VIOLATION
4 = FRAUDULENT_SOURCE_PROOF
5 = MALFORMED_PHASE3_PROOF
6 = CANONICALIZATION_MISMATCH
7 = MALICIOUS_OUTLIER
```

---

## 10. Storage Layout

## 10.1 Operator storage

```text
oracle/operator/{operator}
```

Fields:

- status
- role_flags
- self_stake
- delegated_stake
- slashable_stake
- unstake_request_block
- metadata_uri_hash
- capability_root
- min_proof_mode
- reputation_score
- rounds_participated
- rounds_missed
- rounds_slashed
- last_active_block

## 10.2 Query storage

```text
oracle/query/{query_id}
```

Fields:

- creator
- query_type
- query_class
- spec_hash
- reward_pool
- min_responses
- threshold_m
- max_reporters_n
- proof_mode
- source_policy_hash
- normalizer_hash
- commit_deadline_block
- reveal_deadline_block
- dispute_deadline_block
- state
- current_round_id
- creation_block

## 10.3 Round storage

```text
oracle/round/{query_id}/{round_id}
```

Fields:

- state
- open_block
- commit_count
- reveal_count
- finalize_block
- disputed
- final_result_hash
- final_confidence_bps
- winning_result_hash
- agreed_weight
- disagreed_weight
- proof_mode
- phase3_verified

## 10.4 Commit storage

```text
oracle/commit/{query_id}/{round_id}/{operator}
```

Fields:

- commitment_hash
- committed_at
- revealed
- slashed_for_nonreveal

## 10.5 Reveal storage

```text
oracle/reveal/{query_id}/{round_id}/{operator}
```

Fields:

- canonical_result_hash
- canonical_result_blob_hash
- confidence_bps
- evidence_root
- source_proofs_root
- prompt_hash
- policy_hash
- model_set_id
- aux_hash
- reporter_signature_hash
- accepted
- slash_reason

## 10.6 Challenge storage

```text
oracle/challenge/{query_id}/{round_id}/{challenge_id}
```

Fields:

- challenger
- target_operator
- challenge_type
- challenge_evidence_hash
- bond
- opened_at
- resolved_at
- outcome

## 10.7 Final result storage

```text
oracle/final/{query_id}/{round_id}
```

Fields:

- status
- final_result_hash
- final_confidence_bps
- agreed_reporters_root
- disagreed_reporters_root
- evidence_bundle_root
- proof_mode
- proof_hash
- resolved_at

---

## 11. Slot Prefixes

Recommended slot preimages:

```text
"gtos.oracle.operator"
"gtos.oracle.query"
"gtos.oracle.round"
"gtos.oracle.commit"
"gtos.oracle.reveal"
"gtos.oracle.challenge"
"gtos.oracle.final"
```

Derived slots:

```text
slot = keccak256(prefix || key1 || key2 || ...)
```

---

## 12. State Machines

## 12.1 Query state machine

```text
CREATED
  -> OPEN
  -> COMMIT_CLOSED
  -> REVEAL_CLOSED
  -> FINALIZED
  -> DISPUTED
  -> RESOLVED
  -> EXPIRED
  -> CANCELLED
```

## 12.2 Operator state machine

```text
INACTIVE
  -> ACTIVE
  -> JAILED
  -> EXIT_PENDING
  -> EXITED
```

## 12.3 Round state machine

```text
ROUND_OPEN
  -> COMMIT_PHASE
  -> REVEAL_PHASE
  -> AGGREGATION
  -> FINALIZED
  -> DISPUTED
  -> RESOLVED
  -> FAILED
```

---

## 13. Aggregation Rules

### 13.1 Equality rule

Two reports are equal if all required consensus fields match:

- canonical_result_hash
- proof_mode
- required policy fields
- required evidence constraints

### 13.2 Threshold rule

A result is finalizable if:

- `reveal_count >= min_responses`
- some canonical result reaches threshold `m`
- no unresolved valid challenge blocks finalization

### 13.3 Aggregation modes

```text
0 = COUNT_MAJORITY
1 = STAKE_WEIGHTED
2 = REPUTATION_WEIGHTED
3 = HYBRID_STAKE_REPUTATION
4 = PROOF_PRIORITY_THEN_STAKE
```

Recommended use:

- Phase I: `STAKE_WEIGHTED`
- Phase II: `HYBRID_STAKE_REPUTATION`
- Phase III: `PROOF_PRIORITY_THEN_STAKE`

---

## 14. Evidence Model

```text
EvidenceBundle {
  query_id
  round_id
  source_type
  source_uri_hash
  source_auth_proof_hash
  fetched_at
  model_set_id
  prompt_hash
  tool_policy_hash
  raw_observation_hash
  normalized_output_hash
  confidence_bps
}
```

The chain stores only compact roots and hashes, not full evidence.

---

## 15. Phase III: Verifiable AI Oracle

Phase III is intended to verify a bounded evidence-processing pipeline, not to bless arbitrary model outputs. In the intended design, authenticated source bytes are bound to a committed interpretation policy, reduced into a canonical result, aggregated across an `M-of-N` oracle committee, and optionally compressed into a succinct proof that the on-chain verifier can check efficiently.

## 15.1 Verifiable modes

### A. Evidence-authenticated mode
Includes authenticated source proof hashes such as zkTLS or TLSNotary digests. This mode proves where the evidence came from, even if full inference is not proved.

### B. TEE-attested mode
Includes enclave attestation for the inference or evidence-processing environment.

### C. ZK-aggregated committee mode
A proof shows that at least `M` out of `N` valid committee reports, each bound to the same evidence and policy commitments, agreed on the canonical result.

### D. zkML classifier mode
For narrow bounded classification tasks only.

## 15.2 Public inputs for proofs

- query_id
- round_id
- canonical_result_hash
- evidence_root
- source_proofs_root
- policy_hash
- verifier_key_id

## 15.3 Verification path

```text
ORACLE_SUBMIT_PHASE3_PROOF
  -> store proof hash / public inputs hash
ORACLE_VERIFY_PHASE3_PROOF
  -> native verifier call
  -> set phase3_verified = true
  -> unlock FINALIZED / RESOLVED transition
```

---

## 16. Transaction Flows

## 16.1 Operator onboarding

1. operator submits `ORACLE_REGISTER_OPERATOR`
2. operator stakes bond with `ORACLE_STAKE`
3. operator becomes `ACTIVE`

## 16.2 Query creation

1. creator submits `ORACLE_CREATE_QUERY`
2. reward pool is escrowed
3. query enters `CREATED`
4. `ORACLE_OPEN_ROUND` opens round 1

## 16.3 Commit/reveal flow

1. operators submit `ORACLE_COMMIT`
2. commit window closes
3. operators submit `ORACLE_REVEAL`
4. OracleHub checks commitment match
5. aggregation computes winning canonical result
6. `ORACLE_FINALIZE` finalizes if threshold is met

## 16.4 Challenge flow

1. challenger submits `ORACLE_CHALLENGE`
2. target may respond
3. challenge is resolved
4. successful challenge may slash target or block finalization

## 16.5 Phase III proof flow

1. reveal completes
2. proof submitter submits `ORACLE_SUBMIT_PHASE3_PROOF`
3. verifier action runs
4. if valid, round marks `phase3_verified = true`
5. finalization proceeds

---

## 17. Reward and Slashing

### 17.1 Rewards

Rewards come from:

- query reward pool
- optional protocol subsidy
- optional premium for higher proof modes

### 17.2 Slashing classes

- **light slash**: non-reveal, late reveal, malformed payload
- **medium slash**: repeated failure, policy mismatch
- **heavy slash**: fraudulent source proof, fake attestation, deceptive proof

### 17.3 Reputation effects

Correct, timely, and evidence-compliant participation improves reputation.  
Missed rounds and slashed misconduct reduce reputation.

---

## 18. Integration with GTOS Modules

- **AgentRegistry**: oracle operators may be agent-class participants
- **DelegationRegistry**: delegators can back oracle operators
- **ReputationHub**: stores oracle performance scores
- **TaskScheduler**: opens recurring rounds automatically

---

## 19. Recommended Constants

```go
const (
    OracleRegisterGas           uint64 = 50_000
    OracleStakeGas              uint64 = 40_000
    OracleCreateQueryGas        uint64 = 80_000
    OracleCommitGas             uint64 = 30_000
    OracleRevealGas             uint64 = 80_000
    OracleFinalizeGas           uint64 = 100_000
    OracleChallengeGas          uint64 = 90_000
    OracleResolveChallengeGas   uint64 = 120_000
    OracleVerifyProofGasBase    uint64 = 150_000

    OracleMaxReportersPerRound  uint64 = 15
    OracleMaxChallengesPerRound uint64 = 16
)
```

---

## 20. Why this design fits prediction markets

### 20.1 For Polymarket-style markets
OracleHub provides:

- binary resolution
- enum resolution
- invalid and disputed outcomes
- evidence-aware settlement

### 20.2 For Kalshi-style markets
OracleHub provides:

- scalar settlement
- bucket/range settlement
- publication-time aware reference values
- official-source evidence support

---

## 21. Conclusion

OracleHub should not be a generic price feed clone. It should be a native GTOS oracle system for:

- event markets
- scalar markets
- AI-assisted market resolution
- proof-aware settlement for high-value markets

The core principles are:

1. canonical outputs only
2. commit/reveal and economic accountability
3. evidence-aware reporting
4. optional proof-carrying finalization
