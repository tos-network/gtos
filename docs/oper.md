# GTOS Operations Alignment Plan

## Purpose

This document turns the remaining operations gaps between GTOS and the BSC Parlia operating model into an implementation plan.

It is not a generic ideas list. It is a staged delivery plan with:

- the remaining gaps
- the target behavior
- the code and tooling changes required
- rollout order
- acceptance criteria

The goal is to move GTOS from a production-capable validator workflow to a more complete operator platform.

## Current Position

GTOS already has a strong baseline:

- template-driven validator deployment via `gtos-validator@.service`
- separate RPC role via `gtos-rpc@.service`
- grouped-turn-aware validator checks
- native validator monitor flags:
  - `--monitor.doublesign`
  - `--monitor.maliciousvote`
  - `--monitor.journal-dir`
  - `--vote-journal-path`
- native operator evidence commands:
  - `gtos vote export-evidence`
  - `gtos vote submit-evidence`
- continuous watchdog and report tooling:
  - `validator_guard.sh`
  - `validator_guard_report.sh`
- protocol-aware validator maintenance:
  - `VALIDATOR_ENTER_MAINTENANCE`
  - `VALIDATOR_EXIT_MAINTENANCE`

This means GTOS is no longer in an ad hoc operations state.

However, it is still not fully aligned with the stronger BSC operator model.

## The Remaining Gaps

Gap 1 and Gap 2 are now implemented in the current branch and are retained here
as delivery records. The remaining active roadmap items are Gap 3 through Gap 5.

### Gap 1: No native vote journal

### Problem

GTOS currently writes operator monitor journals, but it does not persist the validator voting lifecycle as a first-class local journal.

That means the node can alert on suspicious behavior, but it does not yet maintain a durable, structured record of:

- locally produced votes
- remotely received votes
- conflicting votes
- vote settlement state
- replay/restart recovery state for votes

### Why it matters

A vote journal is needed for:

- restart-safe vote recovery
- better forensic analysis after finality incidents
- evidence retention for future slashing or dispute workflows
- deterministic operator visibility into what the validator actually voted for

### Target

Introduce a dedicated native vote journal path:

- `--vote-journal-path`

This journal should be distinct from `--monitor.journal-dir`.

### Scope

Record at least:

- `local_vote_signed`
- `vote_received`
- `vote_conflict`
- `vote_rebroadcast`
- `vote_finalized` or `vote_settled`

### Deliverables

Code:

- new CLI/config flag for `vote-journal-path`
- DPoS journal writer for checkpoint vote lifecycle
- bounded retention policy
- restart reload logic

Ops:

- per-validator vote journal directory under `/data/gtos/ops/vote_journal/nodeN`
- documentation of journal rotation and retention

### Acceptance Criteria

- a validator restart does not lose visibility into previously signed votes
- the operator can reconstruct vote history for a finalized checkpoint from disk alone
- journal entries are distinct from generic monitor alerts

## Gap 2: No malicious-vote evidence submission pipeline

### Problem

GTOS can now detect suspicious checkpoint vote conflicts, but it cannot yet turn that observation into a structured evidence submission flow.

BSC goes further than monitoring: it also has tooling around malicious vote evidence and slashing-related submission workflows.

### Why it matters

Detection without an evidence path leaves operators with an incomplete response model.

That causes two problems:

- incidents stop at alerting
- enforcement remains manual and inconsistent

### Target

Add an operator-facing evidence pipeline for malicious vote incidents.

This does not require immediate slashing activation, but it does require a standard evidence format and a standard operator command path.

### Scope

Minimum v1:

- define a canonical `MaliciousVoteEvidence` structure
- export evidence from monitor/journal data
- add a command or script to package evidence
- add a submission path placeholder even if final protocol enforcement is delayed

Possible CLI examples:

- `gtos vote export-evidence ...`
- `gtos vote submit-evidence ...`

### Deliverables

Code:

- evidence schema
- evidence serialization
- CLI export command
- submission stub or RPC

Ops:

- runbook for incident handling
- evidence retention rules

### Acceptance Criteria

- an equivocation event can be exported into a canonical evidence file
- two operators observing the same event produce equivalent evidence output
- evidence can be submitted or at least staged through a standard command path

## Gap 3: Maintenance governance is still operational, not protocol-enforced

### Problem

GTOS maintenance mode is now real and protocol-aware, but maintenance overrun handling still lives entirely in runbooks and operator alerts.

Today the system can:

- enter maintenance
- exit maintenance
- warn when maintenance lasts too long

It cannot yet:

- enforce maintenance duration limits
- escalate beyond operator warnings
- define governance action for forgotten or abused maintenance

### Why it matters

This is acceptable for a first production phase, but not for a more complete validator governance model.

A validator that remains in maintenance indefinitely should not depend only on humans noticing an alert.

### Target

Define and implement a formal maintenance governance policy.

This can be delivered in two stages.

### Stage A: Governance-hard, protocol-soft

Implement:

- explicit maintenance SLA in the runbook
- severity escalation after threshold breach
- mandatory incident creation path
- cluster dashboards tracking maintenance duration

### Stage B: Protocol-hard

Optionally implement:

- maintenance expiry
- forced maintenance state transitions
- slashing or stake impact for extreme abuse

### Deliverables

Ops:

- maintenance duration policy
- alert severity ladder
- operator escalation path

Protocol, if chosen:

- on-chain maintenance expiry or enforcement rules

### Acceptance Criteria

- there is a documented maximum tolerated maintenance duration
- guard alerts escalate deterministically after threshold breach
- the team can answer what happens after 2h, 6h, 24h, and multi-day maintenance cases

## Gap 4: Deployment is not yet fully TOML-first

### Problem

GTOS is much better than before, but part of the node runtime still depends on env-driven and systemd-driven injection, especially for role-specific network parameters.

BSC is stronger here: more of the operating surface is explicitly centralized in TOML.

### Why it matters

The more runtime behavior lives in systemd env files, the easier it is to create drift between nodes.

This is not just cosmetic. Drift increases the chance of:

- port mismatches
- API exposure mismatches
- peer topology mismatches
- different operational defaults between validator and RPC fleets

### Target

Move as much non-secret node behavior as possible into:

- `config.toml`
- `config-rpc.toml`

Reserve env files for:

- datadir
- ports
- account identity
- password file
- secrets
- small machine-local overrides

### Scope

Move or normalize:

- HTTP/WS API sets
- P2P defaults where practical
- logging defaults
- monitoring defaults that are network-wide rather than node-local

Keep in env:

- validator account address
- password path
- machine-specific ports
- webhook/SMTP secrets

### Deliverables

- slimmer `validator.env`
- slimmer `rpc.env`
- expanded TOML templates
- documented separation rules

### Acceptance Criteria

- a new validator can be bootstrapped primarily from TOML plus one small env file
- two validators with identical TOML and different envs behave identically except for identity and ports
- node role drift becomes auditable by diffing TOML files first

## Gap 5: No single authoritative chain-status operator tool

### Problem

GTOS currently has multiple useful pieces:

- `validator_cluster.sh status`
- `validator_guard.sh`
- `validator_guard_report.sh`
- `dpos_livenet_soak.sh`

But there is still no single authoritative operator command that answers:

- head / finalized / lag
- validator role health
- grouped-turn status
- maintenance status
- RPC role status
- recent alerts

BSC has a more mature habit of shipping operator-oriented status tooling in addition to node flags.

### Why it matters

Operational maturity improves when on-call engineers do not need to mentally join output from multiple scripts.

### Target

Add a single cluster/operator status command.

Possible form:

- `scripts/gtos_chain_status.sh`
- or `gtos ops status`

### Scope

Minimum output:

- validator service health
- RPC service health
- head block
- finalized block
- finality lag
- grouped-turn current owner / expected proposer
- maintenance state for each validator
- latest alerts summary

### Deliverables

- one canonical status tool
- machine-readable JSON mode
- operator-friendly human mode

### Acceptance Criteria

- on-call can answer core health questions from one command
- JSON output can feed dashboards or automation
- the tool replaces ad hoc manual querying for routine operations

## Recommended Delivery Order

The five gaps should not be implemented in arbitrary order.

Recommended sequence:

1. **Vote journal**
   - establishes durable vote state
   - reduces risk before evidence and enforcement work

2. **Authoritative status tool**
   - improves operator visibility immediately
   - simplifies adoption of later features

3. **Malicious-vote evidence pipeline**
   - builds on journaled data
   - creates a proper response path

4. **TOML-first cleanup**
   - lowers long-term configuration drift
   - reduces operational variance

5. **Maintenance governance hardening**
   - should be done after operators already have reliable visibility and evidence

## Suggested Milestones

### Milestone 1: Visibility Foundation

Deliver:

- `--vote-journal-path`
- vote lifecycle persistence
- unified chain status command

Success condition:

- operator can diagnose vote and finality state without manual log archaeology

### Milestone 2: Incident Handling

Deliver:

- malicious vote evidence export
- evidence submission path
- runbook update for validator incident response

Success condition:

- suspicious vote incidents move from detection to repeatable response

### Milestone 3: Config Hardening

Deliver:

- slimmer env files
- stronger TOML templates
- explicit role boundaries for validator vs RPC fleets

Success condition:

- deployment drift is materially reduced

### Milestone 4: Governance Hardening

Deliver:

- maintenance SLA enforcement policy
- optional protocol-level maintenance controls

Success condition:

- maintenance abuse or operator neglect has a deterministic handling path

## Risks and Constraints

### Do not overload one release

The vote journal and evidence pipeline touch validator safety. They should not be bundled with unrelated consensus changes.

### Keep monitor and vote journal separate

Do not collapse these into one directory or one file model.

- monitor journal = operator alerts and health events
- vote journal = validator vote lifecycle persistence

### Do not make maintenance enforcement implicit

If GTOS moves from warnings to penalties, that must be an explicit governance and protocol decision.

### Keep role separation clear

Validator and RPC nodes must remain distinct templates even if they share some TOML structure.

## Final Recommendation

GTOS should treat the remaining BSC alignment work as an operator-platform roadmap, not as miscellaneous cleanup.

The highest-value next step is:

1. native vote journal

The highest-value second step is:

2. one authoritative chain-status tool

Those two changes improve reliability immediately and create the base needed for evidence handling and stronger governance.
