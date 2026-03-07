# GTOS Validator Operations Plan

## Goal

This document defines an operational model for GTOS validators based on the
current GTOS codebase and the lessons that can be taken from BSC Parlia
operations.

The objectives are:

- make validator deployment reproducible and easier to audit
- reduce configuration drift between nodes
- separate chain configuration from machine-local process settings
- support safe validator maintenance through on-chain state changes
- provide a clear rollout path for local testnets and production-like clusters

This is an operations design document. It describes how GTOS validators should
be deployed and managed. It does not itself change consensus rules.

## Current GTOS Baseline

At the time of writing, GTOS already has:

- on-chain validator registration and withdrawal via system actions
- validator state stored under `params.ValidatorRegistryAddress`
- DPoS block production based on the active validator set
- `ed25519-only` DPoS sealing
- grouped-turn DPoS proposer ownership via `TurnLength`
- a local three-node deployment script:
  - [validator_cluster.sh](/home/tomi/gtos/scripts/validator_cluster.sh)
- per-node `systemd` units with validator-specific flags embedded directly in
  `ExecStart`

The current approach works for local testing, but it has clear operational
limits:

- each validator unit duplicates a long command line
- validator-specific and network-wide settings are mixed together
- startup ordering and peering behavior have to be encoded in shell logic
- there is no protocol-aware maintenance workflow

Current DPoS rotation semantics are no longer "one proposer per block". GTOS
uses grouped turns:

- `TurnLength` is a consensus parameter
- one in-turn validator owns `TurnLength` consecutive slots
- with the current defaults:
  - `PeriodMs = 360`
  - `TurnLength = 16`
  - `TurnGroupDurationMs = 5760`

## Design Principles

GTOS validator operations should follow these principles:

1. **One shared node template, many per-node overrides**
   - `systemd` units should be template-driven
   - node-specific values should live in environment files

2. **Chain configuration is file-based**
   - network-wide behavior should be generated into config files and genesis
   - `ExecStart` should not be the primary source of truth

3. **Validator maintenance must be protocol-aware**
   - a validator should leave block production rotation before the process is
     stopped
   - operational maintenance should map to explicit on-chain state

4. **Validator and RPC/full nodes should be separate roles**
   - validators sign and mine
   - RPC/full nodes do not unlock validator accounts

5. **Operational safety must be explicit**
   - peer readiness
   - signer correctness
   - checkpoint retention constraints
   - finalized head health
   - grouped-turn rotation awareness

## Target Deployment Model

The recommended GTOS validator deployment model has four layers:

1. **Genesis and chain config**
   - network ID
   - DPoS config
   - checkpoint finality config
   - initial validator list

2. **Shared node config file**
   - common RPC modules
   - log behavior
   - sync and retention defaults
   - common P2P defaults

3. **Per-validator environment file**
   - datadir
   - ports
   - validator address
   - password file
   - bootnodes/static peers
   - process-local overrides

4. **Template `systemd` unit**
   - one service definition reused by all validators

## Recommended File Layout

Recommended layout under `/data/gtos`:

```text
/data/gtos/
  genesis.json
  config.toml
  pass.txt
  bootnodes.csv
  validators.csv
  node1/
    validator.env
    validator.address
    keystore/
    gtos/
  node2/
    validator.env
    validator.address
    keystore/
    gtos/
  node3/
    validator.env
    validator.address
    keystore/
    gtos/
```

## Shared Config File

GTOS should adopt a shared configuration file similar in spirit to BSC's
`config.toml`.

This file should contain network-wide defaults that are not validator-identity
specific.

Recommended contents:

- node logging defaults
- HTTP/WS module defaults
- sync mode defaults
- state retention defaults
- P2P defaults
- txpool defaults

This file should not contain:

- validator unlock address
- validator password path
- validator coinbase
- node-specific ports
- node-specific datadir

Those belong in per-node environment files.

## Template `systemd` Unit

Replace per-node hardcoded service files with a single template service:

`/etc/systemd/system/gtos-validator@.service`

The template should:

- load node-specific variables from:
  - `/data/gtos/node%i/validator.env`
- use the shared `config.toml`
- keep process management in one place

Recommended pattern:

```ini
[Unit]
Description=GTOS Validator %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tomi
Group=tomi
WorkingDirectory=/home/tomi/gtos
EnvironmentFile=/data/gtos/node%i/validator.env
ExecStart=/usr/local/bin/gtos \
  --config ${GTOS_CONFIG} \
  --datadir ${GTOS_DATADIR} \
  --networkid ${GTOS_NETWORK_ID} \
  --port ${GTOS_P2P_PORT} \
  --http --http.addr 127.0.0.1 --http.port ${GTOS_HTTP_PORT} \
  --http.api admin,net,web3,tos,dpos,miner \
  --ws --ws.addr 127.0.0.1 --ws.port ${GTOS_WS_PORT} \
  --ws.api net,web3,tos,dpos \
  --authrpc.addr 127.0.0.1 --authrpc.port ${GTOS_AUTHRPC_PORT} \
  --unlock ${GTOS_VALIDATOR_ADDR} \
  --password ${GTOS_PASSFILE} \
  --allow-insecure-unlock \
  --mine \
  --miner.coinbase ${GTOS_VALIDATOR_ADDR} \
  --syncmode ${GTOS_SYNCMODE} \
  ${GTOS_GC_FLAGS} \
  --verbosity ${GTOS_VERBOSITY} \
  --bootnodes ${GTOS_BOOTNODES}
Restart=always
RestartSec=2
LimitNOFILE=1048576
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
```

## Per-Node Environment File

Each validator should have a per-node environment file, for example:

`/data/gtos/node1/validator.env`

```bash
GTOS_CONFIG=/data/gtos/config.toml
GTOS_DATADIR=/data/gtos/node1
GTOS_NETWORK_ID=1666
GTOS_P2P_PORT=30311
GTOS_HTTP_PORT=8545
GTOS_WS_PORT=8645
GTOS_AUTHRPC_PORT=9551
GTOS_VALIDATOR_ADDR=0x...
GTOS_PASSFILE=/data/gtos/pass.txt
GTOS_SYNCMODE=full
GTOS_GC_FLAGS=
GTOS_VERBOSITY=3
GTOS_BOOTNODES=enode://...@127.0.0.1:30311,enode://...@127.0.0.1:30312,enode://...@127.0.0.1:30313
```

This separates:

- node identity and ports
- validator key material and password path
- process-level options

from the shared node configuration.

## Validator Roles

GTOS should distinguish between two node roles:

### Validator

A validator node:

- unlocks its validator account
- runs with `--mine`
- sets `--miner.coinbase`
- participates in DPoS rotation
- may participate in checkpoint finality

### RPC / Full Node

An RPC/full node:

- does not unlock a validator account
- does not run `--mine`
- does not need validator password files
- may keep broader RPC exposure

This role split should be reflected in separate deployment templates.

## Grouped-Turn Operations

Operators must interpret validator health in grouped-turn terms, not simple
per-block round-robin terms.

Normal behavior now includes:

- the same validator producing multiple consecutive blocks inside its owned turn
  group
- no proposer switch until the current `TurnLength` slot group is exhausted

This means alerts and dashboards must not treat "same validator produced several
consecutive blocks" as a fault by itself.

Recommended grouped-turn metrics:

- `turnLength`
- `turnGroupDurationMs = PeriodMs * TurnLength`
- current in-turn validator
- last completed turn group
- missed turn groups, not only missed individual blocks
- unexpected out-of-turn production rate

## Maintenance Mode

GTOS should support a protocol-aware maintenance flow similar in purpose to
BSC Parlia validator maintenance.

### Why Maintenance Mode Is Needed

Stopping a validator process directly is operationally incomplete:

- the chain still considers the validator active
- the validator may continue to be selected in rotation
- missed turns reduce liveness and create noisy operational failures

A safer workflow is:

1. mark the validator as temporarily non-producing on-chain
2. wait until the validator leaves the active producer set
3. stop the process
4. restart the process after maintenance
5. re-enable the validator on-chain

### Proposed On-Chain Actions

Add two validator system actions:

- `VALIDATOR_ENTER_MAINTENANCE`
- `VALIDATOR_EXIT_MAINTENANCE`

And extend validator state:

- `Inactive`
- `Active`
- `Maintenance`

Recommended semantics:

- `Active`
  - validator participates in block production
- `Maintenance`
  - validator keeps stake locked but is excluded from active producer selection
- `Inactive`
  - validator has withdrawn

### DPoS Integration Rule

`ReadActiveValidators` should continue to return only validators whose status is
`Active`.

That keeps maintenance semantics simple:

- no new DPoS selection API is needed
- maintenance automatically excludes the validator from rotation
- epoch and checkpoint validator sets automatically reflect maintenance state

### Effective-Timing Rule

The current GTOS DPoS implementation refreshes the active proposer set at epoch
boundaries through the snapshot path.

Operationally, that means:

- `VALIDATOR_ENTER_MAINTENANCE` updates validator registry state immediately
- the validator is removed from the proposer set when the next epoch snapshot
  takes effect
- `VALIDATOR_EXIT_MAINTENANCE` updates validator registry state immediately
- the validator re-enters the proposer set when the next epoch snapshot takes
  effect

Maintenance mode is therefore protocol-aware, but not instant. Operators must
treat maintenance entry and exit as "next epoch effective" actions.

Grouped turns do not change that rule:

- maintenance still becomes effective at the next epoch snapshot
- before that epoch transition, the validator may still appear to finish normal
  epoch-scoped proposer eligibility
- after the next epoch removes it from the active set, it no longer receives
  future turn groups

### Maintenance Workflow

Recommended operator workflow:

#### Enter maintenance

1. Submit `VALIDATOR_ENTER_MAINTENANCE`
2. Wait until the next epoch snapshot removes the validator from the active
   producer set
3. Confirm that recent blocks are produced by other validators
4. Stop the service

#### Exit maintenance

1. Start the service
2. Wait until the node is healthy:
   - peers connected
   - head caught up
   - finalized head not lagging unexpectedly
3. Submit `VALIDATOR_EXIT_MAINTENANCE`
4. Confirm the validator re-enters the active producer set at the next epoch

### Current Operational Commands

The local testnet script now exposes:

- `enter-maintenance <node>`
- `exit-maintenance <node>`
- `drain <node>`
- `resume <node>`

Suggested meanings:

- `enter-maintenance`
  - ensure signer metadata exists
  - ensure validator registry state exists
  - send the on-chain maintenance transaction
  - report the next epoch at which proposer-set removal takes effect
- `exit-maintenance`
  - ensure signer metadata exists
  - send the on-chain exit transaction
  - report the next epoch at which proposer-set rejoin takes effect when needed
- `drain`
  - enter maintenance, wait until the next epoch removes the validator from the
    active proposer set, then stop service
- `resume`
  - start service, wait for sync, then exit maintenance

Status checks for these commands should always be read together with grouped-turn
context:

- a validator may legitimately produce several consecutive blocks before the next
  proposer takes over
- maintenance success should be measured by epoch-based active-set removal, not
  by an assumption of immediate per-block proposer switching

## Local Testnet Operations

The current local three-node script should remain the main bootstrap tool for
developer and validator testing.

Its role should be narrowed and made explicit.

### Script Responsibilities

The script should:

- create validator accounts
- generate genesis
- generate shared config
- generate per-node env files
- install or update the template `systemd` unit
- initialize node datadirs
- start and stop validator instances
- verify peer connectivity and block growth
- orchestrate maintenance operations

For local validator maintenance, the script now also performs two safety
bootstrap steps when needed:

- auto-submit `ACCOUNT_SET_SIGNER(ed25519)` if the validator account still uses
  default sender fallback semantics
- auto-submit `VALIDATOR_REGISTER` if the local validator exists in genesis
  snapshot rotation but is not yet present in the on-chain validator registry

This is required because maintenance actions operate on validator registry
state, not only on the genesis snapshot validator list.

### Script Should Not Be the Source of Truth for Long-Term Config

The script should generate configuration artifacts, but runtime configuration
should live in files:

- genesis
- config.toml
- validator.env

This avoids a situation where shell logic and live service state drift apart.

## Startup and Peering Requirements

The local script recently hit a real operational bug:

- nodes were started with a genesis timestamp too close to real time
- one validator started mining before others were peered
- isolated validators produced competing block 1 candidates
- the network stalled on competing early branches

The corrected approach is:

- generate genesis with a short future start delay
- start all validator nodes promptly
- connect the peer mesh before expecting block growth

This should remain a required startup invariant for local validator clusters.

## Key Management

GTOS DPoS sealing is now `ed25519-only`.

Operational consequences:

- validator keys must be `ed25519`
- validator setup tooling must default to `ed25519`
- service startup must not silently rely on incompatible signer types

Validator operational checks should include:

- the unlocked account exists
- the keystore entry uses `ed25519`
- the validator address in the service env file matches the expected keystore
- the chain config expects `SealSignerType = ed25519`

## State Retention and Checkpoint Finality

If checkpoint finality is enabled, validator operations must account for state
retention.

### Archive vs Full Mode

- `archive`
  - keeps historical state
  - safest operational mode
- `full`
  - keeps only a bounded recent state window
  - acceptable only if the checkpoint rules fit within the retained window

With the current GTOS assumptions:

- `TriesInMemory = 128`
- QC staleness window = `2 * CheckpointInterval`

then non-archive validator nodes must satisfy:

```text
CheckpointInterval <= 64
```

This is already encoded into the local deployment checks and should remain an
explicit operational invariant.

## Monitoring Requirements

Validator operations should track at least the following:

### Node health

- systemd service state
- process PID
- IPC availability
- HTTP/WS availability

### Network health

- peer count
- current head
- finalized head
- sync lag

### Validator health

- validator address
- validator status:
  - `Active`
  - `Maintenance`
  - `Inactive`
- recent block production
- missed-turn streaks
- missed turn groups
- prolonged absence during owned turn groups

### Finality health

- latest finalized block number
- finalized lag relative to head
- checkpoint QC verification failures

### Operational alerts

- validator service down while validator status is still `Active`
- validator in `Maintenance` for longer than expected
- validator restarted but not re-entered active set
- unexpectedly low peer count
- no recent local block production while validator is `Active`

## Recommended Rollout Plan

### Phase 1: Configuration Cleanup

- introduce shared `config.toml`
- introduce per-node `validator.env`
- introduce `gtos-validator@.service`
- keep current local script as the artifact generator

### Phase 2: Role Separation

- separate validator and RPC/fullnode deployment templates
- stop using unlocked validator accounts on non-validator nodes

### Phase 3: Maintenance Mode

- add `VALIDATOR_ENTER_MAINTENANCE`
- add `VALIDATOR_EXIT_MAINTENANCE`
- update DPoS selection to exclude maintenance validators
- add script support for `drain` and `resume`

Status:

- complete in the current local-validator workflow
- operators must still account for "next epoch effective" timing
- operators must also account for grouped-turn block bursts when evaluating
  proposer rotation

### Phase 4: Monitoring and Runbooks

- add validator health checks
- add finalized-head monitoring
- add maintenance runbook
- add restart and recovery drills

## Non-Goals for v1

This operations plan does not require the following in its first version:

- automatic slashing for maintenance abuse
- maintenance quotas or maintenance scheduling windows
- automatic maintenance expiry
- complex remote signer integration
- BLS-based voting or BSC-style fast finality operations

Those can be added later if needed.

## Summary

The GTOS validator operations model should move from:

- per-node hardcoded `systemd` commands
- shell-driven runtime configuration
- direct stop/start maintenance

to:

- shared config artifacts
- template service deployment
- explicit validator role separation
- on-chain maintenance mode
- operational checks for checkpoint retention and finalized-state health

This gives GTOS a cleaner operational model while staying compatible with the
current DPoS implementation and validator registry design.
