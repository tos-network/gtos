# GTOS Agent Integration Design (Based on geth v1.10.25)

## 1. Goal

Build `gtos` as a unified node stack based on `geth v1.10.25`:

- Reuse geth as the deterministic chain core (accounts, transfer, consensus, replay).
- Integrate key `tosd` capabilities into the same node process.
- Expose Agent-facing control and discovery APIs (including MCP extensions).

This means we do **not** run a separate `tosd + geth` pair per node. Instead, each node runs one `gtos` binary with chain + agent capabilities.

## 2. Core Idea

`gtos` is split into three planes:

1. Chain Core Plane
- account balance state
- token transfer
- consensus/finality
- deterministic execution of system actions

2. Agent Control Plane
- agent registration / update / status
- capability metadata publication
- agent governance actions (challenge/slash/jail/release)

3. Discovery & Query Plane
- fast local capability index
- agent search and filtering
- MCP API extensions for external agent clients

## 3. On-chain vs Off-chain Boundary

On-chain (must be globally consistent):
- agent identity root facts (agent_id, owner, status)
- penalties and governance state (challenged/slashed/jailed)
- settlement facts (escrow/challenge/release/refund outcomes)
- account balances and transfer states

Off-chain (optimized for performance):
- high-frequency capability index and search
- ranking heuristics and query cache
- network gossip hints for discovery fanout

Rule:
- Discovery results must be filtered by latest on-chain status (e.g. jailed agents are excluded).

## 4. System Action Set (Restricted Execution Engine)

Instead of custom EVM opcodes, use restricted "system actions" handled by deterministic execution logic:

- `AGENT_REGISTER`
- `AGENT_UPDATE`
- `AGENT_HEARTBEAT`
- `ESCROW_OPEN`
- `ESCROW_RELEASE`
- `ESCROW_REFUND`
- `CHALLENGE_OPEN`
- `CHALLENGE_RESOLVE`
- `SLASH`
- `JAIL`
- `UNJAIL`

Encoding pattern (MVP):
- special destination address (system executor)
- typed action payload in tx data
- strict validation and replay-safe state transitions

## 5. MCP/RPC Extension

Add dedicated RPC namespaces in `gtos`:

- `agent_*`:
  - register/update/query agent profile
  - query on-chain agent status

- `discover_*`:
  - search by category/tool/capability
  - region/tier/latency aware filtering

- `mcp_*`:
  - lightweight MCP-oriented discovery and invocation bootstrap

- `governance_*`:
  - signed governance actions for challenge/slash/jail/release

Compatibility:
- keep existing `eth_*`, `net_*`, `web3_*` intact.

## 6. Determinism and Safety Requirements

- all system actions are pure state transitions under consensus rules
- no wall-clock-dependent behavior in execution path
- strict nonce/replay protection
- auditable event trail for every penalty/settlement transition
- invalid transitions must fail deterministically on all nodes

## 7. Execution Flow (High Level)

1. Agent sends `AGENT_REGISTER` system tx.
2. Block inclusion updates canonical agent registry state.
3. Discovery indexer consumes chain events and updates local search index.
4. Query API returns candidate agents after status/policy gating.
5. Job settlement and disputes emit system actions (`ESCROW_*`, `CHALLENGE_*`, `SLASH/JAIL`).
6. Governance/audit APIs can inspect full transition history.

## 8. Migration Plan

Phase 1 (MVP)
- transfer + balances + basic agent registration
- read-only discovery index over chain events
- minimal MCP query endpoints

Phase 2
- escrow/challenge system actions
- PoI-linked slashing/jail state transitions
- signed governance endpoint set

Phase 3
- performance hardening (query cache/sharding)
- multi-region discovery routing
- benchmark and SLO gates

## 9. Non-goals (for initial version)

- full general-purpose smart contract platform for agent logic
- custom EVM opcode modifications
- putting all discovery/ranking logic directly on-chain

## 10. Why This Design

Benefits:
- single-node operational model (`gtos` only)
- deterministic shared state for balances and governance
- high-performance discovery kept off-chain but chain-verified
- clear upgrade path from current `tosd` architecture

Tradeoff:
- higher node complexity than pure geth
- requires careful module boundaries to avoid long-term fork-maintenance burden

## 11. Next Implementation Deliverables

1. define `gtos` internal module boundaries (`chaincore`, `agentcore`, `discovery`, `mcpapi`)
2. specify system action tx schema and validation rules
3. implement event indexer: chain events -> local capability index
4. expose initial RPC endpoints (`agent_*`, `discover_*`, `mcp_*`)
5. add integration tests for registration/discovery/challenge/slash/jail flows

