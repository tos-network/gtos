# GTOS Agent & Staking Integration Plan

## Overview

`gtos` is built on go-ethereum v1.10.25. This document describes the plan to integrate the TOS Agent Network capabilities into the gtos node binary, covering:

- **Agent Registration & Discovery**: Regular users run a Python client, register an account, and publish MCP capabilities. gtos nodes serve as Discovery Index Nodes.
- **Node Staking**: gtos node operators must stake a minimum amount of TOS tokens to participate in the network and earn block rewards.
- **Delegation**: TOS token holders can delegate their tokens to gtos nodes, increasing the node's stake weight.
- **Reward Distribution**: Block rewards are split proportionally between node operators and their delegators.

The existing `agentos` codebase (`~/agentos`) already implements agent registration, discovery, and job settlement logic. The staking and delegation layer will be designed and implemented fresh inside gtos.

---

## New Module Structure (inside gtos/)

```
gtos/
├── agent/                      # Agent registration & discovery (ported from agentos/agent)
│   ├── types.go                # AgentRecord, ToolManifest, ToolSpec
│   ├── registry.go             # In-memory capability index + query
│   ├── identity.go             # ed25519 identity (reused from agentos)
│   └── indexer.go              # Consume chain events → update local index
├── staking/                    # Node staking + delegation + rewards (new)
│   ├── types.go                # StakeRecord, DelegationRecord, RewardRecord
│   ├── state.go                # Read/write staking state via StateDB
│   └── reward.go               # Reward calculation and distribution logic
├── sysaction/                  # System Action encode/decode and validation
│   ├── types.go                # Action type constants + payload structs
│   ├── codec.go                # Encode/decode (tx.Data ↔ SysAction)
│   └── executor.go             # Execute system actions inside state_processor
└── internal/agentapi/          # RPC namespaces
    ├── agent_api.go            # agent_* methods
    ├── discover_api.go         # discover_* methods
    └── staking_api.go          # staking_* methods (query stake/delegation/rewards)
```

---

## System Action Design

System actions use a reserved destination address (`SYSTEM_ACTION_ADDRESS = 0x00...00TOS0001`) to distinguish them from ordinary transactions. The `tx.Data` field carries a JSON-encoded payload:

```json
{
  "action": "AGENT_REGISTER",
  "payload": { ... }
}
```

### Action Set (Phase 1)

| Action | Description |
|--------|-------------|
| `AGENT_REGISTER` | Register an agent; payload = AgentRecord + ToolManifest |
| `AGENT_UPDATE` | Update agent capability info |
| `AGENT_HEARTBEAT` | Heartbeat to refresh `expires_at` |
| `NODE_STAKE` | Node operator stakes TOS (`tx.Value` = stake amount) |
| `NODE_UNSTAKE` | Request stake withdrawal (subject to lock period) |
| `DELEGATE` | Token holder delegates to a node (`tx.Value` = delegation amount) |
| `UNDELEGATE` | Cancel delegation |
| `CLAIM_REWARD` | Claim accumulated staking/delegation rewards |

---

## On-Chain State Design (via StateDB)

Two reserved system contract addresses store state using storage slots, similar to how Clique stores signer lists.

### Agent Registry State (address `AGENT_REGISTRY_ADDR`)

```
keccak256(agent_id || "record")   → hash of latest AgentRecord
keccak256(agent_id || "manifest") → hash of latest ToolManifest
keccak256(agent_id || "status")   → uint8 (0=active, 1=jailed, 2=exited)
keccak256(agent_id || "owner")    → address (tx.From of the registration tx)
```

### Staking State (address `STAKING_ADDR`)

```
keccak256(node_addr || "selfStake")       → uint256 (operator's own stake)
keccak256(node_addr || "totalStake")      → uint256 (self + delegated)
keccak256(node_addr || "commission")      → uint16  (commission rate in bps, e.g. 1000 = 10%)
keccak256(node_addr || "status")          → uint8   (active/inactive/jailed)
keccak256(delegator || node_addr || "shares") → uint256 (delegator's share units)
keccak256(node_addr || "rewardPerShare")  → uint256 (cumulative reward per share, scaled 1e18)
keccak256(addr || "pendingReward")        → uint256 (unclaimed reward balance)
```

---

## Reward Model

Block rewards are distributed inside the consensus engine's `Finalize()` hook at each block:

```
blockReward = BASE_BLOCK_REWARD   // configurable, e.g. 2 TOS/block

for each active node:
    nodeShare      = blockReward * nodeStake / totalNetworkStake
    commissionPart = nodeShare * commission / 10000
    delegatorPool  = nodeShare - commissionPart
    rewardPerShare[node] += delegatorPool / totalShares[node]
    pendingReward[nodeOperator] += commissionPart
```

When `CLAIM_REWARD` system action is processed:

```
earned = shares * (rewardPerShare[node] - lastClaimedRewardPerShare[claimant][node])
transfer earned TOS to claimant address
update lastClaimedRewardPerShare
```

Minimum node stake: `MIN_NODE_STAKE = 10_000 TOS` (defined in `params/tos_params.go`).

---

## Integration Points (Existing Files to Modify)

### 1. `go.mod`
Rename module from `github.com/ethereum/go-ethereum` to `github.com/tos-network/gtos`. Update all internal imports accordingly.

### 2. `core/state_processor.go`
In `applyTransaction()`, detect system actions before EVM execution:

```go
if msg.To() != nil && *msg.To() == params.SystemActionAddress {
    return sysaction.Execute(msg, statedb, header, chainConfig)
}
```

### 3. `consensus/ethash/consensus.go` (or new `consensus/tos/`)
In `Finalize()`, after standard uncle/block reward logic, call:

```go
staking.DistributeBlockRewards(statedb, header, chain)
```

### 4. `eth/backend.go`
In `APIs()`, append the new RPC namespaces:

```go
{Namespace: "agent",    Service: agentapi.NewAgentAPI(agentRegistry)},
{Namespace: "discover", Service: agentapi.NewDiscoverAPI(agentRegistry)},
{Namespace: "staking",  Service: agentapi.NewStakingAPI(stakingState, s.APIBackend)},
```

### 5. `cmd/geth/main.go` (or renamed `cmd/gtos/`)
On node startup, initialize and start the agent chain indexer:

```go
agentIndexer := agent.NewIndexer(eth.BlockChain(), agentRegistry)
agentIndexer.Start()
```

### 6. `params/tos_params.go` (new file)
Define TOS-specific constants:

```go
var SystemActionAddress = common.HexToAddress("0x0000000000000000000000000000000000001001")
var AgentRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000001002")
var StakingAddress       = common.HexToAddress("0x0000000000000000000000000000000000001003")

const MinNodeStake     = 10_000e18  // 10,000 TOS in wei units
const BaseBlockReward  = 2e18       // 2 TOS per block
const UnstakeLockBlocks = 50_400    // ~7 days at 12s/block
```

---

## Agent Discovery Flow

```
1. On-chain:   User sends AGENT_REGISTER system tx (from Python client or CLI)
2. Indexer:    Node receives NewChainEvent → scans txs for system action → parses AgentRecord/ToolManifest
3. Local index: Updates in-memory agent registry (reuses agentos agent registry query logic)
4. RPC:        discover_query(category, q, facets) → queries local index → returns AgentRecord[]
```

The full lifecycle for an end user:
```
[Python client] → sign AGENT_REGISTER tx → broadcast to gtos network
                → gtos node includes tx in block
                → all nodes' indexers ingest the event
                → agent becomes discoverable via discover_query RPC
```

---

## RPC Namespaces

### `agent_*`

```
agent_register(manifest ToolManifest) → txHash
    Build and submit AGENT_REGISTER system tx from the caller's account.

agent_getRecord(agentID string) → AgentRecord
    Return the latest on-chain AgentRecord for the given agent ID.

agent_status(agentID string) → string
    Return agent status: "active" | "jailed" | "exited" | "unknown"
```

### `discover_*`

```
discover_query(req QueryRequest) → []AgentRecord
    Search local capability index by category, keyword, and facets.
    QueryRequest mirrors agentos: {category, q, facets, limit, order_by, ...}

discover_resolve(manifestHash string) → ToolManifest
    Fetch full ToolManifest by its hash.
```

### `staking_*`

```
staking_nodeInfo(nodeAddr Address) → StakeRecord
    Return stake record for a node: selfStake, totalStake, commission, status.

staking_delegations(delegatorAddr Address) → []DelegationInfo
    List all delegations for a delegator (node, shares, estimatedReward).

staking_pendingReward(addr Address) → *big.Int
    Return unclaimed reward balance.

staking_claimReward(ctx) → txHash
    Submit CLAIM_REWARD system tx to transfer pending rewards to caller.
```

---

## Reuse from agentos

| Source (agentos) | Target (gtos) | Notes |
|------------------|---------------|-------|
| `agent/types.go` — AgentRecord, ToolManifest, ToolSpec | `gtos/agent/types.go` | Copy directly; adjust import paths |
| `agent/registry.go` — Query, IngestRemoteRecord | `gtos/agent/registry.go` | Keep query/index logic; remove P2P sync |
| `agent/identity.go` — ed25519 sign/verify | `gtos/agent/identity.go` | Copy directly |
| `ledger/settlement.go` — PaymentProof | Stays in agentos | Job escrow settlement stays in agentos; gtos verifies via RPC |

---

## Implementation Order

1. **Rename module** — Update `go.mod` and all internal imports
2. **Add params** — Create `params/tos_params.go` with system addresses and constants
3. **Create `sysaction` package** — Action type constants, JSON codec, validation stubs
4. **Create `agent` package** — Port types/identity from agentos; implement in-memory registry and chain event indexer
5. **Create `staking` package** — StateDB read/write helpers, reward accumulation logic
6. **Modify `state_processor.go`** — Route system action txs to sysaction executor
7. **Modify consensus `Finalize()`** — Add per-block staking reward distribution
8. **Create `internal/agentapi` package** — Implement three RPC namespaces
9. **Modify `eth/backend.go`** — Register new APIs
10. **Modify `cmd/geth` entrypoint** — Wire up agent indexer on startup

---

## Verification

```bash
# Build
cd ~/gtos && go build ./...

# Start dev node with agent/discover/staking APIs enabled
./build/bin/geth --dev --http --http.api agent,discover,staking,eth,net

# Register an agent
curl -s -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"agent_register","params":[{...}],"id":1}'

# Query agents
curl -s -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"discover_query","params":[{"category":"Dev","q":"code review","limit":10}],"id":2}'

# Check node staking info
curl -s -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"staking_nodeInfo","params":["0xYOUR_NODE_ADDR"],"id":3}'
```

---

## Non-Goals (Phase 1)

- Full EVM smart contract platform for agent logic
- Custom EVM opcode modifications
- On-chain discovery/ranking index (ranking stays off-chain)
- Full dispute arbitration workflow (Phase 2)
- Multi-region discovery routing (Phase 3)
