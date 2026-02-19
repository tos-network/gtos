# GTOS Agent Integration Plan

## Overview

`gtos` is built on go-ethereum v1.10.25, rebranded under `github.com/tos-network/gtos`. This document describes how the TOS Agent Network capabilities are integrated into the gtos node binary:

- **Agent Registration**: Users (via Python client or CLI) submit `AGENT_REGISTER` system action transactions. gtos nodes process and index these on-chain.
- **Agent Discovery**: gtos nodes maintain an in-memory capability index populated from chain events. Clients query it via RPC.
- **System Action Protocol**: A non-EVM transaction protocol for agent lifecycle operations (and other chain-native actions), routed via a reserved address.

EVM smart contract execution is **not available** in GTOS (removed). All on-chain logic for agent management goes through the system action protocol.

---

## Module Identity

```
Module path:  github.com/tos-network/gtos
Go version:   1.17
Base:         go-ethereum v1.10.25
Consensus:    Tosash (PoW, Ethash-derived), or Clique (PoA for dev/test)
```

---

## Actual Package Structure

### New TOS-Specific Packages

```
gtos/
├── agent/                      # Core agent types + in-memory registry
│   ├── types.go                # AgentRecord, ToolManifest, ToolSpec, Endpoint,
│   │                           #   QueryRequest, QueryResult
│   ├── registry.go             # In-memory capability index: Get, Upsert, Remove, Query
│   ├── handler.go              # System action handler: AGENT_REGISTER, AGENT_UPDATE,
│   │                           #   AGENT_HEARTBEAT → updates registry + StateDB
│   └── hash.go                 # HashManifest() utility
│
├── agentidx/                   # Chain event → registry indexer
│   └── indexer.go              # Subscribes to NewChainEvents, parses AGENT_* system
│                               #   actions from blocks, calls registry.Upsert/Remove
│
├── sysaction/                  # System Action protocol (non-EVM tx processing)
│   ├── types.go                # ActionKind constants, payload structs (AgentRegisterPayload etc.)
│   ├── codec.go                # Encode/decode: tx.Data ↔ SysAction (JSON)
│   └── executor.go             # Dispatch table: routes ActionKind to registered handlers
│
├── params/
│   └── tos_params.go           # TOS system addresses + agent-related constants
│
└── internal/agentapi/          # RPC namespace implementations
    ├── agent_api.go            # agent_* methods
    ├── discover_api.go         # discover_* methods
    └── staking_api.go          # staking_* stub (query only, no write methods here)
```

### Key Existing Packages (Modified)

```
gtos/
├── core/
│   └── state_processor.go     # Routes system action txs to sysaction.Execute()
├── consensus/
│   ├── tosash/                 # Tosash PoW engine (Finalize distributes block rewards)
│   └── clique/                 # PoA engine for dev/test
├── tos/
│   ├── backend.go              # Creates agentRegistry + agentIndexer; registers APIs
│   └── tosconfig/config.go     # CreateConsensusEngine() → Tosash or Clique
└── cmd/gtos/                   # CLI entrypoint (starts node, wires agent indexer)
```

---

## System Action Protocol

Transactions sent to `params.SystemActionAddress` bypass EVM execution. `tx.Data` carries a JSON payload:

```json
{
  "action": "AGENT_REGISTER",
  "payload": { ... }
}
```

**Reserved addresses** (defined in `params/tos_params.go`):

```go
SystemActionAddress  = common.HexToAddress("0x0000000000000000000000000000000054534F31") // "TOS1"
AgentRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000054534F32") // "TOS2"
```

**Fixed gas cost:** `SysActionGas = 100_000` (no EVM gas metering needed).

### Agent Action Set

| Action | Description |
|--------|-------------|
| `AGENT_REGISTER` | Register a new agent; payload = AgentRecord + ToolManifest |
| `AGENT_UPDATE` | Update agent capability info or endpoints |
| `AGENT_HEARTBEAT` | Refresh `expires_at`; signals agent is still active |

---

## On-Chain Agent State (via StateDB)

Agent state is stored as storage slots under `AgentRegistryAddress`, using `keccak256`-derived keys:

```
keccak256(agent_id || "record")   → hash of latest AgentRecord (bytes32)
keccak256(agent_id || "manifest") → hash of latest ToolManifest (bytes32)
keccak256(agent_id || "status")   → uint8  (0=active, 1=jailed, 2=exited)
keccak256(agent_id || "owner")    → address (tx.From of the registration tx)
```

Full record and manifest content is stored off-chain (IPFS or embedded in tx.Data) and referenced by hash on-chain.

---

## Agent Discovery Flow

```
1. On-chain:     User sends AGENT_REGISTER system tx
                 (from Python client or gtos CLI)

2. Processing:   state_processor detects tx.To == SystemActionAddress
                 → calls sysaction.Execute(msg, statedb, header)
                 → routes to agent.Handler
                 → writes record/manifest hashes to AgentRegistryAddress slots

3. Indexing:     agentidx.Indexer receives NewChainEvent
                 → scans block txs for AGENT_* system actions
                 → parses AgentRecord + ToolManifest from tx.Data
                 → calls agentRegistry.Upsert(record)

4. Discovery:    Client calls discover_query via RPC
                 → queries in-memory agentRegistry
                 → returns []AgentRecord matching filters
```

Full lifecycle from user perspective:

```
[Python client]
  → build AGENT_REGISTER payload (AgentRecord + ToolManifest)
  → sign tx with account key, tx.To = SystemActionAddress
  → broadcast to gtos network
    → node includes tx in block
    → all nodes' indexers ingest the event
    → agent becomes discoverable via discover_query
```

---

## RPC Namespaces

Both namespaces are registered in `tos/backend.go → APIs()` and exposed over IPC, HTTP, and WebSocket.

### `agent_*`

```
agent_getRecord(agentID string) → AgentRecord
    Return the latest indexed AgentRecord for the given agent ID.

agent_status(agentID string) → string
    Return agent status: "active" | "jailed" | "exited" | "unknown"
```

### `discover_*`

```
discover_query(req QueryRequest) → []AgentRecord
    Search in-memory capability index.
    QueryRequest fields: category, q (keyword), facets, limit, order_by

discover_resolve(agentID string) → ToolManifest
    Return full ToolManifest for the given agent ID.
```

---

## Integration Points

### 1. `core/state_processor.go`

System action detection in `applyTransaction()`:

```go
if msg.To() != nil && *msg.To() == params.SystemActionAddress {
    return sysaction.Execute(msg, statedb, header, chainConfig)
}
```

### 2. `consensus/tosash/consensus.go` — `Finalize()`

Block finalization currently distributes standard Tosash block rewards. Future: hook for additional per-block logic.

### 3. `tos/backend.go` — `APIs()`

Agent and discovery RPC namespaces are registered here:

```go
{Namespace: "agent",    Version: "1.0", Service: agentapi.NewAgentAPI(s.agentRegistry)},
{Namespace: "discover", Version: "1.0", Service: agentapi.NewDiscoverAPI(s.agentRegistry)},
```

### 4. `tos/backend.go` — Constructor

Agent indexer is started when the TOS backend initializes:

```go
s.agentRegistry = agent.NewRegistry()
s.agentIndexer  = agentidx.NewIndexer(s.blockchain, s.agentRegistry)
s.agentIndexer.Start()
```

### 5. `params/tos_params.go`

TOS-specific constants (already implemented):

```go
var SystemActionAddress  = common.HexToAddress("0x0000000000000000000000000000000054534F31")
var AgentRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000054534F32")

const SysActionGas = 100_000
```

---

## Reuse from agentos

| Source (`~/agentos`) | Target (`gtos`) | Status |
|----------------------|-----------------|--------|
| `agent/types.go` — AgentRecord, ToolManifest, ToolSpec | `gtos/agent/types.go` | Ported; import paths updated |
| `agent/registry.go` — Query, Upsert logic | `gtos/agent/registry.go` | Ported; P2P sync removed |
| `agent/identity.go` — ed25519 sign/verify | `gtos/agent/identity.go` | Ported directly |
| `ledger/settlement.go` — PaymentProof | Stays in agentos | Escrow settlement remains in agentos; gtos verifies via RPC |

---

## Verification

```bash
# Build
cd ~/gtos && go build ./...

# Start dev node with agent and discover APIs
./build/bin/gtos --dev --http --http.api agent,discover,tos,net

# Register an agent
curl -s -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "agent_getRecord",
    "params": ["<agent_id>"],
    "id": 1
  }'

# Query agents by capability
curl -s -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "discover_query",
    "params": [{"category": "Dev", "q": "code review", "limit": 10}],
    "id": 2
  }'

# Run tests
go test ./agent/... ./agentidx/... ./sysaction/... ./internal/agentapi/...
```

---

## Non-Goals (Phase 1)

- EVM smart contract execution (removed from GTOS)
- On-chain ranking index (ranking stays in-memory, off-chain)
- Full dispute arbitration workflow
- Multi-region discovery routing
- Node staking and delegation (designed separately)
