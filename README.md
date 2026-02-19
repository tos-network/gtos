# GTOS (Chain + TOS Agent Network)

GTOS is a unified node implementation for TOS Network.

Its goal is to combine two capability sets in a single node process:

- Blockchain core: account balances, transfers, consensus, deterministic state execution
- Agent network: agent registration, capability discovery, MCP extensions, and challenge/escrow/slash/jail governance

The GTOS direction is not "run multiple stacked daemons on every machine". Instead, each machine runs one `gtos` node that provides both chain and agent control-plane capabilities.

## Vision

GTOS is intended to be the chain and collaboration substrate for TOS Network:

1. Use on-chain state to keep balances and governance outcomes globally consistent.
2. Use off-chain indexing for high-performance capability search and routing.
3. Support business-critical agent actions via a restricted execution engine.
4. Provide a unified access layer for upper agents through MCP/RPC extensions.

## Current Status

Current repository status:

- Chain-core baseline has been imported.
- GTOS integration design document has been added.
- Restricted execution engine and full agent control-plane integration are planned next phases (not fully implemented yet).

Design document:

- `docs/gtos-agent-integration-design.md`

## Target Architecture

GTOS is planned as three planes:

1. Chain Core Plane
- accounts and transfers
- consensus and finality
- deterministic system-action execution

2. Agent Control Plane
- agent register/update/status
- governance actions (challenge/slash/jail/release)
- settlement-critical states (escrow/challenge/release/refund)

3. Discovery & Query Plane
- capability indexing
- capability search and filtering
- MCP extension interfaces

Boundary principle:

- On-chain: facts and constraints (balances, identity, penalties, settlement)
- Off-chain: high-frequency search and ranking (must still be constrained by on-chain status)

## Restricted Execution Engine (Planned)

GTOS plans to use restricted "system actions" instead of custom EVM opcodes.

Planned MVP action set:

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

## Build (Baseline)

You can currently build the full tool suite:

```bash
make all
```

> Note: these commands reflect the current chain-core baseline phase. GTOS-specific subcommands and Agent/RPC extensions will be added in later iterations.

## Roadmap (Short)

1. Define internal GTOS module boundaries (`chaincore`, `agentcore`, `discovery`, `mcpapi`).
2. Define system-action transaction schema and state-machine validation.
3. Implement event indexing pipeline: chain events -> capability index.
4. Add RPC namespaces: `agent_*`, `discover_*`, `mcp_*`.
5. Add integrated tests for register/discover/challenge/slash/jail flows.

## Development Notes

- This repository uses a v1.10.25 chain-core baseline; all changes should prioritize determinism and consensus safety.
- Advanced discovery/ranking logic should stay in the off-chain indexing layer, not in consensus-critical execution.
- Governance and penalty actions must emit auditable transition events.

## License

This repository follows the current licensing model:

- Library code (outside `cmd`): LGPL-3.0 (`COPYING.LESSER`)
- Binary-related code (inside `cmd`): GPL-3.0 (`COPYING`)
