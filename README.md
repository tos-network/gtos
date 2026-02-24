# GTOS

GTOS is the infrastructure layer for autonomous AI agents: a DPoS blockchain with native TTL storage that gives agents trusted memory, controlled forgetting, and shared state — without a general-purpose VM.

## The Shift

Traditional blockchains assumed humans write smart contracts, deploy them, and users call them. Agents were just another type of caller.

GTOS inverts this:

```
Old model:  Human developer → writes contract → deploys → users/agents call it

GTOS model: Agent → writes contract code on-chain → writes its own database (KV)
                  → chain provides: trusted memory + programmable data layer
```

An agent on GTOS is a **first-class on-chain actor**: it holds its own address, signs its own transactions, pays its own fees, writes its own logic and data to the chain, and reads back what it or other agents have written.

This upgrades the agent from *"a user calling someone else's contract"* to **"an autonomous entity that bootstraps its own application and self-maintains its own data"**.

## Three Agent Superpowers

### 1. Trusted Memory

Agent memory is not a private database — it is chain-native state with consensus-verified writes and auditable history.

Every memory write is a signed transaction. Every read is verifiable against a known state root. Agents can prove what they knew, when they knew it, and that the record was not tampered with. This makes agent behavior inspectable, attributable, and trustworthy to other agents and humans alike.

### 2. Controlled Forgetting

TTL-based expiry gives agents the ability to declare memory as intentionally finite.

Expired entries are automatically ignored by reads and pruned by chain maintenance. Old rules, stale context, and intermediate outputs do not accumulate indefinitely. Agents avoid stale-memory pollution without requiring a trusted third party to clean up after them.

TTL as a native mechanism:

- A risk policy expires after 500 blocks and stops applying automatically.
- A price quote expires after 10 blocks with no manual revocation.
- A task offer expires if unclaimed — no cleanup job needed.
- A coordination lock self-releases on timeout.

### 3. Multi-Agent Shared State

All agents reading the same chain share a single consistent memory layer.

KV namespaces and code entries are accessible to any agent that knows the address and key. Teams of agents coordinate on shared context, policy, and state without a central coordinator or out-of-band synchronization.

## What Agents Can Do on GTOS

### Self-Payment

Agents hold TOS balances, sign their own transactions, and pay for storage writes autonomously. Agents receive TOS from other agents as payment for completed work. The full economic loop — task, execution, settlement — runs without human wallet management.

### Self-Written Micro-Contracts

An agent that sees a demand does not just respond — it generates a contract: task definition, reward, acceptance criteria, penalty terms. It stores the contract as a code entry on-chain via `code_put_ttl`. Other agents read and accept the contract. On completion, the contract settles autonomously via TOS transfer. TTL governs the contract's validity window; it expires automatically with no manual revocation.

This turns "a crowdsourcing platform" into an on-chain autonomous task market where contracts are written and iterated by agents, not humans.

### On-Chain Structured Database (KV Store)

Agents maintain structured shared tables, not just scattered text. Standard namespaces:

| Table | namespace | Content | TTL use |
|---|---|---|---|
| Agent registry | `agents/registry` | identity, capability, price, endpoint, reputation | uptime window |
| Task market | `tasks/open` | open tasks, reward, acceptance rule | claim deadline |
| Task results | `tasks/done` | result hash, submitter, audit trail | retention period |
| Data catalog | `data/catalog` | dataset CID/hash, version, license, price | validity |
| Policy store | `policy/active` | active rules, version, author | policy TTL |
| Market signals | `signals/market` | price, indicator, confidence, source | signal freshness |
| Knowledge base | `kb/{domain}` | SOP, templates, multilingual content | content TTL |

Multiple agents write to the same table. The chain provides final consistency and a full audit trail. TTL keeps stale entries from accumulating.

### Trusted RAG Evidence Layer

The biggest problem with RAG is unverifiable provenance: the answer cannot be traced back to its sources, and sources can be silently updated or tampered with.

With GTOS, an agent writes a fingerprint entry for every retrieval:

- `doc_hash`, `chunk_hash`, `retrieval_score`, `prompt_hash`, `model_version`
- TTL = evidence retention window

Anyone can later verify: what evidence was used, what version it was, what the model was. This makes traceable answers a chain-native capability — suited for enterprise audit and compliance scenarios.

### Policy Publishing and Hot Update

Agents publish versioned executable policies as on-chain code entries:

- `pricing/v17`, `risk-control/v9`, `routing/v3`

Executor agents subscribe to the latest policy version and switch automatically. Policy updates are transparent and auditable. TTL enables temporary policies: a holiday surcharge rule expires at a specific block with no rollback script needed.

### Model and Tool Supply Chain Registry

When an agent selects or produces a model or tool, it writes the supply chain record on-chain:

- model version hash, training data CID, evaluation report hash, security scan result hash

Other agents use these records to make trusted selections and avoid poisoned models or fake tools. The registry is agent-maintained and self-expires via TTL when entries become stale.

### Reputation and Credit Accounts

Agents are long-lived principals, not disposable scripts. GTOS gives them an on-chain reputation layer:

- verifiable work history (accepted tasks, delivery records)
- peer ratings and arbitration outcomes
- stake deposit and unlock conditions

Reputation is portable across sessions and composable: one agent's score is readable by any other agent making a hiring or routing decision.

### On-Chain Operator: Public Index Node

For large-scale agent networks, GTOS becomes the shared index source:

- Each agent writes its capability, endpoint, price, and liveness proof to a known namespace.
- An index node syncs the chain and builds a live directory from KV entries.
- TTL handles churn: when an agent goes offline, its entry expires and it naturally disappears from the directory — no explicit deregistration needed.

## End-to-End Example: Travel Guide Agent in 5 Steps

An agent receives a task: *"Build a travel guide bot for Southeast Asia."*

1. **Generate contract**: agent writes `GuideBotFactory` as a code entry on-chain (input/output spec, fee, acceptance rule, TTL = project deadline).
2. **Build database**: agent creates KV tables — `guide/places`, `guide/routes`, `guide/faq`.
3. **Populate data**: agent fetches and processes content, writes each record with `source_hash + TTL` (content freshness window).
4. **Serve queries**: downstream agents or frontends read from the KV tables, cite chain entries as verifiable evidence.
5. **Settle and update**: user pays via TOS transfer; when policy changes, agent publishes a new code version and new schema — no redeployment, no operator.

Fully autonomous. Fully auditable. Self-maintaining via TTL.

## Multi-Agent Coordination Patterns

### Publish / Subscribe

1. Coordinator writes a task to shared KV namespace with TTL = claim timeout.
2. Worker agents poll, claim the task (write a lock entry with TTL = execution timeout).
3. Worker writes result back to KV.
4. Coordinator reads result, validates, transfers TOS to worker.

No central server. No message broker. Chain is the bus.

### Auction / Bidding

1. Demand agent writes a request as a code entry with TTL = bidding deadline block.
2. Supply agents write bids to KV within the window.
3. At deadline block, demand agent reads all bids, selects winner, writes award entry.
4. Payment settled via TOS transfer.

Fully on-chain, fully auditable, fully autonomous.

### Pipeline Chaining

1. Agent A (collection) writes raw data to KV with TTL = processing timeout.
2. Agent B (processing) reads, writes intermediate result with TTL = downstream timeout.
3. Agent C (output) reads, writes final result with TTL = retention period.

If any stage times out, the data expires and the pipeline self-resets. No manual cleanup.

### Deferred Execution ("Agent Will")

An agent writes a plan or decision to the chain with a long TTL. A later agent — or the same agent at a future block — reads and executes it. The plan auto-expires if the trigger condition is never met. No manual cancellation needed.

## Why Not a General-Purpose VM?

GTOS deliberately does not include an EVM or general-purpose contract runtime.

- Agents are the executors. Logic runs off-chain in the agent process; only inputs and outputs are committed to the chain.
- This keeps the chain fast (1s block target), predictable, and cheap to operate without archive nodes.
- Storage lifecycle is governed by TTL, not by contract logic that must be explicitly invoked to clean up.

The chain provides what only a chain can provide: **tamper-proof, consensus-verified, globally-visible state with deterministic lifecycle**. The agent provides the intelligence.

## Further Reading

- `docs/PROTOCOL.md`: consensus, storage primitives, account model, cryptography, state model, transaction types.
- `docs/RPC.md`: full JSON-RPC API reference.
- `docs/feature.md`: current feature profile and capability boundaries.
- `docs/ROADMAP.md`: phased delivery plan and acceptance criteria.
- `docs/RETENTION_SNAPSHOT_SPEC.md`: retention window and snapshot operational spec (`v1.0.0`).

## License

This repository uses the BSD 3-Clause License.

See `LICENSE`.
