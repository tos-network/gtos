# Agent Discovery v1

Status: Draft  
Audience: agent runtime authors, GTOS networking, service operators, agent developers

## 1. Summary

Agent Discovery v1 is an application-layer discovery profile built on top of discv5,
ENR, and optional identity/payment primitives.

Its purpose is to let agents discover other online agents with specific capabilities,
verify basic identity and policy information, and connect to them for paid or
sponsored work.

Examples:

- find an agent that can resolve an oracle query
- find an agent that can perform an observation job
- find an agent that can provide a constrained bootstrap top-up

This protocol does not replace discv5. It is a profile over the existing discovery
transport already present in GTOS and reusable by any agent application.

## 2. Goals

- Discover live agents without requiring a centralized control plane
- Support capability-oriented search
- Keep discovery metadata small enough for ENR and TALKREQ
- Bind discovered agents to verifiable identities and invocation endpoints
- Support both paid services and tightly constrained sponsor-style services

## 3. Non-Goals

- Replacing GTOS peer discovery
- Storing full capability metadata inside ENR
- Building a full decentralized reputation market in v1
- Supporting arbitrary anonymous "free money" requests
- Proving capability claims cryptographically in v1

## 4. Design Principles

### 4.1 Layering

Agent Discovery v1 separates four concerns:

- Discovery plane: discv5 and ENR
- Metadata plane: signed Agent Card
- Trust plane: identity, optional registry, optional reputation
- Settlement plane: optional payment or sponsor policies

### 4.2 Minimal ENR, Rich Signed Metadata

ENR should only carry compact discovery hints. Rich metadata belongs in a signed Agent
Card fetched after discovery.

### 4.3 Capability Search, Not Just Peer Search

The protocol is optimized for "find an agent that can do X", not only "find any node".

### 4.4 Sponsor Capabilities Must Be Constrained

An agent advertising a sponsor or top-up capability must expose policy, quota, and
rate limits. V1 does not support unrestricted free-token distribution.

## 5. Roles

- Requester: the agent searching for a capability
- Provider: the agent offering a capability
- Directory agent: an optional agent that indexes capability claims and returns
  candidate providers
- Bootstrap node: a discv5 bootnode used only to join the discovery network

## 6. Identity Model

Each provider in v1 has:

- a discv5 node identity for network discovery
- a metadata signing key for Agent Card signatures
- zero or more settlement identities, such as a TOS wallet address

V1 recommendation:

- one provider process advertises one primary settlement identity
- one provider process exposes one signed Agent Card

This keeps the first version simple. Multi-wallet or multi-tenant providers can be
added later.

## 7. Discovery Transport

Agent Discovery v1 uses the existing GTOS discv5 implementation as the base transport.

Relevant GTOS components:

- `p2p/discover/v5_udp.go`
- `p2p/server.go`
- `cmd/utils/flags.go`

The profile does not require a GTOS hard fork. It can be implemented by any agent
runtime or service running on top of the current stack.

## 8. ENR Profile

Each provider implementing Agent Discovery v1 SHOULD publish the following ENR
entries.

| Key | Type | Meaning |
| --- | --- | --- |
| `agv` | `u16` | Agent Discovery profile version. V1 value is `1`. |
| `aga` | `bytes32` | Primary settlement identity or canonical agent address. |
| `agm` | `u8` | Supported connection modes bitset. |
| `agb` | `bytes32` | 256-bit capability bloom filter. |
| `ags` | `u64` | Optional Agent Card sequence number. |

Connection mode bits for `agm`:

- `0x01`: supports discv5 `TALKREQ` metadata exchange
- `0x02`: supports HTTPS endpoint invocation
- `0x04`: supports WebSocket or streaming endpoint invocation

Notes:

- ENR MUST NOT contain full capability documents
- ENR MUST NOT contain full pricing tables
- ENR MAY omit `ags` if sequence tracking is not implemented

## 9. Capability Naming

Capabilities are canonical lowercase strings using dot-separated segments.

Examples:

- `oracle.resolve`
- `observation.once`
- `observation.window`
- `sponsor.topup.testnet`
- `directory.search`

Rules:

- lowercase ASCII only
- allowed characters: `a-z`, `0-9`, `.`, `-`, `_`
- names SHOULD be stable and human-readable

The capability bloom filter in `agb` is constructed from these canonical names.

## 10. Capability Bloom Filter

Because ENR is small, V1 uses a 256-bit bloom filter instead of embedding capability
names directly.

Bloom construction:

1. Normalize the capability name to canonical lowercase form
2. Compute `keccak256(capability_name)`
3. Use the first three 16-bit words modulo 256 as bit positions
4. Set those three bits in the bloom

Implications:

- false positives are acceptable
- false negatives are not acceptable if encoding is correct
- a requester MUST fetch and verify the Agent Card before trusting a match

## 11. Agent Card

After finding a candidate ENR, the requester fetches a signed Agent Card.

The Agent Card is the primary metadata object for Agent Discovery v1.

Suggested canonical JSON shape:

```json
{
  "version": 1,
  "agent_id": "0x...",
  "primary_identity": {
    "kind": "tos",
    "value": "0x..."
  },
  "discovery_node_id": "enode://...",
  "card_seq": 7,
  "issued_at": 1770000000,
  "expires_at": 1770003600,
  "display_name": "Sponsor Node A",
  "endpoints": [
    {
      "kind": "https",
      "url": "https://agent.example.com"
    }
  ],
  "capabilities": [
    {
      "name": "sponsor.topup.testnet",
      "mode": "sponsored",
      "policy_ref": "https://agent.example.com/policies/topup-v1.json",
      "rate_limit": "1/day",
      "max_amount": "10000000000000000"
    },
    {
      "name": "oracle.resolve",
      "mode": "paid",
      "price_model": "x402-exact"
    }
  ],
  "reputation_refs": [],
  "signature": "0x..."
}
```

Agent Card requirements:

- MUST be signed by the provider's metadata signing key
- MUST include at least one identity usable for settlement or attribution
- MUST include expiry
- MUST include at least one supported endpoint or TALKREQ-only mode
- SHOULD include a sequence number for refresh logic

## 12. Metadata Exchange Protocol

V1 defines a small metadata exchange protocol over discv5 `TALKREQ`.

Protocol name:

```text
agent/discovery/1
```

Suggested message set:

- `PING`
- `PONG`
- `GET_CARD`
- `CARD`
- `SEARCH`
- `RESULTS`
- `ERROR`

Suggested encoding:

- CBOR or canonical JSON

V1 implementation guidance:

- `GET_CARD` and `CARD` are required
- `SEARCH` and `RESULTS` are optional and only required for directory agents

## 13. Direct Discovery Flow

Direct discovery is the default flow.

1. Requester joins the discovery network using known bootnodes
2. Requester iterates candidate nodes via discv5 lookup or random iteration
3. Requester filters candidates whose ENR contains `agv=1`
4. Requester tests the candidate capability against `agb`
5. Requester sends `GET_CARD`
6. Provider returns `CARD`
7. Requester verifies signature, expiry, identities, and capability policy
8. Requester connects to the provider endpoint
9. Requester invokes the capability using the provider's declared paid or sponsor flow

## 14. Directory-Assisted Discovery Flow

V1 also allows optional directory agents.

A directory agent advertises:

- capability `directory.search`
- an index of recent Agent Cards or provider summaries

Directory search flow:

1. Requester discovers a directory agent
2. Requester sends `SEARCH` with capability constraints
3. Directory agent returns candidate summaries or ENRs
4. Requester still fetches each provider's Agent Card directly
5. Requester never treats directory output as final truth

Directory agents improve search efficiency but do not replace provider verification.

## 15. Service Invocation

Discovery only finds providers. Actual service invocation happens over a provider
endpoint or another higher-level session transport.

V1 recommended invocation methods:

- HTTPS endpoint with optional x402
- WebSocket endpoint for streaming or long-running tasks
- TALKREQ-only invocation for small metadata operations

V1 recommendation:

- use `TALKREQ` for metadata
- use HTTPS for paid or sponsored service calls
- bind payment semantics separately from discovery semantics

## 16. Paid vs Sponsored Capabilities

Each capability in an Agent Card declares one of these modes:

- `paid`
- `sponsored`
- `hybrid`

### 16.1 Paid

The provider exposes:

- accepted payment method
- price model
- endpoint

GTOS recommendation:

- use x402 exact payment with TOS-native settlement where appropriate

### 16.2 Sponsored

The provider exposes:

- eligibility policy
- quota
- cooldown
- max payout or subsidy amount

Examples:

- one-time bootstrap top-up
- testnet faucet
- approved campaign airdrop

### 16.3 Hybrid

The provider may sponsor some requests and charge for others depending on policy.

## 17. Top-Up and Airdrop Use Case

The example "find an agent that can give me some tokens" should be modeled as a
constrained sponsor capability, not a generic free-transfer capability.

Recommended capability names:

- `sponsor.topup.testnet`
- `sponsor.bootstrap`
- `airdrop.campaign.<campaign_id>`

Required controls:

- per-requester quota
- cooldown
- replay protection
- policy disclosure
- optional allowlist or reputation threshold
- optional proof that the requester is itself a valid registered agent

## 18. Verification Rules

Before trusting a discovered capability, the requester SHOULD verify:

- the ENR advertises `agv=1`
- the Agent Card signature is valid
- the Agent Card is not expired
- the Agent Card capability list contains the requested capability
- the Agent Card identity fields match the expected settlement or attribution identity
- the provider endpoint speaks the declared mode

Optional additional checks:

- on-chain agent registry entry
- capability registry membership
- reputation score
- stake or bond

## 19. Security Considerations

### 19.1 Capability Claims Are Not Truth by Themselves

Discovery only provides candidate providers. Capability claims are self-asserted until
checked against signature, policy, reputation, or actual service behavior.

### 19.2 Sybil Resistance

V1 discovery itself is Sybil-sensitive. Mitigations should come from:

- identity binding
- reputation
- stake or bond
- sponsor quotas
- optional directory curation

### 19.3 ENR Privacy

Do not place sensitive policy or private endpoint details in ENR.

### 19.4 Sponsor Abuse

Never expose a completely unrestricted "send me tokens" capability.

### 19.5 Replay and Duplicate Invocation

Sponsored or paid flows must bind requests to:

- requester identity
- nonce
- capability name
- expiry

## 20. Minimal V1 Implementation Scope

A realistic V1 should implement only:

- ENR entries `agv`, `aga`, `agm`, `agb`
- `GET_CARD` and `CARD` over `TALKREQ`
- signed Agent Card verification
- HTTPS invocation for paid capabilities
- one sponsor capability example such as `sponsor.topup.testnet`

This is enough to make agent-to-agent capability discovery real without requiring a new
base networking protocol.

## 21. Suggested Rollout

### Phase A

- publish bootnodes
- add ENR Agent Discovery entries
- implement Agent Card signing and fetch

### Phase B

- add capability invocation flows
- add one paid capability example
- add one sponsored capability example

### Phase C

- add directory agents
- add registry and reputation hooks
- add richer capability indexing and policy references

### Phase C.1

- treat the current V1 implementation as the discovery and invocation baseline
- keep the transport unchanged:
  - discv5
  - ENR
  - TALKREQ metadata exchange
  - signed Agent Card
- focus all post-V1 work on provider selection quality rather than replacing the
  discovery transport

## 21A. GTOS Primitive Status

The next implementation steps do not require GTOS to invent a new agent identity
stack. GTOS already provides the core primitives needed for post-V1 trust hooks:

- `AgentRegistry`
  - registration status
  - suspended status
  - locked stake
- `CapabilityRegistry`
  - capability name to bit mapping
  - per-agent capability bitmap
- `ReputationHub`
  - cumulative score
  - rating count
- LVM and native read paths for these values

This means the post-V1 roadmap is primarily about integrating existing GTOS
primitives into:

- requester-side filtering
- requester-side ranking
- directory agent ranking and curation

rather than building a brand new registry layer from scratch.

## 21B. Post-V1 Implementation Roadmap

The most practical next steps are listed below in the recommended order.

### Phase D. Registry-Aware Filtering

Goal:

- exclude providers that should not be treated as eligible candidates at all

Mechanics:

- before accepting a provider candidate, the requester or directory checks:
  - provider is a registered agent
  - provider is not suspended
  - provider stake is above a configured minimum

Recommended GTOS data sources:

- `tos.agentload(addr, "is_registered")`
- `tos.agentload(addr, "suspended")`
- `tos.agentload(addr, "stake")`

Implementation guidance:

- start with requester-side filtering in OpenFox or another runtime
- then add the same checks to directory agent ranking
- make these checks configurable per capability class

Recommended defaults:

- `sponsor.*`:
  - registered
  - not suspended
  - non-zero minimum stake
- `observation.*`:
  - registered
  - not suspended
  - stronger minimum stake than sponsor
- `oracle.*`:
  - registered
  - not suspended
  - highest minimum stake of the three

Expected outcome:

- unregistered or suspended providers no longer surface as normal candidates
- basic Sybil resistance improves without changing the transport

### Phase E. Capability Registry Hook

Goal:

- verify that a provider not only claims a capability in its Agent Card, but
  also holds the corresponding on-chain capability bit

Mechanics:

1. resolve the capability name to a capability bit
2. check the provider capability bitmap
3. require both:
   - card claim
   - on-chain capability membership

Recommended GTOS data sources:

- `tos.capabilitybit(name)`
- `tos.agentload(addr, "capabilities")`
- optional native helper methods returning the full bitmap

Implementation guidance:

- start with a soft mode:
  - if the capability is registered on-chain, prefer providers that hold the bit
- move to strict mode for higher-value capability families:
  - `oracle.*`
  - `kyc.*`
  - sponsored distribution capabilities with spending risk

Recommended policy modes:

- `off`
  - trust only the Agent Card
- `prefer_onchain`
  - rank on-chain-capable providers higher
- `require_onchain`
  - reject candidates without the on-chain capability bit

Expected outcome:

- capability spoofing becomes materially harder
- capability assignment can be governed separately from discovery

### Phase F. Reputation-Aware Ranking

Goal:

- improve provider selection quality using service history instead of only live
  availability

Mechanics:

- pull:
  - total reputation score
  - rating count
- compute a local ranking score
- prefer providers with:
  - higher score
  - higher rating count
  - lower failure rate or timeout rate if available locally

Recommended GTOS data sources:

- `tos.agentload(addr, "reputation")`
- `tos.agentload(addr, "rating_count")`

Implementation guidance:

- requester and directory agents should both support local ranking formulas
- the formula does not need to be consensus-critical
- start simple:

```text
rank_score = weighted(service_mode, max_amount, onchain_registration, reputation, rating_count)
```

Suggested guardrails:

- do not over-trust a high raw score with low sample count
- use rating count as a confidence term
- prefer coarse thresholding first, sophisticated ranking second

Expected outcome:

- search results become more useful in practice
- stable providers are selected more often than noisy providers

### Phase G. Stake and Bond Policy by Capability Class

Goal:

- give higher-risk capabilities stronger economic requirements

Mechanics:

- define per-capability-family minimum stake or bond thresholds
- apply them during candidate filtering
- optionally expose them in directory metadata or policy references

Recommended policy examples:

- `sponsor.topup.testnet`
  - low but non-zero minimum stake
- `observation.once`
  - medium minimum stake
- `oracle.resolve`
  - higher minimum stake or a dedicated bond

Important distinction:

- GTOS already has a base `AgentMinStake`
- post-V1 discovery should add capability-specific thresholds on top of that

Expected outcome:

- sponsor and oracle providers become more expensive to fake at scale
- the same agent registry can support different trust levels by capability class

### Phase H. Directory Ranking and Summary Output

Goal:

- make directory agents useful without turning them into a source of truth

Mechanics:

- directory agents collect recent provider cards and GTOS trust signals
- directory `RESULTS` should return:
  - provider identity summary
  - capability match
  - optional ranking explanation
  - optional freshness indicators

Recommended summary fields:

- node id
- primary identity
- advertised capability
- card sequence
- registration status
- suspended flag
- stake bucket
- reputation bucket
- local rank reason

Implementation guidance:

- requester must still fetch the provider card directly
- directory output remains advisory
- directory ranking policies can differ across operators

Expected outcome:

- better search UX
- lower requester cost
- faster provider selection

### Phase I. Policy References and Provider Scoring Feedback

Goal:

- connect invocation outcomes back into discovery quality

Mechanics:

- requester records:
  - success
  - failure
  - timeout
  - malformed response
  - sponsor abuse
- requester or operator may:
  - update local provider scores
  - submit reputation updates through GTOS-native reputation flows

Recommended first step:

- maintain local runtime scoring before making scoring globally visible

Recommended second step:

- authorize specific scorers for capability families
- submit signed or policy-controlled reputation updates on-chain

Expected outcome:

- discovery ranking improves over time
- reputation becomes tied to real service behavior, not just self-asserted claims

## 21C. Concrete Post-V1 Deliverables

The first concrete deliverables after V1 should be:

1. requester-side registry and suspension filtering
2. requester-side capability-bit verification
3. requester-side reputation-aware ranking
4. directory result summaries that expose registration, stake, and reputation buckets
5. one capability-family policy profile for each of:
   - `sponsor.*`
   - `observation.*`
   - `oracle.*`

This keeps the work grounded in GTOS features that already exist today.

## 22. Final Position

Agent Discovery v1 should be treated as:

- a discv5-based discovery profile for agents
- capability-oriented
- identity-aware
- payment-compatible but not payment-specific
- reusable across multiple agent applications

It should not be treated as a replacement for GTOS node discovery itself.

## 23. Example: OpenFox Testnet Faucet Flow

This section shows how an agent application such as OpenFox can use Agent
Discovery v1 without changing the protocol itself.

### 23.1 Local Preconditions

OpenFox already maintains:

- a local wallet in `~/.openfox/wallet.json`
- a derived TOS address
- TOS RPC connectivity for balance checks and receipt tracking
- HTTPS and `x402` request capability for paid services

In other words, OpenFox already has the minimum local identity and payment
surface needed to act as a requester.

### 23.2 User Intent

The creator asks OpenFox for a faucet-style bootstrap top-up.

Example user-facing intents:

- `Get me a small testnet faucet top-up`
- `Find a faucet agent and top up my TOS wallet`

An application MAY expose this through a shortcut such as `/faucet`, but the
discovery protocol does not depend on any specific command syntax.

### 23.3 Intent to Capability Mapping

OpenFox translates the user intent into a capability query.

Recommended capability for this flow:

```text
sponsor.topup.testnet
```

This is intentionally narrower than a generic "airdrop" concept. The provider is
not advertising arbitrary free transfers. It is advertising a constrained sponsor
capability with explicit policy and quota.

### 23.4 Discovery Step

OpenFox runs the Agent Discovery flow:

1. join the discovery network through known bootnodes
2. iterate candidate ENRs via discv5
3. keep nodes where `agv=1`
4. test the candidate capability against `agb`
5. fetch the Agent Card using `GET_CARD`
6. verify signature, expiry, identity fields, and endpoint metadata

At this stage, OpenFox has a shortlist of faucet-capable provider agents.

### 23.5 Provider Selection

OpenFox then filters candidate providers using local policy.

Typical selection criteria:

- capability list contains `sponsor.topup.testnet`
- endpoint kind is `https`
- policy advertises a reasonable quota and cooldown
- provider identity matches expected settlement network
- provider reputation or allowlist passes local policy

For example, OpenFox may prefer:

- a provider with a short cooldown
- a provider with higher reputation
- a provider whose max amount is sufficient for bootstrap use

### 23.6 Invocation Request

After choosing `AgentA`, OpenFox sends an invocation request to the provider
endpoint.

Suggested request shape:

```json
{
  "capability": "sponsor.topup.testnet",
  "requester": {
    "agent_id": "0xRequesterAgent",
    "identity": {
      "kind": "tos",
      "value": "0xRequesterTOSAddress"
    }
  },
  "request_nonce": "7a6f1d4b4a3d4d58b0b1d3e5f0123456",
  "requested_amount": "10000000000000000",
  "reason": "bootstrap openfox wallet"
}
```

The requester identity should match the local OpenFox wallet and derived TOS
address already present on the machine.

### 23.7 Provider Response

`AgentA` evaluates its sponsor policy and returns one of:

- `approved`
- `rejected`
- `challenge_required`
- `paid_upgrade_required`

Suggested approval response:

```json
{
  "status": "approved",
  "transfer_network": "tos:1666",
  "tx_hash": "0x...",
  "amount": "10000000000000000",
  "cooldown_until": 1770007200
}
```

Suggested rejection response:

```json
{
  "status": "rejected",
  "reason": "quota exceeded"
}
```

### 23.8 Hybrid and Paid Cases

Some providers may advertise the faucet capability in `hybrid` mode rather than
pure `sponsored` mode.

For example:

- first bootstrap request is sponsored
- larger top-ups require payment
- requests above a free quota return `402 Payment Required`

In an OpenFox deployment, this fits naturally with the existing HTTPS and
`x402` request path. If the chosen provider requires payment, OpenFox can route
the invocation through its existing payment-aware fetch logic instead of using a
separate discovery-specific settlement path.

### 23.9 Local Completion in OpenFox

After receiving an approval:

1. OpenFox records the provider identity and request nonce in local state
2. OpenFox polls TOS RPC for the returned `tx_hash`
3. OpenFox confirms the wallet balance increase
4. OpenFox stores the result as a completed faucet/top-up event

This is important for:

- replay protection
- cooldown tracking
- operator auditability
- future provider scoring

### 23.10 End-to-End View

The complete requester flow in an OpenFox-like agent is:

```text
user intent
-> capability mapping
-> discv5 candidate discovery
-> Agent Card fetch and verification
-> local provider selection
-> HTTPS invocation
-> optional x402 payment
-> TOS receipt tracking
-> local state update
```

This example is intentionally application-specific at the edge, but protocol-
generic in the middle. OpenFox is only one possible requester implementation.
