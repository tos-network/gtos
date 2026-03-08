# OpenFox Agent Discovery v1

Status: Draft  
Audience: OpenFox runtime, GTOS networking, service operators, agent developers

## 1. Summary

OpenFox Agent Discovery v1 is an application-layer discovery profile built on top of
discv5, ENR, and TOS-native identity/payment primitives.

Its purpose is to let OpenFox agents discover other online agents with specific
capabilities, verify basic identity and policy information, and connect to them for
paid or sponsored work.

Examples:

- find an agent that can resolve an oracle query
- find an agent that can perform an observation job
- find an agent that can offer a one-time TOS bootstrap top-up

The protocol is not a new replacement for discv5. It is a profile over the existing
discv5 transport already present in GTOS.

## 2. Goals

- Discover live OpenFox agents without requiring a centralized control plane
- Support capability-oriented search
- Keep discovery metadata small enough for ENR and TALKREQ
- Bind discovered agents to TOS identities and payment endpoints
- Support both paid services and tightly constrained sponsor/faucet-style services

## 3. Non-Goals

- Replacing GTOS peer discovery
- Storing full capability metadata inside ENR
- Building a full decentralized reputation market in v1
- Supporting arbitrary anonymous "free money" requests
- Proving capability claims cryptographically in v1

## 4. Design Principles

### 4.1 Layering

OpenFox Agent Discovery v1 separates four concerns:

- Discovery plane: discv5 and ENR
- Metadata plane: signed OpenFox Agent Card
- Trust plane: TOS identity, optional on-chain registry, optional reputation
- Settlement plane: x402 and TOS-native payment or sponsor policies

### 4.2 Minimal ENR, Rich Signed Metadata

ENR should only carry compact discovery hints. Rich metadata belongs in a signed Agent
Card fetched after discovery.

### 4.3 Capability Search, Not Just Peer Search

The protocol is optimized for "find an agent that can do X", not only "find any node".

### 4.4 Sponsor Capabilities Must Be Constrained

An agent advertising a TOS top-up or sponsor capability must expose policy, quota, and
rate limits. V1 does not support unrestricted free-token distribution.

## 5. Roles

- Requester: the OpenFox agent searching for a capability
- Provider: the OpenFox agent offering a capability
- Directory agent: an optional OpenFox agent that indexes capability claims and returns
  candidate providers
- Bootstrap node: a discv5 bootnode used only to join the discovery network

## 6. Identity Model

Each OpenFox provider in v1 has:

- a discv5 node identity for network discovery
- a TOS wallet address for settlement and external identity
- an OpenFox signing key for Agent Card signatures

V1 recommendation:

- one provider process advertises one primary TOS wallet address
- one provider process exposes one signed Agent Card

This keeps the first version simple. Multi-wallet or multi-tenant providers can be
added later.

## 7. Discovery Transport

OpenFox Agent Discovery v1 uses the existing GTOS discv5 implementation as the base
transport.

Relevant GTOS components:

- `p2p/discover/v5_udp.go`
- `p2p/server.go`
- `cmd/utils/flags.go`

The profile does not require a GTOS hard fork. It can be implemented by OpenFox nodes
and OpenFox-aware services running on top of the current stack.

## 8. ENR Profile

Each OpenFox-capable provider SHOULD publish the following ENR entries.

| Key | Type | Meaning |
| --- | --- | --- |
| `ofx` | `u16` | OpenFox discovery profile version. V1 value is `1`. |
| `ofa` | `bytes32` | TOS wallet address or canonical 32-byte agent address. |
| `ofm` | `u8` | Supported connection modes bitset. |
| `ofb` | `bytes32` | 256-bit capability bloom filter. |
| `ofs` | `u64` | Optional agent card sequence number. |

Connection mode bits for `ofm`:

- `0x01`: supports discv5 `TALKREQ` metadata exchange
- `0x02`: supports HTTPS endpoint invocation
- `0x04`: supports WebSocket or streaming endpoint invocation

Notes:

- ENR MUST NOT contain full capability documents
- ENR MUST NOT contain full pricing tables
- ENR MAY omit `ofs` if sequence tracking is not implemented

## 9. Capability Naming

Capabilities are canonical lowercase strings using dot-separated segments.

Examples:

- `oracle.resolve`
- `observation.once`
- `observation.window`
- `sponsor.topup.tos.testnet`
- `directory.search`

Rules:

- lowercase ASCII only
- allowed characters: `a-z`, `0-9`, `.`, `-`, `_`
- names SHOULD be stable and human-readable

The capability bloom filter in `ofb` is constructed from these canonical names.

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

## 11. OpenFox Agent Card

After finding a candidate ENR, the requester fetches a signed Agent Card.

The Agent Card is the primary metadata object for OpenFox Agent Discovery v1.

Suggested canonical JSON shape:

```json
{
  "version": 1,
  "agent_id": "0x...",
  "tos_address": "0x...",
  "discovery_node_id": "enode://...",
  "card_seq": 7,
  "issued_at": 1770000000,
  "expires_at": 1770003600,
  "display_name": "OpenFox Sponsor Node A",
  "endpoints": [
    {
      "kind": "https",
      "url": "https://agent.example.com"
    }
  ],
  "capabilities": [
    {
      "name": "sponsor.topup.tos.testnet",
      "mode": "sponsored",
      "policy_ref": "https://agent.example.com/policies/topup-v1.json",
      "rate_limit": "1/day",
      "max_amount_wei": "10000000000000000"
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

- MUST be signed by the provider's OpenFox signing key
- MUST include the TOS address used for settlement
- MUST include expiry
- MUST include at least one supported endpoint or TALKREQ-only mode
- SHOULD include a sequence number for refresh logic

## 12. Metadata Exchange Protocol

V1 defines a small metadata exchange protocol over discv5 `TALKREQ`.

Protocol name:

```text
openfox/discovery/1
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

1. Requester joins the OpenFox discovery network using known bootnodes
2. Requester iterates candidate nodes via discv5 lookup / random iteration
3. Requester filters candidates whose ENR contains `ofx=1`
4. Requester tests the candidate capability against `ofb`
5. Requester sends `GET_CARD`
6. Provider returns `CARD`
7. Requester verifies signature, expiry, TOS address, and capability policy
8. Requester connects to the provider endpoint
9. Requester invokes the capability using x402-paid or sponsor flow

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

- HTTPS endpoint with x402
- WebSocket endpoint for streaming or long-running tasks
- TALKREQ-only invocation for small metadata operations

V1 recommendation:

- use `TALKREQ` for metadata
- use HTTPS plus x402 for paid service calls

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

V1 recommendation:

- use x402 exact payment with TOS-native settlement

### 16.2 Sponsored

The provider exposes:

- eligibility policy
- quota
- cooldown
- max payout

Examples:

- one-time bootstrap top-up
- testnet faucet
- approved campaign airdrop

### 16.3 Hybrid

The provider may sponsor some requests and charge for others depending on policy.

## 17. TOS Top-Up and Airdrop Use Case

The example "find an agent that can give me some TOS" should be modeled as a
constrained sponsor capability, not a generic free-transfer capability.

Recommended capability names:

- `sponsor.topup.tos.testnet`
- `sponsor.bootstrap.tos`
- `airdrop.campaign.<campaign_id>`

Required controls:

- per-requester quota
- cooldown
- replay protection
- policy disclosure
- optional allowlist or reputation threshold
- optional proof that the requester is itself a valid OpenFox agent

## 18. Verification Rules

Before trusting a discovered capability, the requester SHOULD verify:

- the ENR advertises `ofx=1`
- the Agent Card signature is valid
- the Agent Card is not expired
- the Agent Card capability list contains the requested capability
- the Agent Card TOS address matches the expected settlement identity
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

- TOS identity
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

A realistic V1 for OpenFox should implement only:

- ENR entries `ofx`, `ofa`, `ofm`, `ofb`
- `GET_CARD` / `CARD` over `TALKREQ`
- signed Agent Card verification
- HTTPS plus x402 invocation for paid capabilities
- one sponsor capability example such as `sponsor.topup.tos.testnet`

This is enough to make agent-to-agent capability discovery real without requiring a new
base networking protocol.

## 21. Suggested Rollout

### Phase A

- Publish OpenFox bootnodes
- Add ENR OpenFox entries
- Implement Agent Card signing and fetch

### Phase B

- Add x402-bound capability invocation
- Add one paid capability example
- Add one sponsored capability example

### Phase C

- Add directory agents
- Add on-chain registry and reputation hooks
- Add richer capability indexing and policy references

## 22. Final Position

OpenFox Agent Discovery v1 should be treated as:

- a discv5-based OpenFox profile
- capability-oriented
- wallet-aware
- x402-aware
- TOS-settlement-ready

It should not be treated as a replacement for GTOS node discovery itself.
