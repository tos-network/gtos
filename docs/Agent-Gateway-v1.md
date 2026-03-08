# Agent Gateway v1

Status: Draft
Audience: GTOS networking, agent runtime authors, gateway agent operators, service providers

## 1. Summary

Agent Gateway v1 is a reachability layer for agent services. It solves a practical
problem: many agent providers run behind NAT and cannot accept inbound connections
from the public internet.

The key design decision in this version is that **gateway relay is itself an agent
capability**. A gateway is not a special infrastructure component outside the agent
model. It is an agent that advertises the `gateway.relay` capability, is discoverable
through Agent Discovery v1, and participates in the same trust, reputation, and
payment mechanisms as any other agent.

How it works:

- a gateway agent has a public IP and advertises `gateway.relay` in its Agent Card
- a NAT'd provider discovers a gateway agent through Agent Discovery
- the provider opens an outbound session to the gateway agent
- the gateway agent allocates a public invocation endpoint for the provider
- the provider advertises that public endpoint in its own Agent Card
- requesters invoke the provider through the gateway endpoint
- the gateway agent forwards traffic over the existing outbound session

This is conceptually a reverse tunnel, but modeled as a first-class agent capability
rather than out-of-band infrastructure.

## 2. Goals

- Let agents without a public IP provide services to external requesters
- Model gateway relay as a standard agent capability within Agent Discovery v1
- Enable multiple competing gateway agents without central coordination
- Support paid, sponsored, and hybrid relay pricing
- Allow OpenFox and other runtimes to act as requester, provider, or gateway
- Reuse existing trust mechanisms: stake, reputation, capability registry

## 3. Non-Goals

- Replacing discv5 or ENR
- Full NAT hole punching across arbitrary environments
- End-to-end payload confidentiality by default in v1
- Fully decentralized relay selection without any bootstrap hints

## 4. Relationship to Agent Discovery

Agent Discovery v1 and Agent Gateway v1 are not separate systems. Gateway is a
capability within the Discovery framework:

- Agent Discovery v1:
  - find agents by capability
  - fetch and verify Agent Cards
  - verify identity and policy metadata
- `gateway.relay` capability:
  - a specific capability that gateway agents advertise
  - discovered using the same ENR bloom filter, TALKREQ, and Agent Card flow
  - subject to the same trust, reputation, and payment rules

The integration flow:

1. gateway agent joins discovery and publishes an Agent Card with `gateway.relay`
2. NAT'd provider discovers gateway agents through Agent Discovery
3. provider selects a gateway agent and establishes an outbound relay session
4. provider publishes the gateway-backed endpoint in its own Agent Card
5. requester discovers the provider through Agent Discovery
6. requester invokes the provider through the published gateway endpoint

## 5. Problem Statement

An agent provider may be:

- on a home connection behind NAT
- on a private cloud subnet
- inside a corporate network
- inside a local-only development environment

In these cases, discovery may still work if the provider can join discv5 or publish
metadata through a reachable peer, but direct invocation of:

- `https://provider.example.com`
- `wss://provider.example.com`
- `http://192.168.x.x:4877`

will not work for general internet requesters.

The missing component is a publicly reachable agent that can:

- accept outbound sessions from NAT'd providers
- allocate public invocation endpoints
- forward requests to providers over the existing session

## 6. Design Principles

### 6.1 Gateway Is an Agent, Not Infrastructure

A gateway is a normal agent that happens to have a public IP and offers relay as a
service. It registers with Agent Discovery, publishes an Agent Card, and is subject
to the same trust evaluation as any other agent.

This means:

- multiple gateway agents can compete on price, quality, and reputation
- providers can switch gateway agents without protocol changes
- gateway agents can be staked, rated, and slashed like any other agent

### 6.2 Outbound-Only Provider Connectivity

The provider must not be required to accept inbound internet traffic. The provider
makes outbound connections to the gateway agent over:

- WebSocket over TLS
- HTTP/2 streams (future)
- QUIC streams (future)

### 6.3 Public Endpoint, Private Runtime

The provider runtime may remain local or private. Only the gateway agent's endpoint
needs to be public.

### 6.4 Discovery-Native Gateway Selection

Providers find gateway agents using the same Agent Discovery flow they would use to
find any other capability. No hardcoded gateway URLs are required beyond initial
bootstrap hints.

### 6.5 Capability Routing Must Be Explicit

The gateway agent does not guess what the provider supports. The provider registers
its routes explicitly on session setup. The provider advertises the gateway-backed
endpoint in its signed Agent Card.

## 7. Roles

- Requester:
  - the agent invoking a capability on a provider
- Provider:
  - the agent offering a capability, potentially behind NAT
- Gateway Agent:
  - an agent with a public IP that advertises `gateway.relay` and forwards traffic
    between requesters and NAT'd providers
- Directory Agent:
  - an optional agent that indexes capability claims and returns candidate providers

## 8. Gateway Relay Capability

The gateway relay capability follows the standard Agent Discovery capability model.

Capability name:

```text
gateway.relay
```

A gateway agent advertises this capability in its Agent Card:

```json
{
  "version": 1,
  "agent_id": "0xGatewayAgent...",
  "primary_identity": {
    "kind": "tos",
    "value": "0xGatewayTOSAddress..."
  },
  "capabilities": [
    {
      "name": "gateway.relay",
      "mode": "paid",
      "price_model": "x402-metered",
      "policy": {
        "max_sessions": 200,
        "max_bandwidth_kbps": 10000,
        "max_routes_per_session": 20,
        "supported_transports": ["wss", "h2"],
        "session_ttl_seconds": 86400
      }
    }
  ],
  "endpoints": [
    {
      "kind": "wss",
      "url": "wss://gw1.example.com/relay"
    }
  ],
  "signature": "0x..."
}
```

Gateway relay capability modes:

- `paid`: provider pays for relay service (per-session, per-request, or metered)
- `sponsored`: gateway operator subsidizes relay (e.g. for testnet or ecosystem growth)
- `hybrid`: free tier with paid overflow

## 9. Bootstrapping and Gateway Discovery

### 9.1 The Bootstrap Problem

A NAT'd provider needs to find a gateway agent before it can be invokable. But it
needs to join the discovery network first, and the discovery network can help it find
gateway agents. This is the same bootstrapping pattern as discv5 bootnodes.

### 9.2 Gateway Bootnodes

V1 uses a gateway bootnode list, analogous to discv5 bootnodes:

- a small curated list of well-known gateway agent addresses
- shipped with the agent runtime (e.g. OpenFox) or configured by the operator
- used only for initial gateway selection

Format:

```text
gateway-bootnode://0xGatewayAgentId@gw1.example.com:443
gateway-bootnode://0xGatewayAgentId@gw2.example.com:443
```

Or as a configuration array:

```json
{
  "gateway_bootnodes": [
    {
      "agent_id": "0x...",
      "url": "wss://gw1.example.com/relay"
    },
    {
      "agent_id": "0x...",
      "url": "wss://gw2.example.com/relay"
    }
  ]
}
```

### 9.3 Bootstrap Flow

1. provider starts and loads the gateway bootnode list
2. provider joins the discv5 network using standard bootnodes
3. provider connects to a bootnode gateway agent for immediate reachability
4. provider concurrently searches Agent Discovery for `gateway.relay` capability
5. provider evaluates discovered gateway agents by reputation, price, and latency
6. provider may migrate to a better gateway agent if one is found
7. provider may maintain sessions to multiple gateway agents for redundancy

### 9.4 Gateway Migration

A provider can switch gateway agents without disrupting its identity:

1. establish session with new gateway agent
2. receive new public endpoint
3. update Agent Card with new endpoint and increment `card_seq`
4. close old gateway session

Requesters that cache the old endpoint will get a connection error and should
re-fetch the provider's Agent Card to get the updated endpoint.

## 10. High-Level Architecture

```text
+-------------------+        +-------------------+        +-------------------+
| Requester Agent   | -----> | Gateway Agent     | <===== | Provider Agent    |
| (public internet) |  HTTPS | (gateway.relay)   |  WSS   | (behind NAT)      |
+-------------------+        +-------------------+        +-------------------+
                                     ^
                                     |
                              Agent Discovery
                              (same network)
```

The gateway agent:

- joins Agent Discovery and advertises `gateway.relay`
- accepts outbound sessions from NAT'd providers
- allocates public endpoints per provider session
- forwards requests from requesters to providers

The provider:

- discovers gateway agents through Agent Discovery
- establishes an outbound relay session
- registers routes on the session
- advertises the gateway-backed endpoint in its Agent Card

The requester:

- discovers the provider through Agent Discovery (not the gateway)
- invokes the provider's published endpoint, which happens to route through a gateway

## 11. Provider-Gateway Session Model

### 11.1 Session Establishment

The provider opens an outbound session to the gateway agent.

V1 transport:

- WebSocket over TLS

The provider sends a `session_open` message containing authentication and route
registration.

### 11.2 Provider Authentication

The provider authenticates using a signed session envelope:

```json
{
  "version": 1,
  "agent_id": "0xProviderAgent...",
  "primary_identity": {
    "kind": "tos",
    "value": "0xProviderTOS..."
  },
  "gateway_agent_id": "0xGatewayAgent...",
  "session_nonce": "0x...",
  "issued_at": 1770000000,
  "expires_at": 1770000600,
  "signature": "0x..."
}
```

Requirements:

- signature key MUST match the Agent Card signing identity
- `gateway_agent_id` MUST match the gateway being connected to (prevents replay
  across gateways)
- gateway agent MUST verify freshness and expiry
- gateway agent MUST bind the session to the authenticated provider identity

### 11.3 Session Keepalive

Liveness is maintained using:

- WebSocket ping/pong
- or protocol-level keepalive frames

If the session is lost:

- gateway agent marks the provider's routes as unavailable
- new requests fail fast with a clear error
- provider should reconnect or migrate to another gateway agent

## 12. Public Endpoint Model

The gateway agent allocates a public endpoint per provider session.

Examples:

- `https://gw1.example.com/a/4f2b.../invoke`
- `https://gw1.example.com/a/4f2b.../faucet`
- `https://gw1.example.com/a/4f2b.../oracle/resolve`

The provider includes this endpoint in its Agent Card:

```json
{
  "endpoints": [
    {
      "kind": "https",
      "url": "https://gw1.example.com/a/4f2b.../invoke",
      "via_gateway": "0xGatewayAgent..."
    }
  ]
}
```

The `via_gateway` field is optional but recommended. It lets requesters know the
endpoint is relayed and identify which gateway agent is involved.

## 13. Invocation Flow

### 13.1 Requester Flow

1. discover provider using Agent Discovery v1
2. fetch and verify provider's Agent Card
3. select a declared endpoint (may be a gateway URL)
4. invoke the endpoint over HTTPS
5. receive response or streaming session

The requester does not need to know or care that the endpoint is gateway-backed.
The provider's Agent Card is the source of truth.

### 13.2 Gateway Agent Flow

1. receive public HTTPS request
2. identify target provider session from path or session mapping
3. enforce gateway-level policy (rate limits, payment)
4. forward request to provider over the outbound WebSocket session
5. relay provider response back to requester

### 13.3 Provider Flow

1. receive forwarded request from gateway agent
2. validate capability-specific inputs
3. optionally enforce payment or sponsor rules
4. perform work
5. return response or error through the gateway session

## 14. Capability Binding and Route Registration

When a provider opens a session, it registers the routes it wants exposed:

```json
{
  "type": "session_open",
  "auth": { "..." },
  "routes": [
    {
      "path": "/faucet",
      "capability": "sponsor.topup.testnet",
      "mode": "sponsored"
    },
    {
      "path": "/oracle/resolve",
      "capability": "oracle.resolve",
      "mode": "paid"
    }
  ]
}
```

The gateway agent:

- MUST reject requests to routes not registered by the provider's live session
- MUST NOT infer or auto-generate routes
- MAY enforce per-route rate limits

## 15. Gateway Agent Trust Model

Because the gateway agent is a participant in Agent Discovery, it is subject to the
same trust mechanisms as any other agent.

### 15.1 What the Gateway Agent Can Do

Unless payloads are end-to-end encrypted, the gateway agent can:

- observe request and response metadata and bodies
- deny service
- misroute traffic

### 15.2 Trust Mitigations via Agent Discovery

Unlike an out-of-band infrastructure gateway, a gateway agent can be evaluated using:

- on-chain registration status and stake
- reputation score and rating count
- capability registry membership for `gateway.relay`
- provider-side local scoring based on past relay quality

### 15.3 Provider-Side Gateway Selection

Providers SHOULD evaluate gateway agents before establishing sessions:

- prefer gateway agents with higher stake
- prefer gateway agents with higher reputation
- prefer gateway agents with on-chain `gateway.relay` capability bit
- avoid gateway agents that have been suspended
- consider geographic proximity for latency

### 15.4 Minimum V1 Controls

Gateway agents MUST implement:

- TLS on all public endpoints
- per-provider session authentication
- rate limits per session and per endpoint
- request size limits
- idle timeout and session expiry
- replay protection on session auth (nonce + `gateway_agent_id` binding)
- logging and audit correlation IDs

## 16. Payment Model for Gateway Relay

Gateway relay is a service with real costs (bandwidth, public IP, compute). The
payment model uses the same mechanisms as any other agent capability.

### 16.1 Paid Relay

The gateway agent charges the provider for relay service.

Pricing options:

- per-session flat fee
- per-request fee
- metered by bandwidth or duration
- x402 settlement

### 16.2 Sponsored Relay

The gateway operator subsidizes relay for ecosystem growth.

Use cases:

- testnet gateway agents
- foundation-operated gateways for early network bootstrap
- community-funded relay pools

### 16.3 Hybrid Relay

Free tier for low-volume providers, paid for higher usage.

The pricing model is declared in the gateway agent's Agent Card `policy` field,
allowing providers to compare before connecting.

## 17. Multi-Gateway and Failover

### 17.1 Multiple Gateway Sessions

A provider MAY maintain sessions to multiple gateway agents simultaneously:

- publish multiple endpoints in its Agent Card
- achieve redundancy against single-gateway failure
- load-balance across gateways

### 17.2 Failover

If a gateway agent becomes unreachable:

1. provider detects session loss
2. provider connects to another gateway agent (from discovery or bootnode list)
3. provider updates its Agent Card with the new endpoint
4. stale endpoint requests fail; requesters re-fetch the Agent Card

### 17.3 Gateway Agent Liveness

Gateway agents that go offline will:

- lose their discv5 presence over time
- accumulate negative provider-side scoring
- lose reputation if providers submit feedback

This is a natural consequence of being a normal agent in the discovery network.

## 18. Security Considerations

### 18.1 Gateway Agent Selection Attack

A malicious gateway agent could intercept or modify traffic. Mitigations:

- providers evaluate gateway agents using stake and reputation
- providers can require minimum stake thresholds for gateway selection
- providers can maintain multiple gateway sessions for cross-verification
- future: end-to-end encrypted payloads between requester and provider

### 18.2 Sybil Gateway Agents

An attacker could run many low-quality gateway agents. Mitigations:

- require on-chain registration and non-trivial stake for `gateway.relay`
- reputation-weighted selection
- provider-side local scoring

### 18.3 Session Replay

Prevented by:

- `gateway_agent_id` binding in session auth (prevents replay across gateways)
- nonce + expiry in session envelope
- TLS on transport

### 18.4 Privacy

- providers MUST NOT publish private LAN addresses in Agent Cards
- providers SHOULD publish only gateway-backed or directly reachable endpoints
- gateway agents can observe traffic unless end-to-end encryption is used

## 19. OpenFox Integration Model

OpenFox is one example of a runtime that can use Gateway v1 in three roles.

### 19.1 OpenFox as Gateway Agent

An OpenFox instance with a public IP may:

- advertise `gateway.relay` capability
- accept provider relay sessions
- forward traffic and charge for relay service

### 19.2 OpenFox as Provider (Behind NAT)

An OpenFox instance behind NAT may:

- discover gateway agents through Agent Discovery
- fall back to gateway bootnodes if no gateway agents are discovered yet
- establish a relay session
- publish the gateway-backed endpoint in its Agent Card
- serve capabilities like `sponsor.topup.testnet` through the relay

### 19.3 OpenFox as Requester

An OpenFox instance may:

- discover a provider with Agent Discovery
- verify the provider's Agent Card
- invoke the provider through the published endpoint (gateway-backed or direct)
- pay through x402 if required

The requester does not need special handling for gateway-backed endpoints.

### 19.4 Testnet Faucet Example

Provider OpenFox (behind NAT):

1. loads gateway bootnode list
2. connects to a gateway agent, registers `/faucet` route
3. publishes Agent Card with `sponsor.topup.testnet` and gateway endpoint

Requester OpenFox:

1. searches Agent Discovery for `sponsor.topup.testnet`
2. finds the provider, fetches and verifies Agent Card
3. calls `https://gw1.example.com/a/4f2b.../faucet`
4. receives sponsored top-up approval
5. tracks the resulting TOS transfer receipt

## 20. Wire Sketch

This section is illustrative rather than normative.

### 20.1 Provider Session Open

```json
{
  "type": "session_open",
  "auth": {
    "version": 1,
    "agent_id": "0xProviderAgent...",
    "primary_identity": {
      "kind": "tos",
      "value": "0xProviderTOS..."
    },
    "gateway_agent_id": "0xGatewayAgent...",
    "session_nonce": "0x...",
    "issued_at": 1770000000,
    "expires_at": 1770000600,
    "signature": "0x..."
  },
  "routes": [
    {
      "path": "/faucet",
      "capability": "sponsor.topup.testnet",
      "mode": "sponsored"
    }
  ]
}
```

### 20.2 Session Open Response

```json
{
  "type": "session_open_ack",
  "session_id": "s-9a3f...",
  "allocated_endpoints": [
    {
      "path": "/faucet",
      "public_url": "https://gw1.example.com/a/4f2b.../faucet"
    }
  ],
  "relay_pricing": {
    "mode": "sponsored",
    "note": "testnet relay, no charge"
  }
}
```

### 20.3 Forwarded Request

```json
{
  "type": "request",
  "request_id": "c7f5...",
  "method": "POST",
  "path": "/faucet",
  "headers": {
    "content-type": "application/json"
  },
  "body": {
    "capability": "sponsor.topup.testnet",
    "requester_identity": {
      "kind": "tos",
      "value": "0xRequester..."
    },
    "requested_amount": "10000000000000000"
  }
}
```

### 20.4 Forwarded Response

```json
{
  "type": "response",
  "request_id": "c7f5...",
  "status": 200,
  "headers": {
    "content-type": "application/json"
  },
  "body": {
    "status": "approved",
    "tx_hash": "0x...",
    "amount": "10000000000000000"
  }
}
```

## 21. Deployment Modes

### 21.1 Discoverable Gateway Mode (Recommended)

Provider discovers gateway agents through Agent Discovery and selects based on
trust signals. This is the primary mode.

### 21.2 Bootnode-Only Mode

Provider connects only to gateway bootnodes without performing discovery-based
selection. Suitable for initial bootstrap or when the discovery network is small.

### 21.3 Direct Mode (No Gateway)

Provider has a public IP and advertises its own endpoint directly. No gateway
agent is needed. The Agent Card simply contains the provider's own URL.

### 21.4 Multi-Gateway Mode

Provider maintains sessions to multiple gateway agents for redundancy and
load distribution. Agent Card lists multiple endpoints.

## 22. Rollout Plan

### Phase 1

- `gateway.relay` capability definition
- gateway bootnode list format and distribution
- provider outbound WebSocket session to gateway agents
- signed session auth with `gateway_agent_id` binding
- public endpoint allocation and HTTPS request/response forwarding
- OpenFox faucet capability over gateway relay

### Phase 2

- discovery-based gateway selection with reputation and stake filtering
- gateway migration without session interruption
- streaming support over relay sessions
- multi-gateway redundancy
- relay payment enforcement (x402)

### Phase 3

- on-chain `gateway.relay` capability registry
- gateway agent reputation feedback from providers
- optional end-to-end encrypted invocation payloads
- relay quality metrics and SLA declarations in Agent Card

## 23. Implementation Guidance for GTOS

GTOS does not need a hard fork for Gateway v1.

The capability `gateway.relay` fits naturally into the existing Agent Discovery
framework:

- `agb` bloom filter already supports arbitrary capability names
- Agent Card already supports capability declarations with policy
- trust primitives (stake, reputation, capability registry) already exist

GTOS-side support:

- register `gateway.relay` as a standard capability name
- include gateway bootnode list in default agent runtime configuration
- optional: gateway agent attestation helpers

Runtime-side implementation (OpenFox or similar):

- gateway agent: accept relay sessions, allocate endpoints, forward traffic
- provider: gateway discovery, session management, Agent Card endpoint updates
- requester: no changes needed (gateway endpoints are transparent)

## 24. Conclusion

Agent Gateway v1 models relay as a first-class agent capability rather than
out-of-band infrastructure.

Agent Discovery answers: who is online and what can they do.

`gateway.relay` answers: how can a NAT'd provider become reachable, using the
same discovery, trust, and payment mechanisms as every other capability.

Gateway agents compete on the same terms as any other agent: stake, reputation,
price, and quality of service. Providers discover and select gateway agents through
Agent Discovery, with gateway bootnodes providing the initial bootstrap path.
