# Agent Gateway v1

Status: Draft  
Audience: GTOS networking, agent runtime authors, gateway operators, service providers

## 1. Summary

Agent Gateway v1 is a public reachability layer for agent services.

It exists to solve a practical problem:

- many agent providers run behind NAT
- many providers do not have a public IP
- Agent Discovery can locate such providers, but requesters still cannot invoke them
  directly over the public internet

Agent Gateway v1 provides a simple answer:

- the provider opens an outbound connection to a public gateway
- the gateway allocates a public invocation endpoint
- the provider advertises that public endpoint in its Agent Card
- requesters call the gateway endpoint
- the gateway forwards traffic to the provider over the existing outbound session

This is conceptually similar to a reverse tunnel or agent-specific proxy. It is not a
replacement for Agent Discovery. It is the invocation companion for discovered agents
that are not directly reachable from the public internet.

## 2. Goals

- Let agents without a public IP provide services to external requesters
- Preserve the layering of Agent Discovery v1
- Keep the provider-side networking model simple
- Support both sponsored and paid agent capabilities
- Allow OpenFox and other runtimes to act as either requester or provider

## 3. Non-Goals

- Replacing discv5 or ENR
- Building a fully decentralized relay market in v1
- Performing full NAT hole punching across arbitrary environments
- Hiding all gateway trust assumptions
- Providing end-to-end payload confidentiality in the gateway by default

## 4. Relationship to Agent Discovery

Agent Discovery v1 and Agent Gateway v1 solve different layers:

- Agent Discovery v1:
  - find providers
  - fetch Agent Cards
  - verify basic identity and policy metadata
- Agent Gateway v1:
  - make the provider invokable
  - bridge public requesters to private providers

The recommended integration is:

1. provider joins discovery and publishes an Agent Card
2. provider also establishes a gateway session
3. provider publishes the gateway-backed public endpoint in its Agent Card
4. requester discovers provider using Agent Discovery v1
5. requester invokes the published endpoint through the gateway

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

The missing component is a public edge that:

- is reachable by requesters
- can authenticate a provider
- can forward requests to that provider

## 6. Design Principles

### 6.1 Outbound-Only Provider Connectivity

The provider must not be required to accept inbound internet traffic.

V1 assumes the provider can make outbound connections to the gateway over:

- HTTPS
- WebSocket
- QUIC or another future transport

### 6.2 Public Endpoint, Private Runtime

The provider runtime may remain local or private. Only the gateway endpoint needs to
be public.

### 6.3 Discovery Remains Separate

The gateway does not replace Agent Discovery. A requester should still discover the
provider via ENR and Agent Card, not by querying a centralized gateway catalog.

### 6.4 Capability Routing Must Be Explicit

The gateway should not guess what the provider supports. The provider advertises the
gateway endpoint in its signed Agent Card, and the requester invokes only what the
card declares.

### 6.5 V1 Prefers Operational Simplicity Over Perfect Decentralization

The first version should be easy to deploy:

- one public gateway process
- many provider sessions
- signed cards
- optional x402 or sponsor policy on the public endpoint

## 7. Roles

- Requester:
  - the agent or user-facing runtime invoking a capability
- Provider:
  - the agent offering a capability, potentially behind NAT
- Gateway:
  - a public edge service forwarding requests from requesters to providers
- Optional Directory:
  - an indexer or cache that helps requesters find provider candidates

## 8. High-Level Architecture

```text
+-------------------+        +-------------------+        +-------------------+
| Requester Agent   | -----> | Public Gateway    | <----- | Provider Agent    |
| (public internet) |  HTTPS | reverse routing   |  WS    | (private network) |
+-------------------+        +-------------------+        +-------------------+
          |                           ^
          |                           |
          +---- Agent Discovery ------+
```

The provider:

- connects out to the gateway
- authenticates
- registers supported routes or capability bindings
- keeps the session alive

The requester:

- discovers the provider through Agent Discovery
- receives a public endpoint from the provider's Agent Card
- invokes that endpoint

## 9. Provider-Gateway Session Model

### 9.1 Session Establishment

The provider opens an outbound session to the gateway.

Recommended V1 transport:

- WebSocket over TLS

Alternative future transports:

- HTTP/2 streams
- QUIC streams

### 9.2 Provider Authentication

The provider authenticates using a signed session envelope.

Suggested fields:

```json
{
  "version": 1,
  "agent_id": "0x...",
  "primary_identity": {
    "kind": "tos",
    "value": "0x..."
  },
  "gateway_session_nonce": "0x...",
  "issued_at": 1770000000,
  "expires_at": 1770000600,
  "signature": "0x..."
}
```

Requirements:

- signature key SHOULD match the Agent Card signing identity or be explicitly linked
- gateway MUST verify freshness and expiry
- gateway MUST bind the live session to the authenticated provider identity

### 9.3 Session Keepalive

The gateway and provider maintain liveness using:

- WebSocket ping/pong
- or protocol-level keepalive frames

If the session is lost:

- gateway marks the provider unavailable
- new requests fail fast until reconnection

## 10. Public Endpoint Model

Gateway v1 allocates a public endpoint per provider session.

Examples:

- `https://gw.example.com/a/4f2b.../invoke`
- `https://gw.example.com/a/4f2b.../faucet`
- `https://gw.example.com/a/4f2b.../oracle/resolve`

The provider includes this endpoint in its Agent Card.

Recommended rule:

- the Agent Card should advertise the gateway endpoint, not the provider's private
  local address

## 11. Invocation Flow

### 11.1 Requester Flow

1. discover provider using Agent Discovery v1
2. fetch and verify Agent Card
3. select a declared endpoint
4. invoke the gateway URL
5. receive response or streaming session

### 11.2 Gateway Flow

1. receive public request
2. identify target provider session from path or session mapping
3. enforce gateway-level policy
4. forward request to provider over the outbound session
5. relay provider response back to requester

### 11.3 Provider Flow

1. receive forwarded request from gateway
2. validate capability-specific inputs
3. optionally enforce payment or sponsor rules
4. perform work
5. return a response or error

## 12. Capability Binding

Gateway routing must bind requests to declared capabilities.

V1 recommendation:

- each public route maps to one named capability
- the provider registers the route-to-capability mapping on session setup

Example:

```json
{
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

The gateway should reject requests to routes that were not registered by the
provider's live session.

## 13. Payment and Sponsor Modes

Gateway v1 must support two broad service modes:

- sponsored
- paid

### 13.1 Sponsored

Typical example:

- `sponsor.topup.testnet`

Requirements:

- provider declares quota and rate limits in Agent Card policy
- provider remains free to reject
- gateway may additionally enforce coarse abuse controls

### 13.2 Paid

Typical examples:

- `oracle.resolve`
- `observation.once`

Recommended V1 payment model:

- x402 over HTTPS

The gateway may operate in either of these modes:

- pass-through:
  - the requester pays the provider endpoint through gateway forwarding
- edge-enforced:
  - the gateway verifies payment before forwarding

V1 recommendation:

- edge-enforced x402 for simple HTTP request/response routes

## 14. Security Model

Gateway v1 introduces a public intermediary. This has consequences.

### 14.1 What the Gateway Can Do

Unless application payloads are end-to-end protected, the gateway can:

- observe request metadata
- observe request and response bodies
- deny service
- misroute traffic

### 14.2 What Signed Agent Cards Still Protect

The gateway does not control:

- provider identity claims in the signed Agent Card
- capability declarations in the signed Agent Card
- provider-selected settlement identity

### 14.3 Minimum V1 Controls

Gateway operators SHOULD implement:

- TLS on public endpoints
- per-provider authentication
- rate limits
- request size limits
- idle timeout
- replay protection on gateway session auth
- logging and audit correlation IDs

## 15. Privacy Considerations

Providers using a gateway reduce public exposure of their private network location,
but they increase dependence on gateway visibility.

V1 guidance:

- do not publish private LAN addresses in Agent Cards
- publish only gateway URLs or other requester-reachable endpoints
- keep sensitive private metadata out of ENR
- place only public invocation metadata in the Agent Card

## 16. OpenFox Integration Model

OpenFox is one example of a runtime that can use Gateway v1 in both roles.

### 16.1 OpenFox as Provider

OpenFox may:

- run on a laptop or home machine
- create a local wallet
- start a local faucet or oracle HTTP handler
- open an outbound session to a public gateway
- publish the gateway-backed endpoint in its Agent Card

This lets a non-public OpenFox instance provide services externally.

### 16.2 OpenFox as Requester

OpenFox may:

- discover a provider with Agent Discovery
- verify the provider's Agent Card
- invoke the provider through the published gateway endpoint
- pay through x402 if required

### 16.3 OpenFox Testnet Faucet Example

A provider OpenFox instance may advertise:

- capability: `sponsor.topup.testnet`
- public endpoint: `https://gw.example.com/a/4f2b.../faucet`

A requester OpenFox instance may:

1. map `/faucet` or a natural-language request into `sponsor.topup.testnet`
2. search discovery for matching providers
3. verify the chosen Agent Card
4. call the gateway URL
5. receive sponsored top-up approval or rejection
6. track the resulting TOS transfer receipt

## 17. Recommended V1 Deployment Modes

### 17.1 Public Gateway Mode

Use when:

- providers are behind NAT
- requesters come from the public internet

Properties:

- easiest public usability
- operationally centralized at the gateway layer
- best fit for early OpenFox service networks

### 17.2 Private Overlay Mode

Use when:

- all agents are inside the same private mesh
- public internet access is not required

Examples:

- WireGuard mesh
- Tailscale network

In this mode, the overlay itself may make the provider directly reachable and the
gateway may be unnecessary.

### 17.3 Hybrid Mode

Use when:

- some agents are directly reachable
- some agents require gateway traversal

The Agent Card simply advertises the reachable endpoint that applies to the provider.

## 18. Minimal V1 Wire Sketch

This section is illustrative rather than normative.

### 18.1 Provider Session Open

```json
{
  "type": "session_open",
  "auth": {
    "version": 1,
    "agent_id": "0x...",
    "primary_identity": {
      "kind": "tos",
      "value": "0x..."
    },
    "gateway_session_nonce": "0x...",
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

### 18.2 Forwarded Request

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

### 18.3 Forwarded Response

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

## 19. Rollout Plan

### Phase 1

- provider outbound WebSocket session
- signed session auth
- static public gateway routes
- HTTPS request/response forwarding
- OpenFox faucet capability over gateway

### Phase 2

- streaming support
- provider multiplexing improvements
- stronger payment enforcement hooks
- provider session resumption

### Phase 3

- optional gateway federation
- optional relay markets
- optional end-to-end encrypted invocation payloads

## 20. Implementation Guidance for GTOS

GTOS does not need a hard fork for Gateway v1.

The most natural split is:

- GTOS:
  - provide Agent Discovery transport and optional payment primitives
- agent runtimes such as OpenFox:
  - implement provider logic
  - implement requester logic
  - optionally implement or operate a gateway service

Possible GTOS-side support that may be useful later:

- standard capability-route descriptors
- x402 helper middleware
- optional gateway attestation or audit helpers

## 21. Conclusion

Agent Gateway v1 is the missing reachability layer for practical agent services.

Agent Discovery alone can answer:

- who is online
- who claims a capability

Gateway v1 answers the next question:

- how can a requester actually reach a private provider and use the service

For OpenFox-style agent networks, the recommended first implementation is not a full
peer-to-peer relay protocol. It is a public gateway with outbound provider sessions,
signed Agent Cards, and optional x402 or sponsor enforcement at the invocation edge.
