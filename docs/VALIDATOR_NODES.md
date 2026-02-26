# GTOS Validator Node Requirements

Hardware, network, and deployment requirements for running a GTOS DPoS validator node.

## 1. Hardware Requirements

### Benchmark reference machine

Tests run on `Intel(R) Xeon(R) Platinum 8455C` (`go test -bench -benchtime=20x`, diskdb):

| Operation | Time |
|---|---|
| Empty block import (diskdb) | ~250–300 µs |
| Block with transactions import (diskdb) | ~350–400 µs |
| TTL prune, 128 active records | ~4–6 ms |
| ed25519 seal | < 50 µs |
| **Total local processing per block** | **< 7 ms** |

With `periodMs=360` the slot budget is 360 ms. Local processing consumes **under 2%** of that budget.

### Slot timeline (worst-case global propagation, US ↔ Australia, P = 135 ms)

```
T =   0ms   parent block received by in-turn validator
T ≈ 0.5ms   parent imported and verified
T ≈   6ms   FinalizeAndAssemble + state root + TTL prune complete
T ≈ 6.1ms   ed25519 seal complete, block ready to broadcast
T ≈ 141ms   block received by all 15 validators  (6ms + 135ms propagation)
             → 219ms remaining in the 360ms slot
```

### Minimum recommended spec

| Resource | Minimum |
|---|---|
| CPU | 4-core x86-64, single-core performance ≥ modern Xeon/EPYC class |
| RAM | 8 GB |
| Disk | SSD, ≥ 100 GB (NVMe preferred) |
| OS | Linux 64-bit |

## 2. Network Requirements

### Block propagation model

GTOS uses go-ethereum flat p2p gossip (`BroadcastBlock` in `tos/handler.go`):

- Full block sent directly to `sqrt(peers)` peers per hop.
- Remaining peers receive a hash announcement and pull on demand.
- With 15 validators in near-full-mesh topology: **2 hops** to reach all validators.

### One-way latency limits and in-turn win probability

The in-turn validator seals at exactly `header.Time = parent.Time + periodMs`.
Out-of-turn validators add a uniform random delay `rand(0, wiggle)` before sealing.

```
P(in-turn wins) = (wiggle - P) / wiggle
```

where `P` is the one-way network propagation latency between validators.

At `periodMs=360`, `wiggle=720ms`:

| Route | One-way latency P | P(in-turn wins) | Assessment |
|---|---|---|---|
| US internal | ~20 ms | 97.2% | Stable |
| US ↔ Europe | ~80 ms | 88.9% | Stable |
| Europe ↔ Asia-Pacific | ~100 ms | 86.1% | Usable |
| US ↔ Asia-Pacific | ~130 ms | 81.9% | Usable |
| US ↔ Australia | ~135 ms | 81.3% | Usable |

**Hard limit**: one-way latency to a quorum of peers (`N/3 + 1` validators) must be **under 200 ms**.
Beyond that, in-turn win probability drops below 72% and fork rate rises sharply.

All major global cloud regions are within the usable zone.

### Port requirements

| Port | Protocol | Purpose |
|---|---|---|
| 30303 (default) | TCP + UDP | P2P discovery and block/tx gossip |
| 8545 | TCP | HTTP-RPC (optional, validator-internal) |
| 9551 | TCP | Engine AuthRPC |

Validator nodes must have **inbound TCP reachable** on the P2P port from other validators.
NAT without port forwarding will prevent inbound connections and degrade block propagation.

## 3. Consensus Timing Parameters

| Constant | Value | Source |
|---|---|---|
| `periodMs` | `360` | genesis / node config |
| `allowedFutureBlockTime` | `1200 ms` | `consensus/dpos/dpos.go` |
| `minWiggleTime` | `100 ms` | `consensus/dpos/dpos.go` |
| `maxWiggleTime` | `1000 ms` | `consensus/dpos/dpos.go` |
| `outOfTurnWiggleWindow` | `clamp(period×2, 100ms, 1000ms)` | computed |
| `recents limit` | `validators/3 + 1` | `params/config.go::RecentSignerWindowSize` |
| `DPoSMaxValidators` | `15` | `params/tos_params.go` |

With `periodMs=360`:
- `wiggle = clamp(720ms, 100ms, 1000ms) = 720ms`
- With 15 validators: `recents limit = 6` (a validator may not sign again for 6 consecutive blocks)
- Set `epoch=1667` to keep epoch rotation near 10 minutes (`1667 × 0.36s ≈ 600s`)

## 4. Recommended Deployment Profiles

| Profile | `periodMs` | `allowedFutureBlockTime` | `wiggle` | `maxValidators` | `recents limit` |
|---|---:|---:|---:|---:|---:|
| Regional / low-latency | `360ms` | `800ms` | `720ms` | `21` | `N/3 + 1` |
| Global public network | `360ms` | `1080ms` | `720ms` | `15` | `N/3 + 1` |

**Regional profile**: all validators within the same continent or cloud region (P < 30 ms).
**Global profile**: validators spread across continents; requires all validators within 200 ms one-way of a quorum.

## 5. Clock Synchronization

Validator nodes must run NTP or equivalent clock synchronization.

- Clock skew beyond `allowedFutureBlockTime / 2` (~600 ms) will cause future-block rejections.
- Recommended: `chrony` or `systemd-timesyncd` with stratum-1/2 sources, targeting < 50 ms offset.
