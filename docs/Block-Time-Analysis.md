# Block Time Analysis: GTOS 360ms vs BSC 750ms

**Status**: reference document

---

## Summary

GTOS achieves a 360ms block period while BSC operates at approximately 750ms. This
document explains the architectural differences that make this possible.

---

## 1. Signature Algorithm

| | GTOS | BSC |
|---|---|---|
| Algorithm | ed25519 | secp256k1 (ecrecover) |
| Sign latency | ~15us | ~50-80us |
| Verify latency | ~40us | ~400us |

Ed25519 verification is roughly 10x faster than secp256k1 ecrecover. Every block seal
verification and every checkpoint vote verification benefits from this difference.

---

## 2. Validator Set Size

| | GTOS | BSC |
|---|---|---|
| Active validators | 3 (current default) | 21+ |
| P2P gossip fan-out | minimal | large |
| Consensus convergence | sub-millisecond (LAN) | tens to hundreds of ms |

Fewer validators means lower network latency for block propagation and vote collection.
The gossip overhead scales with validator count.

---

## 3. Per-Block Overhead

BSC layers **fast finality (BLS vote attestation)** on top of Parlia. Every block must:

1. Collect BLS votes from the previous round
2. Aggregate BLS signatures
3. Encode vote attestation into the block Extra field
4. Verify the aggregated BLS signature during block import

GTOS checkpoint finality is **periodic** (every `CheckpointInterval` blocks), not
per-block. Ordinary blocks carry only an ed25519 seal with no additional vote or
aggregation payload.

---

## 4. MEV/PBS Pipeline

BSC block production includes MEV builder/proposer separation, which adds latency to the
block construction pipeline.

GTOS has no MEV infrastructure. The proposer directly assembles and executes
transactions.

---

## 5. P2P Protocol Weight

BSC validators broadcast BLS votes to all peers every block. With 21 validators, this
creates a per-block vote gossip storm.

GTOS has fewer protocol message types and no per-block vote broadcast. Checkpoint votes
are gossiped only at checkpoint boundaries.

---

## 6. Practical Bottlenecks at 360ms

At 360ms block period, the limiting factors are:

- **Network propagation latency**: near-zero on LAN; 50-200ms on WAN
- **State execution time**: grows with transaction complexity and block gas usage
- **Disk I/O**: state trie commit and WAL sync

These factors determine the practical lower bound for block time regardless of consensus
algorithm choice.

---

## 7. Scaling Implications

The current 360ms target is achievable because of the combination of all factors above.
If GTOS scales to a larger validator set or adds per-block fast finality in the future,
the block period may need to increase.

| Change | Impact on block time |
|---|---|
| Expand to 21 validators | Higher gossip latency, may require 500ms+ |
| Add per-block BLS attestation | Additional signing, aggregation, and verification overhead |
| Add MEV/PBS pipeline | Additional block construction latency |

---

## 8. Summary

```
BSC 750ms = secp256k1 slow verify + 21 validators gossip + per-block BLS attestation + MEV pipeline
GTOS 360ms = ed25519 fast verify + 3 validators low latency + periodic checkpoint + no MEV overhead
```

The core advantages are **ed25519**, **small validator set**, and **no per-block finality
overhead**.
