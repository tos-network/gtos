# GTOS Storage Feature Modes

This document captures six differentiated product modes for GTOS decentralized storage.

## 1. Data-as-Lease

- Treat `ttl` as a storage lease period.
- Expiry means automatic invalidation, renew by submitting a new tx.
- Best for logs, caches, temp artifacts, and AI intermediate outputs.

## 2. Proof of Expiry

- Provide verifiable proof that a key/code expired at block `N`.
- Make expiry auditable for compliance, legal, and operational checks.

## 3. Namespace Leasing Market

- Lease namespaces by block window (fixed rent or auction).
- On expiry, namespace ownership is released automatically.
- Turns storage namespace into a tradable on-chain resource.

## 4. Release Channel Model (Code + KV Streams)

- Keep one active version per channel/account.
- New publishes move forward; old versions age out by TTL.
- Fits plugin distribution, policy rollout, and config delivery.

## 5. Retention-Window Friendly Retrieval

- Keep chain nodes lightweight (short history retention).
- Add off-chain indexers for long-range search with on-chain verifiable anchors.
- Balance low node cost with query usability.

## 6. Storage SLA Tiers

- Offer multiple storage classes (e.g., standard / high-availability).
- Same `put_ttl` semantics, different replication/price/reliability profile.
- Enables clear ToB packaging and monetization.
