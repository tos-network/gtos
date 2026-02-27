# GTOS Genesis Configuration Guide (DPoS)

This guide covers the complete `genesis.json` configuration for a GTOS DPoS network, based on:

- [DPOS_GENESIS_VALIDATOR_SLOTS.md](./DPOS_GENESIS_VALIDATOR_SLOTS.md)
- The 3-node testnet instance currently running on this machine

## 1. Scope

- How to construct a valid GTOS DPoS genesis
- How to pre-seed the TOS3 (validator registry) storage slots at genesis
- How to initialize 3 nodes from the same genesis
- How to verify the genesis is correctly applied after startup

## 2. Data Directory Paths

The canonical testnet data directory on this machine is:

- `/data/gtos`

To use a `~/data` path instead, override `BASE_DIR` when invoking the script:

```bash
cd ~/gtos
mkdir -p ~/data/gtos
BASE_DIR=~/data/gtos scripts/local_testnet_3nodes.sh setup
```

The examples below use `~/data/gtos`. Replace the prefix with `/data/gtos` if that is your actual data directory.

## 3. Required Genesis Fields (DPoS)

A valid GTOS DPoS genesis must contain at minimum:

- `config.chainId`
- `config.dpos.periodMs`
- `config.dpos.epoch`
- `config.dpos.maxValidators`
- `config.dpos.sealSignerType`
- `extraData` — 32-byte vanity followed by the sorted initial validator addresses (concatenated, no `0x`)
- `alloc` — initial account balances
- TOS3 (`0x...0003`) validator registry storage slots

Notes:

- GTOS addresses are 32 bytes (`0x` + 64 hex characters).
- If TOS3 validator slots are not pre-seeded at genesis, the chain will stall at the first epoch boundary.

## 4. Recommended Method: Script-Based Generation

Use `scripts/local_testnet_3nodes.sh`.

### 4.1 Generate Accounts, Genesis, and Initialize

```bash
cd ~/gtos
BASE_DIR=~/data/gtos scripts/local_testnet_3nodes.sh setup
```

This command automatically:

- Creates or reuses validator accounts for node1, node2, and node3
- Generates `genesis_testnet_3vals.json`
- Runs `gtos init` for all three data directories

Key output files:

- `~/data/gtos/validator_accounts.txt`
- `~/data/gtos/validators.sorted`
- `~/data/gtos/genesis_testnet_3vals.json`

### 4.2 (Optional) Pre-Collect Enode Addresses and Peer Files

```bash
cd ~/gtos
BASE_DIR=~/data/gtos scripts/local_testnet_3nodes.sh precollect-enode
```

Output:

- `~/data/gtos/node_enodes.txt`
- `~/data/gtos/bootnodes.csv`
- `~/data/gtos/node{1,2,3}/gtos/static-nodes.json`

## 5. Manual Method (Building from Scratch)

### 5.1 Choose DPoS Parameters

Example parameters:

| Parameter        | Value       |
|-----------------|-------------|
| `chainId`       | `1666`      |
| `periodMs`      | `360`       |
| `epoch`         | `1667`      |
| `maxValidators` | `15`        |
| `sealSignerType`| `"ed25519"` |

### 5.2 Prepare Validator Addresses

Obtain 3 or more 32-byte validator addresses. Sort them lexicographically — this order is used in both `extraData` and the `validatorList` storage slots.

### 5.3 Generate TOS3 Storage Slots

```bash
cd ~/gtos
go run ./scripts/gen_genesis_slots/main.go \
  <validator1> <validator2> <validator3>
```

This prints a `"storage"` JSON fragment ready to paste into the genesis `alloc` entry for TOS3. It includes:

- `validatorCount`
- `validatorList[i]` (one entry per validator)
- `selfStake` (initial stake per validator)
- `registered` flag
- `status`

### 5.4 Construct `extraData`

The `extraData` field layout:

```
[ 32 bytes vanity (may be all zeros) ][ validator1_bytes ][ validator2_bytes ][ validator3_bytes ]
```

Concatenate the sorted validator addresses directly (without `0x` prefixes). The result is a hex string of length `64 + N*64` characters (plus the leading `0x`).

### 5.5 Assemble the Genesis

- Add each validator address to `alloc` with an initial balance.
- Add the TOS3 address (`0x0000...0003`) to `alloc` with `"balance": "0x0"` and the `storage` map produced in step 5.3.

## 6. Live Testnet Reference (Concrete Values)

Source: `/data/gtos`.

### 6.1 Current Validator Set (Sorted)

From `/data/gtos/validators.sorted`:

- `0x116935ffb42c06360f8d7f78c8107f5b14b43400e7da9e71082a81db08b87c44`
- `0x15f0aeb8f7a7562b8fcbeba8845518bd5c1d93c76ecf0756cfe3e9a96e2343bc`
- `0x89ecd491f12a6b43d7fbb8aff4dab13aeb47eaae43211d21299d246b40643c28`

### 6.2 DPoS Configuration

From `/data/gtos/genesis_testnet_3vals.json`:

| Field            | Value         |
|-----------------|---------------|
| `chainId`       | `1666`        |
| `periodMs`      | `360`         |
| `epoch`         | `1667`        |
| `maxValidators` | `15`          |
| `sealSignerType`| `ed25519`     |
| `gasLimit`      | `0x1c9c380`   |

### 6.3 Enode Addresses and Ports (Running Instance)

From `/data/gtos/node_enodes.txt` and systemd:

| Node  | Enode                                                                                                                                       | P2P Port | HTTP RPC |
|-------|---------------------------------------------------------------------------------------------------------------------------------------------|----------|----------|
| node1 | `enode://9c7e161d30c346e136c2d3706d734085a62d066c67db33e1d6c7d6fa044a08e33b3bc198886f7e5caa9bae693c22b29606673745d1e2fab6e707f3110b52eeec@127.0.0.1:30311` | 30311 | 8545 |
| node2 | `enode://15e124f7f7d42cbab626d31617e1b132acaac9fbe7e8994d5735c9d769a5f1a801450c1d039a02eff24902321b0426f13b8dd323fc707cef60b7c8b2ad7af0f4@127.0.0.1:30312` | 30312 | 8547 |
| node3 | `enode://86af05fe22d851eb5bb53e9810e4a6fce2777736e29cf44622b5488532bdbd2f66e9d45f5cc60d5df8594bc5ab0697c21bb2b4e2103b4e1199245616820de171@127.0.0.1:30313` | 30313 | 8549 |

### 6.4 Complete Genesis Example

```json
{
  "config": {
    "chainId": 1666,
    "dpos": {
      "periodMs": 360,
      "epoch": 1667,
      "maxValidators": 15,
      "sealSignerType": "ed25519"
    }
  },
  "nonce": "0x676",
  "timestamp": "0x19c9c3b263a",
  "extraData": "0x0000000000000000000000000000000000000000000000000000000000000000116935ffb42c06360f8d7f78c8107f5b14b43400e7da9e71082a81db08b87c4415f0aeb8f7a7562b8fcbeba8845518bd5c1d93c76ecf0756cfe3e9a96e2343bc89ecd491f12a6b43d7fbb8aff4dab13aeb47eaae43211d21299d246b40643c28",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x1",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "alloc": {
    "0x116935ffb42c06360f8d7f78c8107f5b14b43400e7da9e71082a81db08b87c44": {"balance": "0x33b2e3c9fd0803ce8000000"},
    "0x15f0aeb8f7a7562b8fcbeba8845518bd5c1d93c76ecf0756cfe3e9a96e2343bc": {"balance": "0x33b2e3c9fd0803ce8000000"},
    "0x89ecd491f12a6b43d7fbb8aff4dab13aeb47eaae43211d21299d246b40643c28": {"balance": "0x33b2e3c9fd0803ce8000000"},
    "0x0000000000000000000000000000000000000000000000000000000000000003": {
      "balance": "0x0",
      "storage": {
        "0x0527edb3a67402d2a8affa098caaf69b78767f62d7b93f020378e3d7fdf5c34b": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x168d7800e35e8b01d3d05d86252434216d93e549bf5b2e1d7749a2d51eaee753": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x2461ef560038c211106f33241dc829dd7b5a9456c084053600e58f47d516e05f": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
        "0x40271349d9585dbf0a30ac55dbd944752815c305a1817b461d5c59783662dc85": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x42bfcb6ee7a7c371140dfb14c864b766db5dba31278c425cc5ee96736cc278be": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x68548e55eaf7caec6f0219aee15962b2a1ecc5740450eb0df179f210833d1b2a": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x7128f32328a93312b8f0458d4a29aabf775611a2b3917ef33a78c8ac454722df": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0xa67b4fd16902d3655d8530d7e57cfa9c78a745710b46320df416427057c89148": "0x15f0aeb8f7a7562b8fcbeba8845518bd5c1d93c76ecf0756cfe3e9a96e2343bc",
        "0xc64b0d1536f1a6b9d45ef010620d4c9040080fdfa99324a2f064bce8a987ffd2": "0x89ecd491f12a6b43d7fbb8aff4dab13aeb47eaae43211d21299d246b40643c28",
        "0xd3d4bbf6c70cd62303384d0f5f650a621550d6fce3463c8a5145f70373758537": "0x0000000000000000000000000000000000000000000000000000000000000003",
        "0xd49405b51d73a1c45f56246c692f9495732e47ccc651a97d4a7d0e1c40c9873b": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
        "0xf7f2d086e720cf4c5da04e841ff408f6cffbe08f1462d312ea5febaa7f730dca": "0x116935ffb42c06360f8d7f78c8107f5b14b43400e7da9e71082a81db08b87c44",
        "0xff77e887eb3ea6ca8da195b6af901572751a7ab862ad1eda46f986322d34312e": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"
      }
    }
  },
  "number": "0x0",
  "gasUsed": "0x0",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
```

## 7. Initialization and Startup

Assuming three data directories:

- `~/data/gtos/node1`
- `~/data/gtos/node2`
- `~/data/gtos/node3`

Initialize all three from the same genesis:

```bash
~/gtos/build/bin/gtos --datadir ~/data/gtos/node1 init ~/data/gtos/genesis_testnet_3vals.json
~/gtos/build/bin/gtos --datadir ~/data/gtos/node2 init ~/data/gtos/genesis_testnet_3vals.json
~/gtos/build/bin/gtos --datadir ~/data/gtos/node3 init ~/data/gtos/genesis_testnet_3vals.json
```

If you are using systemd:

```bash
sudo systemctl daemon-reload
sudo systemctl start gtos-node1 gtos-node2 gtos-node3
```

For full systemd service deployment, see: [LOCAL_TESTNET_3NODES_SYSTEMD.md](./LOCAL_TESTNET_3NODES_SYSTEMD.md)

## 8. Post-Startup Verification

### 8.1 Verify the TOS3 Validator Count

```bash
curl -s -X POST http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "method":"tos_getStorageAt",
    "params":[
      "0x0000000000000000000000000000000000000000000000000000000000000003",
      "0xd3d4bbf6c70cd62303384d0f5f650a621550d6fce3463c8a5145f70373758537",
      "latest"
    ],
    "id":1
  }'
```

Expected response: a hex value of `0x...03` (validator count = 3).

### 8.2 Verify Network Status

```bash
cd ~/gtos
BASE_DIR=~/data/gtos scripts/local_testnet_3nodes.sh status
BASE_DIR=~/data/gtos scripts/local_testnet_3nodes.sh verify
```

Expected:

- All 3 nodes are running
- `peerCount > 0` on each node
- Block height is increasing
- Validator rotation is occurring across nodes

## 9. Common Issues

**Chain stalls at epoch boundary (no new blocks)**
- Cause: TOS3 validator slots were not pre-seeded in the genesis.
- Fix: Re-run `scripts/gen_genesis_slots/main.go`, rebuild the genesis file, wipe `chaindata`, and re-initialize all nodes.

**Genesis mismatch between nodes**
- Cause: Different nodes were initialized from different genesis files.
- Fix: Use a single canonical `genesis_testnet_3vals.json` for all nodes. Wipe `chaindata` on all nodes and re-initialize.

**Nodes fail to connect (peers = 0)**
- Check `bootnodes.csv`, `static-nodes.json` on each node, and that ports `30311–30313` are reachable between nodes.

## 10. References

- DPoS validator slots layout: [DPOS_GENESIS_VALIDATOR_SLOTS.md](./DPOS_GENESIS_VALIDATOR_SLOTS.md)
- 3-node systemd deployment: [LOCAL_TESTNET_3NODES_SYSTEMD.md](./LOCAL_TESTNET_3NODES_SYSTEMD.md)
- Automation script: `scripts/local_testnet_3nodes.sh`
