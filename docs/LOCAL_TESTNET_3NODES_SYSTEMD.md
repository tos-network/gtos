# Local 3-Node GTOS Testnet (systemd)

This document defines the setup and startup procedure for a local 3-validator GTOS DPoS network using systemd services.

## 1. Prerequisites

- Repository: `~/gtos`
- Binary: `~/gtos/build/bin/gtos`
- Data root: `/data/gtos`
- Helper script: `scripts/local_testnet_3nodes.sh`
- `sudo` access (to write systemd unit files)

## 2. Initialize chain data and validator accounts

```bash
cd ~/gtos
scripts/local_testnet_3nodes.sh setup
```

This step will:

- Create or reuse validator accounts for node1/node2/node3
- Generate `genesis_testnet_3vals.json`
- Run `init` for all three node datadirs

Key outputs:

- `/data/gtos/validator_accounts.txt`
- `/data/gtos/genesis_testnet_3vals.json`
- `/data/gtos/node1`, `/data/gtos/node2`, `/data/gtos/node3`

## 3. Precollect enodes and write peer artifacts

```bash
cd ~/gtos
scripts/local_testnet_3nodes.sh precollect-enode
```

This action temporarily starts nodes, collects enodes, writes peer/bootnode artifacts, then stops nodes.

Key outputs:

- `/data/gtos/node_enodes.txt`
- `/data/gtos/bootnodes.csv`
- `/data/gtos/node{1,2,3}/gtos/static-nodes.json`

## 4. Create systemd services

Create three service files:

- `/etc/systemd/system/gtos-node1.service`
- `/etc/systemd/system/gtos-node2.service`
- `/etc/systemd/system/gtos-node3.service`

Core per-node parameters:

- Datadir: `/data/gtos/node{1,2,3}`
- P2P ports: `30311`, `30312`, `30313`
- HTTP ports: `8545`, `8547`, `8549`
- WS ports: `8645`, `8647`, `8649`
- AuthRPC ports: `9551`, `9552`, `9553`
- `--bootnodes`: read from `/data/gtos/bootnodes.csv`
- `--password`: `/data/gtos/pass.txt`
- `--unlock` / `--miner.coinbase`: addresses from `/data/gtos/validator_accounts.txt`

Recommended service settings:

- `Restart=always`
- `RestartSec=2`
- `LimitNOFILE=1048576`
- `WantedBy=multi-user.target`

## 5. Enable and start services

```bash
sudo systemctl daemon-reload
sudo systemctl enable gtos-node1 gtos-node2 gtos-node3
sudo systemctl start gtos-node1 gtos-node2 gtos-node3
```

## 6. Verify network health

```bash
cd ~/gtos
scripts/local_testnet_3nodes.sh status
scripts/local_testnet_3nodes.sh verify
```

Expected results:

- All 3 services are `active (running)`
- Each node has `peers=2`
- Block height keeps increasing
- Miner/validator rotation is visible across all 3 validator addresses

## 7. Service operations

Start:

```bash
sudo systemctl start gtos-node1 gtos-node2 gtos-node3
```

Stop:

```bash
sudo systemctl stop gtos-node1 gtos-node2 gtos-node3
```

Restart:

```bash
sudo systemctl restart gtos-node1 gtos-node2 gtos-node3
```

Status:

```bash
systemctl status gtos-node1 gtos-node2 gtos-node3
```

Logs:

```bash
journalctl -u gtos-node1 -u gtos-node2 -u gtos-node3 -f
```

## 8. Cleanup

Stop services first:

```bash
sudo systemctl stop gtos-node1 gtos-node2 gtos-node3
```

Clean chain data and runtime logs (keystore preserved):

```bash
cd ~/gtos
scripts/local_testnet_3nodes.sh clean
```

## 9. Common issues

- Services start but blocks do not grow:
  - Confirm validator accounts are unlocked
  - Check `--password /data/gtos/pass.txt` is valid
  - Re-run `precollect-enode`, then restart services
- Nodes have no peers:
  - Verify `/data/gtos/bootnodes.csv` and `static-nodes.json`
  - Ensure ports `30311-30313` are free
- Datadir not initialized:
  - Run `scripts/local_testnet_3nodes.sh setup` again
- Miner silently stalls at the first epoch boundary (no new blocks, no logs):
  - The genesis `alloc` is missing TOS3 validator slots.
  - See [docs/DPOS_GENESIS_VALIDATOR_SLOTS.md](DPOS_GENESIS_VALIDATOR_SLOTS.md)
    for the slot layout and how to regenerate them with
    `scripts/gen_genesis_slots/main.go`.
