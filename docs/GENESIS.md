# GTOS Genesis 配置指南（DPoS）

本文给出 GTOS DPoS 的 `genesis.json` 完整配置方法，基于：

- [DPOS_GENESIS_VALIDATOR_SLOTS.md](./DPOS_GENESIS_VALIDATOR_SLOTS.md)
- 当前机器上正在运行的 3 节点 testnet 实例参数

## 1. 本文覆盖内容

- 如何构造可用的 GTOS DPoS genesis
- 如何在创世块预写 TOS3（验证者注册表）slots
- 如何用同一 genesis 初始化 3 个节点
- 如何在启动后验证 genesis 是否正确

## 2. `~/data` 与 `/data` 路径说明

当前机器的真实 testnet 数据目录是：

- `/data/gtos`

如果你希望使用 `~/data` 路径，可以通过脚本覆盖 `BASE_DIR`：

```bash
cd ~/gtos
mkdir -p ~/data/gtos
BASE_DIR=~/data/gtos scripts/local_testnet_3nodes.sh setup
```

下文示例统一写 `~/data/gtos`，若你的运行目录是 `/data/gtos`，直接替换前缀即可。

## 3. Genesis 必要字段（DPoS）

GTOS DPoS genesis 至少应包含：

- `config.chainId`
- `config.dpos.periodMs`
- `config.dpos.epoch`
- `config.dpos.maxValidators`
- `config.dpos.sealSignerType`
- `extraData`（32-byte vanity + 初始验证者地址串）
- `alloc`（账户初始余额）
- TOS3（`0x...0003`）的验证者注册表 storage

注意：

- GTOS 地址长度是 32 字节（`0x` + 64 hex）。
- 如果创世时 TOS3 没有预置验证者 slots，链可能在 epoch 边界停产。

## 4. 推荐方法：脚本自动生成

使用 `scripts/local_testnet_3nodes.sh`。

### 4.1 生成账户 + genesis + init

```bash
cd ~/gtos
BASE_DIR=~/data/gtos scripts/local_testnet_3nodes.sh setup
```

这一步会自动完成：

- 创建/复用 node1/node2/node3 的验证者账户
- 生成 `genesis_testnet_3vals.json`
- 对 3 个 datadir 执行 `gtos init`

关键输出：

- `~/data/gtos/validator_accounts.txt`
- `~/data/gtos/validators.sorted`
- `~/data/gtos/genesis_testnet_3vals.json`

### 4.2（可选）预采集 enode 与 peers 文件

```bash
cd ~/gtos
BASE_DIR=~/data/gtos scripts/local_testnet_3nodes.sh precollect-enode
```

输出：

- `~/data/gtos/node_enodes.txt`
- `~/data/gtos/bootnodes.csv`
- `~/data/gtos/node{1,2,3}/gtos/static-nodes.json`

## 5. 手工方法（从零构造）

### 5.1 确定 DPoS 参数

示例参数：

- `chainId = 1666`
- `periodMs = 360`
- `epoch = 1667`
- `maxValidators = 15`
- `sealSignerType = "ed25519"`

### 5.2 准备验证者地址

准备 3 个 32-byte 地址，并按字典序排序（用于 `extraData` 与 `validatorList`）。

### 5.3 生成 TOS3 storage slots

```bash
cd ~/gtos
go run ./scripts/gen_genesis_slots/main.go \
  <validator1> <validator2> <validator3>
```

该命令会输出可直接粘贴到 genesis 的 `"storage"` JSON，包含：

- `validatorCount`
- `validatorList[i]`
- `selfStake`
- `registered`
- `status`

### 5.4 构造 `extraData`

`extraData` 格式：

- 32-byte vanity（可全 0）
- 后接排序后的验证者地址（去掉 `0x`，直接拼接）

### 5.5 组装 genesis

- 把验证者账户写入 `alloc` 并给初始余额
- 把 TOS3 账户（`0x...0003`）写入 `alloc`，并填入步骤 5.3 的 `storage`

## 6. 当前 testnet 实例（真实值示例）

来源：`/data/gtos`。

### 6.1 当前验证者集合（已排序）

来自 `/data/gtos/validators.sorted`：

- `0x116935ffb42c06360f8d7f78c8107f5b14b43400e7da9e71082a81db08b87c44`
- `0x15f0aeb8f7a7562b8fcbeba8845518bd5c1d93c76ecf0756cfe3e9a96e2343bc`
- `0x89ecd491f12a6b43d7fbb8aff4dab13aeb47eaae43211d21299d246b40643c28`

### 6.2 当前 DPoS 配置

来自 `/data/gtos/genesis_testnet_3vals.json`：

- `chainId: 1666`
- `periodMs: 360`
- `epoch: 1667`
- `maxValidators: 15`
- `sealSignerType: ed25519`
- `gasLimit: 0x1c9c380`

### 6.3 当前 testnet 的 enode/端口（运行中实例）

来自 `/data/gtos/node_enodes.txt` 与 systemd：

- node1: `enode://9c7e161d30c346e136c2d3706d734085a62d066c67db33e1d6c7d6fa044a08e33b3bc198886f7e5caa9bae693c22b29606673745d1e2fab6e707f3110b52eeec@127.0.0.1:30311`
- node2: `enode://15e124f7f7d42cbab626d31617e1b132acaac9fbe7e8994d5735c9d769a5f1a801450c1d039a02eff24902321b0426f13b8dd323fc707cef60b7c8b2ad7af0f4@127.0.0.1:30312`
- node3: `enode://86af05fe22d851eb5bb53e9810e4a6fce2777736e29cf44622b5488532bdbd2f66e9d45f5cc60d5df8594bc5ab0697c21bb2b4e2103b4e1199245616820de171@127.0.0.1:30313`

HTTP RPC 端口：

- node1: `8545`
- node2: `8547`
- node3: `8549`

### 6.4 完整 genesis 示例（同参数）

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

## 7. 初始化与启动

假设 3 个数据目录：

- `~/data/gtos/node1`
- `~/data/gtos/node2`
- `~/data/gtos/node3`

统一初始化：

```bash
~/gtos/build/bin/gtos --datadir ~/data/gtos/node1 init ~/data/gtos/genesis_testnet_3vals.json
~/gtos/build/bin/gtos --datadir ~/data/gtos/node2 init ~/data/gtos/genesis_testnet_3vals.json
~/gtos/build/bin/gtos --datadir ~/data/gtos/node3 init ~/data/gtos/genesis_testnet_3vals.json
```

如果你使用 systemd：

```bash
sudo systemctl daemon-reload
sudo systemctl start gtos-node1 gtos-node2 gtos-node3
```

完整服务部署见：[LOCAL_TESTNET_3NODES_SYSTEMD.md](./LOCAL_TESTNET_3NODES_SYSTEMD.md)

## 8. 启动后校验

### 8.1 校验 TOS3 的 validatorCount

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

期望返回十六进制 `0x...03`（即验证者数量为 3）。

### 8.2 校验网络状态

```bash
cd ~/gtos
BASE_DIR=~/data/gtos scripts/local_testnet_3nodes.sh status
BASE_DIR=~/data/gtos scripts/local_testnet_3nodes.sh verify
```

期望：

- 3 节点都在运行
- peerCount > 0
- 区块高度持续增长
- miner/validator 有轮转

## 9. 常见故障

- **epoch 边界停产（无新块）**
  - 原因：genesis 未预置 TOS3 validator slots
  - 处理：重跑 `scripts/gen_genesis_slots/main.go`，重建 genesis，清库后重新 init

- **节点间 genesis 不一致**
  - 原因：不同节点 init 了不同内容的 genesis 文件
  - 处理：统一一个 `genesis_testnet_3vals.json`，清理 chaindata 后全部重 init

- **节点互联失败（peers=0）**
  - 检查 `bootnodes.csv`、`static-nodes.json`、端口 `30311-30313`

## 10. 参考文档

- DPoS validator slots： [DPOS_GENESIS_VALIDATOR_SLOTS.md](./DPOS_GENESIS_VALIDATOR_SLOTS.md)
- 3 节点 systemd： [LOCAL_TESTNET_3NODES_SYSTEMD.md](./LOCAL_TESTNET_3NODES_SYSTEMD.md)
- 自动化脚本： `scripts/local_testnet_3nodes.sh`
