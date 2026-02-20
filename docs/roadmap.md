下面给你们一个“最顶端”的一体化设计（**Go: gtos=共识/排序/最终性** + **Rust: tos=执行/状态/txpool/并行**），并给一份按阶段推进的 roadmap，分别列出 gtos 和 tos 需要改什么。

> 文档状态（截至 2026-02-20）：**规划已确认，实施中（Phase 1：`~/gtos` 中段、`~/tos` 早段）**。

> 当前进度快照（截至 2026-02-20）：
> - `~/gtos`（`main`）：已完成 Engine API 客户端接线、提议/导入路径调用、BFT vote/QC 骨架与网络桥接、QC 触发 safe/finalized 推进、`tosalign` 签名地址库引入。
> - `~/tos`（`feature/execution-layer`）：已完成 `execution_layer_mode`、禁用 mining/getwork 主路径、`submit_execution_block` RPC，且已新增 `engine_getPayload / engine_newPayload / engine_forkchoiceUpdated` 最小服务端骨架。
> - 关键未完成项：`~/tos` Engine API 目前仍是“最小语义”（空 payload/基础校验）；`forkchoiceUpdated` 已支持 `head/safe/finalized` 哈希持久化并可按 `finalized_hash` 推进 stable 指针，但尚未接入真实 payload 构建与执行校验路径，双端闭环联调（3 节点 100+ finalized）尚未完成。

> 你们已经做了一个非常关键的选择：**Base 验证者同时也是 TOS 执行者**。这让体系可以像“以太坊合并后”那样分层，同时还能把“执行结果（state_hash）”纳入共识签名闭环。

---

## 1) 顶层目标与核心原则

### 目标

* **共识侧（gtos）**：只负责 *排序 + BFT 最终性 + 区块传播 + 验证者集合管理*
* **执行侧（tos）**：只负责 *交易池 + 并行执行 + 状态DB + receipts + state_hash 计算 + 查询RPC*
* 区块最终签名对象必须包含：
  **`(tx_payload_commitment + state_hash + parent)`**
  这样“顺序”和“执行结果”一起被 2/3 最终化。

### 核心原则（很重要）

1. **mempool 只保留在 tos**（执行侧），gtos 不维护完整 txpool
2. **状态DB 只保留在 tos**（执行侧），gtos 不维护用户 balance/nonce/合约状态
3. gtos 与 tos 用 **本地 RPC（Engine API 风格）**交互，接口是“合同”，防止分叉
4. 一个高度的区块提议流程中：**先执行得到 state_hash，再投票签最终性**

---

## 2) 节点形态

### Validator 节点（你们的主节点）

同一台机器跑两个进程：

* `gtos-consensusd`（Go）：共识 P2P、提议、投票、finality(QC)
* `tos-executord`（Rust）：tx gossip + mempool + lanes 打包 + 并行执行 + state DB

二者通过本地 socket（Unix domain socket / 127.0.0.1）通讯，带认证（JWT/mTLS/文件权限）。

### RPC / Fullnode（非验证者）

可以只跑 `tos-executord`（用于对外 RPC、索引、交易转发），用 gtos 的最终区块流做同步。

---

## 3) 顶层数据流（最关键）

### 3.1 交易流（tx path）

1. 用户 → `tos-executord` 提交交易
2. `tos` 做基本校验 + 放入 mempool + gossip
3. `gtos` **不直接接收用户交易**（或只接收转发但不建完整 txpool）

### 3.2 出块与最终性（block proposal & finality）

假设高度 `h`：

**(A) proposer（gtos）向本机 tos 要 payload**

* `gtos -> tos: GetPayload(parent_hash, height, limits, validator_context)`
* `tos` 从 mempool 选交易、做 lanes 分组（并行友好），并在本机执行得到：

  * `payload(lanes/txs)`
  * `state_hash_h`
  * `receipts_hash_h`（可选但强烈建议）
* `tos -> gtos: Payload + state_hash_h + receipts_hash_h`

**(B) gtos 提议区块并广播**

* 区块头包含：`parent, height, payload_commitment, state_hash_h, receipts_hash_h, validator_set_id`
* 区块体包含：`payload(lanes/tx_bytes or tx_hashes+body)`（MVP 建议带 tx_bytes）

**(C) 其他验证者验证提议（执行在投票前）**

* 他们收到 proposal 后：

  * `gtos -> local tos: NewPayload(payload, parent_hash)`
  * `tos` 重新执行，算出 `state_hash'`
  * 若 `state_hash' == proposal.state_hash_h`，则 `gtos` 投票
* 达到 2/3 后形成 `QC`，区块 finalized

**(D) finalized 通知执行端**

* `gtos -> tos: ForkchoiceUpdated(finalized_head, safe_head)`
* `tos` 标记 finalized，高度推进，可做裁剪/快照

> 这一套流程，本质就是你们自己的 “Engine API” + BFT finality 版以太坊合并架构。

---

## 4) 共识要签的区块结构（建议的最小集合）

### BaseBlockHeader（gtos 共识对象）

* `parent_hash`
* `height`
* `timestamp/slot`
* `validator_set_id`
* `payload_commitment`（例如 hash(lanes+txs)）
* `state_hash`（执行后状态承诺）
* `receipts_hash`（可选，强烈建议）
* `qc` / `finality_proof`（2/3+，最好阈值签名）

### BaseBlockBody

* `lanes[]`（每 lane 一组交易，lane 内串行，lane 间并行）
* `tx_bytes[]`（MVP 直接带完整 tx；后续可升级为 DA/按需拉取）

---

## 5) Roadmap（分阶段交付，不需要一次做完）

我按“最短闭环 → 并行提升 → Solana式冲突显式化”的顺序排。

### Phase 0：规格冻结（必须先做，不然后面一定分叉）

**共同工作**

* 冻结 **区块头字段**、`payload_commitment/state_hash` 计算口径
* 冻结 **Engine API**（本地RPC）方法与字段
* 冻结 **交易序列化与 hash**（至少 tos 内部先统一，后续再做跨语言库）

交付物：

* `spec/block.md`
* `spec/engine_api.md`
* `spec/state_hash.md`

---

### Phase 1：最小可跑闭环（先把链跑起来）

**gtos（Go）要做**

* 接入/实现 BFT finality（2/3 QC）+ DPoS validator set（epoch 轮换）
* 实现 Engine API “客户端”（调用本机 tos）：

  * `GetPayload`
  * `NewPayload`
  * `ForkchoiceUpdated`
* 共识出块流程改为：**先拿 state_hash，再提议，再投票**
* 区块头增加 `payload_commitment + state_hash (+ receipts_hash)` 并参与签名

**tos（Rust）要做**

* 实现 Engine API “服务端”（被 gtos 调用）
* 先用 **串行执行**也可以（你们现有执行逻辑先顶上），但必须输出确定的 `state_hash`
* `GetPayload`：从 mempool 选 tx（可先复用你现有 tx 选择逻辑）
* `NewPayload`：执行并校验 `state_hash`
* `ForkchoiceUpdated`：推进 finalized 高度

---

### Phase 2：去掉 tos 的 BlockDAG 共识（把 tos 变成纯执行层）

**tos（Rust）要做**

* 删除/旁路“BlockDAG 排序与分叉选择”路径，改为：

  * 只按 gtos finalized blocks 输入执行
* 将原来 “本地挖矿/出块/排序” 代码迁移到 `GetPayload`（由执行端给 proposer 提供 payload）
* 执行 pipeline 做成“输入 block → 执行 → 写DB → 产出 state_hash”

**gtos（Go）要做**

* 区块同步/广播逻辑完善（保证所有验证者能拿到完整 payload）
* finalized head 的推进逻辑清晰（forkchoice 简化也行）

---

### Phase 3：引入 lanes 并行（把吞吐拉起来）

**tos（Rust）要做**

* 引入 `lanes[]` 执行模型：

  * lane 内串行
  * lane 间并行
* 改造状态写入方式（关键！）：

  * 不要每笔 tx 直接落 DB
  * 做 `InMemoryState / StateDelta` + batch commit
* 确保 `state_hash` 在并行下仍然确定（deterministic）

**gtos（Go）要做**

* 区块体支持 lanes（只是携带与传播）
* proposer/validator 流程不变：投票前本机执行校验 state_hash

---

### Phase 4：Solana式“冲突摆在明处”（并行效率进一步提升）

这是你们想要“像 Solana 一样”的关键阶段。

**tos（Rust）要做**

* 交易新增 `access_list`（只读/可写对象列表）——或至少可写集合
* runtime 硬约束：交易执行期间 **只能访问声明对象**，否则 abort
* lanes 打包依据从“地址排他”升级为“writable objects 不相交”
* 对热点对象做 bucket 化（否则并行被热点打回原形）

**gtos（Go）要做**

* 共识仍然不需要理解 access_list 细节（可以当 payload opaque）
* 但建议在共识层加“payload 体积/对象数上限”的 DoS 防护参数

---

### Phase 5：工程化与性能化（把系统变成生产级）

* 快速同步：snapshot / state sync（只对 finalized 高度）
* receipts/log 索引、事件订阅、交易回执稳定性
* 网络分层：共识消息与交易 gossip 分开 QoS
* 数据可用性优化：payload 由“全量 tx_bytes”升级为 “commitment + 按需拉取/纠删码”

---

## 6) gtos / tos 各自需要修改什么（按模块拆）

### gtos（Go，共识侧）需要的改动清单

1. **共识内核**

   * 从“原有出块/挖矿/PoW/PoA”切到：`DPoS validator set + BFT finality(QC)`
   * epoch 管理、validator set 更新、投票权重、（可选）slashing/jailing

2. **区块结构**

   * header 增加：`payload_commitment`、`state_hash`、`receipts_hash`、`validator_set_id`、`qc`
   * body 增加：`payload(lanes + tx)`（MVP 先全量携带）

3. **Engine Bridge（关键新增）**

   * 作为客户端调用本机 `tos-executord`
   * proposer 时：`GetPayload`
   * validator 时：`NewPayload`
   * finalized 后：`ForkchoiceUpdated`

4. **mempool/用户账户状态**

   * 删除或禁用“完整 txpool/account state”（避免双状态源）
   * 最多保留轻量转发缓存/去重缓存

5. **对外 RPC**

   * 共识层 RPC 只提供：区块头/最终高度/validator set 等
   * 用户余额/交易回执查询全部走 tos

---

### tos（Rust，执行侧）需要的改动清单

1. **删除/旁路 BlockDAG 共识**

   * 把现有“blockdag 排序、重排、分叉处理”从主路径移出
   * 主路径变成：`Import finalized block -> Execute -> Commit state -> Serve queries`

2. **Engine API Server（关键新增）**

   * `GetPayload`: txpool 选 tx + lanes 打包（可先复用现有 selector）
   * `NewPayload`: 执行并返回 computed state_hash（用于验证 proposal）
   * `ForkchoiceUpdated`: 更新 head/finalized，做 prune/snapshot

3. **txpool/mempool（保留并强化）**

   * 交易准入：签名/nonce/费用/过期/替换策略
   * 交易传播（gossip）也建议留在 tos

4. **并行执行（lanes）**

   * 引入 lane scheduler + worker pool
   * 引入 `InMemoryState/StateDelta`，最后 batch commit 到 DB
   * 定义 deterministic commit order（例如 `(height,lane_id,idx)`）

5. **state_hash/receipts_hash**

   * 必须定义稳定算法（hash 输入必须确定、排序确定）
   * 建议同时输出 receipts digest，避免“执行结果无法对账”

6. **Solana式 access_list（后续阶段）**

   * 交易结构增加读写集合
   * runtime 强约束不越权访问
   * lanes 打包基于 writable set

---

## 7) 你们最先要拍板的 3 个“规格开关”

不需要你现在回答我，我给默认建议（你们可以按默认直接做）：

1. **Engine API 用 gRPC + protobuf**（比 JSON-RPC 更适合传 payload/批量结果）
2. **MVP：gtos 传播 full payload（含 tx_bytes）**，后面再做 DA/按需拉取
3. **state_hash：先做“变更集摘要（diff commitment）”或“全状态hash”二选一**

   * MVP 可先 diff commitment（更容易做且快），后续再加周期 checkpoint root

---

如果你愿意，我下一步可以把 “Engine API” 直接写成一份 proto（Go/Rust 都能生成代码），并把每个 RPC 的字段定死：

* `GetPayloadRequest/Response`
* `NewPayloadRequest/Response`
* `ForkchoiceUpdatedRequest/Response`
  以及 `BlockHeader/Lane/Tx/TxResult` 的结构，确保你们两边实现不会分叉。
