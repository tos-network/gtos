# GTOS->CL + TOS->EL Phase 1 最小落地改造清单（按周）

## 0. 当前完成状态（截至 2026-02-20）

- 总体状态：`Phase 1 进行中（中段）：~/gtos 进度领先，~/tos 仍在早段`
- Week 1：`部分完成（~/gtos 已完成规格与客户端骨架；~/tos 的 engine_api server 骨架未落地）`
- Week 2：`部分完成（~/gtos 主路径已接 Engine API 客户端；~/tos 的 GetPayload 服务端未落地）`
- Week 3：`部分完成（~/tos 已完成 execution_layer_mode、外部入块 RPC、Engine API 三方法骨架；执行语义未完成）`
- Week 4：`部分完成（~/gtos 已有 BFT/QC 骨架+网络桥接+签名校验；3 节点闭环联调未完成）`
- Week 5：`未开始`

已完成（`~/gtos`）：
- [x] 新增 `docs/spec/block.md`
- [x] 新增 `docs/spec/engine_api.md`
- [x] 新增 `docs/spec/state_hash.md`
- [x] 新增 `engineapi/proto/engine.proto`
- [x] 新增 `engineapi/client/client.go`（week-1 scaffold）
- [x] `engineapi/client` 接入真实 JSON-RPC 调用（`GetPayload/NewPayload/ForkchoiceUpdated`，含 method fallback + JWT header）
- [x] `cmd/gtos` 增加 `engine.*` 配置与 CLI flags 接线
- [x] `gtos` 启动时可注入 Engine bridge 客户端（stub，未切换出块主路径）
- [x] `miner.fillTransactions` 先尝试 `GetPayload`；新增 `engine.allow-txpool-fallback` 兼容开关（默认关闭）
- [x] 导入区块前接入 `NewPayload` 校验钩子；校验 `state_hash` 与区块 `stateRoot` 一致；`ForkchoiceUpdated` 改为按 `head/safe/finalized` 变化触发（失败降级）
- [x] 新增 `consensus/bft` 最小骨架：`types.go`、`vote_pool.go`、`qc.go`、`reactor.go`（含单测）
- [x] `tos` 协议层接入 `Vote/QC` 消息（`protocol/handler/peer`）并桥接到 `consensus/bft`（含广播与接收处理）
- [x] QC 到达后推进本地 `chain safe/finalized`，并回调触发 `ForkchoiceUpdated` 通知执行层
- [x] 链头事件触发本地验证者自动投票（DPoS 签名），并抑制重复 vote/QC 广播
- [x] `Vote/QC` 接收侧增加签名校验与 QC 见证集合一致性校验
- [x] `tos/bft_bridge.go` 拆分为 `bft_codec.go / bft_finality.go / bft_verifier.go`，并补充桥接测试覆盖
- [x] 新增 `crypto/tosalign/*`，引入与 `~/tos` 对齐的地址与签名相关算法实现
- [x] 新增 `tos/backend_engine_validation_test.go`，覆盖 Engine `NewPayload` 导入校验关键分支（拒绝/匹配/降级）

已完成（`~/tos`，分支 `feature/execution-layer`）：
- [x] 新增执行层模式开关：`execution_layer_mode`
- [x] 执行层模式下自动禁用 `getwork` 与 mining RPC 注册
- [x] 新增执行层入块 RPC：`submit_execution_block`
- [x] 新增 Engine API 三方法：`engine_getPayload / engine_newPayload / engine_forkchoiceUpdated`（含 snake/camel 方法名兼容）

进行中 / 未完成（Phase 1 关键阻塞）：
- [ ] `~/tos` Engine API 仍为最小骨架：`GetPayload` 仍返回空 payload，`NewPayload` 尚未接入真实执行校验
- [ ] `~/tos` 已支持 `ForkchoiceUpdated` 的 `head/safe/finalized` 哈希持久化，并可按 `finalized_hash` 推进 stable 指针；完整执行侧收敛路径仍未完成
- [ ] `~/gtos` 与 `~/tos` 尚未完成 3 验证者 `2/3 QC` 连续 finalized 100+ 区块联调
- [ ] 端到端用例缺口：`~/gtos/tests/cl_el_phase1_test.go`、`~/tos` 侧 Engine API Phase1 测试仍需补齐

## 1. Phase 1 范围（只做“能跑通”）

- 目标：`~/gtos` 负责提议/投票/QC最终性/验证者集；`~/tos` 负责 txpool/执行/状态/查询。
- 交易范围（MVP）：先只支持 `GTOS transfer + system action(VALIDATOR_*)`。
- 执行模型：先串行执行，不上 lanes。
- 网络目标：先跑通单节点闭环，再跑通 3 验证者 `2/3` QC。

## 2. Phase 1 完成标准（DoD）

- `gtos proposer` 只通过 Engine API 向 `tos` 要 payload，不再本地选 tx。
- `gtos validator` 投票前必须调用 `tos.NewPayload`，并校验 `state_hash` 一致。
- 达到 QC 后 `gtos` 调用 `tos.ForkchoiceUpdated(finalized,safe)`。
- `tos` 开启 `engine_mode` 时不再走本地出块/本地排序主路径（getwork 与 blockdag 主路径旁路）。
- 3 节点联调可连续 finalized 100+ blocks。

---

## Week 1：规格冻结 + 双端骨架

### gtos 仓修改

- 新增 `docs/spec/block.md`
- 新增 `docs/spec/engine_api.md`
- 新增 `docs/spec/state_hash.md`
- 新增 `engineapi/proto/engine.proto`
- 新增 `engineapi/client/client.go`（先打桩）
- 修改 `cmd/gtos/config.go`（新增 `engine` 配置项）

### tos 仓修改（`/home/tomi/tos`）

- 新增 `daemon/src/engine_api/mod.rs`
- 新增 `daemon/src/engine_api/server.rs`（先返回 mock）
- 修改 `daemon/src/config.rs`（新增 `engine_mode`、engine listen 地址）
- 修改 `daemon/src/main.rs`（启动 engine api server）

### 本周验收

- 双端都能编译。
- `GetPayload/NewPayload/ForkchoiceUpdated` 三个接口可连通（先 mock 返回）。

---

## Week 2：gtos 提议路径切到 Engine API

### gtos 仓修改

- 修改 `tos/backend.go`（初始化并注入 Engine client）
- 修改 `miner/worker.go`
  - 把 `fillTransactions` 主路径替换为 `GetPayload` 返回值
  - 本地 txpool 仅保留兼容开关（默认关闭）
- 新增 `consensus/clpayload/extra.go`
  - 定义 Phase 1 的 `header.Extra` 承载结构（版本号 + qc 占位）
- 修改 `consensus/dpos/dpos.go`（保持签名覆盖新增 Extra 编码）
- 修改 `cmd/gtos/main.go`（增加 `--engine.*` 启动参数接线）

### tos 仓修改

- 修改 `daemon/src/engine_api/server.rs`
  - 实现 `GetPayload`：复用 tx 选择逻辑生成 payload
- 修改 `daemon/src/core/blockchain.rs`
  - 抽出 payload 构建函数（从 mempool 取 tx，返回 tx bytes + commitment）

### 本周验收

- 单节点下，`gtos` 出块使用的是 `tos.GetPayload` 返回的数据。
- 区块可连续生产（先不要求多节点投票）。

---

## Week 3：tos 执行校验 + gtos 投票前校验

### tos 仓修改

- 修改 `daemon/src/engine_api/server.rs`
  - 实现 `NewPayload`：执行并回传 `computed_state_hash`
  - 实现 `ForkchoiceUpdated`：更新 finalized/safe head
- 修改 `daemon/src/core/blockchain.rs`
  - 新增 payload dry-run 执行入口
  - 新增 finalized 标记与提交入口
- 修改 `daemon/src/core/config.rs`（`engine_mode` 下行为开关）
- 修改 `daemon/src/rpc/getwork/mod.rs`（`engine_mode` 下禁用）
- 修改 `daemon/src/rpc/rpc.rs`（`submit_block/get_block_template` 在 `engine_mode` 下禁用）

### gtos 仓修改

- 新增 `consensus/enginebridge/verifier.go`
  - 在投票前调用 `NewPayload`
- 修改 `consensus/dpos/dpos.go` 或投票调度调用点
  - 未通过 `NewPayload` 校验不得投票
- 修改 `core/blockchain.go`
  - finalized 事件触发 `ForkchoiceUpdated`

### 本周验收

- follower 收到 proposal 后会先执行 `NewPayload`，`state_hash` 不一致时拒绝投票。
- finalized 后 `tos` 头部状态可观察推进。

---

## Week 4：最小 QC 闭环（3 节点）

### gtos 仓修改

- 新增 `consensus/bft/types.go`
- 新增 `consensus/bft/vote_pool.go`
- 新增 `consensus/bft/qc.go`
- 新增 `consensus/bft/reactor.go`
- 修改 `tos/protocols/tos/protocol.go`（增加 vote/qc 消息类型）
- 修改 `tos/protocols/tos/handler.go`（处理 vote/qc 消息）
- 修改 `validator/state.go`（导出 validator_set_id 读取接口）

### tos 仓修改

- 修改 `daemon/src/engine_api/server.rs`
  - `ForkchoiceUpdated` 增加 finalized 落盘与裁剪触发点
- 修改 `daemon/src/core/blockchain.rs`
  - finalized 高度以下禁止重排（engine_mode）

### 本周验收

- 3 验证者环境达到 `2/3` 即形成 QC 并 finalized。
- 连续 finalized 100 blocks 无卡死、无状态分叉。

---

## Week 5：收口、压测、切换准备

### gtos 仓修改

- 新增 `tests/cl_el_phase1_test.go`（端到端）
- 修改 `cmd/gtos/config.go`（默认启用 engine 模式，保留回滚开关）
- 修改 `README.md`（新增 CL/EL 启动方式）

### tos 仓修改

- 新增 `daemon/tests/engine_api_phase1.rs`
- 修改 `daemon/src/p2p/mod.rs`（engine_mode 下只保留 tx gossip 必需子集）
- 修改 `README.md`（新增 executor 模式启动参数）

### 本周验收

- 基线压测（最小场景）可稳定运行 24h。
- 回滚开关验证通过（可切回旧路径）。

---

## 3. 实施顺序硬约束（不要打乱）

1. 先冻结三份 spec（Week 1）。
2. 再切 proposer 的 `GetPayload`（Week 2）。
3. 再上 validator 的 `NewPayload` 校验（Week 3）。
4. 最后接入 QC 最终性（Week 4）。

## 4. Phase 1 风险点（必须提前规避）

- 交易模型不一致风险：Week 1 必须明确统一交易编码与哈希口径。
- 状态哈希口径不一致风险：`state_hash` 输入范围必须写死在 `state_hash.md`。
- 双写路径风险：`engine_mode` 下要严格关停本地出块路径，避免双共识源。
