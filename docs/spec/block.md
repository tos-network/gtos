# CL/EL Block Spec (Phase 1)

状态：`Draft (Phase 1)`

## Header 字段（最小集）

- `parent_hash`
- `height`
- `timestamp`
- `validator_set_id`
- `payload_commitment`
- `state_hash`
- `receipts_hash`（可选，Phase 1 建议保留字段）
- `qc`（2/3 最终性证明）

## 共识签名对象

共识签名必须覆盖以下字段：

- `parent_hash`
- `height`
- `payload_commitment`
- `state_hash`
- `validator_set_id`

## Body（Phase 1）

- `payload`：先允许全量交易字节（后续可升级为 commitment + data availability）

## 验证规则（Phase 1）

- 提议前：proposer 先向执行层获取 `payload + state_hash`。
- 投票前：validator 必须本地重放执行并校验 `state_hash` 一致。
- finalized 后：共识层向执行层下发 forkchoice 更新。
