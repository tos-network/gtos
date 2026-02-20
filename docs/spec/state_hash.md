# State Hash Spec (Phase 1)

状态：`Phase 1 规格已冻结，实现联调进行中（截至 2026-02-20）`

## 目标

定义共识层与执行层一致的 `state_hash` 口径，避免分叉。

## Phase 1 规则

- 采用执行层最终提交状态根（post-state root）作为 `state_hash`。
- 同一 `parent + payload` 必须得到确定性唯一 `state_hash`。
- 校验发生在投票前，不一致直接拒绝投票。

## 输入边界

- `parent_hash`
- `payload`（交易顺序必须固定）
- 执行规则版本（硬分叉高度对应版本）

## 非目标（Phase 1）

- 不在本阶段定义并行 lanes 的合并哈希规则。
- 不在本阶段定义跨实现的零拷贝序列化规范。

## 后续扩展（Phase 2+）

- lanes 并行执行后的确定性归并规则。
- `receipts_hash` 与 `state_hash` 的联动约束。
