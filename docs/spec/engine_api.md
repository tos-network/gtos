# Engine API Spec (Phase 1)

状态：`Phase 1 规格已冻结，双端实现部分完成（截至 2026-02-21）`

共识层（`gtos`）与执行层（`tos`）使用本地 Engine API 交互。

## 1. `GetPayload`

用途：proposer 请求可提议 payload 及执行结果承诺。

请求最小字段：

- `parent_hash`
- `height`
- `timestamp`

响应最小字段：

- `payload`
- `payload_encoding`
- `payload_commitment`
- `state_hash`
- `receipts_hash`

Phase 1 约定（当前 gtos 适配器）：

- `payload_encoding` 基线为 `tos_v1`。
- `payload` 当前可返回占位空字节（`0x`），`payload_commitment` 为 payload 原始字节哈希。
- `gtos` proposer 侧会校验 `payload_encoding/payload_commitment`，不匹配时按 fallback 开关处理。
- 非空 `tos_v1` payload 的解码执行路径仍在 Phase 1 后续任务中实现。

## 2. `NewPayload`

用途：validator 在投票前执行校验。

请求最小字段：

- `payload`
- `parent_hash`

响应最小字段：

- `valid`
- `state_hash`

## 3. `ForkchoiceUpdated`

用途：finalized 后同步执行层头部状态。

请求最小字段：

- `head_hash`
- `safe_hash`
- `finalized_hash`

响应：空响应即可（Phase 1）。

## 安全要求（Phase 1）

- 仅本地监听（`127.0.0.1` 或 Unix socket）。
- 支持 JWT 文件鉴权配置（先保留配置位，后续强制）。
