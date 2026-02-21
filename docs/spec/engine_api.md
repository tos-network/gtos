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
- `payload` 当前默认返回 canonical 空 `tos_v1` frame（`0x0100000000`），`payload_commitment` 为 payload 原始字节哈希。
- `gtos` proposer 侧会校验 `payload_encoding/payload_commitment`，不匹配时按 fallback 开关处理。
- `gtos` proposer 侧已支持 `tos_v1` frame 解码（tx blob 列表）；`tos` 侧 `NewPayload` 已接入 `tos_v1` 结构校验。
- `~/gtos` 与 `~/tos` 的交易对象语义仍未统一（仅完成 frame 级对齐），真实执行闭环仍待完成。

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
