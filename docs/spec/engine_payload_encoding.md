# Engine Payload Encoding（Phase 1 协商）

文档更新时间：`2026-02-21`

## 1. 背景

当前 `~/gtos` 与 `~/tos` 在交易对象与执行语义上尚未完全统一。为避免在 Engine API 上出现“同名字段、不同语义”的隐式分叉，Phase 1 增加显式编码协商位：`payload_encoding`。

## 2. 字段定义

`engine_getPayload` 返回：

- `payload`: 十六进制字节串（`0x...`）
- `payload_encoding`: 字符串编码标识
- `payload_commitment`: 对 `payload` 原始字节计算的承诺值

## 3. 已启用编码

### `tos_v1`

- 含义：`payload` 为 TOS 执行层定义的 `tos_v1` 编码字节。
- 二进制格式（固定）：
  - `version`：`u8`，当前固定为 `0x01`
  - `tx_count`：`u32`（大端）
  - 重复 `tx_count` 次：
    - `tx_len`：`u32`（大端）
    - `tx_bytes`：长度为 `tx_len` 的原始交易字节
- 当前 Phase 1 实现状态：
  - `~/tos` `GetPayload` 返回 canonical 空 frame：`payload = 0x0100000000`，并标注 `payload_encoding=tos_v1`。
  - `~/tos` `NewPayload` 已接入 `tos_v1` 结构化校验（版本、长度、trailing bytes）。
  - `~/gtos` 在 proposer 路径校验：
    - `payload_encoding` 必须为空或 `tos_v1`
    - `payload_commitment` 必须与 `payload` 字节一致（按 BLAKE3）
    - `tos_v1` payload 已接入 frame 解码；对格式错误按 fallback 开关处理

## 4. 兼容规则

1. `payload_encoding` 为空：视为旧节点，按 `tos_v1` 兼容路径处理。
2. `payload_encoding` 非空且未知：
   - 若启用 fallback：回退到本地 txpool。
   - 若禁用 fallback：直接报错拒绝该 payload。

## 5. Phase 1 到 100% 的前置要求

以下任一方案落定后，才能把 `GetPayload/NewPayload` 从“最小语义”推进到真实执行闭环：

1. 统一交易模型：`~/gtos` 与 `~/tos` 共享同一交易编码与执行对象。
2. 明确转换层：定义并实现 `tos tx -> gtos tx`（或反向）可验证映射，并冻结哈希/签名口径。
