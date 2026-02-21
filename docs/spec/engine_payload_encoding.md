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

### `eth_rlp_txs`

- 含义：`payload` 为 Ethereum 风格 RLP 交易列表字节。
- 当前 Phase 1 实现状态：
  - `~/tos` 返回占位空列表：`payload = 0xc0`，并标注 `payload_encoding=eth_rlp_txs`。
  - `~/gtos` 在 proposer 路径校验：
    - `payload_encoding` 必须为空或 `eth_rlp_txs`
    - `payload_commitment` 必须与 `payload` 字节一致（按 BLAKE3）

## 4. 兼容规则

1. `payload_encoding` 为空：视为旧节点，按 `eth_rlp_txs` 兼容路径处理。
2. `payload_encoding` 非空且未知：
   - 若启用 fallback：回退到本地 txpool。
   - 若禁用 fallback：直接报错拒绝该 payload。

## 5. Phase 1 到 100% 的前置要求

以下任一方案落定后，才能把 `GetPayload/NewPayload` 从“最小语义”推进到真实执行闭环：

1. 统一交易模型：`~/gtos` 与 `~/tos` 共享同一交易编码与执行对象。
2. 明确转换层：定义并实现 `tos tx -> gtos tx`（或反向）可验证映射，并冻结哈希/签名口径。
