# gtos Security Bug Tracker

Audit date: 2026-03-07
Baseline: go-ethereum v1.10.25
Status: `CONFIRMED` · `FALSE_POSITIVE` · `BY_DESIGN` · `FIXED`

---

## Critical

### C-1 LVM gas 计量 uint64 溢出
**File**: `core/vm/lvm.go:630`
**Status**: CONFIRMED

```go
if vmUsed+totalChildGas+primGasCharged+cost > gasLimit {
```
全部 uint64，三项累加已接近 `math.MaxUint64` 时加 `cost` 回绕归零，
比较结果为假，绕过 gas 上限任意执行不扣费。

**Fix**:
```go
remaining := gasLimit - vmUsed - totalChildGas - primGasCharged
if cost > remaining { L.RaiseError("lua: gas limit exceeded"); return }
```

---

### C-2 共识层缺少 `GasUsed ≤ GasLimit` 头部校验
**File**: `consensus/dpos/dpos.go:431–469` — `verifyCascadingFields`
**Status**: CONFIRMED

`verifyCascadingFields` 只检查时间戳、slot、seal，未校验
`header.GasUsed <= header.GasLimit`。geth Clique 在此函数中做该检查。
gtos 的校验推迟到 `core/block_validator.go:83`（状态执行后），
造成头部链短暂接受 GasUsed > GasLimit 的无效块。

**Fix**: 在 `verifyCascadingFields` 添加：
```go
if header.GasUsed > header.GasLimit {
    return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d",
        header.GasUsed, header.GasLimit)
}
```

---

### C-3 共识层 `GasLimit` 下限校验不完整
**File**: `consensus/dpos/dpos.go:398–403` — `verifyHeader`
**Status**: CONFIRMED

```go
if header.GasLimit == 0 { return errors.New("invalid gasLimit: zero") }
if header.GasLimit > params.MaxGasLimit { ... }
```
`params.MinGasLimit = 5000`，当前只拒绝 0，值 1–4999 可通过验证。
geth 通过 `misc.VerifyGaslimit(parent.GasLimit, header.GasLimit)` 同时
校验下限和父块差距。

**Fix**: 替换为 `misc.VerifyGaslimit(parent.GasLimit, header.GasLimit)`
（需将下限检查移至获取 parent 后的位置）。

---

### C-4 Receipt `EncodeIndex` 对非 SignerTxType 静默写空
**File**: `core/types/receipt.go:365–373`
**Status**: CONFIRMED

```go
func (rs Receipts) EncodeIndex(i int, w *bytes.Buffer) {
    r := rs[i]
    if r.Type != SignerTxType {
        return          // 写入空内容，DefaultDeriveSha 产生错误 receipts root
    }
    ...
}
```
`EncodeIndex` 用于 `DeriveSha()` 构建 receipts root Merkle 树。
任何非 SignerTxType 的 receipt 导致对应叶节点为空，root hash 完全错误。
虽然 gtos 当前只有 SignerTxType，但防御性要求此处不能静默成功。

**Fix**: 将静默 `return` 改为 `panic` 或加断言，确保未知类型在测试阶段暴露。

---

### C-5 并行执行器 Receipt 缺少 `ContractAddress`
**File**: `core/parallel/executor.go:206–223`
**Status**: CONFIRMED

Receipt struct 构建时无 `ContractAddress` 字段赋值。
geth `state_processor.go:127` 做：
```go
if msg.To() == nil {
    receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
}
```
合约部署交易的 ContractAddress 永为零地址，破坏合约追踪、区块浏览器索引。

**Fix**: 在并行执行器 receipt 构建后，若 `tx.To() == nil` 则设置
`receipt.ContractAddress = crypto.CreateAddress(msg.From(), tx.Nonce())`。

---

## High

### H-1 非 secp256k1 签名者无法在 `accessListSigner.Sender` 验证
**File**: `core/types/transaction_signing.go:474–476`
**Status**: FALSE_POSITIVE

`accessListSigner.Sender()` 对 signerType != secp256k1 返回
`ErrTxTypeNotSupported`，但这是设计行为——txpool、state_transition
等所有调用方均使用 `core.ResolveSender()`（`core/accountsigner_sender.go`），
该函数通过 `accountsigner.VerifyRawSignature()` 做全量密码学验证。
非 secp256k1 签名被正确验证，无漏洞。

---

### H-2 RPC `DoCall` 缺少超时取消 goroutine
**File**: `internal/tosapi/api.go:1017–1044`
**Status**: FALSE_POSITIVE

gtos 通过 LVM 的 Lua interrupt 机制处理超时，等价于 geth 的 goroutine 方案：
```go
// core/vm/lvm.go:609–610
if ctx.GoCtx != nil {
    L.SetInterrupt(ctx.GoCtx.Done())  // context 超时时 Lua 立即中断
}
```
`DoCall` 创建 `context.WithTimeout`，通过 `ApplyMessage → GoCtx` 链路
传入 LVM，超时时 `ctx.Done()` 关闭触发中断。代码注释亦明确说明：
"Analogous to the goroutine + evm.Cancel() pattern in go-ethereum."

---

### H-3 UNO proof 结构校验在 txpool 关键路径
**File**: `core/tx_pool.go:603, 675, 690`
**Status**: CONFIRMED

```go
extraGas, err := validateUNOTxPrecheck(tx, from, pool.currentState)
```
`validateUNOTxPrecheck` 对每笔 UNO 交易：
1. `uno.DecodeEnvelope(data)` — 解析最大 `params.UNOMaxPayloadBytes` 的负载
2. `uno.ValidateShieldProofBundleShape(payload.ProofBundle)` — 解析最大 96KB 的 proof bundle
3. `uno.RequireElgamalSigner(statedb, from)` — 状态读取

全部在 txpool 准入关键路径，无 gas 预收费。攻击者可批量发送体积合法
但结构无效的 UNO 交易，强制节点做昂贵的解析而不消耗任何 gas。

**Fix**: 将 proof 结构验证移至区块执行阶段；txpool 只保留大小检查
（`len(data) > params.UNOMaxPayloadBytes`）和 envelope 格式检查。

---

### H-4 并行执行器 `CumulativeGasUsed` 两阶段赋值
**File**: `core/parallel/executor.go:208, 226–234`
**Status**: CONFIRMED (降级为 Medium)

```go
receipt := &types.Receipt{
    CumulativeGasUsed: 0, // line 208: 先为 0
    ...
}
receipt.Bloom = types.CreateBloom(types.Receipts{receipt}) // line 221: Bloom 不含 CumGas，正确
// ...
receipt.CumulativeGasUsed = cumulativeGasUsed // line 233: 后回填
```
Bloom 计算只依赖 Logs，不含 CumulativeGasUsed，所以 Bloom 本身正确。
两阶段的实际风险：中间没有外部读取，当前无运行时错误。
但代码结构脆弱——任何未来在两阶段间插入的读取都会拿到错误值。

**Fix**: 在第一阶段累加时即时赋值，消除两阶段结构。

---

### H-5 DPoS `verifyCascadingFields` 未校验 BaseFee
**File**: `consensus/dpos/dpos.go:431–469`
**Status**: BY_DESIGN (当前)，未来风险 CONFIRMED

gtos 当前使用固定 TxPrice，没有启用 London/EIP-1559 fork，
`header.BaseFee` 对所有区块均为 nil，不需要校验。
若未来启用 EIP-1559 兼容模式，`verifyCascadingFields` 必须加入
`misc.VerifyEip1559Header()` 调用，否则 fork 边界两侧节点会接受不同区块。

---

## Medium

### M-1 secp256k1 签名高 s 值（签名可塑性）
**File**: `core/types/transaction.go:188`
**Status**: CONFIRMED

```go
if !crypto.ValidateSignatureValues(plainV, r, s, false) { // strict=false
```
`strict=false` 接受高 s 值，同一笔交易可生成两个有效的不同 txid。
对非 secp256k1 类型（ed25519/schnorr），`sanityCheckSignerTxSignature`
只检查 bit 长度，不做曲线特定的低 s 约束。
实际影响：两条 txid 不同但 nonce 相同的交易只有一条能上链，
危害有限，但破坏幂等性假设（如交易所充值监控）。

**Fix**: 对 secp256k1 传 `strict=true`；对其他类型按曲线规范添加约束。

---

### M-2 交易字段无独立大小上限
**File**: `core/types/signer_tx.go`
**Status**: FALSE_POSITIVE

txpool 在 `tx_pool.go:575` 已做 `txMaxSize = 128KB` 的全局总大小检查。
单个字段无独立上限，但总量受 128KB 约束，不存在 OOM 风险。

---

### M-3 `DoCall` StateOverride 无账户/插槽数量上限
**File**: `internal/tosapi/api.go:917–949`
**Status**: CONFIRMED

`StateOverride.Apply()` 遍历所有账户和存储插槽无数量限制。
攻击者可通过 JSON-RPC 提交包含数千账户、每账户数万插槽的 override
强制节点做大量内存分配和写入。节点通常有 RPC 访问控制，但需加硬限制。

**Fix**: 限制最多 N 个账户（建议 100），每账户最多 M 个插槽（建议 1000）。

---

### M-4 EpochExtra 验证时序窗口
**File**: `consensus/dpos/dpos.go:661–685`
**Status**: CONFIRMED

Epoch 区块的 Extra（验证人集合）在头部验证时不检查正确性，
执行完区块内所有交易后才由 `VerifyEpochExtra()` 验证。
含错误验证人集合的 Epoch 块可通过头部验证进入头部链，
执行后才被拒绝，形成短暂 reorg 窗口。
风险相对有限（只有出块验证人可以制造此场景），但应尽早校验。

---

### M-5 `ResolveSender` 每笔交易被调用两次
**File**: `core/tx_pool.go:599, 741`
**Status**: CONFIRMED

`validateTx()`（line 599）和 `add()`（line 741）各调用一次 `ResolveSender`，
每次包含 signature 恢复 + 至少一次 SLOAD（accountsigner.Get）。
高吞吐时双倍开销明显。

**Fix**: 在 `add()` 中缓存 `ResolveSender` 结果，传入 `validateTx`。

---

### M-6 ABI revert reason 未解码
**File**: `internal/tosapi/api.go:1046–1050`
**Status**: CONFIRMED

```go
func newRevertError(result *core.ExecutionResult) *revertError {
    return &revertError{
        error:  errors.New("execution reverted"),
        reason: hexutil.Encode(result.Revert()), // 原始 hex，未解码
    }
}
```
geth 调用 `abi.UnpackRevert()` 将 `Error(string)` 格式的 revert 原因
解码为人类可读文本。gtos 返回原始 hex，增加调试难度。

---

## Low

### L-1 `ChainID=0` 的交易不拒绝
**File**: `core/types/transaction_signing.go:502`
**Status**: CONFIRMED

```go
if txdata.ChainID.Sign() != 0 && txdata.ChainID.Cmp(s.chainId) != 0 {
    return nil, nil, nil, ErrInvalidChainId
}
```
ChainID=0 的交易绕过链 ID 检查，允许跨链重放。
（注：txpool 的 `ResolveSender` 有 chainId 检查，但此处是
`SignatureValues` 级别的直接漏洞。）

---

### L-2 `Hash()` 函数对空 `signerType` 静默返回零 hash
**File**: `core/types/transaction_signing.go:522–524`
**Status**: CONFIRMED (代码味道)

```go
signerType, ok := tx.SignerType()
if !ok {
    return common.Hash{}  // 静默返回零 hash
}
```
空 signerType 的交易会得到 `common.Hash{}`，对任何验证函数来说
都是错误的输入，应 `panic` 或返回显式错误而非零值。
实际上游 `sanityCheckSignerTxSignature` 会拒绝空 signerType，
但防御性设计要求此处不静默。

---

### L-3 `LastElement()` 对空列表 panic 风险
**File**: `core/tx_pool.go:1260`
**Status**: CONFIRMED (当前安全，潜在风险)

```go
for addr, list := range pool.pending {
    highestPending := list.LastElement() // 空列表时 panic
    nonces[addr] = highestPending.Nonce() + 1
}
```
当前安全：`demoteUnexecutables()`（line 1628–1629）在此循环前删除空列表。
但二者的顺序依赖未文档化，未来重构可能破坏此假设。

**Fix**: 添加防御性检查：`if list.Len() == 0 { continue }`

---

### L-4 `VerifyForkHashes` 钩子未调用
**File**: `consensus/dpos/dpos.go` — `verifyHeader`
**Status**: FALSE_POSITIVE (当前)

`misc.VerifyForkHashes()` 在 gtos 是空实现（`consensus/misc/forks.go`），
调用与否没有区别。低优先级，待有实际 fork hash 需求时处理。

---

## 核实结论汇总

| 编号 | 问题 | 核实结果 | 优先级 |
|------|------|---------|--------|
| C-1 | LVM gas uint64 溢出 | **CONFIRMED** | 立即 |
| C-2 | GasUsed≤GasLimit 头部校验缺失 | **CONFIRMED** | 立即 |
| C-3 | GasLimit 下限不完整 | **CONFIRMED** | 立即 |
| C-4 | EncodeIndex 静默写空 | **CONFIRMED** | 立即 |
| C-5 | ContractAddress 缺失 | **CONFIRMED** | 立即 |
| H-1 | 非 secp256k1 发送方无法验证 | **FALSE_POSITIVE** | — |
| H-2 | DoCall 无超时取消 | **FALSE_POSITIVE** | — |
| H-3 | UNO proof 在 txpool 关键路径 | **CONFIRMED** | 本迭代 |
| H-4 | CumulativeGasUsed 两阶段 | **CONFIRMED** (降 Medium) | 本迭代 |
| H-5 | BaseFee 校验缺失 | **BY_DESIGN** (未来风险) | 规划 |
| M-1 | 签名可塑性 secp256k1 | **CONFIRMED** | 下迭代 |
| M-2 | 交易字段无独立大小限制 | **FALSE_POSITIVE** | — |
| M-3 | StateOverride 无数量上限 | **CONFIRMED** | 下迭代 |
| M-4 | EpochExtra 时序窗口 | **CONFIRMED** | 下迭代 |
| M-5 | ResolveSender 双重调用 | **CONFIRMED** | 下迭代 |
| M-6 | revert reason 未解码 | **CONFIRMED** | 下迭代 |
| L-1 | ChainID=0 不拒绝 | **CONFIRMED** | 下迭代 |
| L-2 | Hash 静默返回零 | **CONFIRMED** | 下迭代 |
| L-3 | LastElement 空列表 panic | **CONFIRMED** (当前安全) | 下迭代 |
| L-4 | VerifyForkHashes 未调用 | **FALSE_POSITIVE** | — |

**有效 Bug 数**: 14 confirmed（5 Critical, 2 High, 4 Medium, 3 Low）
**误报**: 5 False Positive（H-1, H-2, M-2, L-4 + BY_DESIGN H-5）
