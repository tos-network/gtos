# GTOS Security Audit — go-ethereum Divergence Review

**审计日期**：2026-03-05
**审计范围**：gtos vs go-ethereum v1.10.25，聚焦分叉风险与安全问题
**覆盖模块**：`core/state_transition.go`、`core/parallel/`、`core/lvm/lvm.go`、`consensus/dpos/`

---

## 方法论

gtos 从 go-ethereum 克隆，做了两项核心改造：

1. **EVM → LVM**：移除 EVM 解释器，以 Lua VM (LVM) 取代智能合约执行
2. **串行 → 并行**：移除 `ApplyTransaction`，以基于 DAG 的并行执行器取代

本次审计通过四路并行 agent 分别覆盖四个模块，再对产出结果逐条交叉验证、去除误报，最终形成本文档。

---

## 误报说明（已验证为正确实现）

下列问题被初步标记，经验证后确认是正确的或无害的设计：

| 被标记问题 | 验证结论 |
|-----------|---------|
| 并行执行：Nonce Merge 使用绝对值覆盖 | 正确。同 sender 的 tx 必被 DAG 分配到不同 level（Write-Write 冲突），absolute `SetNonce` 语义正确 |
| `LVM.Create()` 缺少 caller nonce 递增 | 正确。`state_transition.go:245` 对所有 tx 统一递增，LVM.Create 接收 pre-tx nonce 仅用于地址派生 |
| Receipt 缺少 `PostState` 字段 | 正确。Byzantium+ 使用 `Status` 字节而非 PostState；`Status` 已正确设置 |
| `VerifyEpochExtra` 在 tx 执行后调用 | 正确。`FinalizeAndAssemble` 与 `Process` 均读取 post-tx state，双方一致 |
| `tos.send` 在 readonly 模式跳过 primGas | 正确。Lua opcode counter 持续计费；primGas 是叠加的精细计费，非唯一计费机制 |
| sigcache 在 Snapshot.copy() 中共享指针 | 无害。sigcache 为只读 LRU，同一 (hash→signer) 对结果幂等，跨 fork 安全 |

---

## 真实问题

### HIGH-1：Sysaction gas 不足时 handler 仍执行状态变更

**文件**：`core/state_transition.go:267–275`
**分类**：安全漏洞（gas 计费语义错误）

#### 问题代码

```go
gasUsed, execErr := sysaction.Execute(msg, st.state, ...)
// ↑ handler 已执行完毕（VALIDATOR_REGISTER 等状态变更已写入 StateDB）
if st.gas >= gasUsed {
    st.gas -= gasUsed
} else {
    st.gas = 0   // 静默 clamp，不返回 ErrOutOfGas
}
vmerr = execErr
```

#### 影响

`params.SysActionGas` 在 `sysaction.Execute()` 返回后才与 `st.gas` 比较。若 tx gas 恰好够通过 `intrinsicGas` 检查但低于 `SysActionGas`，handler 的状态变更（如 VALIDATOR_REGISTER）已落地，但 sender 只支付了较少的 gas fee。经济损失有限（注册仍需质押），但违背"gas 不足则操作不执行"的基本原则。

#### go-ethereum 对齐方案

go-ethereum 在 EVM 执行前通过 gas 预检保证充足（`ErrOutOfGas` 在执行前抛出）。GTOS 应在调用 handler 前检查：

```go
if st.gas < params.SysActionGas {
    st.gas = 0
    vmerr = ErrOutOfGas
} else {
    gasUsed, execErr := sysaction.Execute(msg, st.state, ...)
    st.gas -= gasUsed
    vmerr = execErr
}
```

---

### HIGH-2：合约创建 tx 跳过 EOA sender 检查

**文件**：`core/state_transition.go:212–219`
**分类**：协议层与 go-ethereum 语义分叉

#### 问题代码

```go
// GTOS：仅对 To != nil 的 tx 检查 sender 是否为 EOA
if st.msg.To() != nil {
    if codeHash := st.state.GetCodeHash(st.msg.From()); ... {
        return ErrSenderNoEOA
    }
}
```

```go
// go-ethereum：无条件检查（所有 tx 类型）
if codeHash := st.state.GetCodeHash(st.msg.From()); ... {
    return ErrSenderNoEOA
}
```

#### 影响

若某 Lua 合约地址（有 codeHash）的私钥被持有（理论上不可能，实践中极罕见），可发送 `To == nil` 的创建 tx 绕过 EOA 校验。协议层存在语义缺口，与 go-ethereum 不一致。

#### go-ethereum 对齐方案

删除 `if st.msg.To() != nil` 的条件包裹，始终执行 EOA 检查：

```go
if !st.msg.IsFake() {
    // nonce checks ...

    // Sender must always be an EOA (no code at sender address).
    if codeHash := st.state.GetCodeHash(st.msg.From()); codeHash != emptyCodeHash && codeHash != (common.Hash{}) {
        return fmt.Errorf("%w: address %v, codehash: %s", ErrSenderNoEOA, st.msg.From().Hex(), codeHash)
    }
}
```

---

### MEDIUM-1：`tos.arrPush` uint64 长度溢出

**文件**：`core/lvm/lvm.go:1214, 1221`
**分类**：整数溢出（实践中受 gas 限制，理论可达）

#### 问题代码

```go
length := new(big.Int).SetBytes(raw[:]).Uint64()  // storage slot 可被直接写为 MaxUint64
// ...
new(big.Int).SetUint64(length + 1).FillBytes(...)  // uint64 溢出 → 0，数组长度归零
```

#### 影响

数组长度从 storage slot 读取，若 slot 被写为 `math.MaxUint64`（例如通过 `storeState` 直接写入），下次 `arrPush` 会将长度溢出至 0，后续 `arrPop` 返回 nil，数组所有元素变为僵尸数据。gas 成本使正常操作路径不可达，但缺乏显式守卫。

#### go-ethereum 对齐方案

go-ethereum 对所有存储操作的边界值做显式检查。应在操作前加守卫：

```go
if length == math.MaxUint64 {
    L.RaiseError("tos.arrPush: array length overflow")
    return 0
}
```

---

### MEDIUM-2：`tos.bytes.slice` / `tos.bytes.fromUint256` 的 Int64 截断

**文件**：`core/lvm/lvm.go:934, 941, 970`
**分类**：整数截断（错误信息误导，边界检查兜底）

#### 问题代码

```go
offset := int(parseBigInt(L, 2).Int64())  // 若传入 > 2^63-1，高位截断为负数
length := int(parseBigInt(L, 3).Int64())  // 同上
```

#### 影响

负 offset/length 触发 bounds check 返回错误，但错误信息为 "index out of range" 而非 "integer overflow"，调试困难。未来若移除 bounds check 或逻辑变更，溢出可能产生实质危害。

#### go-ethereum 对齐方案

go-ethereum 对所有外部输入的数值做范围校验后再转换。应在转换前检查：

```go
v := parseBigInt(L, 2)
if !v.IsInt64() || v.Sign() < 0 {
    L.RaiseError("tos.bytes.slice: offset out of range")
    return 0
}
offset := int(v.Int64())
```

---

### MEDIUM-3：DPoS `gasLimit` 缺少下界及父块相对约束

**文件**：`consensus/dpos/dpos.go:398–400`
**分类**：头部验证不完整

#### 问题代码

```go
if header.GasLimit > params.MaxGasLimit {
    return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
}
// 缺：下界检查（gasLimit > 0）
// 缺：父块相对变化约束（|cur - parent| < parent/1024）
```

#### 影响

`gasLimit == 0` 的块能通过头验证，但 `Process` 阶段第一个 tx 即因 gas pool 耗尽失败；`gasLimit` 跨块剧烈波动（如 1 → MaxGasLimit）可被用于 DoS 矿工的 tx 选择逻辑。

#### go-ethereum 对齐方案

Clique 遵循 go-ethereum `misc.VerifyGaslimit()` 的约束：

```go
// 下界
if header.GasLimit == 0 {
    return errors.New("invalid gasLimit: zero")
}
// 父块相对约束（EIP-1559 前规则，同样适用于 DPoS）
diff := int64(parent.GasLimit) - int64(header.GasLimit)
if diff < 0 { diff = -diff }
limit := parent.GasLimit / params.GasLimitBoundDivisor  // 1024
if uint64(diff) >= limit {
    return fmt.Errorf("invalid gas limit: have %d, want %d +-= %d", header.GasLimit, parent.GasLimit, limit-1)
}
```

---

## 设计差异（LOW — 有意为之，非 bug，记录备查）

以下差异是 GTOS 与 go-ethereum 的有意分叉，不构成安全漏洞或共识分叉风险，但与 go-ethereum 原始行为不一致，记录以备未来维护参考。

---

### D-1：Gas 退款系数固定为 2（未实现 EIP-3529）

**文件**：`core/state_transition.go:309`

```go
// GTOS（固定）
st.refundGas(params.RefundQuotient)  // 始终为 2

// go-ethereum（伦敦升级后切换）
if rules.IsLondon {
    st.refundGas(params.RefundQuotientEIP3529)  // 5
} else {
    st.refundGas(params.RefundQuotient)          // 2
}
```

**说明**：GTOS 为自定义链，选择永久使用 pre-London 退款规则（系数 2，退款上限 = gasUsed/2）。EIP-3529 将上限降低至 gasUsed/5 以减少 gas token 套利。GTOS 若未来启用 London 规则，需同步更新此处。

**go-ethereum 对齐方向**：在 `chainConfig` 中加入 `IsLondon()` 条件判断，按 fork 规则动态选择退款系数。

---

### D-2：`PrepareAccessList` 未调用（EIP-2929 warm/cold 不适用）

**文件**：`core/state_transition.go`（缺失调用）

```go
// go-ethereum（柏林升级后）
if rules.IsBerlin {
    st.state.PrepareAccessList(msg.From(), msg.To(),
        vm.ActivePrecompiles(rules), msg.AccessList())
}
// GTOS：不调用 PrepareAccessList
```

**说明**：EIP-2929 的 warm/cold storage 区分依赖 EVM 的 `SLOAD`/`SSTORE` 操作码计费。GTOS 使用 LVM，gas 模型完全自定义（`gasSLoad`/`gasSStore` 为固定常量），不区分 warm/cold。Access list tx 的 IntrinsicGas 仍被收取（字节计费），但 slot 预热语义无效。

**go-ethereum 对齐方向**：若 GTOS 未来需兼容 EIP-2930 access list tx 的完整语义，需在 LVM 内引入 warm set 追踪，或在 IntrinsicGas 中拒绝含非空 AccessList 的 tx。

---

### D-3：`ExecutionResult.ReturnData` 恒为 nil

**文件**：`core/state_transition.go:320`

```go
// GTOS
return &ExecutionResult{
    UsedGas:    st.gasUsed(),
    Err:        vmerr,
    ReturnData: nil,   // 始终为空
}, nil

// go-ethereum
return &ExecutionResult{
    UsedGas:    st.gasUsed(),
    Err:        vmerr,
    ReturnData: ret,   // EVM call/create 的返回数据
}, nil
```

**说明**：GTOS 的系统动作、KV put、UNO 动作、纯转账均无需向 tx 发送方返回数据；LVM 合约的返回值通过链上 event/storage 交互，不走 returndata 通道。此为有意设计，`eth_call` 在 GTOS 中不适用。

**go-ethereum 对齐方向**：若未来 LVM 支持 `eth_call` 模拟，需在 `lvm.Call()` 返回路径上传递 Lua 函数的返回值。

---

### D-4：4-byte dispatch tag 碰撞（package 调用）

**文件**：`core/lvm/lvm.go:2987–2988`

```go
tag := crypto.Keccak256([]byte("pkg:" + contractName))[:4]
```

**说明**：同一 `.tor` package 内不同合约名若 `keccak256("pkg:"+name)` 前 4 字节相同，后者不可达（首匹配命中）。生日界约为 65,536 个名称才有 50% 碰撞概率，正常 package 规模不可达。go-ethereum ABI selector 同样使用 4 字节选择器，有相同理论风险。

**go-ethereum 对齐方向**：在 package 部署时校验 tag 唯一性（manifest 解析阶段），若有碰撞拒绝部署。

---

### D-5：Epoch Extra 验证由 snapshot 延迟至 Process（R2-H1 MVP 限制）

**文件**：`consensus/dpos/snapshot.go:171–176`，`core/state_processor.go:103–109`

**说明**：`snapshot.apply()` 无法访问 StateDB，因此无法即时验证 epoch 块的 `header.Extra` 中的验证人列表是否与链上 TOS3 registry 一致。验证推迟至 `Process()` 末尾的 `VerifyEpochExtra()` 调用（需访问 StateDB）。在此窗口期内，拜占庭节点可广播含伪造验证人列表的 epoch 块，但诚实节点在 `VerifyEpochExtra` 时会拒绝并切换到诚实链。已记录为 MVP 已知限制。

**go-ethereum 对齐方向**：Clique 在 `snapshot.apply()` 内直接从 Extra 解析检查点验证人，不依赖外部 StateDB。GTOS 长期方案为将 `ReadActiveValidators()` 的结果缓存到 snapshot，在 `apply()` 时做离线比对。

---

## 已修复问题（本次 review 之前）

以下问题在本次 review 之前已修复（commit `6ed98f1`），记录存档：

| 问题 | 修复位置 | 修复描述 |
|------|---------|---------|
| `tos.call` 孤立快照（CanTransfer 失败路径） | `lvm.go` | guard 检查移至 Snapshot 之前，CanTransfer 失败时无快照泄漏 |
| 子调用缺少 EIP-150 63/64 gas 规则 | `lvm.go`（4处） | `available - available/64` 替代 `available`，保留 1/64 给父帧 |
| `tos.deploy` SetNonce 在 CanTransfer 之前 | `lvm.go` | CanTransfer guard 前移，通过后再写 nonce |
| `LVM.Create` / `LVM.CreatePackage` 无快照 | `lvm.go` | guard 检查后、首次状态变更前插入 `Snapshot()` |

---

## 待修复优先级

| 优先级 | 编号 | 文件:行 | 描述 |
|-------|------|---------|------|
| P1 | HIGH-1 | `state_transition.go:267` | Sysaction gas 不足时 handler 仍执行 |
| P1 | HIGH-2 | `state_transition.go:214` | 合约创建 tx 跳过 EOA 检查 |
| P2 | MEDIUM-1 | `lvm.go:1221` | arrPush uint64 溢出守卫 |
| P2 | MEDIUM-2 | `lvm.go:934,941,970` | Int64 转换前 IsInt64() 检查 |
| P2 | MEDIUM-3 | `dpos.go:398` | gasLimit 下界 + 父块相对约束 |
| P3 | D-1 | `state_transition.go:309` | London 规则 RefundQuotient 条件化 |
| P3 | D-2 | `state_transition.go` | AccessList 语义对齐或显式拒绝 |
| P4 | D-4 | `lvm.go:2988` | Package 部署时校验 dispatch tag 唯一性 |
