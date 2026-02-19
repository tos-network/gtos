# GTOS (Geth + TOS Agent Network)

GTOS 是基于 `go-ethereum v1.10.25` 演进的统一节点实现。

目标是把两类能力融合到同一个节点进程中：

- 区块链核心能力：账户余额、转账、共识、确定性状态执行
- Agent 网络能力：Agent 注册、能力发现、MCP 扩展、challenge/escrow/slash/jail 治理

GTOS 的方向不是“每台机器都跑 `tosd + geth` 两套系统”，而是“单一 `gtos` 节点进程”承载链上与 Agent 控制面。

## Vision

我们希望 GTOS 成为 TOS Network 的链核与 Agent 协作底座：

1. 用链上状态确保余额和治理结果全网一致
2. 用链下索引提供高性能能力检索和路由
3. 用受限执行引擎支持 Agent 业务关键动作
4. 通过 MCP/RPC 扩展为上层 Agent 提供统一接入面

## Current Status

当前仓库状态：

- 已导入 `go-ethereum v1.10.25` 代码基线
- 已新增 GTOS 方案设计文档
- 受限执行引擎与 Agent 控制面属于下一阶段实现内容（尚未全部落地）

设计文档：

- `docs/gtos-agent-integration-design.md`

## Target Architecture

GTOS 规划为三层：

1. Chain Core Plane
- 账户与转账
- 共识与最终性
- 确定性系统动作执行

2. Agent Control Plane
- Agent 注册/更新/状态
- 治理动作（challenge/slash/jail/release）
- 结算关键状态（escrow/challenge/release/refund）

3. Discovery & Query Plane
- 能力索引
- 能力检索与过滤
- MCP 扩展接口

边界原则：

- 链上：事实与约束（余额、身份、惩罚、结算）
- 链下：高频查询与排序（但必须受链上状态约束）

## Restricted Execution Engine (Planned)

GTOS 计划采用“系统动作（system actions）”而不是自定义 EVM opcode。

MVP 动作集合（规划）：

- `AGENT_REGISTER`
- `AGENT_UPDATE`
- `AGENT_HEARTBEAT`
- `ESCROW_OPEN`
- `ESCROW_RELEASE`
- `ESCROW_REFUND`
- `CHALLENGE_OPEN`
- `CHALLENGE_RESOLVE`
- `SLASH`
- `JAIL`
- `UNJAIL`

## Build (Baseline)

当前可以按 geth 方式构建基础二进制：

```bash
make geth
```

或构建完整工具集：

```bash
make all
```

> 说明：上述命令对应当前“geth 基线阶段”。`gtos` 专用子命令与 Agent/RPC 扩展将在后续迭代加入。

## Roadmap (Short)

1. 定义 `gtos` 内部模块边界（chaincore / agentcore / discovery / mcpapi）
2. 定义系统动作交易格式与状态机校验
3. 实现链事件到能力索引的同步链路
4. 增加 `agent_*`, `discover_*`, `mcp_*` RPC namespace
5. 增加注册/发现/challenge/slash/jail 一体化集成测试

## Development Notes

- 本仓库以 `go-ethereum v1.10.25` 为底座，所有改造应优先保证确定性与共识一致性
- Agent 高级检索逻辑应放在链下索引层，避免把高频查询写入共识路径
- 治理/惩罚动作必须具备可审计事件输出

## License

沿用 go-ethereum 原始许可：

- 库代码（`cmd` 目录外）：LGPL-3.0 (`COPYING.LESSER`)
- 二进制相关代码（`cmd` 目录内）：GPL-3.0 (`COPYING`)
