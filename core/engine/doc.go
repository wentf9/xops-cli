// Package engine 是 XOps v2 六边形核心（core）面向外部宿主（cmd/xops、internal/entry/{cli,tui,sftpshell,mcpcmd,muxdaemon} 与外部 xops-mcp）
// 唯一公开的运行期装配与全量业务门面（ADR-001 / ADR-008 / ADR-009 / ADR-010 / Plan P3-T5）。
//
// 核心架构与安全不变量：
//   - 生产源码严格零引用 core/ports/tck 与 core/internal/sim（由 xopsvet/archbound 强制），
//     仅装配真实主机密钥信任库（sshnet/hostkey）、真实 SSH 拨号器（sshnet/dial）、透明 ControlMaster
//     客户端复用适配器、双通道纯内存 Actor 连接池（pool）、独占能力门控（gate）、全部 6 大用例服务
//     （usecase/{inventory,credential,session,transfer,automation,observability}）以及沙箱隔离的 MCP 运行时（mcpruntime）；
//   - 严格将 gate.OnHaltFunc 接线至 pool.GateHalted：StrictAgentProfile 下任一 AuditPostWriteError
//     触发不可逆 Halted 熔断后，连接池立即失效全部活跃句柄并拒绝一切后续租约；
//   - 为 MCPServer 独立装配共享活跃句柄表但物理零 OperatorReadFS 的 Transfer/Automation 用例服务，阻断沙箱逃逸；
//   - 完整暴露不透明公开值类型、枚举常量、构造/解析代理、语义哨兵错误映射及两步审批/引用冲突提取契约，
//     使 internal/entry/** 仅依赖 core/{domain,events,engine,conc} 即可驱动全量业务而零触碰 core/internal/** 或 core/ports；
//   - 退出期 Close(ctx) 严格按派生 MCPServer & Projection -> 在途 UseCases 排空 -> 连接池 Pool -> 自有 SystemBus 逆序优雅停机，
//     绝不代为关闭由外部组合根（cmd/xops）持有的 AuditSink、ScopedRootFS 或外部注入的 SystemBus；
//   - 全包 0 init()、0 可变包级变量、0 裸 go 语句、0 nolint 豁免。
package engine
