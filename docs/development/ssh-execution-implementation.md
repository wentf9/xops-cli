# SSH 执行兼容性实施计划

依据：[SSH 多解释器执行与兼容性设计](./ssh-execution-compatibility.md)。状态：实施中；各项完成须同时具备代码、测试及双语文档，不能以本计划替代验证证据。

## 交付顺序

### P1-A：命令计划与有界执行基础（当前批次）

- [x] 新增不可变 command 计划：server 原样载荷、已知 POSIX 启动方言下的 Bash、登录选项校验、输入快照、计划摘要
- [x] 新增有限 stdin、有界合并输出的执行 API；会话创建、exec 请求、执行及关闭有期限，取消后回收所有工作协程
- [x] 提供 not_started/completed/unknown、退出码/信号、输出截断和独立清理错误；启动响应丢失不重放
- [x] `exec` 开放显式 `--interpreter`、`--launch-dialect`、`--login-shell` 的普通命令入口；未指定新参数仍使用旧路径
- [x] 拒绝尚未迁移的新参数与脚本、PTY、提权、流式输出组合；明确帮助与错误，不静默忽略
- [x] SSH fixture 验证原样字节、引用、stdin/EOF、非零/信号/缺失状态、启动拒绝/无响应、取消、截断与无重放；CLI 参数回归

该批次的新 API 只接收有限输入和内部内存输出，不接受不可取消的外部 reader/writer。默认总时限 5 分钟、启动阶段 10 秒（继承 connector 的握手期限）、关闭宽限 1 秒；core 允许调用者缩短或指定总时限。原命令和引用后的 exec 载荷各最多 64 KiB，stdin 最多 16 MiB，默认保留最后 5 MiB 输出，最大输出窗口 64 MiB。达到输出窗口后继续排空并明确标记截断。这些是本批次新增 API 的限额，旧 API 的默认值不在本批次切换。

### P1-B：现有入口统一及交互修复

- [ ] Run、RunWithoutLogin、RunCommandWithIO 和旧 Bash 脚本委托统一计划，保持各入口原有登录默认
- [ ] 为终端/管道提供可取消输出桥；迁移流式输出、文件输出和 SSH CLI，保持 stdin 所有权与 EOF 契约
- [ ] 将 PTY/Shell 请求纳入有界生命周期；区分完整登录会话与一次性 PTY 命令，修复普通/root/免密/密码 sudo/su 的退出状态传播
- [ ] 新 CLI 参数进入 PTY 路径；显式空命令与未提供命令分开；shell session 选项适用范围明确
- [ ] P1 全量 build/test/lint、SSH/I/O race 与泄漏回归通过后才声明 P1 完成

### P2-A：配置及调用方绑定

- [ ] 全局/Node/Playbook execution schema、presence、继承和 DTO/克隆/导入导出往返测试
- [ ] MCP 输入、ports、宿主 backend 传递计划与结构化结果；审批展示及摘要绑定有效执行配置
- [ ] Node/global execution 变化使旧审批失效，无关配置不误失效；请求方言声明不能降低风险
- [ ] Playbook 脚本源字节和 node+step 计划冻结；不确定结果及附加清理错误禁止重试
- [ ] ensure 结果来源协议、check/action/verify 分类及旧工作流迁移

### P2-B：适配器及高级操作

- [ ] 无 Bash 的 ash/dash 上验收 sh；明确 shebang 白名单、未知声明、BOM/CRLF 和独立运行时输入
- [ ] Windows cmd/PowerShell/pwsh 的启动矩阵、引用、profile、编码、载荷长度和退出码协议冻结；原生 OpenSSH 验收
- [ ] sudo/su 控制协议与用户解释器分离；认证、终端交接、取消和引用回归
- [ ] SFTP cwd 适配与纯 server 拒绝；文件后端语义验收
- [ ] 内置探测、监控、日志、防火墙逐项声明平台/解释器要求

### P3：发布默认切换

- [ ] P1/P2 全部验收且共享 core 消费者验证通过；明确发布版本
- [ ] 命令默认统一为 server；无可靠解释器的脚本执行前拒绝
- [ ] 发布命令/脚本各自的 Bash 兼容迁移、SFTP 限制与可回退 schema 版本说明
- [ ] 原生 Windows 与真正无 Bash Unix 平台证据齐备；禁止通过失败后更换解释器回退

## 验证与提交

每批新增能力和 Bug 修复均须有对应测试。提交 PR 或 push 前执行 `go build ./...`、`go test ./...`、`golangci-lint run ./...`；文档执行 `npm run docs:check`，本地源码链接另行验证。涉及 SSH 并发的批次补充 `go test -race ./core/ssh ./cmd`。没有平台证据的适配器保持未开放状态。

## P1-A 验证记录（2026-10-09）

已完成上列 P1-A 条目。主要实现位于 `core/ssh/command_plan.go`、`core/ssh/command_execution.go` 和 `cmd/exec_execution.go`；对应测试覆盖真实 SSH 协议、POSIX/Bash 引用、大小限制、取消/泄漏、结果分类和 CLI 联调。

- `go build ./...`：通过
- `go test ./...`：通过
- `golangci-lint run ./...`：0 issues
- `go test -race ./core/ssh ./cmd`：通过；最终参数/载荷校验的针对性 race 测试也通过
- `npm run docs:build`：通过；双语结构、本地链接与格式检查通过
- `python3 scripts/check_core.py`：Linux/Windows/macOS 依赖边界通过，独立抽取模块 build/test 通过

Windows 原生运行、无 Bash Unix 适配器、PTY/提权和现有入口统一仍属于后续验收范围；不能由此次交叉平台依赖检查推断已验证。下一批从 P1-B 的旧方法委托、可取消 I/O 桥与 PTY 退出状态修复开始。
