# SSH 分级诊断

## 范围与边界

`xops ssh -v/-vv/-vvv` 复用 SCP 的结构化诊断及受控输出，不切换 SSH 后端、不修改认证候选顺序、主机信任、连接租约、解释器载荷或命令重试策略。
`--debug` / `--log-level` 仍独立控制内部日志。参数与用户限制见 [SSH 指南](../guide/ssh.md)。

参考 [ssh(1)](https://man.openbsd.org/ssh.1) 和 OpenSSH portable 的
[ssh.c](https://github.com/openssh/openssh-portable/blob/master/ssh.c)、
[clientloop.c](https://github.com/openssh/openssh-portable/blob/master/clientloop.c)。
对齐选项顺序、诊断类别及 `debug1/2/3:` 风格，不承诺逐行一致。

## 参数和等级

- `cmd/diagnostic_flags.go` 保存公共有序 bool 参数、OpenSSH 日志级别间距及限长/转义。
- SSH 只有一个日志级别；第一次 `-v` 设 DEBUG1，后续递增到 DEBUG3；`-q` 设 QUIET。
  因而 `-qv` 启用诊断，`-vq` 关闭，`-vqv` 只到 FATAL，不立即恢复 DEBUG1。
- SCP 继续保留独立的自身 verbose 等级及 SSH 日志级别，尤其保留 `-vq` 的 SFTP 诊断。
- DEBUG1：连接、信任、认证、协商、会话开始、真实退出结果和转发监听生命周期。
- DEBUG2：会话打开/请求发送与确认、转发连接接受及结束。
- DEBUG3：会话通道清理结果。它不是完整 SSH 报文、窗口调整或 rekey 跟踪。
- 远程命令之后的参数仍由 `cmd/argument_routing.go` 保留，远程 `-v` 不变成本地诊断参数。

## 事件来源

`core/log.Diagnostic` 新增协商、会话请求/开始/结束/清理、转发生命周期事件，以及带 presence 的退出码。
新增字段为附加元数据；未注入观察者的调用方不产生诊断输出，不增加协议请求或监控 goroutine。

- `Connector.configureClient` 将命令拥有的观察者注入创建和复用的 Client 包装对象。
- 认证回调从 `ClientAuthContext.Metadata/Algorithms` 每次物理握手最多报告一次协商结果，认证失败也可保留已观察到的版本和算法。
  初始 none 认证成功不虚构尝试；原有认证完成摘要仍使用真实握手结果。SCP 不渲染新增的认证前协商事件，保留原摘要行为。
- `Client.sessionRequest` / `newSessionContext` 在实际请求边界报告结果，不提前声称请求成功。
- `Client.waitSession` 在合并 I/O/取消错误、应用完整登录 Shell 的旧退出政策之前观察 `Session.Wait`。
  非零、信号、缺失状态分别报告；缺失状态、断连和取消不得合成为退出码 0。
- `ExecuteCommand` 仍使用原 CommandResult 的 completed/not_started/unknown 与可选退出码，不重放命令。
- 转发在现有 listener/handler 生命周期报告，不另启监听器或监控器；既有单连接失败隔离保持原样。CLI 错误回调只向受控队列入队，不直接写标准流。

## 输出与所有权

`cmd/diagnostic_output.go` 替代 SCP 原私有输出队列；SSH 和 SCP 共用它以及 SSH 事件格式化。
SCP 的 SFTP、传输及进度格式化仍由 SCP 拥有。

- 命令拥有观察者、容量 128 的队列、writer 和 output binding；协议回调只非阻塞入队，满时丢弃辅助显示并在结束时报告数量。
- SSH 的 `RunContext` 保持观察者存活到隧道、Client 和 Connector 均结束，然后关闭队列、汇合 writer、释放 binding；借用的标准流不关闭。
- verbose 转发错误复用命令的 stderr 队列；未启用 verbose 时，由现有 `sshTunnelGroup` 拥有错误队列，等转发回调全部退出后排空、汇合。已失败的 writer 不再执行后续错误写入，不能回退 `logger.PrintErrorf`。
- `-N` 就绪提示保留原有 stdout 和文本，但改为受控队列，由隧道组在结束时回收。即使 stdout/stderr 指向同一堵塞管道，也没有同步 `fmt.Printf` 绕过。队列使用命令 context，隧道组单独取消自身 child context 及会话 context，正常关闭不会提前取消待排空的输出。
- 写入超过一秒取消自有输出 binding。普通文件内核写入必须返回后才能汇合，不承诺硬取消期限；不支持的 sink 跳过辅助输出，不回退 raw Write。
- SSH writer 与既有提示 gate 协调，等待可由输出 context 取消，不在密码/信任提示持有 gate 时写诊断。
  终端诊断和转发错误采用 CRLF，避免 raw mode 下依赖已关闭的 OPOST；日志文件保持 LF。用户可见转发错误保留原文本和颜色，不放入仅允许公开协议元数据的 Diagnostic 字段。
- SSH 输出错误使用既有 `ssh.OutputError` 保留借用 sink 身份；SCP 保留 `SCPOutputError` 包装。
  顶层沿用 `HasStandardOutputError`，不向失败或堵塞的标准流重新打印错误。
- `-f -N` 保持现有父进程验证、子进程重新连接和丢弃子进程标准流的行为，不新增后台日志文件。

事件不携带命令、脚本、凭据、私钥、环境变量值或原始远端错误文本。
CLI 限制并转义不可信字符串；公开元数据仍包含地址、用户名、指纹及转发端点，日志并非匿名数据。

## 验证入口与平台边界

回归包含等级/quiet 顺序、远程参数边界、独立内部日志、成功/非零/信号/缺失状态/拒绝/取消、PTY 旧退出政策与终端恢复、转发监听、诊断脱敏、提示 gate 取消、有限队列、不支持 sink、堵塞 pipe 和输出错误身份。新增组合回归覆盖 local/remote/SOCKS5 在 verbose 开关两种状态下的“stderr 写满、诊断超时、转发失败、关闭”，以及 stdout 就绪提示的堵塞/错误/正常排空和借用流所有权。
Windows 堵塞测试先通过 `GetNamedPipeInfo` 查询对应写入方向的缓冲额度，完成该额度的写入，再验证额外一个字节会阻塞直到取消。不能仅凭一次超额大写入被取消就认定管道已满：Windows 可能丢弃未完成写入的数据，仍为后续诊断或就绪提示留下空间。Unix 仍通过已提交部分字节的大写入建立堵塞条件。

系统 OpenSSH 对照只连接固定公钥的回环 fixture，不访问用户服务器，也不做逐行文本快照。

```sh
go test -race -shuffle=on -count=1 ./core/ssh ./cmd
python3 -m unittest discover -s scripts -p test_check_core.py
python3 scripts/check_core.py --race
npm run docs:check
```

交叉编译不等于原生终端测试；Windows/macOS 行为仍需相应原生 CI 确认。
共享输出的详细平台限制见 [原生可取消输出](./native-cancelable-output.md)，SCP 保持的语义见 [SCP 诊断](./scp-diagnostics.md)。
