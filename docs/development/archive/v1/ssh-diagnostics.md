# SSH 分级诊断

## 范围与边界

`xops ssh -v/-vv/-vvv` 复用 SCP 的结构化诊断及受控输出，不切换 SSH 后端、不修改认证候选顺序、主机信任、连接租约、解释器载荷或命令重试策略。
`--debug` / `--log-level` 仍独立控制内部日志。参数与用户限制见 [SSH 指南](../guide/ssh.md)。

`xops sftp -v/-vv/-vvv` 复用同一个 `sshDiagnostics` 观察器与单一日志级别（只注册 `-v`，没有 `-q`），同时把观察器传给连接器和 `sftp.WithDiagnostics`。SFTP 协议事件通过与 SCP 共享的 `formatSFTPDiagnostic` 渲染为 `debugN: [sftp N] ...`，不带 `scp:` 前缀；SCP 输出保持不变。观察器先于连接器、SFTP 客户端和 shell 的清理注册，因此最后释放。

参考 [ssh(1)](https://man.openbsd.org/ssh.1) 和 OpenSSH portable 的
[ssh.c](https://github.com/openssh/openssh-portable/blob/master/ssh.c)、
[clientloop.c](https://github.com/openssh/openssh-portable/blob/master/clientloop.c)。
对齐选项顺序、诊断类别及 `debug1/2/3:` 风格，不承诺逐行一致。

## 参数和等级

- `cmd/diagnostic_flags.go` 保存公共有序 bool 参数、OpenSSH 日志级别间距及限长/转义。
- SSH 只有一个日志级别；第一次 `-v` 设 DEBUG1，后续递增到 DEBUG3；`-q` 设 QUIET。
  因而 `-qv` 启用诊断，`-vq` 关闭，`-vqv` 只到 FATAL，不立即恢复 DEBUG1。
- SCP 继续保留独立的自身 verbose 等级及 SSH 日志级别，尤其保留 `-vq` 的 SFTP 诊断。
- DEBUG1：连接、信任、认证、协商、会话开始、真实退出结果、提权模式/尝试/就绪/结果和转发监听生命周期。
- DEBUG2：会话打开/请求发送与确认、提权探测/凭据查找/密码交互、转发连接接受及结束。
- DEBUG3：终端交接/恢复与会话通道清理结果。它不是完整 SSH 报文、窗口调整或 rekey 跟踪。
- 远程命令之后的参数仍由 `cmd/argument_routing.go` 保留，远程 `-v` 不变成本地诊断参数。

## 事件来源

`core/log.Diagnostic` 新增协商、会话请求/开始/结束/清理、转发生命周期事件，以及带 presence 的退出码。
新增字段为附加元数据；未注入观察者的调用方不产生诊断输出，不增加协议请求或监控 goroutine。

- `Connector.configureClient` 将命令拥有的观察者注入创建和复用的 Client 包装对象。
- 认证回调从 `ClientAuthContext.Metadata/Algorithms` 每次物理握手最多报告一次协商结果，认证失败也可保留已观察到的版本和算法。
  初始 none 认证成功不虚构尝试；SCP 不渲染认证前协商事件。
- `authenticationTrace` 属于单次握手，不维护全局映射。它记录回调实际选择的协议方法及 `PartialSuccessMethods`，每次回调清除上一轮的终结方法。依据 x/crypto v0.57.0 的认证循环，失败或部分成功后会再次调用回调，成功后直接返回；只有 `NewClientConn` 成功后才将服务端确认的部分成功链加上终结方法写入 `Authenticated.Methods`，`Method` 为最后的成功方法。未发生回调且握手成功证明初始 none 成功；未知选择不从配置猜测。记录器不改回调返回值、回退或重试顺序，不包含凭据；未装配观察者时不启用。
- AEAD 的 `ReadMAC/WriteMAC` 原始字段保持空值，因为协议未协商独立 MAC。共享 SSH/SCP formatter 对已知 AES-GCM、ChaCha20-Poly1305 显示 OpenSSH 风格的 `<implicit>`；其他非空 MAC 显示实际名称，空白但非已知 AEAD 的元数据明确显示 `<unknown>`，不能将所有空值冒充 AEAD。
- `Client.sessionRequest` / `newSessionContext` 在实际请求边界报告结果，不提前声称请求成功。
- `Client.waitSession` 在合并 I/O/取消错误、应用完整登录 Shell 的旧退出政策之前观察 `Session.Wait`。
  非零、信号、缺失状态分别报告；缺失状态、断连和取消不得合成为退出码 0。
- `ExecuteCommand` 仍使用原 CommandResult 的 completed/not_started/unknown 与可选退出码，不重放命令。
- 转发在现有 listener/handler 生命周期报告，不另启监听器或监控器；既有单连接失败隔离保持原样。CLI 错误回调只向受控队列入队，不直接写标准流。

## 提权阶段

`PrivilegeLifecycle` 复用 `Operation` 表示提权模式、`Outcome` 表示固定阶段名；`Attempt` 为 1 起始的 exchange 尝试次数，密码提示/响应事件则表示当前 exchange 内的密码尝试次数，0 表示不适用。`core/ssh/privilege_diagnostics.go` 只组织元数据，不拥有连接、终端、凭据或后台任务。附加字段 `PrivilegeCommand` 为脱敏调用，`PrivilegePromptPattern` 为实际使用的匹配规则，`PrivilegePrompt` 为实际识别的提示文本。

- `Client.maybeDetectSudoMode` / `detectRootOrSudoer` 从既有探测报告 root 身份确认、免密 sudo 可用或尚未确认，并报告配置/探测后选择的模式。配置中的 root/免密模式不是新的认证证据；不额外执行探测。
- `resolvePrivilegeMaterial` 只报告凭据查找、可用、交互提示及失败，不含后端错误、路径或机密值。查找到凭据不等于验证成功。
- `runPrivilegeOperation` 和既有免密/单次 sudo 路径报告尝试与最终 completed/failed/canceled/timed_out。completed 表示按原退出政策结束，不覆盖会话的真实退出码，也不是新的 CommandResult 可重试判定。旧式非控制帧路径不虚构认证成功。
- 提权调用在发送前报告。普通与 portable 路径的实际调用和诊断视图复用同一 wrapper 构造器，只将整个控制/用户载荷替换为 `<privileged payload>`，将随机提示标记替换为 `<password-prompt>`，不靠正则猜测用户命令中的秘密。旧式 sudo 路径展示对应的固定调用前缀。匹配规则在启动前报告；提示文本在完整匹配后、消费该提示前报告，兼容分片及 sudo-rs 包装，core 限制为 1024 字节，CLI 继续限长并转义。观察者不接触密码响应缓冲区，就绪后的用户输出不参与提示诊断。
- sudo 提示回退只接受 `Client` 构造时有效的显式节点/全局 `password_prompt_pattern`（节点优先）；未配置、编译失败、可匹配空字符串的配置不回落到内置默认值。仅 `SudoModeSudo` 启用，`SudoModeSudoer` 不启用；su 原有默认行为保留。`privilegeFrameWriter.findPrompt` 优先匹配随机标记，保留 sudo-rs 完整包装等待及 xtrace 排除，跳过零宽匹配。主标记未命中且无未完成包装时才匹配回退；同缓冲区已有 ready 时优先 ready，不为旧的泛化提示排队。提示缓冲区保持 4096 字节 look-behind，但截断时额外保存每流的真实行前缀分类与正则边界类别，不保留已丢弃的原文；匹配时加入不可被提示消费的边界上下文，避免伪造 `^`、`\A`、`\b`，并跨截断保留 xtrace 排除。上下文搜索使用每流缓存的正则，先在提示捕获组外强制消费一个上下文 rune，再惰性寻找真实提示；不再用 `FindAllIndex` 丢弃首个合成候选，以免其遮蔽内部真实换行后的 `\s*Password:`。恢复搜索使用真实前置 rune 并保留原有边界含义，零宽候选按 rune 前进；原始表达式先经 `regexp/syntax` 规范化，兼容捕获组、内联选项与未闭合的 `\Q` 引用。只有成功消费提示/控制帧才重置协议匹配区域；不接受包含已丢弃区域的候选。就绪后不再识别密码提示。回退沿用现有 `respond`、三次上限及输入门禁，不增加会话或重放命令，不实现 OTP。`password_prompt_fallback_pattern` / `password_prompt_fallback` 为 DEBUG2 的规则/命中事件。单次非门禁 sudo 入口原有 stdin 行为不变。
- `privilegeExchange` 只在解析实际 ready 帧时报告 `elevated_shell_ready`，未开始就结束则报告 `elevation_not_confirmed`。密码提示、响应已发送、再次提示与既有 su 拒绝归类各自报告；拒绝事件需满足原 `finish` 的退出/错误条件，不凭 banner 中的拒绝样式文字提前断言；不会将提权后用户命令的非零结果或拒绝样式输出重新判为认证失败。
- `privilege_terminal` 从原激活/ACK/终端确认/输入转发/恢复边界报告；诊断不改变输入门禁、取消、恢复、凭据确认持久化或重试时机。回调仍只向命令的有限队列入队，不新增 I/O worker 或 raw 写入。

本地 SSH fixture 回归覆盖 sudo/su 重试后非零命令（仍只执行一次）、三次拒绝且不消费用户 stdin、root/免密/auto 模式、凭据查找不冒充认证、提示中取消、终端交接超时及恢复失败。断言阶段顺序、分级过滤和密码/用户命令/控制帧/原始错误不进入诊断。调用/提示回归另覆盖 sudo、sudo -i、sudo-rs、su、fish/zsh portable 控制 Shell、免密 -n、逐字节/任意双分片提示、限长/转义，以及就绪后输出不进入提示诊断。

sudo 回退测试使用忽略 `-p` 的本地 fixture，覆盖普通/portable/PTY 路径、密码重试后非零命令仍只执行一次、无显式配置不发送密码、三次拒绝与提示中取消不消费 stdin；单元回归覆盖节点/全局优先级、无效/空/零宽正则、主标记优先、sudo-rs 分片、xtrace、ready 优先及就绪后输出不匹配。长行回归覆盖超过 4 KiB 的 xtrace、行首/文本首/词边界伪造、不同截断边界、超长 `+` 前缀、后续真实提示及无换行重试恢复、主标记/sudo-rs 分片恢复，并断言无错误提示排队及敏感诊断。另覆盖长空白 banner 后 `(?m)^\s*Password:` / `\s*Password:` 的真实提示恢复，以及被排除 xtrace 后的继续搜索、Unicode/零宽匹配、捕获范围和正则缓存有界性。

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

事件可携带脱敏的 sudo/su 调用及识别到的密码提示词/规则，但不携带用户命令、脚本、凭据响应、私钥、用户环境变量值或原始远端错误文本。
CLI 限制并转义不可信字符串；公开元数据仍包含地址、用户名、指纹及转发端点，日志并非匿名数据。

## 验证入口与平台边界

认证回归覆盖固定密码/公钥、auto 公钥、失败公钥后密码回退、初始 none、公钥加密码多阶段成功/失败，以及三种 AEAD 和 AES-CTR/HMAC 的实际协商元数据。成功事件不得包含失败尝试；CLI 检查最终方法、成功链、逐方向 MAC 和未知值展示。

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
