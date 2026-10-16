# SCP 分级诊断

`cmd/scp.go` 继续通过现有 `core/ssh.Connector` 和 `core/sftp.Client` 传输。
`core/log.DiagnosticObserver` 是可选的结构化生命周期事件接口，与项目 `DebugLogger` 独立；
SSH/SFTP 的 `WithDiagnostics` 只装配观察者，不改变连接租约、认证候选顺序、信任验证和取消行为。
其他 CLI、MCP、Playbook 调用方未装配观察者时维持现有行为，无协议 schema 变更。

## 参数与输出契约

- 删除 `--progress`，终端默认显示进度；重定向或管道不显示进度。
- `-q` 关闭进度、SSH 警告及诊断；失败错误与必要安全确认保留，批量成功/跳过提示隐藏。
- `-v` 显示 SSH/SFTP 生命周期和 SCP 传输诊断；全局 `--debug` 只控制项目日志，不受 `-q/-v` 改写。
- 与 OpenSSH 一样，SCP 自身 verbose 状态与 SSH 日志级别分别计算：`-qv` 有 SSH 诊断、无进度；
  `-vq` 无 SSH 诊断、无进度，保留 SCP 自身（包括 SFTP 初始化）的诊断。
  SSH 第一次 `-v` 设 DEBUG1，后续 `-v` 从当前级别递增到 DEBUG3，`-q` 将当前级别设 QUIET；
  因此 `-vqv` 不恢复 DEBUG1。SCP 自身的 `-vv`、`-vvv` 分别增加 DEBUG2、DEBUG3 事件，不受 SSH quiet 级别改写。

依据：[scp(1)](https://man.openbsd.org/scp.1)、
[scp.c 参数处理](https://github.com/openssh/openssh-portable/blob/master/scp.c)、
[ssh.c 参数处理](https://github.com/openssh/openssh-portable/blob/master/ssh.c)。
对齐诊断类别和选项语义，不宣称 Go SSH 后端逐行复刻 OpenSSH。

## 事件、所有权与边界

- Connector 报告连接、代理标记、缓存复用、主机密钥指纹与验证结果、认证完成、实际协商算法及连接版本。
  `x/crypto` 的协商元数据在 `activitySSHConn` 包装之前读取。
- 自动认证仅在既有回调选中候选时报告协议方法；固定认证的观察回调返回 nil，保留依赖的原始候选选择。
  不从配置推断认证成功方法；初始 none 成功时不虚构 password/publickey 尝试。
- SFTP 报告初始化开始、失败和成功；成功意味着当前依赖已验证 SFTP v3。
  SCP 报告整体传输开始及最终完成/失败。DEBUG2 报告服务端实际广告的扩展、路径请求以及逐文件传输开始与最终结果；DEBUG3 报告实际 SFTP 包类型、请求 ID、长度、状态码与流编号。远端 stderr 仅记录排空的字节数，省略原文。
- 事件不携带凭据、私钥、文件内容、句柄或原始错误。CLI 转义控制字符，并限制每个字符串长度。
  传输失败仍由原有 `%w` 错误链交付。
- 观察者属于命令，存活到 connector 关闭后；共享握手不使用单个等待者的输出生命周期。
  诊断回调、进度条及选择器上传状态提示只向容量 128 的队列非阻塞入队，满时丢弃辅助显示并汇报数量，不阻塞协议或传输。
- 支持 `ssh.BindOutput` 的输出使用命令拥有的 writer goroutine；单次写入超过一秒取消输出 binding，
  结束时关闭队列、等待 writer、释放 binding。借用的 stdout/stderr 从不关闭。取消原命令也取消输出 binding。
- Windows/macOS 控制台或管道若没有可取消 binding，跳过该输出流上的进度、诊断及上传状态提示并继续传输，结束时也不直接写入；
  可重定向 stderr 到普通日志文件保留诊断。常规文件写入仍受平台原生 Write 的限制，不能声称其可中断。
- 选择器上传的跳过提示仍写 stderr、成功提示仍写 stdout，并保留原有颜色及 `-q` 行为；
  两者复用受控队列，调用方结束时等待并释放绑定，写入失败不作为传输成功返回。
- 辅助输出失败以 `cmd.SCPOutputError` 保留输出流名称、错误链及非零退出状态；stdout/stderr
  可能共用同一管道，CLI 顶层不会再向标准流打印该错误，以免输出超时后再次卡住。其他错误维持原有报告方式。

## 验证范围

本地 SSH/SFTP fixture 覆盖上传、下载、转发、单主机选择器、错误、取消、none 认证不误报、
认证回退及失败、主机密钥拒绝。PTY fixture 检查默认进度及 quiet/重定向行为；Linux pipe fixture
检查诊断写入阻塞能结束；暂停 PTY fixture 检查进度回调及传输取消不受阻；满管道子进程检查失败退出不重写标准流；
选择器上传的成功/跳过分支分别检查 stdout/stderr 写满时能结束，并验证文件内容及借用输出流所有权。
另检查队列容量、控制字符转义、不支持输出零写入、输出错误与 stderr 所有权。
Windows/macOS 原生控制台行为仍由相应原生 CI 验证，交叉编译不代替原生执行。

## 后续实现与依赖边界

按用户选择保持现有依赖，无 fork、vendor 或第二套 SSH 后端。
`x/crypto/ssh` 没有公开 SSH 内部数据包观察接口；本实现不把加密 TCP 流量或 SFTP 包冒充 SSH 包跟踪。
`core/sftp/diagnostics.go` 在现有协议管道边界观察已读/已写字节，仅重组诊断所需的帧元数据；
协议解析、验证、版本支持、错误和重试仍由原依赖及现有 core 负责。

- `core/log.Diagnostic.Level` 为 1–3，零值保持 DEBUG1；可选 `DiagnosticLevel() int` 能力允许观察者过滤高等级事件。
  DEBUG1 不安装协议观察器，未注入观察者的其他调用方没有额外协议 I/O 或 goroutine。
- 发送/接收各使用固定 16 KiB 前缀空间，不根据报文声明长度分配；只截取版本/扩展元数据或第一个路径/扩展名。
  路径最多采集 512 字节、CLI 最多显示 256 字节；超限标注截断。版本扩展超过 16 KiB 也明确标注截断。
- DATA、WRITE、HANDLE 等仅提取类型、请求 ID、长度、状态码等允许字段，文件内容和句柄不进入前缀或事件。
  扩展请求仅提取扩展名，不采集其不透明参数。服务端 STATUS 原文不记录。
- 每个子系统分配进程内唯一流编号；并发请求以流编号和请求 ID 关联，不维护无限增长的请求映射。
- 读写观察器原样返回底层 n/error；不预读、不额外请求、不接管 reader 的关闭。
  writer 的 Close 仍委托给原有拥有者使用的管道，可打断阻塞写入。现有 stderr worker 继续排空并在结束时报告计数。
- 已有私有文件子系统复用同一观察入口，不创建平行传输逻辑。

新增回归覆盖单字节/合并分片、零长度/短帧、4 GiB 声明长度、未知类型、扩展及路径截断、
短写错误与关闭所有权、流编号并发、fuzz、等级/quiet 顺序及约 2 MiB 多线程上传/下载/转发。
本机 OpenSSH 对照测试仍只连接回环 fixture。Windows/macOS 尚无本轮原生运行证据。
