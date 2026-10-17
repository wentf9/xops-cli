# 原生可取消输出

当前入口仍是 `core/ssh.BindOutput` 与 `prepareContextOutputWithLimit`，不创建第二套 SSH/传输后端。
SCP 的诊断、进度和上传状态，以及共享 SSH 流式/PTY 入口均复用这些能力。

| 输出目标 | 实现 | 所有权与限制 |
|---|---|---|
| Linux 终端、管道 | 独立打开 `/proc/self/fd`，Go deadline | 不改变借用描述符的标志 |
| macOS 终端 | `F_GETPATH` 定位实际终端并独立以非阻塞模式重开，验证设备身份，Go deadline | 自有句柄；不修改终端模式 |
| macOS 已有非阻塞管道 | `F_DUPFD_CLOEXEC`、Go deadline | 自有描述符，共享状态；调用方须保持管道非阻塞直到释放绑定 |
| macOS 普通阻塞匿名管道 | 不支持，保留现有安全降级 | 不设置共享 `O_NONBLOCK`，不引入辅助进程 |
| Windows 控制台 | 宿主显式注入中继入口；自有重复句柄，按需启动管道中继子进程，管道请求/ACK 经 `CancelIoEx`/`CancelSynchronousIo` 取消 | 未注入时保留安全降级；取消后检查进程退出，不关闭原句柄或修改控制台模式 |
| Windows 同步/overlapped 管道 | 自有重复句柄，线程取消加针对具体 OVERLAPPED 的 `CancelIoEx` | 自有事件与固定生命周期的 pinned 内存；不取消借用者其他请求 |
| 普通文件（含 PTY 重定向） | 复用同步 `regularFileOutput` | 写入之间检查取消；已进入内核的 Write 必须结束后才返回，不承诺硬取消时限 |

Windows 每次 native 写入的取消协程在完成前持续重试，覆盖“取消先于系统调用”的窗口。
返回前等待 I/O 及取消协程结束，再释放事件、请求缓冲区和线程句柄、解除线程锁定。
OVERLAPPED 事件低位抑制 IOCP 通知，避免向借用管道原有关联的 Go completion port 投递自定义请求。
NUL 通过句柄对象名识别；不使用可能均为零的设备/管道 FileInfo ID 判断，以免把控制台、管道误当普通文件。

Windows 控制台的宿主通过 `work, cleanup := WithConsoleOutputRelay(ctx, ConsoleOutputRelay{Executable, Args, Env})`
显式提供中继程序、私有入口参数和环境快照，并必须持有 `cleanup` 到命令 I/O 全部结束。
作用域拥有所有绑定，包括局部 `closeFn` 清理失败的绑定；作用域关闭先取消输出，再重试回收，失败仍保留所有权供宿主重试。
不创建全局管理器或后台重试协程。CLI 在 `cmd/root.go` 持有该作用域，在 `cmd/cli/main.go` 的正常命令启动前分派
`--xops-console-output-relay` 到 `ServeConsoleOutputRelay`。
core 不读取中继环境变量，不在 `init()` 中退出或接管宿主进程；只导入 core 不会启用中继。
中继首次非空写入时才创建，借用的控制台句柄和模式始终不变。

Windows 10+ 中继通过创建时的 `PROC_THREAD_ATTRIBUTE_JOB_LIST` 原子加入非继承的 kill-on-close Job Object；
不存在先启动再加入 Job 的竞态。父进程异常退出会由 OS 关闭 Job 并终止中继，即使中继正阻塞于控制台写入也不依赖管道 EOF。
不支持该属性或 Job 约束时启动失败，不退回无 Job 的子进程。

Job 终止仍是异步操作，不能当作汇合成功。清理检查 `WAIT_OBJECT_0` 后才释放进程、ACK 和 Job 句柄；
终止后等待最多 5 秒，失败或超时作为保留目标流的 `ssh.OutputError` 返回，禁用后续写入，由命令作用域继续拥有并重试。
SFTP 对这类输出/清理错误立即终止会话，不向故障流补打诊断或恢复行编辑器；取消/断连包装也保留原始错误链。
关闭的中继作用域拒绝新绑定，不静默回退为直接写入。清理错误不代表中继已退出或可以安全交还终端。

macOS 的 `/dev/fd` 与 dup 一样共享文件状态，不能作为 Linux `/proc/self/fd` 的等价替代。
SCP 终端探测使用 `SyscallConn.Control`；不调用可能清除管道 `O_NONBLOCK` 的 `File.Fd`。
不支持的输出维持原契约：严格执行入口在执行前拒绝，旧接口保留其兼容策略，SCP 跳过辅助显示并继续传输。
调用方始终持有原流；绑定只释放自有资源，并要求调用方先取消、汇合写入，再释放绑定。

## PTY 普通文件重定向

`prepareContextOutputWithLimit` 先识别普通文件，再进入各平台终端/管道适配器。严格 PTY 输出复用 `BindOutput` 已使用的同步 `regularFileOutput`，不新增 goroutine、复制文件句柄或文件中继子进程。绑定借用原文件，不关闭、不 fsync、不改变打开标志；共享偏移只随调用方要求的写入更新。终端输入要求与终端/管道原有的取消、每次写入保护保持不变。

普通文件采用明确较弱的取消契约：每次写入前检查 context，正在内核中执行的写入不可承诺中断，返回前必须等待它完成。`waitTerminalOutput`/`waitSessionOutput` 的取消或排空期限只发出停止信号，随后仍汇合输出工作协程；不能将一秒关闭宽限或 PTY 写入保护宣称为文件写入的硬超时。慢盘、NFS 或异常文件系统可能导致取消长时间等待；禁止提前返回并留下延迟写入。写入失败保留 `OutputError.Target` 和原始文件错误；已关闭文件在发送命令前拒绝。

回归包括跨平台的文件追加标志/所有权、取消前置检查、只读/关闭文件错误与受控写入等待模型，以及 Linux PTY 分别/合并重定向、非零退出、失败后的终端恢复、显式提权文件输出和 CLI 显式解释器重定向。SSH 对端均为 fixture；受控等待测试不是原生内核慢盘故障注入，Windows/macOS 原生 PTY 验收仍需各平台 CI。

## CLI 接入

`BindOutput` 识别现有 `LockedWriter`，先绑定底层 writer，再保留同一把互斥锁；等锁期间也检查取消。
不为任意 writer 声明可取消能力。`exec` 的单机/多机流式输出因此保留执行上下文的取消与超时；
最终结果、Playbook 报告和 dry-run 使用同一绑定入口，渲染后释放自有绑定。
主要输出不设置 SCP 辅助显示的一秒限时，也不静默丢弃；不支持的目标保留直接输出的旧契约。
Playbook 的全局日志/步骤提示不属于报告 writer，仍遵循 logger 自身契约。

`ssh` 的显式执行不再按客户端 OS 名称拒绝，core 在发送请求前检查实际 I/O 能力。
普通 SSH 命令及非 PTY Shell 根据输出能力选择严格或兼容入口，不在执行失败后回退重试。
Windows 文件 stdin 优先使用宿主注入的 `Environment.InputBridge`；只有缺少输入桥时才在远端请求前拒绝，
类型化 nil 桥也视为缺失，预检与实际输入管线使用同一能力。
`ssh.OutputError.Target` 保留借用的输出目标，错误链不变；只有标准流故障才抑制 stdout/stderr 上的重复报错，
`exec` 也只在标准流故障后跳过结果补打。独立日志文件失败仍向健康的 stderr 报告，
包括合并的执行及清理错误；检查遍历所有合并分支，避免日志错误掩盖同时发生的标准流故障。
Playbook 同时保留执行、步骤及报告输出错误。

## 验证与边界

中继版本及本轮评审修复尚待 Windows 原生 CI 验证；下述 `vm` 历史记录仅覆盖原管道与控制台降级实现，
不能作为新中继的原生通过证据。回归测试要求实际进入控制台写入后再取消，并在恢复 ConPTY 排空前确认中继进程退出；
另覆盖未注入时降级、环境变量不接管进程、命令作用域接管失败绑定、关闭后拒绝新绑定，以及不运行 Go defer 的杀父回收。
SFTP 便携回归覆盖直接、包装和合并的输出错误（包括与中断合并），验证零补打且不吞掉错误。

原生平台测试包括 Windows 同步/overlapped 管道阻塞取消、借用句柄、控制台绑定与中继写入，
以及 ConPTY 不排空输出时的阻塞写入取消（`integration`）；macOS 覆盖暂停终端、非阻塞管道取消、
阻塞管道拒绝、借用标志和终端可继续使用。已有 CI 分别在 Windows/macOS 执行相应测试，
Windows ConPTY 增加独立回归步骤。本次已在 Windows 11 `vm` 原生验证管道与控制台降级；
macOS 仍待原生 CI，交叉编译和 Wine 不作为原生通过证据。

`vm` 上 core 的 `TestWindowsOutput*`、普通文件/NUL/标准句柄绑定测试，以及 CLI 的
`TestSCPDiagnosticBlockedPipe`、不支持输出和写入错误测试均以 `-test.count=3` 通过。
上传的测试程序已删除，并确认无对应测试进程。该原生运行未启用 race；
Linux 的 `core/ssh`、`cmd` race 测试通过，Windows/macOS race 仍由原生 CI 验证。
上述 `vm` 记录针对平台适配器；后续 CLI 接入回归本轮在 Linux fixture 验证，
并交叉编译 Windows amd64、macOS arm64 测试程序，尚未执行这批新增用例的原生回归。

实现依据：[CancelSynchronousIo](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelsynchronousio)、
[取消 I/O 的竞态与完成语义](https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations)、
[OVERLAPPED 事件与 completion port](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus)、
[Apple XNU dupfdopen](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_descrip.c)。
