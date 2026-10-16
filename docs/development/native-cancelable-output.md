# 原生可取消输出

当前入口仍是 `core/ssh.BindOutput` 与 `prepareContextOutputWithLimit`，不创建第二套 SSH/传输后端。
SCP 的诊断、进度和上传状态，以及共享 SSH 流式/PTY 入口均复用这些能力。

| 输出目标 | 实现 | 所有权与限制 |
|---|---|---|
| Linux 终端、管道 | 独立打开 `/proc/self/fd`，Go deadline | 不改变借用描述符的标志 |
| macOS 终端 | `F_GETPATH` 定位实际终端并独立以非阻塞模式重开，验证设备身份，Go deadline | 自有句柄；不修改终端模式 |
| macOS 已有非阻塞管道 | `F_DUPFD_CLOEXEC`、Go deadline | 自有描述符，共享状态；调用方须保持管道非阻塞直到释放绑定 |
| macOS 普通阻塞匿名管道 | 不支持，保留现有安全降级 | 不设置共享 `O_NONBLOCK`，不引入辅助进程 |
| Windows 控制台 | 不支持，保留安全降级 | Windows 11 原生 ConPTY 阻塞写入不能由 `CancelSynchronousIo` 可靠取消；不引入辅助进程 |
| Windows 同步/overlapped 管道 | 自有重复句柄，线程取消加针对具体 OVERLAPPED 的 `CancelIoEx` | 自有事件与固定生命周期的 pinned 内存；不取消借用者其他请求 |
| 普通文件 | 保留原有实现 | 原生文件系统正在执行的 Write 不承诺可中断 |

Windows 每次 native 写入的取消协程在完成前持续重试，覆盖“取消先于系统调用”的窗口。
返回前等待 I/O 及取消协程结束，再释放事件、请求缓冲区和线程句柄、解除线程锁定。
OVERLAPPED 事件低位抑制 IOCP 通知，避免向借用管道原有关联的 Go completion port 投递自定义请求。
NUL 通过句柄对象名识别；不使用可能均为零的设备/管道 FileInfo ID 判断，以免把控制台、管道误当普通文件。

macOS 的 `/dev/fd` 与 dup 一样共享文件状态，不能作为 Linux `/proc/self/fd` 的等价替代。
SCP 终端探测使用 `SyscallConn.Control`；不调用可能清除管道 `O_NONBLOCK` 的 `File.Fd`。
不支持的输出维持原契约：严格执行入口在执行前拒绝，旧接口保留其兼容策略，SCP 跳过辅助显示并继续传输。
调用方始终持有原流；绑定只释放自有资源，并要求调用方先取消、汇合写入，再释放绑定。

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

原生平台测试包括 Windows 同步/overlapped 管道阻塞取消、借用句柄、控制台降级，
以及 ConPTY 不排空输出时的安全降级（`integration`）；macOS 覆盖暂停终端、非阻塞管道取消、
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
