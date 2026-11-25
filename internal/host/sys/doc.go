// Package sys 实现 XOps v2 本机系统基础设施出站适配器（ADR-002 / ADR-011）：
//   - ports.Clock（真实单调系统时钟与可取消定时器）
//   - ports.Entropy（基于 crypto/rand 的并发安全密码学熵源）
//   - ports.EnvPort（只读环境变量与本机主机/用户/UID/主目录快照）
//   - ports.ProcessPort（受控子进程执行、进程组/Windows JobObject 清理与 stdio 管道连接）
//   - ports.TerminalPort 与 TerminalHandle.Relay（Unix PTY/termios/SIGWINCH 与 Windows ConPTY/Console Mode 原始终端与零泄漏双向中继）
//
// 本包是全仓唯一获准直接调用 os.Getenv / os/exec / PTY 原语的白名单包，但仍严格恪守：
//   - 零裸 go 语句（全部后台监听与中继泵均受 core/conc.Nursery 监督）；
//   - 平台差异实现拆入 _unix.go / _linux.go / _bsd.go / _windows.go 构建标签文件；
//   - 全包生产与测试源码零行内 //nolint:、零裸 OS 文件系统绕过。
package sys

import "errors"

// 本包导出的规范化哨兵错误，供上层以 errors.Is 精确区分系统适配层故障。
var (
	// ErrOrphanedProcessGroup 表示当前进程处于 POSIX 孤儿进程组或会话首进程，不可安全挂起（INV-E1）。
	ErrOrphanedProcessGroup = errors.New("sys: 当前进程处于孤儿进程组或会话首进程，禁止执行挂起")
	// errInputCanceled 为内部哨兵，用于标识本机终端输入读取因 Relay 作用域结束而被主动唤醒取消。
	errInputCanceled = errors.New("sys: 终端输入读取已随作用域取消")
)

func zeroVal[T any]() (z T) { return z }
