// Package helper 实现基于受控子进程（ports.ProcessPort）的外部凭据助手适配器
// 与隔离式 Argon2id KDF Helper 协议（ADR-002 / ADR-011 / P4-T4）。
//
// 本包仅通过注入的 ports.ProcessPort.Run(ctx, spec, stdin) 的标准输入管道传递明文机密，
// 严禁将任何机密放入命令行参数或环境变量；所有明文消费均经 tools/xopsvet/analyzers/secrettaint
// 的 vault/helper 窄钩子静态审计（0 //nolint:、0 os/exec 直接调用）。
package helper

import (
	"errors"
	"time"
)

const (
	// ProtocolVersion 为外部凭据助手 JSON 协议主版本号（v2 纯净协议，零 v1 兼容）。
	ProtocolVersion = 2
	// DefaultHelperTimeout 为外部凭据助手与隔离 KDF 子进程的默认执行超时。
	DefaultHelperTimeout = 15 * time.Second
	// MaxHelperResponseBytes 为外部凭据助手标准输出响应最大字节上限（64 KiB）。
	MaxHelperResponseBytes uint64 = 64 * 1024
)

// 本包导出的规范化哨兵错误。
var (
	// ErrProtocol 表示外部凭据助手或隔离 KDF Helper 返回了畸形协议帧。
	ErrProtocol = errors.New("vault/helper: 助手协议帧非法")
)
