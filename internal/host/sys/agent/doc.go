// Package agent 实现 XOps v2 本机 SSH Agent 出站适配器（ports.SSHAgentPort，ADR-002 / P4-T4）。
//
// 安全边界与跨平台特性：
//   - Unix（Linux / macOS / FreeBSD）通过 core/osfs.ValidateControlSocketPath 与 DialUnixVerified
//     校验套接字路径与对端同 UID 凭证（SO_PEERCRED / LOCAL_PEERCRED）；
//   - Windows 对 \\.\pipe\... 命名管道通过 core/osfs.DialWindowsNamedPipeVerified 执行
//     SECURITY_IDENTIFICATION 防冒充与 DACL/服务端进程令牌校验，并兼容 Windows AF_UNIX 套接字；
//   - 支持 RSA SHA-2 签名算法标志（rsa-sha2-256 / rsa-sha2-512 及对应 OpenSSH 证书算法）。
package agent

const (
	envSSHAuthSock       = "SSH_AUTH_SOCK"
	agentKeywordDefault  = "default"
	agentKeywordNone     = "none"
	maxAgentCommentBytes = 256
)

func zeroVal[T any]() (z T) { return z }
