// Package remotesess 实现 XOps v2 基于 *ssh.Session 的远端命令与交互式 Shell 会话适配器
// （ports.RemoteSession，ADR-009 / ADR-015）。
//
// 核心安全与并发不变量：
//   - 构造期预绑定 StdinPipe / StdoutPipe / StderrPipe，绝不给 ssh.Session.Stdin/Stdout/Stderr 赋值，
//     彻底规避 golang.org/x/crypto/ssh 内部孤儿拷贝协程泄漏；
//   - 所有 env / pty-req / exec / shell 控制请求、输入输出流泵与 Wait 均受上游 lifeNursery 统一监督，
//     全包 0 裸 go 语句与零行内 nolint 豁免；
//   - 输出泵在达到 CommandPlan.MaxOutputBytes 或 dst.Write 失败后继续排空至 EOF，防 SSH 窗口反压死锁。
package remotesess

const sessionCopyBufferBytes = 32 * 1024
