// Package interact 实现 XOps v2 本机人工交互与无回显机密采集出站适配器（ports.InteractionPort，ADR-002 / P4-T4）。
//
// 安全与跨平台特性：
//   - 所有提示与审批摘要（含结构化 i18n.Message 渲染结果）均经 security.SanitizePromptText 脱敏，阻断终端转义序列注入；
//   - 支持实例级并发安全可热替换的 *i18n.Localizer（零全局状态），本地化标题、正文、风险标签与审批外框，
//     同时保持 ApprovalEnvelope.ScopeSummary() / Digest() 逐字节不变（INV-E5）及 ASCII 确认词 [y/N]: / [approve/N]:；
//   - Confirm 与 PromptApproval 严格失败关闭（空输入或非法输入均返回 VerdictDeny），
//     审批响应强绑定 ApprovalEnvelope.Digest()；
//   - PromptSecret 在交互终端上禁用回显（Unix termios ~ECHO / Windows ~ENABLE_ECHO_INPUT），
//     退出前立即恢复终端模式并 clear 零化输入缓冲，仅经 secret.WithBytes 借出 *secret.SecretBox；
//   - Unix 支持在标准输入被重定向时回退打开受控控制终端 /dev/tty（O_RDWR|O_CLOEXEC + termios 校验 +
//     unix.Poll self-pipe 取消）；Windows 管道 stdin 严格失败关闭返回 ports.ErrInteractionUnavailable。
package interact

const (
	maxPromptLineBytes = 4096
)

func zeroVal[T any]() (z T) { return z }
