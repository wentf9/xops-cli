package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// 本文件声明本地人工交互适配器（internal/host/sys/interact）与 CLI 凭据库 6 处交互提示的强类型 MessageID 常量。
// 交互适配器错误与 6 处 CLI 凭据库结构化提示键登记于 interactErrorAndPromptKeys（确保 Message.Canonical() 规范英文兜底）；
// 风险等级与审批外框纯展示标签仅登记于 interactDisplayKeys（确认词 [y/N]: 与 [approve/N]: 保持稳定 ASCII）。
const (
	// 交互适配器错误键（internal/host/sys/interact）。
	KeyInteractNilFileHandles   domi18n.MessageID = "interact.err.nil_file_handles"   // 输入或输出文件句柄为 nil
	KeyInteractNilStreamHandles domi18n.MessageID = "interact.err.nil_stream_handles" // StreamSpec In/Out 为 nil
	KeyInteractInvalidRequest   domi18n.MessageID = "interact.err.invalid_request"    // 交互请求对象无效
	KeyInteractEmptyText        domi18n.MessageID = "interact.err.empty_text"         // 非空文本输入为空
	KeyInteractEmptySecret      domi18n.MessageID = "interact.err.empty_secret"       // 非空机密输入为空
	KeyInteractLineTooLong      domi18n.MessageID = "interact.err.line_too_long"      // 交互输入行超过字节上限
	KeyInteractUnixReadTermios  domi18n.MessageID = "interact.err.unix_read_termios"  // 读取 Unix termios 失败
	KeyInteractUnixDisableEcho  domi18n.MessageID = "interact.err.unix_disable_echo"  // 禁用 Unix 终端回显失败
	KeyInteractUnixWakePipe     domi18n.MessageID = "interact.err.unix_wake_pipe"     // 创建 Unix 唤醒管道失败
	KeyInteractWinReadConsole   domi18n.MessageID = "interact.err.win_read_console"   // 读取 Windows 控制台输入模式失败
	KeyInteractWinDisableEcho   domi18n.MessageID = "interact.err.win_disable_echo"   // 禁用 Windows 控制台回显失败
	KeyInteractWinCancelEvent   domi18n.MessageID = "interact.err.win_cancel_event"   // 创建 Windows 取消事件失败

	// CLI 凭据库 6 处交互式口令提示键（internal/entry/cli/cmdasset/vault*.go）。
	KeyInteractVaultInitTitle        domi18n.MessageID = "interact.vault.init.title"             // 凭据库初始化提示标题
	KeyInteractVaultUnlockTitle      domi18n.MessageID = "interact.vault.unlock.title"           // 凭据库解锁提示标题
	KeyInteractVaultMasterPrompt     domi18n.MessageID = "interact.vault.master.prompt"          // 主口令提示正文
	KeyInteractVaultConfirmTitle     domi18n.MessageID = "interact.vault.confirm.title"          // 二次确认主口令标题
	KeyInteractVaultConfirmPrompt    domi18n.MessageID = "interact.vault.confirm.prompt"         // 二次确认主口令正文
	KeyInteractVaultEnrollPassTitle  domi18n.MessageID = "interact.vault.enroll_password.title"  // 录入 SSH 登录密码标题
	KeyInteractVaultEnrollPassPrompt domi18n.MessageID = "interact.vault.enroll_password.prompt" // 录入 SSH 登录密码正文
	KeyInteractVaultNodePrivTitle    domi18n.MessageID = "interact.vault.node_privilege.title"   // 设置节点提权密码标题
	KeyInteractVaultNodePrivPrompt   domi18n.MessageID = "interact.vault.node_privilege.prompt"  // 设置节点提权密码正文
	KeyInteractVaultRotateTitle      domi18n.MessageID = "interact.vault.rotate.title"           // 轮换凭据标题
	KeyInteractVaultRotatePrompt     domi18n.MessageID = "interact.vault.rotate.prompt"          // 轮换凭据正文
	KeyInteractVaultEnrollKeyTitle   domi18n.MessageID = "interact.vault.enroll_key.title"       // 加密私钥口令标题
	KeyInteractVaultEnrollKeyPrompt  domi18n.MessageID = "interact.vault.enroll_key.prompt"      // 加密私钥口令正文

	// 交互确认与审批外框展示标签（纯展示类，仅存于 interact.yaml）。
	KeyInteractRiskUnknown         domi18n.MessageID = "interact.risk.unknown"          // 风险等级标签：未知
	KeyInteractRiskSafe            domi18n.MessageID = "interact.risk.safe"             // 风险等级标签：安全
	KeyInteractRiskModerate        domi18n.MessageID = "interact.risk.moderate"         // 风险等级标签：中等风险
	KeyInteractRiskDangerous       domi18n.MessageID = "interact.risk.dangerous"        // 风险等级标签：高风险
	KeyInteractRiskCritical        domi18n.MessageID = "interact.risk.critical"         // 风险等级标签：极高风险
	KeyInteractApprovalBanner      domi18n.MessageID = "interact.approval.banner"       // 审批横幅前缀标签
	KeyInteractApprovalDigestLabel domi18n.MessageID = "interact.approval.digest_label" // 审批信封摘要字段标签
)

func interactErrorAndPromptKeys() []domi18n.MessageID {
	return []domi18n.MessageID{
		KeyInteractNilFileHandles, KeyInteractNilStreamHandles, KeyInteractInvalidRequest,
		KeyInteractEmptyText, KeyInteractEmptySecret, KeyInteractLineTooLong,
		KeyInteractUnixReadTermios, KeyInteractUnixDisableEcho, KeyInteractUnixWakePipe,
		KeyInteractWinReadConsole, KeyInteractWinDisableEcho, KeyInteractWinCancelEvent,
		KeyInteractVaultInitTitle, KeyInteractVaultUnlockTitle, KeyInteractVaultMasterPrompt,
		KeyInteractVaultConfirmTitle, KeyInteractVaultConfirmPrompt, KeyInteractVaultEnrollPassTitle,
		KeyInteractVaultEnrollPassPrompt, KeyInteractVaultNodePrivTitle, KeyInteractVaultNodePrivPrompt,
		KeyInteractVaultRotateTitle, KeyInteractVaultRotatePrompt, KeyInteractVaultEnrollKeyTitle,
		KeyInteractVaultEnrollKeyPrompt,
	}
}

func interactDisplayKeys() []domi18n.MessageID {
	return []domi18n.MessageID{
		KeyInteractRiskUnknown, KeyInteractRiskSafe, KeyInteractRiskModerate, KeyInteractRiskDangerous,
		KeyInteractRiskCritical, KeyInteractApprovalBanner, KeyInteractApprovalDigestLabel,
	}
}
