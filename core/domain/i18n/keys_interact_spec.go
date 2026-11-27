package i18n

// 本文件声明 core/ 模块内交互式提示（主机密钥信任、SSH 键盘交互质询、加密私钥口令、
// 远端提权口令及 ControlMaster 确认）使用的强类型 MessageID 常量。
const (
	// KeyInteractHostKeyTitle 表示未知 SSH 主机密钥首次信任确认提示的标题。
	KeyInteractHostKeyTitle MessageID = "interact.hostkey.title"
	// KeyInteractHostKeyBody 表示未知 SSH 主机密钥首次信任确认提示的正文（含 algorithm/fingerprint/endpoint 参数）。
	KeyInteractHostKeyBody MessageID = "interact.hostkey.body"

	// KeyInteractSSHChallengeTitle 表示 SSH Keyboard-Interactive 质询交互提示的标题。
	KeyInteractSSHChallengeTitle MessageID = "interact.ssh_challenge.title"
	// KeyInteractChallengeResponse 表示远端 SSH 质询文本为空时的默认应答提示正文。
	KeyInteractChallengeResponse MessageID = "interact.ssh_challenge.response"

	// KeyInteractKeyPassphraseTitle 表示加密私钥登记流程口令提示的标题。
	KeyInteractKeyPassphraseTitle MessageID = "interact.enroll_key.title"
	// KeyInteractKeyPassphraseBody 表示加密私钥登记流程口令提示的正文。
	KeyInteractKeyPassphraseBody MessageID = "interact.enroll_key.body"

	// KeyInteractPrivilegeTitle 表示远端提权执行口令提示的标题。
	KeyInteractPrivilegeTitle MessageID = "interact.privilege.title"
	// KeyInteractPrivilegeBody 表示远端提权执行口令提示的正文（含 method/node 参数）。
	KeyInteractPrivilegeBody MessageID = "interact.privilege.body"

	// KeyInteractMuxConfirmTitle 表示 ControlMaster 确认提示的标题。
	KeyInteractMuxConfirmTitle MessageID = "interact.mux.confirm_title"
	// KeyInteractMuxStartBody 表示启动新 ControlMaster 监听器的确认正文。
	KeyInteractMuxStartBody MessageID = "interact.mux.start_body"
	// KeyInteractMuxReuseBody 表示复用活跃 ControlMaster 连接的确认正文。
	KeyInteractMuxReuseBody MessageID = "interact.mux.reuse_body"
	// KeyInteractMuxAttachBody 表示经 DialMux 附着活跃 ControlMaster 的确认正文。
	KeyInteractMuxAttachBody MessageID = "interact.mux.attach_body"
)

func interactKeys() []MessageID {
	return []MessageID{
		KeyInteractHostKeyTitle,
		KeyInteractHostKeyBody,
		KeyInteractSSHChallengeTitle,
		KeyInteractChallengeResponse,
		KeyInteractKeyPassphraseTitle,
		KeyInteractKeyPassphraseBody,
		KeyInteractPrivilegeTitle,
		KeyInteractPrivilegeBody,
		KeyInteractMuxConfirmTitle,
		KeyInteractMuxStartBody,
		KeyInteractMuxReuseBody,
		KeyInteractMuxAttachBody,
	}
}
