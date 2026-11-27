package i18n

// 本文件声明 core/ 模块内交互式提示（主机密钥信任、SSH 质询、加密私钥口令、提权口令及 ControlMaster 确认）强类型 MessageID 常量。
const (
	// core/ 交互式提示（主机密钥信任、SSH 质询、私钥口令、提权口令、ControlMaster 确认）既有 M2 契约。
	KeyInteractHostKeyTitle            MessageID = "interact.hostkey.title"                 // 未知主机密钥首次信任确认标题
	KeyInteractHostKeyBody             MessageID = "interact.hostkey.body"                  // 未知主机密钥首次信任确认正文
	KeyInteractSSHChallengeTitle       MessageID = "interact.ssh_challenge.title"           // SSH Keyboard-Interactive 质询标题
	KeyInteractChallengeResponse       MessageID = "interact.ssh_challenge.response"        // 空质询文本默认应答提示
	KeyInteractChallengeBannerResponse MessageID = "interact.ssh_challenge.banner_response" // 含横幅空质询默认应答提示
	KeyInteractKeyPassphraseTitle      MessageID = "interact.enroll_key.title"              // 加密私钥登记口令标题
	KeyInteractKeyPassphraseBody       MessageID = "interact.enroll_key.body"               // 加密私钥登记口令正文
	KeyInteractPrivilegeTitle          MessageID = "interact.privilege.title"               // 远端提权口令标题
	KeyInteractPrivilegeBody           MessageID = "interact.privilege.body"                // 远端提权口令正文
	KeyInteractMuxConfirmTitle         MessageID = "interact.mux.confirm_title"             // ControlMaster 确认标题
	KeyInteractMuxStartBody            MessageID = "interact.mux.start_body"                // 启动 ControlMaster 确认正文
	KeyInteractMuxReuseBody            MessageID = "interact.mux.reuse_body"                // 复用 ControlMaster 确认正文
	KeyInteractMuxAttachBody           MessageID = "interact.mux.attach_body"               // 附着 ControlMaster 确认正文
)
