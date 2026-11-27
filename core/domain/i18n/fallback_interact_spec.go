package i18n

// fallbackInteract 返回 core/ 交互式提示消息标识对应的规范英文兜底模板（纯函数、零包级 var）。
func fallbackInteract(id MessageID) string {
	switch id {
	case KeyInteractHostKeyTitle:
		return "SSH Host Key Verification"
	case KeyInteractHostKeyBody:
		return "Trust unknown SSH host key {algorithm} ({fingerprint}) for {endpoint}?"
	case KeyInteractSSHChallengeTitle:
		return "SSH Challenge"
	case KeyInteractChallengeResponse:
		return "Response:"
	case KeyInteractKeyPassphraseTitle:
		return "Private Key Passphrase"
	case KeyInteractKeyPassphraseBody:
		return "Enter passphrase for encrypted private key"
	case KeyInteractPrivilegeTitle:
		return "Privilege Escalation"
	case KeyInteractPrivilegeBody:
		return "Enter {method} password for {node}"
	case KeyInteractMuxConfirmTitle:
		return "ControlMaster Confirmation"
	case KeyInteractMuxStartBody:
		return "Start ControlMaster listener"
	case KeyInteractMuxReuseBody:
		return "Reuse active ControlMaster connection"
	case KeyInteractMuxAttachBody:
		return "Attach to active ControlMaster via DialMux"
	default:
		return ""
	}
}
