package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// fallbackInteract 返回本地交互适配器错误与 6 处 CLI 凭据库交互提示的规范英文兜底模板。
func fallbackInteract(id domi18n.MessageID) string {
	switch id {
	case KeyInteractNilFileHandles:
		return "input and output file handles must not be nil"
	case KeyInteractNilStreamHandles:
		return "StreamSpec In and Out must not be nil"
	case KeyInteractInvalidRequest:
		return "{kind} is invalid"
	case KeyInteractEmptyText:
		return "text input must not be empty"
	case KeyInteractEmptySecret:
		return "secret input must not be empty"
	case KeyInteractLineTooLong:
		return "input line length exceeds limit of {max} bytes"
	case KeyInteractUnixReadTermios:
		return "failed to read Unix terminal termios"
	case KeyInteractUnixDisableEcho:
		return "failed to disable Unix terminal echo"
	case KeyInteractUnixWakePipe:
		return "failed to create terminal wakeup pipe"
	case KeyInteractWinReadConsole:
		return "failed to read Windows console input mode"
	case KeyInteractWinDisableEcho:
		return "failed to disable Windows console echo"
	case KeyInteractWinCancelEvent:
		return "failed to create Windows cancel event"
	case KeyInteractVaultInitTitle:
		return "Vault init"
	case KeyInteractVaultUnlockTitle:
		return "Vault unlock"
	case KeyInteractVaultMasterPrompt:
		return "Master passphrase"
	case KeyInteractVaultConfirmTitle:
		return "Confirm Vault Passphrase"
	case KeyInteractVaultConfirmPrompt:
		return "Confirm master passphrase"
	case KeyInteractVaultEnrollPassTitle:
		return "Enroll SSH Password"
	case KeyInteractVaultEnrollPassPrompt:
		return "Enter SSH login password"
	case KeyInteractVaultNodePrivTitle:
		return "Set Node Privilege Secret"
	case KeyInteractVaultNodePrivPrompt:
		return "Enter sudo/su/doas privilege password"
	case KeyInteractVaultRotateTitle:
		return "Rotate Secret"
	case KeyInteractVaultRotatePrompt:
		return "Enter new secret value"
	case KeyInteractVaultEnrollKeyTitle:
		return "Private Key Passphrase"
	case KeyInteractVaultEnrollKeyPrompt:
		return "Enter private key passphrase"
	default:
		return ""
	}
}
