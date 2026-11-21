package sshenv

import "github.com/wentf9/xops-cli/core/winsec"

var (
	errUntrustedAgentPipeOwner = winsec.ErrUntrustedAgentPipeOwner
	errInsecureAgentPipeDACL   = winsec.ErrInsecureAgentPipeDACL
)

const (
	windowsInvalidFileAttributes     = winsec.InvalidFileAttributes
	windowsFileAttributeDirectory    = winsec.FileAttributeDirectory
	windowsFileAttributeDevice       = winsec.FileAttributeDevice
	windowsFileAttributeReparsePoint = winsec.FileAttributeReparsePoint

	windowsInheritOnlyACEFlag = winsec.InheritOnlyACEFlag

	windowsAccessAllowedACEType               = winsec.AccessAllowedACEType
	windowsAccessDeniedACEType                = winsec.AccessDeniedACEType
	windowsSystemAuditACEType                 = winsec.SystemAuditACEType
	windowsSystemAlarmACEType                 = winsec.SystemAlarmACEType
	windowsAccessAllowedCompoundACEType       = winsec.AccessAllowedCompoundACEType
	windowsAccessAllowedObjectACEType         = winsec.AccessAllowedObjectACEType
	windowsAccessDeniedObjectACEType          = winsec.AccessDeniedObjectACEType
	windowsSystemAuditObjectACEType           = winsec.SystemAuditObjectACEType
	windowsSystemAlarmObjectACEType           = winsec.SystemAlarmObjectACEType
	windowsAccessAllowedCallbackACEType       = winsec.AccessAllowedCallbackACEType
	windowsAccessDeniedCallbackACEType        = winsec.AccessDeniedCallbackACEType
	windowsAccessAllowedCallbackObjectACEType = winsec.AccessAllowedCallbackObjectACEType
	windowsAccessDeniedCallbackObjectACEType  = winsec.AccessDeniedCallbackObjectACEType
	windowsSystemAuditCallbackACEType         = winsec.SystemAuditCallbackACEType
	windowsSystemAlarmCallbackACEType         = winsec.SystemAlarmCallbackACEType
	windowsSystemMandatoryLabelACEType        = winsec.SystemMandatoryLabelACEType
	windowsSystemResourceAttributeACEType     = winsec.SystemResourceAttributeACEType
	windowsSystemScopedPolicyIDACEType        = winsec.SystemScopedPolicyIDACEType
	windowsSystemProcessTrustLabelACEType     = winsec.SystemProcessTrustLabelACEType

	windowsAccessFileWriteData          = winsec.AccessFileWriteData
	windowsAccessFileAppendData         = winsec.AccessFileAppendData
	windowsAccessFileCreatePipeInstance = winsec.AccessFileCreatePipeInstance
	windowsAccessFileDeleteChild        = winsec.AccessFileDeleteChild
	windowsAccessDelete                 = winsec.AccessDelete
	windowsAccessWriteDAC               = winsec.AccessWriteDAC
	windowsAccessWriteOwner             = winsec.AccessWriteOwner
	windowsAccessGenericAll             = winsec.AccessGenericAll
	windowsAccessGenericWrite           = winsec.AccessGenericWrite

	windowsInsecureSSHObjectWriteMask  = winsec.InsecureSSHObjectWriteMask
	windowsInsecureNamedPipeServerMask = winsec.InsecureNamedPipeServerMask

	windowsAgentPipeDesiredAccess = winsec.AgentPipeDesiredAccess
	win32OpenSSHAgentAUAccessMask = winsec.Win32OpenSSHAgentAUAccessMask
)

type windowsParsedACE = winsec.ParsedACE

func evaluateWindowsAttributes(attrs uint32, expectDir bool) bool {
	return winsec.EvaluateAttributes(attrs, expectDir)
}

func evaluateWindowsObjectSecurity(
	attrs uint32,
	expectDir bool,
	ownerTrusted bool,
	hasDACL bool,
	aces []windowsParsedACE,
) bool {
	return winsec.EvaluateObjectSecurity(attrs, expectDir, ownerTrusted, hasDACL, aces)
}

func evaluateWindowsNamedPipeDACL(hasDACL bool, aces []windowsParsedACE) bool {
	return winsec.EvaluateNamedPipeDACL(hasDACL, aces)
}

func evaluateWindowsAgentPipeSecurity(
	tokenResolved bool,
	tokenTrusted bool,
	serverPID uint32,
	sdErr error,
	hasSDOwner bool,
	sdOwnerTrusted bool,
	daclErr error,
	hasDACL bool,
	aces []windowsParsedACE,
) error {
	return winsec.EvaluateAgentPipeSecurity(
		tokenResolved,
		tokenTrusted,
		serverPID,
		sdErr,
		hasSDOwner,
		sdOwnerTrusted,
		daclErr,
		hasDACL,
		aces,
	)
}

func evaluateWindowsAgentPipeOwner(
	tokenResolved bool,
	tokenTrusted bool,
	serverPID uint32,
	sdErr error,
	hasSDOwner bool,
	sdOwnerTrusted bool,
) error {
	return winsec.EvaluateAgentPipeOwner(
		tokenResolved,
		tokenTrusted,
		serverPID,
		sdErr,
		hasSDOwner,
		sdOwnerTrusted,
	)
}
