package sshenv

import (
	"errors"
	"fmt"
)

var (
	errUntrustedAgentPipeOwner = errors.New("ssh-agent named pipe server is owned by an untrusted local user")
	errInsecureAgentPipeDACL   = errors.New("ssh-agent named pipe DACL grants unsafe access to untrusted principal")
)

// Win32 file attributes, ACE flags, ACE types, and ACCESS_MASK constants from
// winnt.h (verified via compile-time assertions on Windows in dns_servers_windows.go).
const (
	windowsInvalidFileAttributes     uint32 = 0xffffffff
	windowsFileAttributeDirectory    uint32 = 0x00000010
	windowsFileAttributeDevice       uint32 = 0x00000040
	windowsFileAttributeReparsePoint uint32 = 0x00000400

	windowsInheritOnlyACEFlag uint8 = 0x08

	windowsAccessAllowedACEType               uint8 = 0
	windowsAccessDeniedACEType                uint8 = 1
	windowsSystemAuditACEType                 uint8 = 2
	windowsSystemAlarmACEType                 uint8 = 3
	windowsAccessAllowedCompoundACEType       uint8 = 4
	windowsAccessAllowedObjectACEType         uint8 = 5
	windowsAccessDeniedObjectACEType          uint8 = 6
	windowsSystemAuditObjectACEType           uint8 = 7
	windowsSystemAlarmObjectACEType           uint8 = 8
	windowsAccessAllowedCallbackACEType       uint8 = 9
	windowsAccessDeniedCallbackACEType        uint8 = 10
	windowsAccessAllowedCallbackObjectACEType uint8 = 11
	windowsAccessDeniedCallbackObjectACEType  uint8 = 12
	windowsSystemAuditCallbackACEType         uint8 = 13
	windowsSystemAlarmCallbackACEType         uint8 = 14
	windowsSystemMandatoryLabelACEType        uint8 = 17
	windowsSystemResourceAttributeACEType     uint8 = 18
	windowsSystemScopedPolicyIDACEType        uint8 = 19
	windowsSystemProcessTrustLabelACEType     uint8 = 20

	windowsAccessFileWriteData          uint32 = 0x00000002 // FILE_WRITE_DATA / FILE_ADD_FILE
	windowsAccessFileAppendData         uint32 = 0x00000004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	windowsAccessFileCreatePipeInstance uint32 = windowsAccessFileAppendData
	windowsAccessFileDeleteChild        uint32 = 0x00000040 // FILE_DELETE_CHILD
	windowsAccessDelete                 uint32 = 0x00010000 // DELETE
	windowsAccessWriteDAC               uint32 = 0x00040000 // WRITE_DAC
	windowsAccessWriteOwner             uint32 = 0x00080000 // WRITE_OWNER
	windowsAccessGenericAll             uint32 = 0x10000000 // GENERIC_ALL
	windowsAccessGenericWrite           uint32 = 0x40000000 // GENERIC_WRITE

	windowsInsecureSSHObjectWriteMask uint32 = windowsAccessFileWriteData |
		windowsAccessFileAppendData |
		windowsAccessFileDeleteChild |
		windowsAccessDelete |
		windowsAccessWriteDAC |
		windowsAccessWriteOwner |
		windowsAccessGenericWrite |
		windowsAccessGenericAll

	// Named pipes only permit FILE_CREATE_PIPE_INSTANCE, WRITE_DAC, WRITE_OWNER,
	// GENERIC_WRITE, and GENERIC_ALL for trusted principals; client read/write
	// (e.g., Win32-OpenSSH 0x0012019b for Authenticated Users) stays allowed.
	windowsInsecureNamedPipeServerMask uint32 = windowsAccessFileCreatePipeInstance |
		windowsAccessWriteDAC |
		windowsAccessWriteOwner |
		windowsAccessGenericWrite |
		windowsAccessGenericAll
)

type windowsParsedACE struct {
	aceType    uint8
	aceFlags   uint8
	mask       uint32
	sidValid   bool
	sidTrusted bool
}

func isStandardLayoutWindowsAllowACEType(aceType uint8) bool {
	return aceType == windowsAccessAllowedACEType || aceType == windowsAccessAllowedCallbackACEType
}

// evaluateWindowsAttributes verifies Win32 GetFileAttributesEx metadata without
// following reparse points: rejects INVALID_FILE_ATTRIBUTES, reparse points
// (symlinks/junctions/mount points), and device nodes, and checks directory vs
// regular-file type.
func evaluateWindowsAttributes(attrs uint32, expectDir bool) bool {
	if attrs == windowsInvalidFileAttributes {
		return false
	}
	if attrs&(windowsFileAttributeReparsePoint|windowsFileAttributeDevice) != 0 {
		return false
	}
	if expectDir {
		return attrs&windowsFileAttributeDirectory != 0
	}
	return attrs&windowsFileAttributeDirectory == 0
}

// evaluateWindowsACE mirrors Win32-OpenSSH file_PermCheck allowlist semantics:
//   - INHERIT_ONLY_ACE entries do not apply to the object itself and are skipped.
//   - Deny/audit/alarm/mandatory-label/attribute ACEs cannot grant write access and are ignored.
//   - Standard/callback allow ACEs carrying write/delete/DACL/owner bits require a trusted SID.
//   - Unknown, compound, or object-specific allow ACEs (e.g., ACCESS_ALLOWED_OBJECT_ACE_TYPE) fail closed.
func evaluateWindowsACE(ace windowsParsedACE) bool {
	return evaluateWindowsACEWithMask(ace, windowsInsecureSSHObjectWriteMask)
}

func evaluateWindowsNamedPipeACE(ace windowsParsedACE) bool {
	return evaluateWindowsACEWithMask(ace, windowsInsecureNamedPipeServerMask)
}

func evaluateWindowsACEWithMask(ace windowsParsedACE, disallowedMask uint32) bool {
	if ace.aceFlags&windowsInheritOnlyACEFlag != 0 {
		return true
	}
	if isStandardLayoutWindowsAllowACEType(ace.aceType) {
		if !ace.sidValid {
			return false
		}
		if ace.mask&disallowedMask != 0 && !ace.sidTrusted {
			return false
		}
		return true
	}
	switch ace.aceType {
	case windowsAccessDeniedACEType,
		windowsAccessDeniedObjectACEType,
		windowsAccessDeniedCallbackACEType,
		windowsAccessDeniedCallbackObjectACEType,
		windowsSystemAuditACEType,
		windowsSystemAlarmACEType,
		windowsSystemAuditObjectACEType,
		windowsSystemAlarmObjectACEType,
		windowsSystemAuditCallbackACEType,
		windowsSystemAlarmCallbackACEType,
		windowsSystemMandatoryLabelACEType,
		windowsSystemResourceAttributeACEType,
		windowsSystemScopedPolicyIDACEType,
		windowsSystemProcessTrustLabelACEType:
		return true
	default:
		return false
	}
}

func evaluateWindowsObjectSecurity(
	attrs uint32,
	expectDir bool,
	ownerTrusted bool,
	hasDACL bool,
	aces []windowsParsedACE,
) bool {
	if !evaluateWindowsAttributes(attrs, expectDir) {
		return false
	}
	if !ownerTrusted || !hasDACL {
		return false
	}
	for _, ace := range aces {
		if !evaluateWindowsACE(ace) {
			return false
		}
	}
	return true
}

func evaluateWindowsNamedPipeDACL(hasDACL bool, aces []windowsParsedACE) bool {
	if !hasDACL {
		return false
	}
	for _, ace := range aces {
		if !evaluateWindowsNamedPipeACE(ace) {
			return false
		}
	}
	return true
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
	if err := evaluateWindowsAgentPipeOwner(
		tokenResolved,
		tokenTrusted,
		serverPID,
		sdErr,
		hasSDOwner,
		sdOwnerTrusted,
	); err != nil {
		return err
	}
	if sdErr != nil {
		return fmt.Errorf("verify ssh-agent named pipe DACL: %w", sdErr)
	}
	if daclErr != nil {
		return fmt.Errorf("verify ssh-agent named pipe DACL: %w", daclErr)
	}
	if !evaluateWindowsNamedPipeDACL(hasDACL, aces) {
		return errInsecureAgentPipeDACL
	}
	return nil
}

func evaluateWindowsAgentPipeOwner(
	tokenResolved bool,
	tokenTrusted bool,
	serverPID uint32,
	sdErr error,
	hasSDOwner bool,
	sdOwnerTrusted bool,
) error {
	if tokenResolved {
		if !tokenTrusted {
			return fmt.Errorf("%w (pid %d)", errUntrustedAgentPipeOwner, serverPID)
		}
		return nil
	}
	if sdErr != nil {
		return fmt.Errorf("verify ssh-agent named pipe owner: %w", sdErr)
	}
	if !hasSDOwner {
		return errors.New("verify ssh-agent named pipe owner: missing security descriptor owner")
	}
	if !sdOwnerTrusted {
		return errUntrustedAgentPipeOwner
	}
	return nil
}
