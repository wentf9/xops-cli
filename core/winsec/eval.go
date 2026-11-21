package winsec

import (
	"errors"
	"fmt"
)

var (
	// ErrUntrustedAgentPipeOwner reports that a Windows ssh-agent named pipe
	// server is owned by an untrusted local user.
	ErrUntrustedAgentPipeOwner = errors.New("ssh-agent named pipe server is owned by an untrusted local user")
	// ErrInsecureAgentPipeDACL reports that a Windows ssh-agent named pipe DACL
	// grants privileged access to an untrusted principal.
	ErrInsecureAgentPipeDACL = errors.New("ssh-agent named pipe DACL grants unsafe access to untrusted principal")
	// ErrInsecureControlDir reports that a Windows control socket directory or
	// socket file does not satisfy strict owner-only NTFS DACL requirements.
	ErrInsecureControlDir = errors.New("windows control socket directory or file has insecure NTFS permissions")
	// ErrUnauthorizedControlPeer reports that a Windows AF_UNIX peer could not be
	// verified as running under the current user's SID.
	ErrUnauthorizedControlPeer = errors.New("unauthorized Windows AF_UNIX peer")
	// ErrUnsupportedPeerPID reports that SIO_AF_UNIX_GETPEERPID is not supported
	// by the current Windows kernel/Winsock provider.
	ErrUnsupportedPeerPID = errors.New("AF_UNIX peer PID query is not supported on this Windows version")
)

// Win32 file attributes, ACE flags, ACE types, ACCESS_MASK, and Winsock AF_UNIX
// constants from winnt.h / afunix.h (verified via compile-time assertions on
// Windows in windows.go).
const (
	InvalidFileAttributes     uint32 = 0xffffffff
	FileAttributeDirectory    uint32 = 0x00000010
	FileAttributeDevice       uint32 = 0x00000040
	FileAttributeReparsePoint uint32 = 0x00000400

	ObjectInheritACEFlag      uint8 = 0x01
	ContainerInheritACEFlag   uint8 = 0x02
	NoPropagateInheritACEFlag uint8 = 0x04
	InheritOnlyACEFlag        uint8 = 0x08

	AccessAllowedACEType               uint8 = 0
	AccessDeniedACEType                uint8 = 1
	SystemAuditACEType                 uint8 = 2
	SystemAlarmACEType                 uint8 = 3
	AccessAllowedCompoundACEType       uint8 = 4
	AccessAllowedObjectACEType         uint8 = 5
	AccessDeniedObjectACEType          uint8 = 6
	SystemAuditObjectACEType           uint8 = 7
	SystemAlarmObjectACEType           uint8 = 8
	AccessAllowedCallbackACEType       uint8 = 9
	AccessDeniedCallbackACEType        uint8 = 10
	AccessAllowedCallbackObjectACEType uint8 = 11
	AccessDeniedCallbackObjectACEType  uint8 = 12
	SystemAuditCallbackACEType         uint8 = 13
	SystemAlarmCallbackACEType         uint8 = 14
	SystemMandatoryLabelACEType        uint8 = 17
	SystemResourceAttributeACEType     uint8 = 18
	SystemScopedPolicyIDACEType        uint8 = 19
	SystemProcessTrustLabelACEType     uint8 = 20

	AccessFileWriteData          uint32 = 0x00000002 // FILE_WRITE_DATA / FILE_ADD_FILE
	AccessFileAppendData         uint32 = 0x00000004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	AccessFileCreatePipeInstance uint32 = AccessFileAppendData
	AccessFileDeleteChild        uint32 = 0x00000040 // FILE_DELETE_CHILD
	AccessDelete                 uint32 = 0x00010000 // DELETE
	AccessWriteDAC               uint32 = 0x00040000 // WRITE_DAC
	AccessWriteOwner             uint32 = 0x00080000 // WRITE_OWNER
	AccessGenericAll             uint32 = 0x10000000 // GENERIC_ALL
	AccessGenericWrite           uint32 = 0x40000000 // GENERIC_WRITE

	// InsecureSSHObjectWriteMask matches Win32-OpenSSH file_PermCheck write/mutate
	// bits disallowed for untrusted principals on read-shared SSH files (e.g. ssh_known_hosts).
	InsecureSSHObjectWriteMask uint32 = AccessFileWriteData |
		AccessFileAppendData |
		AccessFileDeleteChild |
		AccessDelete |
		AccessWriteDAC |
		AccessWriteOwner |
		AccessGenericWrite |
		AccessGenericAll

	// InsecureSystemAncestorDirMask forbids destructive and takeover rights on
	// a shared system ancestor directory (such as C:\ProgramData) for untrusted
	// principals while permitting Windows' default Builtin\Users FILE_ADD_FILE
	// and FILE_ADD_SUBDIRECTORY rights (and INHERIT_ONLY_ACE entries such as
	// CREATOR OWNER).
	InsecureSystemAncestorDirMask uint32 = AccessFileDeleteChild |
		AccessDelete |
		AccessWriteDAC |
		AccessWriteOwner |
		AccessGenericAll

	// InsecureOwnerOnlyObjectMask forbids ANY access bit for untrusted principals
	// on strictly owner-only objects such as SSH multiplex control directories and sockets.
	InsecureOwnerOnlyObjectMask uint32 = ^uint32(0)

	// InsecureNamedPipeServerMask permits client read/write (e.g. Win32-OpenSSH
	// 0x0012019b for Authenticated Users) while forbidding server-privilege bits
	// for untrusted principals.
	InsecureNamedPipeServerMask uint32 = AccessFileCreatePipeInstance |
		AccessWriteDAC |
		AccessWriteOwner |
		AccessGenericWrite |
		AccessGenericAll

	// AgentPipeDesiredAccess is the minimum client access mask for dialing Windows
	// SSH agent named pipes: FILE_GENERIC_READ | FILE_WRITE_DATA (0x0012008b),
	// excluding FILE_CREATE_PIPE_INSTANCE (0x00000004).
	AgentPipeDesiredAccess        uint32 = 0x0012008b
	Win32OpenSSHAgentAUAccessMask uint32 = 0x0012019b

	// SIOAFUnixGetPeerPID is Windows SDK <afunix.h> _WSAIOR(IOC_VENDOR, 256):
	// IOC_OUT (0x40000000) | IOC_VENDOR (0x18000000) | 256 (0x100) = 0x58000100.
	SIOAFUnixGetPeerPID uint32 = 0x58000100
)

// ParsedACE holds the platform-independent fields of a decoded Windows ACE.
type ParsedACE struct {
	ACEType    uint8
	ACEFlags   uint8
	Mask       uint32
	SIDValid   bool
	SIDTrusted bool
}

// IsStandardLayoutAllowACEType reports whether aceType uses the standard
// ACCESS_ALLOWED_ACE memory layout (header + Mask + SidStart).
func IsStandardLayoutAllowACEType(aceType uint8) bool {
	return aceType == AccessAllowedACEType || aceType == AccessAllowedCallbackACEType
}

// EvaluateAttributes verifies Win32 GetFileAttributesEx metadata without
// following reparse points: rejects INVALID_FILE_ATTRIBUTES, reparse points
// (symlinks/junctions/mount points), and device nodes, and checks directory vs
// regular-file type.
func EvaluateAttributes(attrs uint32, expectDir bool) bool {
	if attrs == InvalidFileAttributes {
		return false
	}
	if attrs&(FileAttributeReparsePoint|FileAttributeDevice) != 0 {
		return false
	}
	if expectDir {
		return attrs&FileAttributeDirectory != 0
	}
	return attrs&FileAttributeDirectory == 0
}

// EvaluatePrincipalTrust reports whether a principal SID is trusted under the
// requested scope. System-global checks (such as %ProgramData%\ssh\ssh_known_hosts)
// pass allowCurrentUser=false so ONLY LocalSystem and Builtin\Administrators
// are trusted; user-scoped checks pass allowCurrentUser=true to additionally
// trust the current process user SID.
func EvaluatePrincipalTrust(
	sidValid bool,
	isLocalSystem bool,
	isBuiltinAdmins bool,
	matchesCurrentUser bool,
	allowCurrentUser bool,
) bool {
	if !sidValid {
		return false
	}
	if isLocalSystem || isBuiltinAdmins {
		return true
	}
	return allowCurrentUser && matchesCurrentUser
}

// EvaluateACE checks a single ACE against InsecureSSHObjectWriteMask.
func EvaluateACE(ace ParsedACE) bool {
	return EvaluateACEWithMask(ace, InsecureSSHObjectWriteMask)
}

// EvaluateSystemAncestorDirACE checks a single ACE on a shared system ancestor
// directory (such as C:\ProgramData) against InsecureSystemAncestorDirMask,
// skipping INHERIT_ONLY_ACE entries (such as CREATOR OWNER) that do not apply
// to the ancestor directory itself.
func EvaluateSystemAncestorDirACE(ace ParsedACE) bool {
	return EvaluateACEWithMask(ace, InsecureSystemAncestorDirMask)
}

// EvaluateOwnerOnlyACE checks a single ACE against InsecureOwnerOnlyObjectMask,
// rejecting any non-zero allow ACE granted to an untrusted principal.
func EvaluateOwnerOnlyACE(ace ParsedACE) bool {
	return EvaluateACEWithMask(ace, InsecureOwnerOnlyObjectMask)
}

// EvaluateNamedPipeACE checks a single ACE against InsecureNamedPipeServerMask.
func EvaluateNamedPipeACE(ace ParsedACE) bool {
	return EvaluateACEWithMask(ace, InsecureNamedPipeServerMask)
}

// EvaluateACEWithMask applies fail-closed allowlist evaluation to a decoded ACE
// for a leaf/single object:
//   - INHERIT_ONLY_ACE entries do not apply to a leaf object itself and are skipped.
//   - Deny/audit/alarm/mandatory-label/attribute ACEs cannot grant access and are ignored.
//   - Standard/callback allow ACEs carrying bits in disallowedMask require a valid trusted SID.
//   - Unknown, compound, or object-specific allow ACEs fail closed.
func EvaluateACEWithMask(ace ParsedACE, disallowedMask uint32) bool {
	return evaluateACEWithMask(ace, disallowedMask, true)
}

func evaluateACEWithMask(ace ParsedACE, disallowedMask uint32, skipInheritOnly bool) bool {
	if skipInheritOnly && ace.ACEFlags&InheritOnlyACEFlag != 0 {
		return true
	}
	if IsStandardLayoutAllowACEType(ace.ACEType) {
		if !ace.SIDValid {
			return false
		}
		if ace.Mask&disallowedMask != 0 && !ace.SIDTrusted {
			return false
		}
		return true
	}
	switch ace.ACEType {
	case AccessDeniedACEType,
		AccessDeniedObjectACEType,
		AccessDeniedCallbackACEType,
		AccessDeniedCallbackObjectACEType,
		SystemAuditACEType,
		SystemAlarmACEType,
		SystemAuditObjectACEType,
		SystemAlarmObjectACEType,
		SystemAuditCallbackACEType,
		SystemAlarmCallbackACEType,
		SystemMandatoryLabelACEType,
		SystemResourceAttributeACEType,
		SystemScopedPolicyIDACEType,
		SystemProcessTrustLabelACEType:
		return true
	default:
		return false
	}
}

func isInheritableACE(flags uint8) bool {
	return flags&(ObjectInheritACEFlag|ContainerInheritACEFlag) != 0
}

// EvaluateObjectSecurity verifies attributes, trusted owner, non-nil DACL, and
// write-restricted ACEs (used for global ssh_known_hosts). For directories
// (expectDir == true), inheritable INHERIT_ONLY_ACE entries carrying
// OBJECT_INHERIT_ACE or CONTAINER_INHERIT_ACE are also evaluated because they
// propagate onto newly created child objects.
func EvaluateObjectSecurity(
	attrs uint32,
	expectDir bool,
	ownerTrusted bool,
	hasDACL bool,
	aces []ParsedACE,
) bool {
	if !EvaluateAttributes(attrs, expectDir) {
		return false
	}
	if !ownerTrusted || !hasDACL {
		return false
	}
	for _, ace := range aces {
		skipInheritOnly := !expectDir || !isInheritableACE(ace.ACEFlags)
		if !evaluateACEWithMask(ace, InsecureSSHObjectWriteMask, skipInheritOnly) {
			return false
		}
	}
	return true
}

// EvaluateSystemAncestorDirSecurity verifies that a shared system ancestor
// directory (such as C:\ProgramData) is a real directory (not a reparse point
// or device), has a trusted system owner (SYSTEM or Builtin\Administrators),
// has a non-nil DACL, and denies destructive/takeover rights
// (InsecureSystemAncestorDirMask) to untrusted principals.
func EvaluateSystemAncestorDirSecurity(
	attrs uint32,
	ownerTrusted bool,
	hasDACL bool,
	aces []ParsedACE,
) bool {
	if !EvaluateAttributes(attrs, true) {
		return false
	}
	if !ownerTrusted || !hasDACL {
		return false
	}
	for _, ace := range aces {
		if !EvaluateSystemAncestorDirACE(ace) {
			return false
		}
	}
	return true
}

// EvaluateOwnerOnlyDirectorySecurity verifies that a directory is not a reparse
// point/device, has a trusted owner, has a non-nil DACL, and grants zero access
// bits to any untrusted principal — including via INHERIT_ONLY_ACE entries that
// would otherwise propagate onto newly created child sockets before post-bind
// hardening runs.
func EvaluateOwnerOnlyDirectorySecurity(
	attrs uint32,
	ownerTrusted bool,
	hasDACL bool,
	aces []ParsedACE,
) bool {
	if !EvaluateAttributes(attrs, true) {
		return false
	}
	if !ownerTrusted || !hasDACL {
		return false
	}
	for _, ace := range aces {
		if !evaluateACEWithMask(ace, InsecureOwnerOnlyObjectMask, false) {
			return false
		}
	}
	return true
}

// EvaluateOwnerOnlySocketSecurity verifies that an AF_UNIX socket object
// (represented on NTFS as an IO_REPARSE_TAG_AF_UNIX reparse point identified by
// isSocket) has a trusted owner, a non-nil DACL, and grants zero access bits to
// any untrusted principal.
func EvaluateOwnerOnlySocketSecurity(
	isSocket bool,
	ownerTrusted bool,
	hasDACL bool,
	aces []ParsedACE,
) bool {
	if !isSocket || !ownerTrusted || !hasDACL {
		return false
	}
	for _, ace := range aces {
		if !EvaluateOwnerOnlyACE(ace) {
			return false
		}
	}
	return true
}

// EvaluateNamedPipeDACL verifies a Windows named pipe DACL against
// InsecureNamedPipeServerMask.
func EvaluateNamedPipeDACL(hasDACL bool, aces []ParsedACE) bool {
	if !hasDACL {
		return false
	}
	for _, ace := range aces {
		if !EvaluateNamedPipeACE(ace) {
			return false
		}
	}
	return true
}

// EvaluateAgentPipeSecurity verifies both owner and DACL of an ssh-agent named pipe.
func EvaluateAgentPipeSecurity(
	tokenResolved bool,
	tokenTrusted bool,
	serverPID uint32,
	sdErr error,
	hasSDOwner bool,
	sdOwnerTrusted bool,
	daclErr error,
	hasDACL bool,
	aces []ParsedACE,
) error {
	if err := EvaluateAgentPipeOwner(
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
	if !EvaluateNamedPipeDACL(hasDACL, aces) {
		return ErrInsecureAgentPipeDACL
	}
	return nil
}

// EvaluateAgentPipeOwner verifies the process token / security descriptor owner
// of an ssh-agent named pipe.
func EvaluateAgentPipeOwner(
	tokenResolved bool,
	tokenTrusted bool,
	serverPID uint32,
	sdErr error,
	hasSDOwner bool,
	sdOwnerTrusted bool,
) error {
	if tokenResolved && !tokenTrusted {
		return fmt.Errorf("%w (pid %d)", ErrUntrustedAgentPipeOwner, serverPID)
	}
	if sdErr != nil {
		return fmt.Errorf("verify ssh-agent named pipe owner: %w", sdErr)
	}
	if !hasSDOwner {
		return errors.New("verify ssh-agent named pipe owner: missing security descriptor owner")
	}
	if !sdOwnerTrusted {
		return ErrUntrustedAgentPipeOwner
	}
	return nil
}

// EvaluatePeerProcessIdentity enforces fail-closed peer identity verification
// for Windows AF_UNIX connections: any PID lookup failure, unsupported IOCTL,
// zero PID, token lookup failure, invalid SID, or SID mismatch against the
// current user fails closed with ErrUnauthorizedControlPeer (and additionally
// wraps ErrUnsupportedPeerPID when pidUnsupported is true).
func EvaluatePeerProcessIdentity(
	peerPID uint32,
	pidErr error,
	pidUnsupported bool,
	tokenSIDValid bool,
	tokenMatchesCurrent bool,
	tokenErr error,
) error {
	if pidUnsupported {
		if pidErr != nil {
			return fmt.Errorf("%w: %w: %w", ErrUnauthorizedControlPeer, ErrUnsupportedPeerPID, pidErr)
		}
		return fmt.Errorf("%w: %w", ErrUnauthorizedControlPeer, ErrUnsupportedPeerPID)
	}
	if pidErr != nil {
		return fmt.Errorf("%w: query AF_UNIX peer PID failed: %w", ErrUnauthorizedControlPeer, pidErr)
	}
	if peerPID == 0 {
		return fmt.Errorf("%w: AF_UNIX peer PID is zero", ErrUnauthorizedControlPeer)
	}
	if tokenErr != nil {
		return fmt.Errorf("%w: inspect peer process %d token failed: %w", ErrUnauthorizedControlPeer, peerPID, tokenErr)
	}
	if !tokenSIDValid {
		return fmt.Errorf("%w: peer process %d has invalid user SID", ErrUnauthorizedControlPeer, peerPID)
	}
	if !tokenMatchesCurrent {
		return fmt.Errorf("%w: peer process %d user SID does not match current user", ErrUnauthorizedControlPeer, peerPID)
	}
	return nil
}
