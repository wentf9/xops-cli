package winsec

import (
	"errors"
	"testing"
)

func TestEvaluateOwnerOnlyDirectoryAndSocketSecurity(t *testing.T) {
	t.Parallel()

	const readOnlyMask = uint32(0x001200a9) // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
	ownerOnlyBaseline := []ParsedACE{
		{ACEType: AccessAllowedACEType, Mask: AccessGenericAll, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedACEType, Mask: AccessGenericAll, SIDValid: true, SIDTrusted: true},
	}

	if !EvaluateOwnerOnlyDirectorySecurity(FileAttributeDirectory, true, true, ownerOnlyBaseline) {
		t.Fatal("trusted owner + owner-only DACL must pass on directory")
	}
	if !EvaluateOwnerOnlySocketSecurity(true, true, true, ownerOnlyBaseline) {
		t.Fatal("trusted owner + owner-only DACL must pass on socket")
	}

	// Reparse point directory must be rejected.
	if EvaluateOwnerOnlyDirectorySecurity(FileAttributeDirectory|FileAttributeReparsePoint, true, true, ownerOnlyBaseline) {
		t.Fatal("directory reparse point must fail closed")
	}
	// Non-directory or non-socket must fail closed.
	if EvaluateOwnerOnlyDirectorySecurity(0x80, true, true, ownerOnlyBaseline) {
		t.Fatal("regular file must fail directory check")
	}
	if EvaluateOwnerOnlySocketSecurity(false, true, true, ownerOnlyBaseline) {
		t.Fatal("non-socket must fail socket check")
	}

	// Untrusted owner or nil DACL must fail closed.
	if EvaluateOwnerOnlyDirectorySecurity(FileAttributeDirectory, false, true, ownerOnlyBaseline) {
		t.Fatal("untrusted directory owner must fail closed")
	}
	if EvaluateOwnerOnlyDirectorySecurity(FileAttributeDirectory, true, false, ownerOnlyBaseline) {
		t.Fatal("nil directory DACL must fail closed")
	}
	if EvaluateOwnerOnlySocketSecurity(true, false, true, ownerOnlyBaseline) {
		t.Fatal("untrusted socket owner must fail closed")
	}
	if EvaluateOwnerOnlySocketSecurity(true, true, false, ownerOnlyBaseline) {
		t.Fatal("nil socket DACL must fail closed")
	}

	// Unlike global known_hosts, even READ-ONLY access for an untrusted SID
	// (e.g. Everyone / Users / Authenticated Users) MUST be rejected on mux control
	// directories and sockets.
	untrustedReadOnly := append(append([]ParsedACE(nil), ownerOnlyBaseline...), ParsedACE{
		ACEType:    AccessAllowedACEType,
		Mask:       readOnlyMask,
		SIDValid:   true,
		SIDTrusted: false,
	})
	if EvaluateOwnerOnlyDirectorySecurity(FileAttributeDirectory, true, true, untrustedReadOnly) {
		t.Fatal("untrusted read-only ACE must be rejected on owner-only directory")
	}
	if EvaluateOwnerOnlySocketSecurity(true, true, true, untrustedReadOnly) {
		t.Fatal("untrusted read-only ACE must be rejected on owner-only socket")
	}

	// Unknown / object / compound allow ACEs and invalid SIDs must fail closed.
	for _, bad := range []ParsedACE{
		{ACEType: AccessAllowedObjectACEType, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedCallbackObjectACEType, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedCompoundACEType, SIDValid: true, SIDTrusted: true},
		{ACEType: 99, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedACEType, Mask: readOnlyMask, SIDValid: false, SIDTrusted: true},
	} {
		aces := append(append([]ParsedACE(nil), ownerOnlyBaseline...), bad)
		if EvaluateOwnerOnlyDirectorySecurity(FileAttributeDirectory, true, true, aces) {
			t.Fatalf("bad ACE %+v must fail closed on directory", bad)
		}
		if EvaluateOwnerOnlySocketSecurity(true, true, true, aces) {
			t.Fatalf("bad ACE %+v must fail closed on socket", bad)
		}
	}
}

func TestEvaluateOwnerOnlyAndObjectSecurity_InheritOnlyACE(t *testing.T) {
	t.Parallel()

	const readOnlyMask = uint32(0x001200a9)
	const fileAttrs = uint32(0x00000080)
	ownerOnlyBaseline := []ParsedACE{
		{ACEType: AccessAllowedACEType, Mask: AccessGenericAll, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedACEType, Mask: AccessGenericAll, SIDValid: true, SIDTrusted: true},
	}

	// Inheritable (and bare) INHERIT_ONLY_ACE entries for untrusted SIDs MUST be
	// rejected on owner-only directories because OBJECT_INHERIT_ACE /
	// CONTAINER_INHERIT_ACE propagate onto newly created child sockets before
	// post-bind hardening runs, whereas leaf sockets ignore INHERIT_ONLY_ACE.
	for _, flags := range []uint8{
		InheritOnlyACEFlag,
		InheritOnlyACEFlag | ObjectInheritACEFlag,
		InheritOnlyACEFlag | ContainerInheritACEFlag,
		InheritOnlyACEFlag | ObjectInheritACEFlag | ContainerInheritACEFlag,
	} {
		assertOwnerOnlyInheritOnlyFlag(t, ownerOnlyBaseline, flags, readOnlyMask)
	}

	// EvaluateObjectSecurity: leaf files skip INHERIT_ONLY_ACE, while directories
	// reject inheritable (OI/CI) untrusted write or unknown allow ACEs.
	for _, flags := range []uint8{
		InheritOnlyACEFlag | ObjectInheritACEFlag,
		InheritOnlyACEFlag | ContainerInheritACEFlag,
		InheritOnlyACEFlag | ObjectInheritACEFlag | ContainerInheritACEFlag,
	} {
		untrustedWrite := append(append([]ParsedACE(nil), ownerOnlyBaseline...), ParsedACE{
			ACEType:    AccessAllowedACEType,
			ACEFlags:   flags,
			Mask:       AccessFileWriteData,
			SIDValid:   true,
			SIDTrusted: false,
		})
		if !EvaluateObjectSecurity(fileAttrs, false, true, true, untrustedWrite) {
			t.Fatalf("leaf file EvaluateObjectSecurity must skip INHERIT_ONLY_ACE (flags=%#x)", flags)
		}
		if EvaluateObjectSecurity(FileAttributeDirectory, true, true, true, untrustedWrite) {
			t.Fatalf("directory EvaluateObjectSecurity must reject inheritable untrusted write ACE (flags=%#x)", flags)
		}
		untrustedRead := append(append([]ParsedACE(nil), ownerOnlyBaseline...), ParsedACE{
			ACEType:    AccessAllowedACEType,
			ACEFlags:   flags,
			Mask:       readOnlyMask,
			SIDValid:   true,
			SIDTrusted: false,
		})
		if !EvaluateObjectSecurity(FileAttributeDirectory, true, true, true, untrustedRead) {
			t.Fatalf("directory EvaluateObjectSecurity should allow inheritable read-only ACE (flags=%#x)", flags)
		}
		unknownAllow := append(append([]ParsedACE(nil), ownerOnlyBaseline...), ParsedACE{
			ACEType:    AccessAllowedObjectACEType,
			ACEFlags:   flags,
			SIDValid:   true,
			SIDTrusted: true,
		})
		if EvaluateObjectSecurity(FileAttributeDirectory, true, true, true, unknownAllow) {
			t.Fatalf("directory EvaluateObjectSecurity must reject inheritable object allow ACE (flags=%#x)", flags)
		}
	}
}

func assertOwnerOnlyInheritOnlyFlag(t *testing.T, baseline []ParsedACE, flags uint8, readOnlyMask uint32) {
	t.Helper()
	for _, mask := range []uint32{AccessGenericAll, readOnlyMask} {
		inheritOnlyUntrusted := append(append([]ParsedACE(nil), baseline...), ParsedACE{
			ACEType:    AccessAllowedACEType,
			ACEFlags:   flags,
			Mask:       mask,
			SIDValid:   true,
			SIDTrusted: false,
		})
		if EvaluateOwnerOnlyDirectorySecurity(FileAttributeDirectory, true, true, inheritOnlyUntrusted) {
			t.Fatalf("INHERIT_ONLY_ACE (flags=%#x, mask=%#x) for untrusted SID must be rejected on owner-only directory", flags, mask)
		}
		if !EvaluateOwnerOnlySocketSecurity(true, true, true, inheritOnlyUntrusted) {
			t.Fatalf("INHERIT_ONLY_ACE (flags=%#x, mask=%#x) should still be ignored on leaf socket", flags, mask)
		}
	}

	inheritOnlyTrusted := append(append([]ParsedACE(nil), baseline...), ParsedACE{
		ACEType:    AccessAllowedACEType,
		ACEFlags:   flags,
		Mask:       AccessGenericAll,
		SIDValid:   true,
		SIDTrusted: true,
	})
	if !EvaluateOwnerOnlyDirectorySecurity(FileAttributeDirectory, true, true, inheritOnlyTrusted) {
		t.Fatalf("INHERIT_ONLY_ACE (flags=%#x) for trusted SID must be allowed on owner-only directory", flags)
	}

	inheritOnlyDeny := append(append([]ParsedACE(nil), baseline...), ParsedACE{
		ACEType:  AccessDeniedACEType,
		ACEFlags: flags,
		Mask:     AccessGenericAll,
	})
	if !EvaluateOwnerOnlyDirectorySecurity(FileAttributeDirectory, true, true, inheritOnlyDeny) {
		t.Fatalf("INHERIT_ONLY_ACE deny ACE (flags=%#x) must be allowed on owner-only directory", flags)
	}

	for _, badInheritOnly := range []ParsedACE{
		{ACEType: AccessAllowedCallbackACEType, ACEFlags: flags, Mask: readOnlyMask, SIDValid: true, SIDTrusted: false},
		{ACEType: AccessAllowedObjectACEType, ACEFlags: flags, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedCallbackObjectACEType, ACEFlags: flags, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedCompoundACEType, ACEFlags: flags, SIDValid: true, SIDTrusted: true},
		{ACEType: 99, ACEFlags: flags, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedACEType, ACEFlags: flags, Mask: readOnlyMask, SIDValid: false, SIDTrusted: true},
	} {
		aces := append(append([]ParsedACE(nil), baseline...), badInheritOnly)
		if EvaluateOwnerOnlyDirectorySecurity(FileAttributeDirectory, true, true, aces) {
			t.Fatalf("bad INHERIT_ONLY_ACE %+v must fail closed on owner-only directory", badInheritOnly)
		}
	}
}

func TestEvaluatePeerProcessIdentity_FailClosed(t *testing.T) {
	t.Parallel()

	if err := EvaluatePeerProcessIdentity(1234, nil, false, true, true, nil); err != nil {
		t.Fatalf("matching current-user peer should succeed, got %v", err)
	}

	sentinel := errors.New("WSAEOPNOTSUPP")
	cases := []struct {
		name            string
		pid             uint32
		pidErr          error
		pidUnsupported  bool
		sidValid        bool
		matches         bool
		tokenErr        error
		wantCause       error
		wantUnsupported bool
	}{
		{"ioctl_unsupported", 0, sentinel, true, false, false, nil, sentinel, true},
		{"ioctl_error", 0, sentinel, false, false, false, nil, sentinel, false},
		{"zero_pid", 0, nil, false, true, true, nil, nil, false},
		{"token_error", 42, nil, false, false, false, sentinel, sentinel, false},
		{"invalid_sid", 42, nil, false, false, true, nil, nil, false},
		{"different_user_sid", 42, nil, false, true, false, nil, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := EvaluatePeerProcessIdentity(tc.pid, tc.pidErr, tc.pidUnsupported, tc.sidValid, tc.matches, tc.tokenErr)
			if !errors.Is(err, ErrUnauthorizedControlPeer) {
				t.Fatalf("got %v, want ErrUnauthorizedControlPeer", err)
			}
			if tc.wantUnsupported && !errors.Is(err, ErrUnsupportedPeerPID) {
				t.Fatalf("got %v, want ErrUnsupportedPeerPID", err)
			}
			if !tc.wantUnsupported && errors.Is(err, ErrUnsupportedPeerPID) {
				t.Fatalf("got unexpected ErrUnsupportedPeerPID in %v", err)
			}
			if tc.wantCause != nil && !errors.Is(err, tc.wantCause) {
				t.Fatalf("got %v, want wrapped cause %v", err, tc.wantCause)
			}
		})
	}
}

func TestEvaluatePrincipalTrust_SystemGlobalVsUserScoped(t *testing.T) {
	t.Parallel()

	// System-global scope (allowCurrentUser=false, i.e. currSID == nil):
	// ONLY LocalSystem and Builtin\Administrators are trusted; current non-admin user MUST be rejected.
	if !EvaluatePrincipalTrust(true, true, false, false, false) {
		t.Fatal("SYSTEM must be trusted in system-global scope")
	}
	if !EvaluatePrincipalTrust(true, false, true, false, false) {
		t.Fatal("Builtin\\Administrators must be trusted in system-global scope")
	}
	if EvaluatePrincipalTrust(true, false, false, true, false) {
		t.Fatal("current non-admin user must NOT be trusted in system-global scope (currSID == nil)")
	}
	if EvaluatePrincipalTrust(true, false, false, false, false) {
		t.Fatal("other untrusted principal must NOT be trusted in system-global scope")
	}
	if EvaluatePrincipalTrust(false, true, true, true, true) {
		t.Fatal("invalid SID must fail closed regardless of flags")
	}

	// User-scoped checks (allowCurrentUser=true, i.e. currSID != nil):
	// LocalSystem, Builtin\Administrators, and current user are trusted.
	if !EvaluatePrincipalTrust(true, false, false, true, true) {
		t.Fatal("current user must be trusted in user-scoped check")
	}
	if EvaluatePrincipalTrust(true, false, false, false, true) {
		t.Fatal("other untrusted principal must NOT be trusted in user-scoped check")
	}

	// Simulate evaluating %ProgramData%\ssh and %ProgramData%\ssh\ssh_known_hosts
	// with current-user owner or current-user write ACE under system-global vs user-scoped trust.
	const fileAttrs = uint32(0x00000080)
	const readExecMask = uint32(0x001200a9)

	for _, allowCurr := range []bool{false, true} {
		currTrusted := EvaluatePrincipalTrust(true, false, false, true, allowCurr)
		sysTrusted := EvaluatePrincipalTrust(true, true, false, false, allowCurr)
		adminTrusted := EvaluatePrincipalTrust(true, false, true, false, allowCurr)
		usersTrusted := EvaluatePrincipalTrust(true, false, false, false, allowCurr)

		systemGlobalACL := []ParsedACE{
			{ACEType: AccessAllowedACEType, Mask: AccessGenericAll, SIDValid: true, SIDTrusted: sysTrusted},
			{ACEType: AccessAllowedACEType, Mask: AccessGenericAll, SIDValid: true, SIDTrusted: adminTrusted},
			{ACEType: AccessAllowedACEType, Mask: readExecMask, SIDValid: true, SIDTrusted: usersTrusted},
		}
		if !EvaluateObjectSecurity(FileAttributeDirectory, true, sysTrusted, true, systemGlobalACL) {
			t.Fatalf("SYSTEM/Admins dir ACL must pass (allowCurr=%v)", allowCurr)
		}
		if !EvaluateObjectSecurity(fileAttrs, false, adminTrusted, true, systemGlobalACL) {
			t.Fatalf("SYSTEM/Admins file ACL must pass (allowCurr=%v)", allowCurr)
		}

		// Current-user-owned object with SYSTEM/Admins DACL.
		if got := EvaluateObjectSecurity(fileAttrs, false, currTrusted, true, systemGlobalACL); got != allowCurr {
			t.Fatalf("current-user-owned object = %v, want %v (allowCurr=%v)", got, allowCurr, allowCurr)
		}

		// SYSTEM-owned object with current-user write ACE.
		currWritableACL := append(append([]ParsedACE(nil), systemGlobalACL...), ParsedACE{
			ACEType:    AccessAllowedACEType,
			Mask:       AccessFileWriteData,
			SIDValid:   true,
			SIDTrusted: currTrusted,
		})
		if got := EvaluateObjectSecurity(FileAttributeDirectory, true, sysTrusted, true, currWritableACL); got != allowCurr {
			t.Fatalf("current-user-writable dir = %v, want %v (allowCurr=%v)", got, allowCurr, allowCurr)
		}
		if got := EvaluateObjectSecurity(fileAttrs, false, sysTrusted, true, currWritableACL); got != allowCurr {
			t.Fatalf("current-user-writable file = %v, want %v (allowCurr=%v)", got, allowCurr, allowCurr)
		}
	}
}

func TestEvaluateSystemAncestorDirSecurity_ProgramDataModel(t *testing.T) {
	t.Parallel()

	const (
		readExecMask       = uint32(0x001200a9)
		programDataAddMask = AccessFileWriteData | AccessFileAppendData | 0x00000110 // FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
	)

	// Standard Windows C:\ProgramData ACL:
	// SYSTEM:F, Administrators:F, CREATOR OWNER:(OI)(CI)(IO)(F), Users:(OI)(CI)(RX),
	// Users:(CI)(FILE_ADD_FILE|FILE_ADD_SUBDIRECTORY|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES).
	standardProgramDataACL := []ParsedACE{
		{ACEType: AccessAllowedACEType, ACEFlags: ObjectInheritACEFlag | ContainerInheritACEFlag, Mask: AccessGenericAll, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedACEType, ACEFlags: ObjectInheritACEFlag | ContainerInheritACEFlag, Mask: AccessGenericAll, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedACEType, ACEFlags: ObjectInheritACEFlag | ContainerInheritACEFlag | InheritOnlyACEFlag, Mask: AccessGenericAll, SIDValid: true, SIDTrusted: false},
		{ACEType: AccessAllowedACEType, ACEFlags: ObjectInheritACEFlag | ContainerInheritACEFlag, Mask: readExecMask, SIDValid: true, SIDTrusted: false},
		{ACEType: AccessAllowedACEType, ACEFlags: ContainerInheritACEFlag, Mask: programDataAddMask, SIDValid: true, SIDTrusted: false},
	}

	if !EvaluateSystemAncestorDirSecurity(FileAttributeDirectory, true, true, standardProgramDataACL) {
		t.Fatal("standard Windows C:\\ProgramData ACL must pass EvaluateSystemAncestorDirSecurity")
	}
	// That same ProgramData ACL MUST be rejected for strict leaf/ssh dir checks.
	if EvaluateObjectSecurity(FileAttributeDirectory, true, true, true, standardProgramDataACL) {
		t.Fatal("ProgramData Users-append/CREATOR-OWNER ACL must be rejected by strict EvaluateObjectSecurity")
	}

	// Reparse point, file, device, untrusted owner, and nil DACL must fail closed.
	if EvaluateSystemAncestorDirSecurity(FileAttributeDirectory|FileAttributeReparsePoint, true, true, standardProgramDataACL) {
		t.Fatal("reparse point ancestor directory must fail closed")
	}
	if EvaluateSystemAncestorDirSecurity(0x80, true, true, standardProgramDataACL) {
		t.Fatal("regular file must fail ancestor directory check")
	}
	if EvaluateSystemAncestorDirSecurity(FileAttributeDevice, true, true, standardProgramDataACL) {
		t.Fatal("device must fail ancestor directory check")
	}
	if EvaluateSystemAncestorDirSecurity(FileAttributeDirectory, false, true, standardProgramDataACL) {
		t.Fatal("untrusted owner (e.g. current non-admin user) must fail closed on ancestor directory")
	}
	if EvaluateSystemAncestorDirSecurity(FileAttributeDirectory, true, false, standardProgramDataACL) {
		t.Fatal("nil DACL must fail closed on ancestor directory")
	}

	// Destructive / takeover bits granted to any untrusted principal must fail closed.
	for _, badMask := range []uint32{
		AccessFileDeleteChild,
		AccessDelete,
		AccessWriteDAC,
		AccessWriteOwner,
		AccessGenericAll,
	} {
		for _, aceType := range []uint8{AccessAllowedACEType, AccessAllowedCallbackACEType} {
			aces := append(append([]ParsedACE(nil), standardProgramDataACL...), ParsedACE{
				ACEType:    aceType,
				Mask:       badMask,
				SIDValid:   true,
				SIDTrusted: false,
			})
			if EvaluateSystemAncestorDirSecurity(FileAttributeDirectory, true, true, aces) {
				t.Fatalf("untrusted ACE type=%d mask=%#x must fail closed on ancestor directory", aceType, badMask)
			}
		}
	}

	// Deny and audit ACEs are harmless; unknown/object/compound allow ACEs and invalid SIDs fail closed.
	withDeny := append(append([]ParsedACE(nil), standardProgramDataACL...),
		ParsedACE{ACEType: AccessDeniedACEType, Mask: AccessGenericAll},
		ParsedACE{ACEType: SystemMandatoryLabelACEType, Mask: AccessGenericAll},
	)
	if !EvaluateSystemAncestorDirSecurity(FileAttributeDirectory, true, true, withDeny) {
		t.Fatal("deny/label ACEs must not reject ancestor directory")
	}
	for _, bad := range []ParsedACE{
		{ACEType: AccessAllowedObjectACEType, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedCompoundACEType, SIDValid: true, SIDTrusted: true},
		{ACEType: 99, SIDValid: true, SIDTrusted: true},
		{ACEType: AccessAllowedACEType, Mask: readExecMask, SIDValid: false, SIDTrusted: true},
	} {
		aces := append(append([]ParsedACE(nil), standardProgramDataACL...), bad)
		if EvaluateSystemAncestorDirSecurity(FileAttributeDirectory, true, true, aces) {
			t.Fatalf("malformed/unknown allow ACE %+v must fail closed on ancestor directory", bad)
		}
	}
}
