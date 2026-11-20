package sshenv

import (
	"errors"
	"testing"
)

func TestEvaluateWindowsAttributes_RejectsReparsePointsDevicesAndWrongType(t *testing.T) {
	const normalFile = uint32(0x00000080) // FILE_ATTRIBUTE_NORMAL
	const normalDir = windowsFileAttributeDirectory

	if !evaluateWindowsAttributes(normalFile, false) {
		t.Fatal("expected normal file attributes to pass expectDir=false")
	}
	if evaluateWindowsAttributes(normalFile, true) {
		t.Fatal("expected file attributes to fail expectDir=true")
	}
	if !evaluateWindowsAttributes(normalDir, true) {
		t.Fatal("expected normal directory attributes to pass expectDir=true")
	}
	if evaluateWindowsAttributes(normalDir, false) {
		t.Fatal("expected directory attributes to fail expectDir=false")
	}

	// Reparse points (NTFS junctions, mount points, symlinks) must fail closed on
	// %ProgramData%, %ProgramData%\ssh, and %ProgramData%\ssh\ssh_known_hosts.
	if evaluateWindowsAttributes(normalDir|windowsFileAttributeReparsePoint, true) {
		t.Fatal("directory reparse point (junction/symlink) must be rejected")
	}
	if evaluateWindowsAttributes(normalFile|windowsFileAttributeReparsePoint, false) {
		t.Fatal("file reparse point (symlink) must be rejected")
	}
	if evaluateWindowsAttributes(windowsInvalidFileAttributes, false) || evaluateWindowsAttributes(windowsInvalidFileAttributes, true) {
		t.Fatal("INVALID_FILE_ATTRIBUTES must be rejected")
	}
	if evaluateWindowsAttributes(windowsFileAttributeDevice, false) {
		t.Fatal("device attribute must be rejected")
	}
}

func TestEvaluateWindowsObjectSecurity_TrustedAllowlistAndObjectACEFailClosed(t *testing.T) {
	const fileAttrs = uint32(0x00000020) // FILE_ATTRIBUTE_ARCHIVE
	const dirAttrs = windowsFileAttributeDirectory
	const readExecuteMask = uint32(0x001200a9)

	trustedBaseline := []windowsParsedACE{
		// SYSTEM full control
		{aceType: windowsAccessAllowedACEType, mask: windowsAccessGenericAll, sidValid: true, sidTrusted: true},
		// Administrators full control
		{aceType: windowsAccessAllowedACEType, mask: windowsAccessGenericAll, sidValid: true, sidTrusted: true},
		// Untrusted principal (e.g. Users / INTERACTIVE / Guests) with read-only access is allowed
		{aceType: windowsAccessAllowedACEType, mask: readExecuteMask, sidValid: true, sidTrusted: false},
	}

	if !evaluateWindowsObjectSecurity(fileAttrs, false, true, true, trustedBaseline) {
		t.Fatal("expected SYSTEM/Administrators write + untrusted read-only DACL to pass on file")
	}
	if !evaluateWindowsObjectSecurity(dirAttrs, true, true, true, trustedBaseline) {
		t.Fatal("expected SYSTEM/Administrators write + untrusted read-only DACL to pass on directory")
	}

	// Untrusted owner or nil DACL must fail closed.
	if evaluateWindowsObjectSecurity(fileAttrs, false, false, true, trustedBaseline) {
		t.Fatal("untrusted owner must be rejected")
	}
	if evaluateWindowsObjectSecurity(fileAttrs, false, true, false, trustedBaseline) {
		t.Fatal("nil DACL must be rejected")
	}

	// Every write/delete/DACL/owner bit granted to ANY untrusted principal (including
	// INTERACTIVE, Guests, LocalService, or another local non-admin user) must be rejected.
	writeBits := []struct {
		name string
		mask uint32
	}{
		{"FILE_WRITE_DATA", windowsAccessFileWriteData},
		{"FILE_APPEND_DATA", windowsAccessFileAppendData},
		{"FILE_DELETE_CHILD", windowsAccessFileDeleteChild},
		{"DELETE", windowsAccessDelete},
		{"WRITE_DAC", windowsAccessWriteDAC},
		{"WRITE_OWNER", windowsAccessWriteOwner},
		{"GENERIC_WRITE", windowsAccessGenericWrite},
		{"GENERIC_ALL", windowsAccessGenericAll},
	}
	for _, wb := range writeBits {
		t.Run("UntrustedAllow_"+wb.name, func(t *testing.T) {
			aces := append(append([]windowsParsedACE(nil), trustedBaseline...), windowsParsedACE{
				aceType:    windowsAccessAllowedACEType,
				mask:       wb.mask,
				sidValid:   true,
				sidTrusted: false,
			})
			if evaluateWindowsObjectSecurity(fileAttrs, false, true, true, aces) {
				t.Fatalf("untrusted allow ACE with %s must be rejected on file", wb.name)
			}
			if evaluateWindowsObjectSecurity(dirAttrs, true, true, true, aces) {
				t.Fatalf("untrusted allow ACE with %s must be rejected on directory", wb.name)
			}

			// Callback allow ACE to untrusted principal with write bit must also be rejected.
			cbAces := append(append([]windowsParsedACE(nil), trustedBaseline...), windowsParsedACE{
				aceType:    windowsAccessAllowedCallbackACEType,
				mask:       wb.mask,
				sidValid:   true,
				sidTrusted: false,
			})
			if evaluateWindowsObjectSecurity(fileAttrs, false, true, true, cbAces) {
				t.Fatalf("untrusted callback allow ACE with %s must be rejected", wb.name)
			}

			// Same bit granted to a trusted principal (currSID / Administrators / SYSTEM) passes.
			trustedAces := append(append([]windowsParsedACE(nil), trustedBaseline...), windowsParsedACE{
				aceType:    windowsAccessAllowedACEType,
				mask:       wb.mask,
				sidValid:   true,
				sidTrusted: true,
			})
			if !evaluateWindowsObjectSecurity(fileAttrs, false, true, true, trustedAces) {
				t.Fatalf("trusted allow ACE with %s must be accepted", wb.name)
			}
		})
	}

	// INHERIT_ONLY_ACE does not apply to the object itself and must be skipped.
	inheritOnlyUntrusted := append(append([]windowsParsedACE(nil), trustedBaseline...), windowsParsedACE{
		aceType:    windowsAccessAllowedACEType,
		aceFlags:   windowsInheritOnlyACEFlag,
		mask:       windowsAccessGenericAll,
		sidValid:   true,
		sidTrusted: false,
	})
	if !evaluateWindowsObjectSecurity(dirAttrs, true, true, true, inheritOnlyUntrusted) {
		t.Fatal("INHERIT_ONLY_ACE must be skipped when evaluating the directory object itself")
	}

	// ACCESS_DENIED_ACE_TYPE and audit/label ACEs must be ignored.
	withDenyAndAudit := append(append([]windowsParsedACE(nil), trustedBaseline...),
		windowsParsedACE{aceType: windowsAccessDeniedACEType, mask: windowsAccessGenericAll},
		windowsParsedACE{aceType: windowsAccessDeniedObjectACEType, mask: windowsAccessGenericAll},
		windowsParsedACE{aceType: windowsSystemAuditACEType, mask: windowsAccessGenericAll},
		windowsParsedACE{aceType: windowsSystemMandatoryLabelACEType, mask: windowsAccessGenericAll},
	)
	if !evaluateWindowsObjectSecurity(fileAttrs, false, true, true, withDenyAndAudit) {
		t.Fatal("deny, audit, and mandatory label ACEs must not cause rejection")
	}

	// Object allow ACEs, compound allow ACEs, invalid SIDs, and unknown ACE types must fail closed.
	failClosedTypes := []struct {
		name string
		ace  windowsParsedACE
	}{
		{"ACCESS_ALLOWED_OBJECT_ACE_TYPE", windowsParsedACE{aceType: windowsAccessAllowedObjectACEType, sidValid: true, sidTrusted: true}},
		{"ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE", windowsParsedACE{aceType: windowsAccessAllowedCallbackObjectACEType, sidValid: true, sidTrusted: true}},
		{"ACCESS_ALLOWED_COMPOUND_ACE_TYPE", windowsParsedACE{aceType: windowsAccessAllowedCompoundACEType, sidValid: true, sidTrusted: true}},
		{"UnknownACEType_99", windowsParsedACE{aceType: 99, sidValid: true, sidTrusted: true}},
		{"InvalidSIDInAllowACE", windowsParsedACE{aceType: windowsAccessAllowedACEType, sidValid: false, sidTrusted: true}},
	}
	for _, tc := range failClosedTypes {
		t.Run(tc.name, func(t *testing.T) {
			aces := append(append([]windowsParsedACE(nil), trustedBaseline...), tc.ace)
			if evaluateWindowsObjectSecurity(fileAttrs, false, true, true, aces) {
				t.Fatalf("%s must fail closed", tc.name)
			}
		})
	}
}

func TestEvaluateWindowsAgentPipeOwner_FailsClosedWhenUnverified(t *testing.T) {
	if err := evaluateWindowsAgentPipeOwner(true, true, 42, nil, false, false); err != nil {
		t.Fatalf("trusted server token should succeed, got %v", err)
	}
	if err := evaluateWindowsAgentPipeOwner(true, false, 42, nil, true, true); !errors.Is(err, errUntrustedAgentPipeOwner) {
		t.Fatalf("untrusted server token must fail with errUntrustedAgentPipeOwner, got %v", err)
	}

	// Token unavailable (e.g. ERROR_ACCESS_DENIED on service process) -> falls back to GetSecurityInfo owner.
	if err := evaluateWindowsAgentPipeOwner(false, false, 0, nil, true, true); err != nil {
		t.Fatalf("trusted kernel object owner should succeed, got %v", err)
	}
	if err := evaluateWindowsAgentPipeOwner(false, false, 0, nil, true, false); !errors.Is(err, errUntrustedAgentPipeOwner) {
		t.Fatalf("untrusted kernel object owner must fail with errUntrustedAgentPipeOwner, got %v", err)
	}

	// Both token lookup AND GetSecurityInfo / sd.Owner() failing MUST fail closed (never return nil!).
	sentinel := errors.New("GetSecurityInfo failed")
	if err := evaluateWindowsAgentPipeOwner(false, false, 0, sentinel, false, false); !errors.Is(err, sentinel) {
		t.Fatalf("GetSecurityInfo failure must fail closed wrapping error, got %v", err)
	}
	if err := evaluateWindowsAgentPipeOwner(false, false, 0, nil, false, false); err == nil {
		t.Fatal("nil security descriptor / missing owner must fail closed")
	}
}

func TestRound4_P2_10_EvaluateWindowsAgentPipeDACL(t *testing.T) {
	// Win32-OpenSSH openssh-ssh-agent default client ACE for Authenticated Users:
	// READ_CONTROL|SYNCHRONIZE|FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|FILE_READ_EA = 0x0012019b.
	openSSHAUACE := windowsParsedACE{
		aceType:    windowsAccessAllowedACEType,
		mask:       0x0012019b,
		sidValid:   true,
		sidTrusted: false,
	}
	trustedOwnerACE := windowsParsedACE{
		aceType:    windowsAccessAllowedACEType,
		mask:       windowsAccessGenericAll | windowsAccessFileCreatePipeInstance,
		sidValid:   true,
		sidTrusted: true,
	}

	if err := evaluateWindowsAgentPipeSecurity(
		true, true, 100,
		nil, true, true,
		nil, true, []windowsParsedACE{trustedOwnerACE, openSSHAUACE},
	); err != nil {
		t.Fatalf("Win32-OpenSSH pipe DACL should be allowed, got %v", err)
	}

	// Null DACL must fail closed even when process token & SD owner are trusted.
	if err := evaluateWindowsAgentPipeSecurity(
		true, true, 100,
		nil, true, true,
		nil, false, nil,
	); !errors.Is(err, errInsecureAgentPipeDACL) {
		t.Fatalf("null DACL got %v, want errInsecureAgentPipeDACL", err)
	}

	// Untrusted SIDs granting pipe instance creation or DACL/owner mutation must fail closed.
	for _, unsafeMask := range []uint32{
		windowsAccessFileCreatePipeInstance,
		windowsAccessWriteDAC,
		windowsAccessWriteOwner,
		windowsAccessGenericWrite,
		windowsAccessGenericAll,
	} {
		err := evaluateWindowsAgentPipeSecurity(
			true, true, 100,
			nil, true, true,
			nil, true, []windowsParsedACE{
				trustedOwnerACE,
				{
					aceType:    windowsAccessAllowedACEType,
					mask:       unsafeMask,
					sidValid:   true,
					sidTrusted: false,
				},
			},
		)
		if !errors.Is(err, errInsecureAgentPipeDACL) {
			t.Fatalf("mask %#x for untrusted SID got %v, want errInsecureAgentPipeDACL", unsafeMask, err)
		}
	}
}
