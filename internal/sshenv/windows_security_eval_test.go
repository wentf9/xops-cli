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
		{ACEType: windowsAccessAllowedACEType, Mask: windowsAccessGenericAll, SIDValid: true, SIDTrusted: true},
		// Administrators full control
		{ACEType: windowsAccessAllowedACEType, Mask: windowsAccessGenericAll, SIDValid: true, SIDTrusted: true},
		// Untrusted principal (e.g. Users / INTERACTIVE / Guests) with read-only access is allowed
		{ACEType: windowsAccessAllowedACEType, Mask: readExecuteMask, SIDValid: true, SIDTrusted: false},
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
				ACEType:    windowsAccessAllowedACEType,
				Mask:       wb.mask,
				SIDValid:   true,
				SIDTrusted: false,
			})
			if evaluateWindowsObjectSecurity(fileAttrs, false, true, true, aces) {
				t.Fatalf("untrusted allow ACE with %s must be rejected on file", wb.name)
			}
			if evaluateWindowsObjectSecurity(dirAttrs, true, true, true, aces) {
				t.Fatalf("untrusted allow ACE with %s must be rejected on directory", wb.name)
			}

			// Callback allow ACE to untrusted principal with write bit must also be rejected.
			cbAces := append(append([]windowsParsedACE(nil), trustedBaseline...), windowsParsedACE{
				ACEType:    windowsAccessAllowedCallbackACEType,
				Mask:       wb.mask,
				SIDValid:   true,
				SIDTrusted: false,
			})
			if evaluateWindowsObjectSecurity(fileAttrs, false, true, true, cbAces) {
				t.Fatalf("untrusted callback allow ACE with %s must be rejected", wb.name)
			}

			// Same bit granted to a trusted principal (currSID / Administrators / SYSTEM) passes.
			trustedAces := append(append([]windowsParsedACE(nil), trustedBaseline...), windowsParsedACE{
				ACEType:    windowsAccessAllowedACEType,
				Mask:       wb.mask,
				SIDValid:   true,
				SIDTrusted: true,
			})
			if !evaluateWindowsObjectSecurity(fileAttrs, false, true, true, trustedAces) {
				t.Fatalf("trusted allow ACE with %s must be accepted", wb.name)
			}
		})
	}

	// INHERIT_ONLY_ACE does not apply to the object itself and must be skipped.
	inheritOnlyUntrusted := append(append([]windowsParsedACE(nil), trustedBaseline...), windowsParsedACE{
		ACEType:    windowsAccessAllowedACEType,
		ACEFlags:   windowsInheritOnlyACEFlag,
		Mask:       windowsAccessGenericAll,
		SIDValid:   true,
		SIDTrusted: false,
	})
	if !evaluateWindowsObjectSecurity(dirAttrs, true, true, true, inheritOnlyUntrusted) {
		t.Fatal("INHERIT_ONLY_ACE must be skipped when evaluating the directory object itself")
	}

	// ACCESS_DENIED_ACE_TYPE and audit/label ACEs must be ignored.
	withDenyAndAudit := append(append([]windowsParsedACE(nil), trustedBaseline...),
		windowsParsedACE{ACEType: windowsAccessDeniedACEType, Mask: windowsAccessGenericAll},
		windowsParsedACE{ACEType: windowsAccessDeniedObjectACEType, Mask: windowsAccessGenericAll},
		windowsParsedACE{ACEType: windowsSystemAuditACEType, Mask: windowsAccessGenericAll},
		windowsParsedACE{ACEType: windowsSystemMandatoryLabelACEType, Mask: windowsAccessGenericAll},
	)
	if !evaluateWindowsObjectSecurity(fileAttrs, false, true, true, withDenyAndAudit) {
		t.Fatal("deny, audit, and mandatory label ACEs must not cause rejection")
	}

	// Object allow ACEs, compound allow ACEs, invalid SIDs, and unknown ACE types must fail closed.
	failClosedTypes := []struct {
		name string
		ace  windowsParsedACE
	}{
		{"ACCESS_ALLOWED_OBJECT_ACE_TYPE", windowsParsedACE{ACEType: windowsAccessAllowedObjectACEType, SIDValid: true, SIDTrusted: true}},
		{"ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE", windowsParsedACE{ACEType: windowsAccessAllowedCallbackObjectACEType, SIDValid: true, SIDTrusted: true}},
		{"ACCESS_ALLOWED_COMPOUND_ACE_TYPE", windowsParsedACE{ACEType: windowsAccessAllowedCompoundACEType, SIDValid: true, SIDTrusted: true}},
		{"UnknownACEType_99", windowsParsedACE{ACEType: 99, SIDValid: true, SIDTrusted: true}},
		{"InvalidSIDInAllowACE", windowsParsedACE{ACEType: windowsAccessAllowedACEType, SIDValid: false, SIDTrusted: true}},
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
	if err := evaluateWindowsAgentPipeOwner(true, true, 42, nil, true, true); err != nil {
		t.Fatalf("trusted server token + trusted kernel object owner should succeed, got %v", err)
	}
	if err := evaluateWindowsAgentPipeOwner(true, true, 42, nil, true, false); !errors.Is(err, errUntrustedAgentPipeOwner) {
		t.Fatalf("trusted server token + untrusted kernel object owner must fail closed, got %v", err)
	}
	if err := evaluateWindowsAgentPipeOwner(true, true, 42, nil, false, false); err == nil {
		t.Fatal("trusted server token + missing kernel object owner must fail closed")
	}
	sentinelOwnerErr := errors.New("sd.Owner failed")
	if err := evaluateWindowsAgentPipeOwner(true, true, 42, sentinelOwnerErr, false, false); !errors.Is(err, sentinelOwnerErr) {
		t.Fatalf("trusted server token + owner query error must fail closed wrapping error, got %v", err)
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
		ACEType:    windowsAccessAllowedACEType,
		Mask:       0x0012019b,
		SIDValid:   true,
		SIDTrusted: false,
	}
	trustedOwnerACE := windowsParsedACE{
		ACEType:    windowsAccessAllowedACEType,
		Mask:       windowsAccessGenericAll | windowsAccessFileCreatePipeInstance,
		SIDValid:   true,
		SIDTrusted: true,
	}

	if err := evaluateWindowsAgentPipeSecurity(
		true, true, 100,
		nil, true, true,
		nil, true, []windowsParsedACE{trustedOwnerACE, openSSHAUACE},
	); err != nil {
		t.Fatalf("Win32-OpenSSH pipe DACL should be allowed, got %v", err)
	}

	if err := evaluateWindowsAgentPipeSecurity(
		true, true, 100,
		nil, true, false,
		nil, true, []windowsParsedACE{trustedOwnerACE, openSSHAUACE},
	); !errors.Is(err, errUntrustedAgentPipeOwner) {
		t.Fatalf("trusted token with untrusted SD owner got %v, want errUntrustedAgentPipeOwner", err)
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
					ACEType:    windowsAccessAllowedACEType,
					Mask:       unsafeMask,
					SIDValid:   true,
					SIDTrusted: false,
				},
			},
		)
		if !errors.Is(err, errInsecureAgentPipeDACL) {
			t.Fatalf("mask %#x for untrusted SID got %v, want errInsecureAgentPipeDACL", unsafeMask, err)
		}
	}
}

func TestRound6_P1_2_And_P3_4_WindowsAgentDesiredAccessAndUnicodeControls(t *testing.T) {
	t.Parallel()

	// P1-2: dialWindowsNamedPipe desiredAccess MUST be a strict subset of Win32-OpenSSH's
	// Authenticated Users ACE (0x0012019b) and MUST NOT include any privileged server mask bit
	// such as FILE_CREATE_PIPE_INSTANCE (0x00000004).
	if extra := windowsAgentPipeDesiredAccess &^ win32OpenSSHAgentAUAccessMask; extra != 0 {
		t.Fatalf("windowsAgentPipeDesiredAccess (%#x) requests bits not in Win32-OpenSSH AU ACE (%#x): extra=%#x",
			windowsAgentPipeDesiredAccess, win32OpenSSHAgentAUAccessMask, extra)
	}
	if overlap := windowsAgentPipeDesiredAccess & windowsInsecureNamedPipeServerMask; overlap != 0 {
		t.Fatalf("windowsAgentPipeDesiredAccess (%#x) overlaps windowsInsecureNamedPipeServerMask (%#x): overlap=%#x",
			windowsAgentPipeDesiredAccess, windowsInsecureNamedPipeServerMask, overlap)
	}
	// A minimal-DACL pipe granting only windowsAgentPipeDesiredAccess to AU must pass evaluation.
	if !evaluateWindowsNamedPipeDACL(true, []windowsParsedACE{
		{
			ACEType:    windowsAccessAllowedACEType,
			Mask:       windowsAccessGenericAll,
			SIDValid:   true,
			SIDTrusted: true,
		},
		{
			ACEType:    windowsAccessAllowedACEType,
			Mask:       windowsAgentPipeDesiredAccess,
			SIDValid:   true,
			SIDTrusted: false,
		},
	}) {
		t.Fatal("minimal-DACL pipe granting 0x0012008b should be allowed")
	}

	// P3-4: C1 control U+0085 (NEL), line/paragraph separators U+2028/U+2029, and invalid UTF-8
	// must be rejected before TrimSpace can launder them.
	for _, bad := range []string{
		"\u0085",
		"\u0085\\\\.\\pipe\\openssh-ssh-agent",
		"\\\\.\\pipe\\openssh-ssh-agent\u0085",
		"\u2028\\\\.\\pipe\\openssh-ssh-agent",
		"\\\\.\\pipe\\openssh-ssh-agent\u2029",
		string([]byte{0x85, '\\', '\\', '.', '\\', 'p', 'i', 'p', 'e', '\\', 'a'}),
	} {
		if !hasWindowsAgentControlChar(bad) {
			t.Fatalf("hasWindowsAgentControlChar(%q) = false, want true", bad)
		}
		if _, _, err := parseWindowsAgentPipePath(bad); err == nil {
			t.Fatalf("parseWindowsAgentPipePath(%q) = nil, want control-char error", bad)
		}
	}
	// Plain ASCII spaces around a valid pipe path remain allowed.
	gotPipe, isPipe, err := parseWindowsAgentPipePath(`  \\.\pipe\openssh-ssh-agent  `)
	if err != nil || !isPipe || gotPipe != defaultWindowsOpenSSHAgentPipe {
		t.Fatalf("parseWindowsAgentPipePath(spaces) = (%q, %v, %v)", gotPipe, isPipe, err)
	}
}
