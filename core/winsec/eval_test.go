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

	// INHERIT_ONLY_ACE does not apply to the directory itself.
	inheritOnlyUntrusted := append(append([]ParsedACE(nil), ownerOnlyBaseline...), ParsedACE{
		ACEType:    AccessAllowedACEType,
		ACEFlags:   InheritOnlyACEFlag,
		Mask:       AccessGenericAll,
		SIDValid:   true,
		SIDTrusted: false,
	})
	if !EvaluateOwnerOnlyDirectorySecurity(FileAttributeDirectory, true, true, inheritOnlyUntrusted) {
		t.Fatal("INHERIT_ONLY_ACE should not reject directory itself")
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
