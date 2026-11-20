package host

import (
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
)

func TestRound8_P2_16_HostAddEditLoadUniformAddressNormalization(t *testing.T) {
	t.Parallel()

	// 1. applyAddTargetArgs trims outer whitespace on --address and rejects malformed brackets.
	addr := " 10.96.0.1 "
	user := ""
	var port uint16 = 22
	var aliases []string
	if err := applyAddTargetArgs(nil, &aliases, &addr, &user, &port, false); err != nil {
		t.Fatalf("applyAddTargetArgs(\" 10.96.0.1 \") failed: %v", err)
	}
	if addr != "10.96.0.1" {
		t.Fatalf("applyAddTargetArgs addr = %q, want 10.96.0.1", addr)
	}

	badAdd := "[badhost]"
	if err := applyAddTargetArgs(nil, &aliases, &badAdd, &user, &port, false); err == nil {
		t.Fatal("applyAddTargetArgs accepted malformed [badhost]")
	}

	v6Add := "[2001:db8::1]"
	if err := applyAddTargetArgs(nil, &aliases, &v6Add, &user, &port, false); err != nil {
		t.Fatalf("applyAddTargetArgs([2001:db8::1]) failed: %v", err)
	}
	if v6Add != "2001:db8::1" {
		t.Fatalf("applyAddTargetArgs IPv6 = %q, want 2001:db8::1", v6Add)
	}

	// 2. applyEditTargetArgs applies identical validation/trimming.
	ef := &editFlags{address: " 10.96.0.2 "}
	if err := applyEditTargetArgs(nil, ef, false); err != nil {
		t.Fatalf("applyEditTargetArgs(\" 10.96.0.2 \") failed: %v", err)
	}
	if ef.address != "10.96.0.2" {
		t.Fatalf("applyEditTargetArgs addr = %q, want 10.96.0.2", ef.address)
	}
	if err := applyEditTargetArgs(nil, &editFlags{address: "[badhost]"}, false); err == nil {
		t.Fatal("applyEditTargetArgs accepted malformed [badhost]")
	}

	// 3. normalizeImportAddress rejects malformed brackets, user@, and embedded ports while accepting IPv6 + zone ID.
	for _, bad := range []string{"[badhost]", "ops@10.96.0.1", "10.96.0.1:2222", "OPENSSH:victim"} {
		if _, err := normalizeImportAddress(utils.HostInfo{Host: bad, User: "ops"}); err == nil {
			t.Errorf("normalizeImportAddress(%q) unexpectedly succeeded", bad)
		}
	}
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"2001:db8::1", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"fe80::1%eth0", "fe80::1%eth0"},
		{" 10.96.0.3 ", "10.96.0.3"},
	} {
		got, err := normalizeImportAddress(utils.HostInfo{Host: tc.in, User: "ops"})
		if err != nil {
			t.Errorf("normalizeImportAddress(%q) failed: %v", tc.in, err)
			continue
		}
		if got.Host != tc.want {
			t.Errorf("normalizeImportAddress(%q).Host = %q, want %q", tc.in, got.Host, tc.want)
		}
	}
}
