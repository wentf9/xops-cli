package osfs_test

import (
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/osfs"
)

func TestEvaluateWindowsObjectACL(t *testing.T) {
	trustedAllow := osfs.ParsedWindowsACE{
		ACEType: osfs.WinACETypeAllow, Mask: osfs.WinAccessGenericAll, SIDValid: true, SIDTrusted: true,
	}
	untrustedRead := osfs.ParsedWindowsACE{
		ACEType: osfs.WinACETypeAllow, Mask: 0x00120089, SIDValid: true, SIDTrusted: false,
	}
	untrustedWrite := osfs.ParsedWindowsACE{
		ACEType: osfs.WinACETypeAllow, Mask: osfs.WinAccessWriteData, SIDValid: true, SIDTrusted: false,
	}
	inheritOnlyUntrusted := osfs.ParsedWindowsACE{
		ACEType: osfs.WinACETypeAllow, ACEFlags: osfs.WinACEFlagInheritOnly, Mask: osfs.WinAccessGenericAll, SIDValid: true, SIDTrusted: false,
	}
	untrustedDeleteChild := osfs.ParsedWindowsACE{
		ACEType: osfs.WinACETypeAllow, Mask: osfs.WinAccessDeleteChild, SIDValid: true, SIDTrusted: false,
	}

	cases := []struct {
		name string
		in   osfs.WindowsACLInput
		want security.Verdict
	}{
		{
			name: "zero_mode_fail_closed",
			in:   osfs.WindowsACLInput{OwnerTrusted: true, HasDACL: true, ACEs: []osfs.ParsedWindowsACE{trustedAllow}},
			want: security.VerdictDeny,
		},
		{
			name: "owner_only_valid_file",
			in:   osfs.WindowsACLInput{Mode: osfs.WindowsACLOwnerOnly, OwnerTrusted: true, HasDACL: true, ACEs: []osfs.ParsedWindowsACE{trustedAllow, inheritOnlyUntrusted}},
			want: security.VerdictAllow,
		},
		{
			name: "owner_only_dir_rejects_untrusted_inherit_only",
			in:   osfs.WindowsACLInput{Mode: osfs.WindowsACLOwnerOnly, Attrs: osfs.WinAttrDirectory, ExpectDir: true, OwnerTrusted: true, HasDACL: true, ACEs: []osfs.ParsedWindowsACE{trustedAllow, inheritOnlyUntrusted}},
			want: security.VerdictDeny,
		},
		{
			name: "write_restricted_dir_rejects_delete_child",
			in:   osfs.WindowsACLInput{Mode: osfs.WindowsACLWriteRestricted, Attrs: osfs.WinAttrDirectory, ExpectDir: true, OwnerTrusted: true, HasDACL: true, ACEs: []osfs.ParsedWindowsACE{trustedAllow, untrustedDeleteChild}},
			want: security.VerdictDeny,
		},
		{
			name: "owner_only_rejects_nil_dacl",
			in:   osfs.WindowsACLInput{Mode: osfs.WindowsACLOwnerOnly, OwnerTrusted: true, HasDACL: false},
			want: security.VerdictDeny,
		},
		{
			name: "owner_only_rejects_untrusted_read",
			in:   osfs.WindowsACLInput{Mode: osfs.WindowsACLOwnerOnly, OwnerTrusted: true, HasDACL: true, ACEs: []osfs.ParsedWindowsACE{trustedAllow, untrustedRead}},
			want: security.VerdictDeny,
		},
		{
			name: "write_restricted_allows_untrusted_read",
			in:   osfs.WindowsACLInput{Mode: osfs.WindowsACLWriteRestricted, OwnerTrusted: true, HasDACL: true, ACEs: []osfs.ParsedWindowsACE{trustedAllow, untrustedRead}},
			want: security.VerdictAllow,
		},
		{
			name: "write_restricted_rejects_untrusted_write",
			in:   osfs.WindowsACLInput{Mode: osfs.WindowsACLWriteRestricted, OwnerTrusted: true, HasDACL: true, ACEs: []osfs.ParsedWindowsACE{trustedAllow, untrustedWrite}},
			want: security.VerdictDeny,
		},
		{
			name: "rejects_unexpected_reparse_point",
			in:   osfs.WindowsACLInput{Mode: osfs.WindowsACLOwnerOnly, Attrs: osfs.WinAttrReparsePoint, OwnerTrusted: true, HasDACL: true, ACEs: []osfs.ParsedWindowsACE{trustedAllow}},
			want: security.VerdictDeny,
		},
		{
			name: "allows_af_unix_reparse_when_expected",
			in:   osfs.WindowsACLInput{Mode: osfs.WindowsACLOwnerOnly, Attrs: osfs.WinAttrReparsePoint, AllowReparse: true, OwnerTrusted: true, HasDACL: true, ACEs: []osfs.ParsedWindowsACE{trustedAllow}},
			want: security.VerdictAllow,
		},
		{
			name: "rejects_device_attribute",
			in:   osfs.WindowsACLInput{Mode: osfs.WindowsACLOwnerOnly, Attrs: osfs.WinAttrDevice, OwnerTrusted: true, HasDACL: true, ACEs: []osfs.ParsedWindowsACE{trustedAllow}},
			want: security.VerdictDeny,
		},
		{
			name: "rejects_unknown_ace_type",
			in:   osfs.WindowsACLInput{Mode: osfs.WindowsACLOwnerOnly, OwnerTrusted: true, HasDACL: true, ACEs: []osfs.ParsedWindowsACE{{ACEType: 0x99}}},
			want: security.VerdictDeny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := osfs.EvaluateWindowsObjectACL(tc.in); got != tc.want {
				t.Fatalf("EvaluateWindowsObjectACL(%s) = %v, 期望 %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestUTF16AndExtendedPathPredicates(t *testing.T) {
	if got := osfs.UTF16CodeUnitLen("abc\U0001F512"); got != 5 {
		t.Fatalf("UTF16CodeUnitLen 代理对计数 = %d, 期望 5", got)
	}
	for _, ext := range []string{`\\?\C:\foo`, `\\.\pipe\x`, `\??\C:\foo`} {
		if !osfs.IsExtendedOrDeviceWindowsPath(ext) {
			t.Fatalf("IsExtendedOrDeviceWindowsPath(%q) 期望 true", ext)
		}
	}
	if osfs.IsExtendedOrDeviceWindowsPath(`C:\normal\path`) {
		t.Fatal("普通盘符路径不应误判为扩展路径")
	}
	longWin := `C:\` + strings.Repeat("a", 260)
	if got := osfs.NormalizeWin32LongPath(longWin); got != `\\?\`+longWin {
		t.Fatalf("NormalizeWin32LongPath(%q) = %q, 期望 %q", longWin, got, `\\?\`+longWin)
	}
}
