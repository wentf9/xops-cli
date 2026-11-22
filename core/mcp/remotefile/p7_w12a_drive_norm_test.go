package remotefile

import "testing"

// TestP7W12a_AB12L1_NormalizeSFTPPathCollapsedDrives verifies AB12-L1:
//   - NormalizeSFTPPath collapses leading "/" and ".." segments before/when
//     detecting Windows drive syntax, canonicalizing "//c:\Users\admin\a.txt"
//     and "/tmp/../c:\Users\admin\a.txt" to "/C:/Users/admin/a.txt", and drive
//     roots such as "//C:/", "///c:\", and "/tmp/../C:/" to "/C:".
//   - Non-drive POSIX paths preserve literal backslashes (no POSIX "\.."
//     collapsing) and relative paths disguised as drives ("./C:/...") are never
//     promoted into absolute "/C:/..." paths.
func TestP7W12a_AB12L1_NormalizeSFTPPathCollapsedDrives(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"double slash lowercase backslash path", `//c:\Users\admin\a.txt`, "/C:/Users/admin/a.txt"},
		{"triple slash lowercase forward path", "///c:/Users/admin/a.txt", "/C:/Users/admin/a.txt"},
		{"double slash drive root forward", "//C:/", "/C:"},
		{"triple slash lowercase drive root backslash", `///c:\`, "/C:"},
		{"double slash bare drive root", "//C:", "/C:"},
		{"dotdot to drive root forward", "/tmp/../C:/", "/C:"},
		{"dotdot to lowercase drive root backslash", `/tmp/../c:\`, "/C:"},
		{"dotdot to lowercase drive backslash file", `/tmp/../c:\Users\admin\a.txt`, "/C:/Users/admin/a.txt"},
		{"dotdot to windows sensitive file", "/tmp/../c:/Windows/System32/config/SAM", "/C:/Windows/System32/config/SAM"},
		{"dot segment before drive backslash file", `/./c:\Users\admin\a.txt`, "/C:/Users/admin/a.txt"},
		{"double slash drive dotdot clamps to drive root", "//C:/Users/../..", "/C:"},
		{"double slash drive dotdot does not cross drives", "//C:/../D:/foo", "/C:/D:/foo"},
		{"dotdot to drive backslash dotdot clamps to drive root", `/tmp/../c:\Users\..\..`, "/C:"},
		{"multi dotdot to D drive root", `/a/b/../../d:\`, "/D:"},
		{"posix literal backslash dotdot preserved", `/opt/custom-protected/\../drop`, `/opt/custom-protected/\../drop`},
		{"relative path disguised as drive stays non-absolute", "./C:/Users/admin", "C:/Users/admin"},
		{"relative bare drive stays non-absolute", "./C:", "C:"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeSFTPPath(tc.in); got != tc.want {
				t.Errorf("NormalizeSFTPPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestP7W12a_AB12L1_IsRootPathAndValidateTransferInputPath verifies that
// IsRootPath and validateTransferInputPath reject collapsed Windows drive roots
// and relative paths disguised as drive paths while canonicalizing valid
// collapsed Windows drive file paths.
func TestP7W12a_AB12L1_IsRootPathAndValidateTransferInputPath(t *testing.T) {
	roots := []string{
		"//C:/",
		"///c:\\",
		"//C:",
		"/tmp/../C:/",
		`/tmp/../c:\`,
		`/tmp/../c:\Users\..\..`,
		"//C:/Users/../..",
		"/tmp/../C:/Users/../..",
		`/a/b/../../d:\`,
	}
	for _, r := range roots {
		if !IsRootPath(r) {
			t.Errorf("IsRootPath(%q) = false, want true", r)
		}
		if got, err := validateTransferInputPath(r); err == nil {
			t.Errorf("validateTransferInputPath(%q) = %q, nil; want error for root path", r, got)
		}
	}

	nonRoots := []string{
		`//c:\Users\admin\a.txt`,
		`/opt/custom-protected/\../drop`,
		"./C:",
	}
	for _, p := range nonRoots {
		if IsRootPath(p) {
			t.Errorf("IsRootPath(%q) = true, want false", p)
		}
	}

	// Relative path disguised as drive must be rejected by validateTransferInputPath.
	for _, rel := range []string{"./C:/Users/admin/a.txt", "foo/../C:/Users/admin/a.txt", "C:relative.txt"} {
		if got, err := validateTransferInputPath(rel); err == nil {
			t.Errorf("validateTransferInputPath(%q) = %q, nil; want error for relative path", rel, got)
		}
	}

	// Valid collapsed drive paths canonicalize to /C:/... and POSIX backslash paths keep '\'.
	validCases := []struct {
		in   string
		want string
	}{
		{`//c:\Users\admin\a.txt`, "/C:/Users/admin/a.txt"},
		{`/tmp/../c:\Users\admin\a.txt`, "/C:/Users/admin/a.txt"},
		{`/opt/custom-protected/\../secret`, `/opt/custom-protected/\../secret`},
	}
	for _, tc := range validCases {
		got, err := validateTransferInputPath(tc.in)
		if err != nil {
			t.Errorf("validateTransferInputPath(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("validateTransferInputPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
