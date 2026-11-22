package remotefile

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/wentf9/xops-cli/core/sftp"
)

// TestP7W14a_AB14M1_MixedBackslashAndWin32DeviceUNCPaths verifies AB14-M1:
//   - Mixed-backslash SFTP drive paths (e.g. "/tmp/..\C:\ ", "/\C:\",
//     "/tmp/..\C:\Protected.\secret.env:$DATA", "/\C:\Protected.\secret.env:$DATA")
//     are recognized as Windows drive paths by extractDrivePath, IsRootPath,
//     NormalizeSFTPPath, and rejected fail-closed by ValidateWindowsDrivePath.
//   - Win32 extended/device prefixes (\\?\, \\.\, \??\, //?/, //./C:...,
//     \\?\UNC\..., \\?\Volume{...}\...) and UNC paths (\\server\share\...,
//     \\localhost\C$\...) are rejected fail-closed by ValidateWindowsDrivePath
//     and validateTransferInputPath.
//   - Non-drive POSIX paths with literal backslashes (e.g.
//     "/opt/custom-protected/\../drop", "/tmp/a\b") remain untouched as POSIX paths.
func TestP7W14a_AB14M1_MixedBackslashAndWin32DeviceUNCPaths(t *testing.T) {
	t.Run("isRootPath_mixed_backslash_and_win32_device_unc_roots", func(t *testing.T) {
		roots := []string{
			`/tmp/..\C:\ `,
			`/\C:\`,
			`/\C:\ `,
			`/tmp/..\C:\`,
			`/tmp/..\C:`,
			`/tmp/..\C:\...`,
			`/tmp/..\C:\::$DATA`,
			`/\c:\Users\..\..`,
			`\\?\C:\`,
			`\\?\C:\ `,
			`\\.\C:\`,
			`\??\C:\`,
			`\\server\share`,
			`\\server\share\`,
			`\\server\share\ `,
			`\\?\UNC\server\share\`,
			`\\localhost\C$`,
			`\\localhost\C$\`,
		}
		for _, r := range roots {
			if !IsRootPath(r) {
				t.Errorf("IsRootPath(%q) = false, want true", r)
			}
		}

		nonRoots := []string{
			`/opt/custom-protected/\../drop`,
			`/tmp/a\b`,
			`\tmp\foo`,
			`\\?\C:\Users\ops\app.log`,
			`\\server\share\file.txt`,
		}
		for _, p := range nonRoots {
			if IsRootPath(p) {
				t.Errorf("IsRootPath(%q) = true, want false", p)
			}
		}
	})

	t.Run("validateWindowsDrivePath_rejects_mixed_backslash_device_and_unc", func(t *testing.T) {
		rejected := []string{
			`/tmp/..\C:\Protected.\secret.env:$DATA`,
			`/\C:\Protected.\secret.env:$DATA`,
			`/tmp/..\C:\ `,
			`/\C:\`,
			`/tmp/..\C:\Users\admin\a.txt`,
			`/\C:\Users\admin\a.txt`,
			`\\?\C:\Protected\secret.env`,
			`\\?\C:\Protected.\secret.env:$DATA`,
			`\\.\C:\Protected\secret.env`,
			`\??\C:\Protected\secret.env`,
			`\\?\UNC\server\share\file.txt`,
			`\\.\UNC\server\share\file.txt`,
			`\??\UNC\server\share\file.txt`,
			`\\?\Volume{00000000-0000-0000-0000-000000000000}\secret.env`,
			`\\?\GLOBALROOT\??\C:\Protected\secret.env`,
			`\\server\share\file.txt`,
			`\\localhost\C$\Protected\secret.env`,
			`\\127.0.0.1\C$\Protected\secret.env`,
			`\\.\pipe\openssh-ssh-agent`,
			`//?/C:/Protected/secret.env`,
			`//./C:/Protected/secret.env`,
			`//?/UNC/server/share/file.txt`,
			`//./UNC/server/share/file.txt`,
			`//?/Volume{00000000-0000-0000-0000-000000000000}/secret.env`,
			`//./pipe/openssh-ssh-agent`,
			`\\?\opt\file`,
			`\etc\passwd`,
			`/tmp/../C:/../D:/foo`,
		}
		for _, p := range rejected {
			if err := ValidateWindowsDrivePath(p); !errors.Is(err, sftp.ErrInvalidRemotePath) {
				t.Errorf("ValidateWindowsDrivePath(%q) = %v, want ErrInvalidRemotePath", p, err)
			}
			if got, inErr := validateTransferInputPath(p); inErr == nil {
				t.Errorf("validateTransferInputPath(%q) = %q, nil; want error", p, got)
			}
		}
	})

	t.Run("normalizeSFTPPath_normalizes_mixed_drives_and_preserves_posix_backslash", func(t *testing.T) {
		cases := []struct {
			in   string
			want string
		}{
			{`/tmp/..\C:\Users\admin\a.txt`, `/C:/Users/admin/a.txt`},
			{`/\C:\`, `/C:`},
			{`/tmp/..\C:\Users\..\..`, `/C:`},
			{`/tmp/../C:/Users/../..`, `/C:`},
			{`/opt/custom-protected/\../drop`, `/opt/custom-protected/\../drop`},
			{`/tmp/a\b`, `/tmp/a\b`},
			{`\tmp\foo`, `\tmp\foo`},
		}
		for _, tc := range cases {
			if got := NormalizeSFTPPath(tc.in); got != tc.want {
				t.Errorf("NormalizeSFTPPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		}

		// Non-drive POSIX paths with literal backslashes or //./ or //?/ still pass validation.
		for _, posix := range []string{`/opt/custom-protected/\../drop`, `/tmp/a\b`, `//./tmp/posix`, `//?/opt/file`, `//?/secret/key.pem`} {
			if err := ValidateWindowsDrivePath(posix); err != nil {
				t.Errorf("ValidateWindowsDrivePath(%q) unexpected error: %v", posix, err)
			}
		}
	})
}

// TestP7W14a_AB14L1_ValidateResolvedRealPathCanonicalizesLowercaseDrive verifies AB14-L1:
//   - validateResolvedRealPath canonicalizes lowercase-drive SFTP RealPath replies
//     ("/c:/Data" -> "/C:/Data", "/c:/" -> "/C:").
//   - Session.Inspect and Session.Remove succeed when RealPath returns "/c:/Data"
//     for canonical uppercase "/C:/Data/..." paths.
//   - Hostile Win32 device/UNC or mixed-backslash RealPath replies fail closed.
func TestP7W14a_AB14L1_ValidateResolvedRealPathCanonicalizesLowercaseDrive(t *testing.T) {
	t.Run("direct_canonicalization", func(t *testing.T) {
		cases := []struct {
			in   string
			want string
		}{
			{"/c:/Data", "/C:/Data"},
			{"/c:/", "/C:"},
			{"/C:/Data", "/C:/Data"},
			{"/d:/Users/Alice", "/D:/Users/Alice"},
			{"/tmp/data", "/tmp/data"},
			{`/opt/custom-protected/\..`, `/opt/custom-protected/\..`},
		}
		for _, tc := range cases {
			got, err := validateResolvedRealPath(tc.in)
			if err != nil {
				t.Errorf("validateResolvedRealPath(%q) unexpected error: %v", tc.in, err)
				continue
			}
			if got != tc.want {
				t.Errorf("validateResolvedRealPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		}

		for _, bad := range []string{
			`\\?\C:\Data`,
			`\\server\share\Data`,
			`/tmp/..\C:\Data`,
			`/\C:\Data`,
			`//?/C:/Data`,
		} {
			if got, err := validateResolvedRealPath(bad); !errors.Is(err, sftp.ErrInvalidRemotePath) {
				t.Errorf("validateResolvedRealPath(%q) = (%q, %v), want ErrInvalidRemotePath", bad, got, err)
			}
		}
	})

	t.Run("inspect_and_remove_canonicalize_lowercase_drive_realpath", func(t *testing.T) {
		const tmpName = "/C:/Data/.xops-transfer-0123456789abcdef0123456789abcdef.tmp"
		h := &w11aHostileHandler{
			realPath: "/c:/Data",
			stats: map[string]os.FileInfo{
				"/C:/Data": w11aFileInfo{name: "Data", mode: os.ModeDir | 0o755},
			},
			lstats: map[string]os.FileInfo{
				"/C:/Data/report.csv": w11aFileInfo{name: "report.csv", size: 42, mode: 0o600},
				tmpName:               w11aFileInfo{name: ".xops-transfer-0123456789abcdef0123456789abcdef.tmp", size: 4, mode: 0o600},
			},
		}
		sess := newW11aSession(t, h)

		meta, err := sess.Inspect(t.Context(), `c:\Data\report.csv`, false, false)
		if err != nil {
			t.Fatalf("Inspect failed: %v", err)
		}
		if meta.Path != "/C:/Data/report.csv" || meta.Size != 42 {
			t.Fatalf("Inspect = %+v, want Path=/C:/Data/report.csv Size=42", meta)
		}

		if err := sess.Remove(t.Context(), tmpName); err != nil {
			t.Fatalf("Remove with lowercase RealPath failed: %v", err)
		}
		h.mu.Lock()
		removes := append([]string(nil), h.removeCalls...)
		h.mu.Unlock()
		if len(removes) != 1 || removes[0] != tmpName {
			t.Fatalf("Remove calls = %v, want [%q]", removes, tmpName)
		}

		// Upload also rejects Win32 extended/device/UNC and mixed-backslash paths directly.
		for _, bad := range []string{`\\?\C:\Data\tmp`, `\\server\share\tmp`, `/tmp/..\C:\Data\tmp`} {
			if _, err := sess.Upload(t.Context(), bad, bytes.NewReader([]byte("x")), 1, nil, nil); !errors.Is(err, sftp.ErrInvalidRemotePath) {
				t.Errorf("Upload(%q) err = %v, want ErrInvalidRemotePath", bad, err)
			}
		}
	})
}
