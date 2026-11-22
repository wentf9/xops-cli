package remotefile

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/wentf9/xops-cli/core/sftp"
)

// TestP7W13a_AB13M1_IsRootPathAndValidateWindowsDrivePath verifies AB13-M1:
//   - IsRootPath returns true for Win32-trimmed drive roots ('C:\ ', '/C:/ ',
//     'C:\.', 'C:\...', '/C:/...', 'C:\::$DATA', '/tmp/../C:/ ').
//   - ValidateWindowsDrivePath rejects Windows drive paths containing NTFS ADS
//     (secondary ':') or Win32-ambiguous trailing '.' / ' ' components (before
//     or after Clean), wrapping sftp.ErrInvalidRemotePath.
//   - Non-drive POSIX paths ('/opt/file.', '/tmp/a:b', '/tmp/foo ', '/tmp/...')
//     and clean Windows drive paths are unaffected.
func TestP7W13a_AB13M1_IsRootPathAndValidateWindowsDrivePath(t *testing.T) {
	t.Run("isRootPath_win32_trimmed_drive_roots", func(t *testing.T) {
		roots := []string{
			`C:\ `,
			`/C:/ `,
			`C:\.`,
			`/C:/.`,
			`C:\...`,
			`/C:/...`,
			`C:\::$DATA`,
			`/C:/::$DATA`,
			`C:\:$DATA`,
			`//C:/ `,
			`//c:\...`,
			`/tmp/../C:/ `,
			`/tmp/../C:/...`,
			`/tmp/../c:\::$DATA`,
			`C:\ . .`,
			`C:\. `,
		}
		for _, r := range roots {
			if !IsRootPath(r) {
				t.Errorf("IsRootPath(%q) = false, want true", r)
			}
		}

		nonRoots := []string{
			`C:\Users\ops\app.log`,
			`/C:/temp/a.txt`,
			`/opt/file.`,
			`/tmp/a:b`,
			`/ `,
			`/...`,
			`/::$DATA`,
			`C:\..\D:\foo`,
		}
		for _, p := range nonRoots {
			if IsRootPath(p) {
				t.Errorf("IsRootPath(%q) = true, want false", p)
			}
		}
	})

	t.Run("validateWindowsDrivePath_rejects_ambiguous_drive_paths", func(t *testing.T) {
		rejected := []string{
			`C:\Protected\secret.env.`,
			`C:\Protected\secret.env `,
			`C:\Protected\secret.env:$DATA`,
			`C:\Protected\secret.env::$DATA`,
			`C:\Protected.\secret.env`,
			`C:\Protected.`,
			`C:\ `,
			`/C:/ `,
			`C:\...`,
			`/C:/...`,
			`C:\::$DATA`,
			`/C:/::$DATA`,
			`C:\foo.\..\bar`,
			`C:\foo:$DATA\..\bar`,
			`//C:/Protected/secret.env.`,
			`/tmp/../C:/Protected/secret.env:$DATA`,
			`/tmp/../C:/foo./../bar`,
			`/tmp/../c:\foo.\..\bar`,
			`C:\..\D:\foo`,
		}
		for _, p := range rejected {
			err := ValidateWindowsDrivePath(p)
			if !errors.Is(err, sftp.ErrInvalidRemotePath) {
				t.Errorf("ValidateWindowsDrivePath(%q) = %v, want ErrInvalidRemotePath", p, err)
			}
			if got, inErr := validateTransferInputPath(p); inErr == nil {
				t.Errorf("validateTransferInputPath(%q) = %q, nil; want error", p, got)
			}
		}
	})

	t.Run("validateWindowsDrivePath_preserves_clean_drive_and_posix_paths", func(t *testing.T) {
		accepted := []struct {
			in   string
			want string
		}{
			{`C:\Users\ops\app.log`, `/C:/Users/ops/app.log`},
			{`/C:/temp/a.txt`, `/C:/temp/a.txt`},
			{`C:\Users\Alice\.ssh\id_ed25519`, `/C:/Users/Alice/.ssh/id_ed25519`},
			{`/C:/Users/ops/my folder/v1.2.3.log`, `/C:/Users/ops/my folder/v1.2.3.log`},
			{`C:\Users\ops\sub\..\app.log`, `/C:/Users/ops/app.log`},
			{`/opt/file.`, `/opt/file.`},
			{`/tmp/a:b`, `/tmp/a:b`},
			{`/tmp/file `, `/tmp/file `},
			{`/tmp/...`, `/tmp/...`},
			{`/tmp/file:$DATA`, `/tmp/file:$DATA`},
		}
		for _, tc := range accepted {
			if err := ValidateWindowsDrivePath(tc.in); err != nil {
				t.Errorf("ValidateWindowsDrivePath(%q) unexpected error: %v", tc.in, err)
			}
			got, err := validateTransferInputPath(tc.in)
			if err != nil {
				t.Errorf("validateTransferInputPath(%q) unexpected error: %v", tc.in, err)
				continue
			}
			if got != tc.want {
				t.Errorf("validateTransferInputPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		}
		// Clean drive roots pass ValidateWindowsDrivePath (used for RealPath parent / stat)
		// while IsRootPath rejects them as transfer file targets.
		for _, root := range []string{`C:\`, `/C:`, `/C:/`, `C:\.`} {
			if err := ValidateWindowsDrivePath(root); err != nil {
				t.Errorf("ValidateWindowsDrivePath(%q) unexpected error: %v", root, err)
			}
			if !IsRootPath(root) {
				t.Errorf("IsRootPath(%q) = false, want true", root)
			}
		}
	})
}

// TestP7W13a_AB13M1_SessionOperationsRejectWin32Anomalies verifies Inspect,
// Upload, Commit, and Remove reject Win32 ADS and trailing dot/space drive
// paths on both direct input and server-returned RealPath resolution.
func TestP7W13a_AB13M1_SessionOperationsRejectWin32Anomalies(t *testing.T) {
	t.Run("inspect_rejects_win32_anomalous_realpath_and_symlink_to_drive", func(t *testing.T) {
		cases := []struct {
			name     string
			input    string
			realPath string
		}{
			{
				name:     "realpath_returns_trailing_dot_dir",
				input:    "/C:/Protected/secret.env",
				realPath: "/C:/Protected.",
			},
			{
				name:     "realpath_returns_ads_dir",
				input:    "/C:/Protected/secret.env",
				realPath: "/C:/Protected:$DATA",
			},
			{
				name:     "posix_symlink_resolving_to_drive_with_trailing_dot_file",
				input:    "/link/secret.env.",
				realPath: "/C:/Protected",
			},
			{
				name:     "posix_symlink_resolving_to_drive_with_ads_file",
				input:    "/link/secret.env:$DATA",
				realPath: "/C:/Protected",
			},
			{
				name:     "posix_symlink_resolving_to_drive_root_with_space_base",
				input:    "/link/ ",
				realPath: "/C:",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				h := &w11aHostileHandler{
					realPath: tc.realPath,
					stats: map[string]os.FileInfo{
						tc.realPath: w11aFileInfo{name: "dir", mode: os.ModeDir | 0o755},
					},
					lstats: map[string]os.FileInfo{
						tc.realPath + "/secret.env":       w11aFileInfo{name: "secret.env", size: 8, mode: 0o600},
						tc.realPath + "/secret.env.":      w11aFileInfo{name: "secret.env.", size: 8, mode: 0o600},
						tc.realPath + "/secret.env:$DATA": w11aFileInfo{name: "secret.env:$DATA", size: 8, mode: 0o600},
					},
				}
				sess := newW11aSession(t, h)
				meta, err := sess.Inspect(t.Context(), tc.input, false, false)
				if !errors.Is(err, sftp.ErrInvalidRemotePath) {
					t.Fatalf("Inspect(%q, realPath=%q) = (%+v, %v), want ErrInvalidRemotePath", tc.input, tc.realPath, meta, err)
				}
				if meta != (Metadata{}) {
					t.Fatalf("Inspect returned non-zero metadata: %+v", meta)
				}
			})
		}
	})

	t.Run("upload_commit_remove_reject_win32_drive_anomalies", func(t *testing.T) {
		h := &w11aHostileHandler{
			realPath: "/C:/Protected",
		}
		sess := newW11aSession(t, h)

		badPaths := []string{
			`/C:/Protected/secret.env.`,
			`/C:/Protected/secret.env `,
			`/C:/Protected/secret.env:$DATA`,
			`/C:/Protected/secret.env::$DATA`,
			`/C:/Protected./secret.env`,
			`/C:/ `,
			`/C:/...`,
			`/C:/::$DATA`,
		}
		for _, p := range badPaths {
			if _, err := sess.Upload(t.Context(), p, bytes.NewReader([]byte("x")), 1, nil, nil); !errors.Is(err, sftp.ErrInvalidRemotePath) {
				t.Errorf("Upload(%q) err = %v, want ErrInvalidRemotePath", p, err)
			}
			if _, err := sess.Commit(t.Context(), p, "/C:/Protected/ok.txt", false); !errors.Is(err, sftp.ErrInvalidRemotePath) {
				t.Errorf("Commit(tmp=%q) err = %v, want ErrInvalidRemotePath", p, err)
			}
			if err := sess.Remove(t.Context(), p); !errors.Is(err, sftp.ErrInvalidRemotePath) {
				t.Errorf("Remove(%q) err = %v, want ErrInvalidRemotePath", p, err)
			}
		}
		h.mu.Lock()
		removes := len(h.removeCalls)
		h.mu.Unlock()
		if removes != 0 {
			t.Fatalf("Remove issued %d calls on rejected paths, want 0", removes)
		}
	})

	t.Run("posix_trailing_dot_and_colon_still_inspect_cleanly", func(t *testing.T) {
		for _, p := range []string{"/opt/file.", "/tmp/a:b"} {
			dir := "/opt"
			base := "file."
			if p == "/tmp/a:b" {
				dir = "/tmp"
				base = "a:b"
			}
			h := &w11aHostileHandler{
				realPath: dir,
				stats: map[string]os.FileInfo{
					dir: w11aFileInfo{name: dir[1:], mode: os.ModeDir | 0o755},
				},
				lstats: map[string]os.FileInfo{
					p: w11aFileInfo{name: base, size: 10, mode: 0o644},
				},
			}
			sess := newW11aSession(t, h)
			meta, err := sess.Inspect(t.Context(), p, false, false)
			if err != nil {
				t.Fatalf("Inspect(%q) unexpected error: %v", p, err)
			}
			if meta.Path != p || meta.Size != 10 {
				t.Fatalf("Inspect(%q) = %+v, want Path=%q Size=10", p, meta, p)
			}
		}
	})
}
