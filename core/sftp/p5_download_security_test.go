package sftp

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
)

type syntheticFileInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (f syntheticFileInfo) Name() string       { return f.name }
func (f syntheticFileInfo) Size() int64        { return f.size }
func (f syntheticFileInfo) Mode() os.FileMode  { return f.mode }
func (f syntheticFileInfo) ModTime() time.Time { return time.Unix(1700000000, 0) }
func (f syntheticFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f syntheticFileInfo) Sys() any           { return nil }

type maliciousSFTPHandler struct {
	statInfos map[string]os.FileInfo
	dirLists  map[string][]os.FileInfo
	files     map[string][]byte
}

func (h *maliciousSFTPHandler) Fileread(r *pkgsftp.Request) (io.ReaderAt, error) {
	if data, ok := h.files[r.Filepath]; ok {
		return bytes.NewReader(data), nil
	}
	return bytes.NewReader([]byte("payload")), nil
}

func (h *maliciousSFTPHandler) Filewrite(*pkgsftp.Request) (io.WriterAt, error) {
	return nil, os.ErrPermission
}

func (h *maliciousSFTPHandler) Filecmd(*pkgsftp.Request) error {
	return os.ErrPermission
}

func (h *maliciousSFTPHandler) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	switch r.Method {
	case "Stat", "Lstat":
		if fi, ok := h.statInfos[r.Filepath]; ok {
			return customListerAt{fi}, nil
		}
		return nil, os.ErrNotExist
	case "List":
		if entries, ok := h.dirLists[r.Filepath]; ok {
			return customListerAt(entries), nil
		}
		return nil, os.ErrNotExist
	default:
		return nil, os.ErrInvalid
	}
}

func TestValidateLocalDownloadComponent(t *testing.T) {
	invalidCases := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "dot", input: "."},
		{name: "dotdot", input: ".."},
		{name: "posix traversal", input: "../escape"},
		{name: "forward slash", input: "a/b"},
		{name: "backslash traversal", input: `..\..\evil.txt`},
		{name: "single backslash", input: `a\b`},
		{name: "ntfs ads", input: "foo:ads"},
		{name: "ntfs zone identifier", input: "report.txt:Zone.Identifier"},
		{name: "windows drive prefix", input: "C:evil.txt"},
		{name: "windows drive bare", input: "C:"},
		{name: "reserved CON", input: "CON"},
		{name: "reserved con lower", input: "con"},
		{name: "reserved CON.txt", input: "CON.txt"},
		{name: "reserved con.tar.gz", input: "con.tar.gz"},
		{name: "reserved CON space dot", input: "CON .txt"},
		{name: "reserved PRN", input: "PRN"},
		{name: "reserved PRN.log", input: "prn.log"},
		{name: "reserved AUX", input: "AUX"},
		{name: "reserved AUX.bin", input: "aux.bin"},
		{name: "reserved NUL", input: "NUL"},
		{name: "reserved NUL.txt", input: "nul.txt"},
		{name: "reserved COM1", input: "COM1"},
		{name: "reserved COM9.dat", input: "com9.dat"},
		{name: "reserved LPT1", input: "LPT1"},
		{name: "reserved LPT9.out", input: "lpt9.out"},
		{name: "nul byte", input: "bad\x00name.txt"},
		{name: "newline", input: "bad\nname.txt"},
		{name: "carriage return", input: "bad\rname.txt"},
		{name: "tab", input: "bad\tname.txt"},
		{name: "escape char", input: "bad\x1bname.txt"},
		{name: "del char", input: "bad\x7fname.txt"},
		{name: "unicode c1 control", input: "bad\u0085name.txt"},
		{name: "asterisk", input: "bad*name.txt"},
		{name: "question mark", input: "bad?name.txt"},
		{name: "double quote", input: `bad"name.txt`},
		{name: "less than", input: "bad<name.txt"},
		{name: "greater than", input: "bad>name.txt"},
		{name: "pipe", input: "bad|name.txt"},
		{name: "trailing dot", input: "report."},
		{name: "trailing space", input: "report "},
		{name: "only dots", input: "..."},
		{name: "only spaces", input: "   "},
	}

	for _, tc := range invalidCases {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			if err := validateLocalDownloadComponent(tc.input); err == nil {
				t.Fatalf("validateLocalDownloadComponent(%q) = nil, want error", tc.input)
			}
		})
	}

	validCases := []string{
		"report.txt",
		".gitignore",
		".env.local",
		"..hidden",
		"my file (1).tar.gz",
		"console.txt",
		"COM10.txt",
		"LPT0.txt",
		"文档.txt",
		"a.b.c",
	}
	for _, input := range validCases {
		t.Run("allow_"+input, func(t *testing.T) {
			if err := validateLocalDownloadComponent(input); err != nil {
				t.Fatalf("validateLocalDownloadComponent(%q) unexpected error: %v", input, err)
			}
		})
	}
}

func TestRemoteRelativePath_Security(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		target  string
		want    string
		wantErr bool
	}{
		{name: "exact root", base: "/data", target: "/data", want: "."},
		{name: "valid nested", base: "/data", target: "/data/nested/dir/report.txt", want: "nested/dir/report.txt"},
		{name: "trailing slash on base", base: "/data/", target: "/data/nested/file.txt", want: "nested/file.txt"},
		{name: "dirty base with clean relative child", base: "/tmp/x/../data", target: "/tmp/x/../data/nested/ok.txt", want: "nested/ok.txt"},
		{name: "parent traversal escape", base: "/data", target: "/data/../escape", wantErr: true},
		{name: "nested dotdot collapse", base: "/data", target: "/data/sub/../escape", wantErr: true},
		{name: "root dotdot collapse", base: "/", target: "/sub/../escape", wantErr: true},
		{name: "windows backslash traversal", base: "/data", target: `/data/..\..\evil.txt`, wantErr: true},
		{name: "nested backslash traversal", base: "/data", target: `/data/sub/..\..\evil.txt`, wantErr: true},
		{name: "ntfs ads colon", base: "/data", target: "/data/sub/foo:ads", wantErr: true},
		{name: "windows reserved device name", base: "/data", target: "/data/sub/CON.txt", wantErr: true},
		{name: "windows reserved directory segment", base: "/data", target: "/data/NUL/file.txt", wantErr: true},
		{name: "control char nul", base: "/data", target: "/data/sub/bad\x00.txt", wantErr: true},
		{name: "control char newline", base: "/data", target: "/data/sub/bad\n.txt", wantErr: true},
		{name: "windows invalid wildcard", base: "/data", target: "/data/sub/bad*.txt", wantErr: true},
		{name: "trailing dot segment", base: "/data", target: "/data/sub/report.", wantErr: true},
		{name: "trailing space segment", base: "/data", target: "/data/sub/report ", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := remoteRelativePath(tc.base, tc.target)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("remoteRelativePath(%q, %q) = %q, nil; want error", tc.base, tc.target, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("remoteRelativePath(%q, %q) unexpected error: %v", tc.base, tc.target, err)
			}
			if got != tc.want {
				t.Fatalf("remoteRelativePath(%q, %q) = %q, want %q", tc.base, tc.target, got, tc.want)
			}
		})
	}
}

func TestEnsureLocalDestWithinDir(t *testing.T) {
	base := t.TempDir()
	inside := filepath.Join(base, "sub", "file.txt")
	outside := filepath.Join(filepath.Dir(base), "escape.txt")
	sibling := base + "-sibling"

	if err := ensureLocalDestWithinDir(base, inside, false); err != nil {
		t.Fatalf("expected child path to be allowed: %v", err)
	}
	if err := ensureLocalDestWithinDir(base, base, true); err != nil {
		t.Fatalf("expected root path to be allowed when allowEqual=true: %v", err)
	}
	if err := ensureLocalDestWithinDir(base, base, false); err == nil {
		t.Fatal("expected root path to be rejected when allowEqual=false")
	}
	if err := ensureLocalDestWithinDir(base, outside, false); err == nil {
		t.Fatal("expected parent escape path to be rejected")
	}
	if err := ensureLocalDestWithinDir(base, filepath.Join(sibling, "file.txt"), false); err == nil {
		t.Fatal("expected sibling prefix escape path to be rejected")
	}
}

func TestClient_Download_RejectsUnsafeRemoteFilenameIntoDir(t *testing.T) {
	unsafeNames := []struct {
		name       string
		remotePath string
	}{
		{name: "backslash_traversal", remotePath: `/remote/..\..\evil.txt`},
		{name: "ntfs_ads", remotePath: "/remote/foo:ads"},
		{name: "reserved_con_txt", remotePath: "/remote/CON.txt"},
		{name: "reserved_nul", remotePath: "/remote/nul"},
		{name: "control_char_newline", remotePath: "/remote/bad\nname.txt"},
		{name: "control_char_esc", remotePath: "/remote/bad\x1bname.txt"},
		{name: "windows_invalid_char", remotePath: "/remote/bad*name.txt"},
		{name: "trailing_dot", remotePath: "/remote/report."},
		{name: "trailing_space", remotePath: "/remote/report "},
		{name: "dotdot_path", remotePath: "/remote/.."},
		{name: "dot_path", remotePath: "/remote/."},
	}

	for _, tc := range unsafeNames {
		t.Run(tc.name, func(t *testing.T) {
			fi := syntheticFileInfo{name: tc.remotePath, size: 7, mode: 0o644}
			cleanRemote := path.Clean(tc.remotePath)
			handler := &maliciousSFTPHandler{
				statInfos: map[string]os.FileInfo{
					tc.remotePath: fi,
					cleanRemote:   fi,
				},
				files: map[string][]byte{
					tc.remotePath: []byte("payload"),
					cleanRemote:   []byte("payload"),
				},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})

			parent := t.TempDir()
			localDir := filepath.Join(parent, "downloads", "nested")
			if err := os.MkdirAll(localDir, 0o755); err != nil {
				t.Fatalf("mkdir localDir: %v", err)
			}

			err := client.Download(t.Context(), tc.remotePath, localDir, nil)
			if err == nil {
				t.Fatalf("Download(%q, %q) succeeded, want fail-closed error", tc.remotePath, localDir)
			}
			if !strings.Contains(err.Error(), "unsafe remote filename") {
				t.Fatalf("Download(%q) error = %v, want unsafe remote filename diagnostic", tc.remotePath, err)
			}

			entries, readErr := os.ReadDir(localDir)
			if readErr != nil {
				t.Fatalf("readdir localDir: %v", readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("localDir must remain empty after rejected download, got %d entries", len(entries))
			}
			if _, statErr := os.Lstat(filepath.Join(parent, "evil.txt")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("unexpected escaped file in parent dir: %v", statErr)
			}
		})
	}
}

func TestClient_DownloadDirectory_RejectsMaliciousRemoteEntries(t *testing.T) {
	tests := []struct {
		name     string
		dirLists map[string][]os.FileInfo
		stats    map[string]os.FileInfo
	}{
		{
			name: "dotdot_escape_at_root",
			stats: map[string]os.FileInfo{
				"/remote": syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					syntheticFileInfo{name: "../escape", size: 7, mode: 0o644},
				},
			},
		},
		{
			name: "dotdot_escape_inside_subdir",
			stats: map[string]os.FileInfo{
				"/remote":     syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
				"/remote/sub": syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
				},
				"/remote/sub": {
					syntheticFileInfo{name: "../escape", size: 7, mode: 0o644},
				},
			},
		},
		{
			name: "windows_backslash_traversal",
			stats: map[string]os.FileInfo{
				"/remote": syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					syntheticFileInfo{name: `..\..\evil.txt`, size: 7, mode: 0o644},
				},
			},
		},
		{
			name: "ntfs_ads_entry",
			stats: map[string]os.FileInfo{
				"/remote": syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					syntheticFileInfo{name: "foo:ads", size: 7, mode: 0o644},
				},
			},
		},
		{
			name: "windows_reserved_device_con_txt",
			stats: map[string]os.FileInfo{
				"/remote": syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					syntheticFileInfo{name: "CON.txt", size: 7, mode: 0o644},
				},
			},
		},
		{
			name: "control_char_entry",
			stats: map[string]os.FileInfo{
				"/remote": syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					syntheticFileInfo{name: "bad\x00.txt", size: 7, mode: 0o644},
				},
			},
		},
		{
			name: "windows_invalid_pipe_char",
			stats: map[string]os.FileInfo{
				"/remote": syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					syntheticFileInfo{name: "bad|name.txt", size: 7, mode: 0o644},
				},
			},
		},
		{
			name: "trailing_dot_and_space",
			stats: map[string]os.FileInfo{
				"/remote": syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					syntheticFileInfo{name: "trailing.", size: 7, mode: 0o644},
				},
			},
		},
		{
			name: "child_dot_slash_dotdot_file_collapses_to_root",
			stats: map[string]os.FileInfo{
				"/remote":     syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
				"/remote/sub": syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
				},
				"/remote/sub": {
					syntheticFileInfo{name: "./..", size: 7, mode: 0o644},
				},
			},
		},
		{
			name: "child_dot_slash_dotdot_dir_collapses_to_root",
			stats: map[string]os.FileInfo{
				"/remote":     syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
				"/remote/sub": syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
				},
				"/remote/sub": {
					syntheticFileInfo{name: "./..", mode: os.ModeDir | 0o755},
				},
			},
		},
		{
			name: "child_nested_traversal_collapses_to_root",
			stats: map[string]os.FileInfo{
				"/remote":     syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
				"/remote/sub": syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
				},
				"/remote/sub": {
					syntheticFileInfo{name: "../sub/..", size: 7, mode: 0o644},
				},
			},
		},
		{
			name: "non_directory_root_rejected",
			stats: map[string]os.FileInfo{
				"/remote": syntheticFileInfo{name: "remote", size: 7, mode: 0o644},
			},
			dirLists: map[string][]os.FileInfo{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := &maliciousSFTPHandler{
				statInfos: tc.stats,
				dirLists:  tc.dirLists,
				files:     map[string][]byte{},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})

			parent := t.TempDir()
			localDir := filepath.Join(parent, "a", "b")
			err := client.DownloadDirectory(t.Context(), "/remote", localDir, nil)
			if err == nil {
				t.Fatalf("DownloadDirectory succeeded for %s, want fail-closed error", tc.name)
			}

			for _, escaped := range []string{
				filepath.Join(parent, "escape"),
				filepath.Join(parent, "a", "escape"),
				filepath.Join(parent, "evil.txt"),
				filepath.Join(localDir, "escape"),
			} {
				if _, statErr := os.Lstat(escaped); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("unexpected file created at %q: %v", escaped, statErr)
				}
			}

			// Ensure nothing (including temp files such as b.xops.tmp.*) was written into filepath.Dir(localDir).
			parentEntries, readErr := os.ReadDir(filepath.Dir(localDir))
			if readErr != nil {
				t.Fatalf("readdir %q: %v", filepath.Dir(localDir), readErr)
			}
			for _, entry := range parentEntries {
				if entry.Name() != filepath.Base(localDir) {
					t.Fatalf("unexpected sibling entry %q created in %q outside download root", entry.Name(), filepath.Dir(localDir))
				}
			}
		})
	}
}

func TestClient_Download_ValidSingleAndNestedDownloads(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	if err := client.state.sftpClient.MkdirAll("/remote_valid/nested/deep"); err != nil {
		t.Fatalf("mkdir remote_valid: %v", err)
	}
	writeRemote := func(remotePath, content string) {
		t.Helper()
		f, err := client.state.sftpClient.Create(remotePath)
		if err != nil {
			t.Fatalf("create %q: %v", remotePath, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			_ = f.Close()
			t.Fatalf("write %q: %v", remotePath, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close %q: %v", remotePath, err)
		}
	}

	writeRemote("/remote_valid/console.txt", "root-console")
	writeRemote("/remote_valid/.gitignore", "hidden-ok")
	writeRemote("/remote_valid/nested/deep/report (1).log", "deep-log")

	// 1. Valid single-file download into existing directory.
	singleDstDir := t.TempDir()
	if err := client.Download(t.Context(), "/remote_valid/console.txt", singleDstDir, nil); err != nil {
		t.Fatalf("Download single file into dir failed: %v", err)
	}
	gotSingle, err := os.ReadFile(filepath.Join(singleDstDir, "console.txt"))
	if err != nil {
		t.Fatalf("read downloaded single file: %v", err)
	}
	if string(gotSingle) != "root-console" {
		t.Fatalf("single download content = %q, want %q", gotSingle, "root-console")
	}

	// 2. Valid recursive directory download with nested subdirectories.
	nestedDstDir := t.TempDir()
	if err := client.DownloadDirectory(t.Context(), "/remote_valid", nestedDstDir, nil); err != nil {
		t.Fatalf("DownloadDirectory valid nested failed: %v", err)
	}
	expected := map[string]string{
		filepath.Join(nestedDstDir, "console.txt"):                      "root-console",
		filepath.Join(nestedDstDir, ".gitignore"):                       "hidden-ok",
		filepath.Join(nestedDstDir, "nested", "deep", "report (1).log"): "deep-log",
	}
	for localFile, want := range expected {
		data, readErr := os.ReadFile(localFile)
		if readErr != nil {
			t.Fatalf("read %q: %v", localFile, readErr)
		}
		if string(data) != want {
			t.Fatalf("%q content = %q, want %q", localFile, data, want)
		}
	}
}
