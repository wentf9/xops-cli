package sftpshell

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type p7W7bDirSetstatFileCmder struct {
	delegate pkgsftp.FileCmder
	lister   pkgsftp.FileLister
}

func (c p7W7bDirSetstatFileCmder) Filecmd(r *pkgsftp.Request) error {
	err := c.delegate.Filecmd(r)
	if errors.Is(err, os.ErrInvalid) && r.Method == "Setstat" && c.lister != nil {
		statReq := pkgsftp.NewRequest("Stat", r.Filepath)
		if _, statErr := c.lister.Filelist(statReq); statErr == nil {
			return nil
		}
	}
	return err
}

func (c p7W7bDirSetstatFileCmder) PosixRename(r *pkgsftp.Request) error {
	if pr, ok := c.delegate.(pkgsftp.PosixRenameFileCmder); ok {
		return pr.PosixRename(r)
	}
	return pkgsftp.ErrSSHFxOpUnsupported
}

func newP7W7bInMemShell(t *testing.T, remoteCwd, localCwd string) *Shell {
	t.Helper()
	handlers := pkgsftp.InMemHandler()
	handlers.FileCmd = p7W7bDirSetstatFileCmder{
		delegate: handlers.FileCmd,
		lister:   handlers.FileList,
	}
	return newP7W7bShellWithHandlers(t, handlers, remoteCwd, localCwd)
}

func newP7W7bShellWithHandlers(t *testing.T, handlers pkgsftp.Handlers, remoteCwd, localCwd string) *Shell {
	t.Helper()
	initTestI18n(t)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("create SSH signer: %v", err)
	}
	serverCfg := &cryptoSSH.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(serverConn net.Conn) {
				defer wg.Done()
				defer func() { _ = serverConn.Close() }()
				stop := context.AfterFunc(ctx, func() { _ = serverConn.Close() })
				defer stop()
				sConn, chans, reqs, srvErr := cryptoSSH.NewServerConn(serverConn, serverCfg)
				if srvErr != nil {
					return
				}
				defer func() { _ = sConn.Close() }()
				go cryptoSSH.DiscardRequests(reqs)
				for newCh := range chans {
					ch, chReqs, acceptChErr := newCh.Accept()
					if acceptChErr != nil {
						return
					}
					wg.Add(1)
					go func(c cryptoSSH.Channel, requests <-chan *cryptoSSH.Request) {
						defer wg.Done()
						defer func() { _ = c.Close() }()
						for req := range requests {
							if req.Type == "subsystem" && string(req.Payload) == string(cryptoSSH.Marshal(struct{ Name string }{"sftp"})) {
								_ = req.Reply(true, nil)
								srv := pkgsftp.NewRequestServer(c, handlers)
								_ = srv.Serve()
								_ = srv.Close()
								return
							}
							if req.WantReply {
								_ = req.Reply(false, nil)
							}
						}
					}(ch, chReqs)
				}
			}(conn)
		}
	}()

	rawSSH, err := cryptoSSH.Dial("tcp", ln.Addr().String(), &cryptoSSH.ClientConfig{
		User:            "test",
		HostKeyCallback: cryptoSSH.FixedHostKey(signer.PublicKey()),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		cancel()
		_ = ln.Close()
		wg.Wait()
		t.Fatalf("SSH dial: %v", err)
	}
	wrappedSSH := ssh.NewTestClientWithRaw(rawSSH, ssh.ConnectionConfig{})
	sftpCli, err := sftp.NewClient(ctx, wrappedSSH, sftp.WithForce(true))
	if err != nil {
		cancel()
		_ = wrappedSSH.Close()
		_ = ln.Close()
		wg.Wait()
		t.Fatalf("sftp.NewClient: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = sftpCli.Close()
		_ = wrappedSSH.Close()
		_ = ln.Close()
		wg.Wait()
	})

	return &Shell{
		client:         sftpCli,
		sshClient:      wrappedSSH,
		cwd:            remoteCwd,
		localCwd:       localCwd,
		stdin:          bytes.NewBuffer(nil),
		stdout:         &bytes.Buffer{},
		stderr:         &bytes.Buffer{},
		batch:          true,
		transferConfig: sftpCli.Config(),
	}
}

func requireShellSymlinkSupport(t *testing.T) {
	t.Helper()
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.Symlink("target", probe); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable on Windows without developer mode/privileges: %v", err)
		}
		t.Fatalf("create probe symlink: %v", err)
	}
}

// TestP7W7b_AB7M2_ResolvePathAndMultiSrcAndHostileGlob covers AB7-M2:
//   - Shell.resolvePath cleans absolute paths while preserving relative "." vs "/"
//   - resolveMultiSrc validates remote paths & basenames via sftp.ParseRemotePath / ParseRemoteName
//   - cp/mv with /work/a/b/.. cannot escape /sandbox/into to /sandbox
//   - cp/mv with .. or / into a directory fails closed
//   - expandRemote rejects hostile SFTP server glob entries ("x/..", "x/.", "/", control chars)
func TestP7W7b_AB7M2_ResolvePathAndMultiSrcAndHostileGlob(t *testing.T) {
	initTestI18n(t)
	t.Run("resolvePath_cleans_absolute_and_preserves_relative", testP7W7bAB7M2ResolvePath)
	t.Run("resolveMultiSrc_rejects_invalid_basenames_and_control_chars", testP7W7bAB7M2ResolveMultiSrc)
	t.Run("cp_and_mv_dirty_dotdot_never_escapes_sandbox_into", testP7W7bAB7M2CpMvDirtyDotDot)
	t.Run("expandRemote_rejects_hostile_server_glob_entries", testP7W7bAB7M2ExpandRemoteHostileGlob)
}

func testP7W7bAB7M2ResolvePath(t *testing.T) {
	t.Helper()
	cases := []struct {
		cwd  string
		in   string
		want string
	}{
		{cwd: "/work", in: "/work/a/b/..", want: "/work/a"},
		{cwd: "/work", in: "/work/..", want: "/"},
		{cwd: "/work", in: "///a//b/./c/", want: "/a/b/c"},
		{cwd: "/work", in: "/", want: "/"},
		{cwd: "/work", in: "sub/file.txt", want: "/work/sub/file.txt"},
		{cwd: ".", in: "..", want: ".."},
		{cwd: ".", in: ".", want: "."},
		{cwd: ".", in: "sub/file.txt", want: "sub/file.txt"},
	}
	for _, tc := range cases {
		s := &Shell{cwd: tc.cwd}
		if got := s.resolvePath(tc.in); got != tc.want {
			t.Fatalf("resolvePath(cwd=%q, %q) = %q, want %q", tc.cwd, tc.in, got, tc.want)
		}
	}
}

func testP7W7bAB7M2ResolveMultiSrc(t *testing.T) {
	t.Helper()
	badSrcs := []struct {
		name string
		src  string
	}{
		{name: "root", src: "/"},
		{name: "dot", src: "."},
		{name: "dotdot", src: ".."},
		{name: "nested_dotdot", src: "../.."},
		{name: "dirty_trailing_dotdot", src: "/work/a/b/.."},
		{name: "dirty_trailing_dot", src: "/work/a/b/."},
		{name: "empty", src: ""},
		{name: "nul_byte", src: "/work/a\x00b"},
		{name: "newline", src: "/work/a\nb"},
	}
	for _, tc := range badSrcs {
		t.Run("single_"+tc.name, func(t *testing.T) {
			got, err := resolveMultiSrc([]string{tc.src}, "/sandbox/into", true)
			if err == nil {
				t.Fatalf("resolveMultiSrc([%q], /sandbox/into, true) = %v, want error", tc.src, got)
			}
		})
		t.Run("multi_"+tc.name, func(t *testing.T) {
			got, err := resolveMultiSrc([]string{"/work/ok.txt", tc.src}, "/sandbox/into", true)
			if err == nil {
				t.Fatalf("resolveMultiSrc([ok, %q], /sandbox/into, true) = %v, want error", tc.src, got)
			}
		})
	}

	if _, err := resolveMultiSrc([]string{"/work/ok.txt"}, "/sandbox/\x00dst", false); err == nil {
		t.Fatal("resolveMultiSrc with control char dst succeeded, want error")
	}
	if _, err := resolveMultiSrc([]string{"/work/\nbad"}, "/sandbox/dst", false); err == nil {
		t.Fatal("resolveMultiSrc with control char src succeeded, want error")
	}
}

func testP7W7bAB7M2CpMvDirtyDotDot(t *testing.T) {
	t.Helper()
	sh := newP7W7bInMemShell(t, "/work", t.TempDir())
	raw := sh.client.SFTPClient()

	for _, dir := range []string{"/work/a/b", "/sandbox/into"} {
		if err := raw.MkdirAll(dir); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	f, err := raw.Create("/work/a/marker.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("from-a"))
	_ = f.Close()

	// cp -f /work/a/b/.. /sandbox/into must land inside /sandbox/into/a, NEVER /sandbox/marker.txt.
	if err := sh.handleCp(t.Context(), []string{"-f", "/work/a/b/..", "/sandbox/into"}); err != nil {
		t.Fatalf("handleCp(/work/a/b/.., /sandbox/into): %v", err)
	}
	if _, err := raw.Lstat("/sandbox/marker.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cp escaped /sandbox/into into /sandbox: Lstat(/sandbox/marker.txt) = %v", err)
	}
	copied, err := raw.Open("/sandbox/into/a/marker.txt")
	if err != nil {
		t.Fatalf("expected /sandbox/into/a/marker.txt, open err = %v", err)
	}
	data, _ := io.ReadAll(copied)
	_ = copied.Close()
	if string(data) != "from-a" {
		t.Fatalf("copied content = %q, want %q", string(data), "from-a")
	}

	// cp/mv of "/" or "/work/.." into a directory must fail closed.
	if err := sh.handleCp(t.Context(), []string{"-f", "/work/..", "/sandbox/into"}); err == nil {
		t.Fatal("handleCp(/work/.., /sandbox/into) succeeded, want fail-closed error")
	}
	if err := sh.handleMv(t.Context(), []string{"-f", "/", "/sandbox/into"}); err == nil {
		t.Fatal("handleMv(/, /sandbox/into) succeeded, want fail-closed error")
	}

	// Relative cwd="." with ".." must fail closed in both cp and mv.
	sh.cwd = "."
	if err := sh.handleCp(t.Context(), []string{"-f", "..", "/sandbox/into"}); err == nil {
		t.Fatal("handleCp(.., /sandbox/into) with cwd='.' succeeded, want fail-closed error")
	}
	if err := sh.handleMv(t.Context(), []string{"-f", "..", "/sandbox/into"}); err == nil {
		t.Fatal("handleMv(.., /sandbox/into) with cwd='.' succeeded, want fail-closed error")
	}
}

func testP7W7bAB7M2ExpandRemoteHostileGlob(t *testing.T) {
	t.Helper()
	for _, hostile := range []string{"x/..", "x/.", "/", "bad\nname"} {
		t.Run(strings.ReplaceAll(hostile, "\n", "_nl_"), func(t *testing.T) {
			handler := &p7ReproSFTPHandler{
				stats: map[string]os.FileInfo{
					"/remote":      p7ReproFileInfo{name: "remote", mode: os.ModeDir | 0o755},
					"/remote/safe": p7ReproFileInfo{name: "safe", mode: os.ModeDir | 0o755},
					"/sandbox":     p7ReproFileInfo{name: "sandbox", mode: os.ModeDir | 0o755},
				},
				dirLists: map[string][]os.FileInfo{
					"/remote/safe": {
						p7ReproFileInfo{name: "good.txt", size: 2, mode: 0o644},
						p7ReproFileInfo{name: hostile, mode: os.ModeDir | 0o755},
					},
				},
				files: map[string][]byte{
					"/remote/safe/good.txt": []byte("ok"),
				},
			}
			sh := newP7ReproSFTPShell(t, handler, "/remote/safe", t.TempDir())

			matches, err := sh.expandRemote(t.Context(), "/remote/safe/*")
			if !errors.Is(err, sftp.ErrInvalidRemoteName) {
				t.Fatalf("expandRemote(/remote/safe/*) with hostile %q = (%v, %v), want ErrInvalidRemoteName", hostile, matches, err)
			}
			if cpErr := sh.handleCp(t.Context(), []string{"-f", "/remote/safe/*", "/sandbox"}); !errors.Is(cpErr, sftp.ErrInvalidRemoteName) {
				t.Fatalf("handleCp with hostile glob %q = %v, want ErrInvalidRemoteName", hostile, cpErr)
			}
			if mvErr := sh.handleMv(t.Context(), []string{"-f", "/remote/safe/*", "/sandbox"}); !errors.Is(mvErr, sftp.ErrInvalidRemoteName) {
				t.Fatalf("handleMv with hostile glob %q = %v, want ErrInvalidRemoteName", hostile, mvErr)
			}
		})
	}
}

// TestP7W7b_AB7L2_HardenedCopyLocalDir covers AB7-L2:
//   - rejects copying a local directory into itself or any subdirectory (including via symlink alias)
//   - refuses pre-existing symlinks and non-directories at finalDst and any subdirectory
//   - sanitizes directory modes (stripping setuid/setgid/sticky), preserves restrictive 0700/0750,
//     and copies 0500 read-only directories by widening to 0700 during copy then restoring 0500
func TestP7W7b_AB7L2_HardenedCopyLocalDir(t *testing.T) {
	initTestI18n(t)
	t.Run("rejects_self_containment_before_creating_any_directory", testP7W7bAB7L2SelfContainment)
	t.Run("rejects_self_containment_via_symlink_alias", testP7W7bAB7L2SelfContainmentSymlink)
	t.Run("refuses_preexisting_symlinks_and_non_directories_at_root_and_subdir", testP7W7bAB7L2RefusesSymlinkAndNonDir)
	t.Run("sanitizes_directory_modes_and_preserves_readonly_0500", testP7W7bAB7L2SanitizesModesAndReadOnly)
}

func testP7W7bAB7L2SelfContainment(t *testing.T) {
	t.Helper()
	base := t.TempDir()
	srcDir := filepath.Join(base, "dir")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(srcDir, "a.txt"), []byte("alpha"))

	sh := &Shell{
		localCwd: base,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
		batch:    true,
	}

	if err := sh.handleLocalCp(t.Context(), []string{"-f", "dir", "dir"}); err == nil {
		t.Fatal("lcp -f dir dir succeeded, want self-containment error")
	}
	if _, err := os.Lstat(filepath.Join(srcDir, "dir")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dir/dir must not be created: %v", err)
	}

	if err := sh.handleLocalCp(t.Context(), []string{"-f", "dir", filepath.Join("dir", "sub")}); err == nil {
		t.Fatal("lcp -f dir dir/sub succeeded, want self-containment error")
	}
	if _, err := os.Lstat(filepath.Join(srcDir, "sub")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dir/sub must not be created: %v", err)
	}

	if err := copyLocalDir(srcDir, srcDir); err == nil {
		t.Fatal("copyLocalDir(dir, dir) succeeded, want error")
	}
	if err := copyLocalDir(srcDir, filepath.Join(srcDir, "nested", "deep")); err == nil {
		t.Fatal("copyLocalDir(dir, dir/nested/deep) succeeded, want error")
	}
	if _, err := os.Lstat(filepath.Join(srcDir, "nested")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dir/nested must not be created: %v", err)
	}

	// Prefix-sharing sibling directory ("dir2") MUST still succeed (no false positive).
	sibling := filepath.Join(base, "dir2")
	if err := copyLocalDir(srcDir, sibling); err != nil {
		t.Fatalf("copyLocalDir(dir, dir2) unexpectedly failed: %v", err)
	}
	if got := string(readTestFile(t, filepath.Join(sibling, "a.txt"))); got != "alpha" {
		t.Fatalf("dir2/a.txt = %q, want %q", got, "alpha")
	}
}

func testP7W7bAB7L2SelfContainmentSymlink(t *testing.T) {
	t.Helper()
	requireShellSymlinkSupport(t)
	base := t.TempDir()
	srcDir := filepath.Join(base, "dir")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(srcDir, "a.txt"), []byte("alpha"))
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(srcDir, alias); err != nil {
		t.Fatal(err)
	}

	if err := copyLocalDir(srcDir, filepath.Join(alias, "sub")); err == nil {
		t.Fatal("copyLocalDir(dir, alias/sub) succeeded, want self-containment error")
	}
	if _, err := os.Lstat(filepath.Join(srcDir, "sub")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dir/sub must not be created via symlink alias: %v", err)
	}
}

func testP7W7bAB7L2RefusesSymlinkAndNonDir(t *testing.T) {
	t.Helper()
	requireShellSymlinkSupport(t)
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	srcDir := filepath.Join(base, "src")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(srcDir, "sub", "payload.txt"), []byte("must-not-escape"))

	dstLink := filepath.Join(base, "dst_link")
	if err := os.Symlink(outside, dstLink); err != nil {
		t.Fatal(err)
	}
	sh := &Shell{
		localCwd: base,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
		batch:    true,
	}
	if err := sh.handleLocalCp(t.Context(), []string{"-f", "src", "dst_link"}); err == nil {
		t.Fatal("lcp -f src dst_link succeeded, want symlink rejection")
	}
	if err := copyLocalDir(srcDir, dstLink); err == nil {
		t.Fatal("copyLocalDir(src, dst_link) succeeded, want symlink rejection")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("outside must remain empty after top-level symlink rejection: entries=%d err=%v", len(entries), err)
	}

	dstDir := filepath.Join(base, "dst_dir")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dstDir, "sub")); err != nil {
		t.Fatal(err)
	}
	if err := copyLocalDir(srcDir, dstDir); err == nil {
		t.Fatal("copyLocalDir into dst_dir with symlinked sub succeeded, want symlink rejection")
	}
	entries, err = os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("outside must remain empty after subdir symlink rejection: entries=%d err=%v", len(entries), err)
	}

	fileDst := filepath.Join(base, "file_dst")
	writeTestFile(t, fileDst, []byte("existing-file"))
	if err := copyLocalDir(srcDir, fileDst); err == nil {
		t.Fatal("copyLocalDir onto regular file succeeded, want error")
	}
	dstWithFileSub := filepath.Join(base, "dst_file_sub")
	if err := os.MkdirAll(dstWithFileSub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dstWithFileSub, "sub"), []byte("blocker"))
	if err := copyLocalDir(srcDir, dstWithFileSub); err == nil {
		t.Fatal("copyLocalDir onto regular file subdir succeeded, want error")
	}
}

func testP7W7bAB7L2SanitizesModesAndReadOnly(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permission bits are not enforced on Windows")
	}

	base := t.TempDir()
	srcRO := filepath.Join(base, "src_ro")
	srcROSub := filepath.Join(srcRO, "sub_ro")
	if err := os.MkdirAll(srcROSub, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(srcRO, "root.txt"), []byte("root"))
	writeTestFile(t, filepath.Join(srcROSub, "child.txt"), []byte("child"))

	t.Cleanup(func() {
		_ = os.Chmod(srcRO, 0o700)
		_ = os.Chmod(srcROSub, 0o700)
	})
	if err := os.Chmod(srcROSub, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(srcRO, 0o500); err != nil {
		t.Fatal(err)
	}

	dstRO := filepath.Join(base, "dst_ro")
	t.Cleanup(func() {
		_ = os.Chmod(dstRO, 0o700)
		_ = os.Chmod(filepath.Join(dstRO, "sub_ro"), 0o700)
	})
	if err := copyLocalDir(srcRO, dstRO); err != nil {
		t.Fatalf("copyLocalDir on 0500 hierarchy failed: %v", err)
	}

	for _, p := range []string{dstRO, filepath.Join(dstRO, "sub_ro")} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("Lstat(%q): %v", p, err)
		}
		if fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			t.Fatalf("%q retained special bits: %v", p, fi.Mode())
		}
		if fi.Mode().Perm() != 0o500 {
			t.Fatalf("%q perm = %04o, want 0500", p, fi.Mode().Perm())
		}
	}
	if got := string(readTestFile(t, filepath.Join(dstRO, "sub_ro", "child.txt"))); got != "child" {
		t.Fatalf("copied child.txt = %q, want %q", got, "child")
	}

	srcSpecial := filepath.Join(base, "src_special")
	if err := os.Mkdir(srcSpecial, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(srcSpecial, os.ModeSticky|0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(srcSpecial, "f.txt"), []byte("ok"))

	dstSpecial := filepath.Join(base, "dst_special")
	if err := copyLocalDir(srcSpecial, dstSpecial); err != nil {
		t.Fatalf("copyLocalDir sticky 0700 failed: %v", err)
	}
	fi, err := os.Lstat(dstSpecial)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("dst_special retained special bits: %v", fi.Mode())
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dst_special perm = %04o, want 0700", fi.Mode().Perm())
	}
}

func TestP7W7b_AB7M1_PutTopLevelSymlinkDirectory(t *testing.T) {
	requireShellSymlinkSupport(t)
	base := t.TempDir()
	realDir := filepath.Join(base, "real_dir")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(realDir, "hello.txt"), []byte("hello-from-link"))
	if err := os.Symlink("hello.txt", filepath.Join(realDir, "inner_link")); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(base, "link_dir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}

	sh := newP7W7bInMemShell(t, "/remote", base)
	raw := sh.client.SFTPClient()
	if err := raw.MkdirAll("/remote"); err != nil {
		t.Fatal(err)
	}

	if err := sh.handlePut(t.Context(), []string{"link_dir", "/remote"}); err != nil {
		t.Fatalf("handlePut(link_dir, /remote) failed: %v", err)
	}
	f, err := raw.Open("/remote/link_dir/hello.txt")
	if err != nil {
		t.Fatalf("open uploaded /remote/link_dir/hello.txt: %v", err)
	}
	got, _ := io.ReadAll(f)
	_ = f.Close()
	if string(got) != "hello-from-link" {
		t.Fatalf("uploaded content = %q, want %q", string(got), "hello-from-link")
	}
	target, err := raw.ReadLink("/remote/link_dir/inner_link")
	if err != nil || target != "hello.txt" {
		t.Fatalf("uploaded inner_link target = (%q, %v), want %q", target, err, "hello.txt")
	}
}
