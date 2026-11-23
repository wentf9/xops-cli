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

func newP7W18bRealFSShell(t *testing.T, remoteRoot, remoteCwd, localCwd string, force bool) *Shell {
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
						continue
					}
					wg.Add(1)
					go func(channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request) {
						defer wg.Done()
						defer func() { _ = channel.Close() }()
						for req := range requests {
							if req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
								_ = req.Reply(true, nil)
								srv, sftpErr := pkgsftp.NewServer(channel, pkgsftp.WithServerWorkingDirectory(remoteRoot))
								if sftpErr == nil {
									_ = srv.Serve()
									_ = srv.Close()
								}
								return
							}
							_ = req.Reply(false, nil)
						}
					}(ch, chReqs)
				}
			}(conn)
		}
	}()

	rawSSH, err := cryptoSSH.Dial("tcp", ln.Addr().String(), &cryptoSSH.ClientConfig{
		User:            "tester",
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
	sftpCli, err := sftp.NewClient(ctx, wrappedSSH, sftp.WithForce(force))
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
		stdin:          strings.NewReader(""),
		stdout:         io.Discard,
		stderr:         io.Discard,
		batch:          true,
		transferConfig: sftpCli.Config(),
	}
}

func createShellW18bSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable on Windows without privilege: %v", err)
		}
		t.Fatalf("os.Symlink(%q, %q): %v", target, link, err)
	}
}

func TestP7W18b_AB18M3_SftpShellPutExactTargetNoDoubleExpansion(t *testing.T) {
	t.Run("one_arg_put_rejects_same_named_remote_dir_without_double_expanding_or_clobbering", testP7W18bShellOneArgPutRejectsDir)
	t.Run("one_arg_put_rejects_same_named_dir_symlink_preserving_nested_dangling_symlink", testP7W18bShellOneArgPutRejectsDirSymlink)
	t.Run("multi_arg_put_rejects_same_named_dir_without_clobbering_nested_file", testP7W18bShellMultiArgPutRejectsDir)
	t.Run("two_arg_put_expands_once_and_honors_no_clobber_and_stops_on_double_nested_dir", testP7W18bShellTwoArgPutSingleExpand)
	t.Run("one_arg_put_directory_merges_without_double_nesting", testP7W18bShellOneArgPutDirMerge)
}

func shellRemotePOSIXPath(p string) string {
	s := filepath.ToSlash(p)
	if !strings.HasPrefix(s, "/") {
		return "/" + s
	}
	return s
}

func testP7W18bShellOneArgPutRejectsDir(t *testing.T) {
	for _, tc := range []struct {
		name        string
		noOverwrite bool
		force       bool
	}{
		{name: "no_clobber", noOverwrite: true, force: false},
		{name: "interactive", noOverwrite: false, force: false},
		{name: "force", noOverwrite: false, force: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remoteRoot := t.TempDir()
			localDir := t.TempDir()
			writeTestFile(t, filepath.Join(localDir, "app"), []byte("incoming-file"))

			workDir := filepath.Join(remoteRoot, "work")
			sameNamedDir := filepath.Join(workDir, "app")
			if err := os.MkdirAll(sameNamedDir, 0o700); err != nil {
				t.Fatal(err)
			}
			nestedFile := filepath.Join(sameNamedDir, "app")
			writeTestFile(t, nestedFile, []byte("nested-keep"))

			sh := newP7W18bRealFSShell(t, remoteRoot, shellRemotePOSIXPath(workDir), localDir, tc.force)
			sh.noOverwrite = tc.noOverwrite
			var stdout, stderr bytes.Buffer
			sh.stdout = &stdout
			sh.stderr = &stderr
			sh.stdin = strings.NewReader("y\n")
			sh.batch = false

			err := sh.handlePut(t.Context(), []string{"app"})
			if err == nil || !strings.Contains(err.Error(), "cannot overwrite remote directory") {
				t.Fatalf("handlePut(1-arg, %s) err = %v, want directory overwrite error", tc.name, err)
			}
			if strings.Contains(stdout.String(), "[y/N]") {
				t.Fatalf("handlePut(1-arg, %s) unexpectedly prompted to overwrite directory: %q", tc.name, stdout.String())
			}
			got, readErr := os.ReadFile(nestedFile)
			if readErr != nil || string(got) != "nested-keep" {
				t.Fatalf("nested file = (%q, %v), want untouched %q", string(got), readErr, "nested-keep")
			}
		})
	}
}

func testP7W18bShellOneArgPutRejectsDirSymlink(t *testing.T) {
	remoteRoot := t.TempDir()
	localDir := t.TempDir()
	writeTestFile(t, filepath.Join(localDir, "app"), []byte("incoming-file"))

	realTargetDir := filepath.Join(remoteRoot, "real_target")
	if err := os.MkdirAll(realTargetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	missingTarget := filepath.Join(remoteRoot, "missing_nested_target")
	nestedDangling := filepath.Join(realTargetDir, "app")
	createShellW18bSymlink(t, missingTarget, nestedDangling)

	workDir := filepath.Join(remoteRoot, "work")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(workDir, "app")
	createShellW18bSymlink(t, realTargetDir, dirLink)

	sh := newP7W18bRealFSShell(t, remoteRoot, shellRemotePOSIXPath(workDir), localDir, true)

	err := sh.handlePut(t.Context(), []string{"app"})
	if err == nil || !strings.Contains(err.Error(), "cannot overwrite remote directory") {
		t.Fatalf("handlePut over dir symlink err = %v, want directory overwrite error", err)
	}
	if info, lstatErr := os.Lstat(nestedDangling); lstatErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("nested dangling symlink was clobbered: info=%v err=%v", info, lstatErr)
	}
	if _, statErr := os.Lstat(missingTarget); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing target created: err=%v", statErr)
	}
}

func testP7W18bShellMultiArgPutRejectsDir(t *testing.T) {
	remoteRoot := t.TempDir()
	localDir := t.TempDir()
	writeTestFile(t, filepath.Join(localDir, "a.item"), []byte("a-body"))
	writeTestFile(t, filepath.Join(localDir, "b.item"), []byte("b-body"))

	workDir := filepath.Join(remoteRoot, "work")
	collisionDir := filepath.Join(workDir, "b.item")
	if err := os.MkdirAll(collisionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	nestedFile := filepath.Join(collisionDir, "b.item")
	writeTestFile(t, nestedFile, []byte("nested-b-keep"))

	remoteWork := shellRemotePOSIXPath(workDir)
	sh := newP7W18bRealFSShell(t, remoteRoot, remoteWork, localDir, true)

	err := sh.handlePut(t.Context(), []string{"*.item", remoteWork})
	if err == nil || !strings.Contains(err.Error(), "cannot overwrite remote directory") {
		t.Fatalf("multi-arg handlePut err = %v, want directory overwrite error", err)
	}
	got, readErr := os.ReadFile(nestedFile)
	if readErr != nil || string(got) != "nested-b-keep" {
		t.Fatalf("nested file = (%q, %v), want untouched %q", string(got), readErr, "nested-b-keep")
	}
}

func testP7W18bShellTwoArgPutSingleExpand(t *testing.T) {
	remoteRoot := t.TempDir()
	localDir := t.TempDir()
	writeTestFile(t, filepath.Join(localDir, "app"), []byte("incoming-file"))

	workDir := filepath.Join(remoteRoot, "work")
	level1 := filepath.Join(workDir, "app")
	if err := os.MkdirAll(level1, 0o700); err != nil {
		t.Fatal(err)
	}
	nestedFile := filepath.Join(level1, "app")
	writeTestFile(t, nestedFile, []byte("keep-level1-app"))

	remoteWork := shellRemotePOSIXPath(workDir)
	remoteLevel1 := shellRemotePOSIXPath(level1)

	// 1. 2-arg put into /work/app expands ONCE to /work/app/app and respects noOverwrite.
	shNoClobber := newP7W18bRealFSShell(t, remoteRoot, remoteWork, localDir, false)
	shNoClobber.noOverwrite = true
	if err := shNoClobber.handlePut(t.Context(), []string{"app", remoteLevel1}); err != nil {
		t.Fatalf("2-arg put -n failed: %v", err)
	}
	got, readErr := os.ReadFile(nestedFile)
	if readErr != nil || string(got) != "keep-level1-app" {
		t.Fatalf("2-arg put -n modified /work/app/app: got=%q err=%v", string(got), readErr)
	}

	// 2. If /work/app/app is itself a directory containing /work/app/app/app, 2-arg put fails closed (no 2nd/3rd expansion).
	if err := os.Remove(nestedFile); err != nil {
		t.Fatal(err)
	}
	level2 := filepath.Join(level1, "app")
	if err := os.MkdirAll(level2, 0o700); err != nil {
		t.Fatal(err)
	}
	level3File := filepath.Join(level2, "app")
	writeTestFile(t, level3File, []byte("keep-level3-app"))

	shForce := newP7W18bRealFSShell(t, remoteRoot, remoteWork, localDir, true)
	err := shForce.handlePut(t.Context(), []string{"app", remoteLevel1})
	if err == nil || !strings.Contains(err.Error(), "cannot overwrite remote directory") {
		t.Fatalf("2-arg put onto nested dir err = %v, want directory overwrite error", err)
	}
	got3, readErr3 := os.ReadFile(level3File)
	if readErr3 != nil || string(got3) != "keep-level3-app" {
		t.Fatalf("level3 file = (%q, %v), want untouched %q", string(got3), readErr3, "keep-level3-app")
	}
}

func testP7W18bShellOneArgPutDirMerge(t *testing.T) {
	remoteRoot := t.TempDir()
	localDir := t.TempDir()
	srcDir := filepath.Join(localDir, "mydir")
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(srcDir, "hello.txt"), []byte("hello-dir"))

	workDir := filepath.Join(remoteRoot, "work")
	existingRemoteDir := filepath.Join(workDir, "mydir")
	if err := os.MkdirAll(existingRemoteDir, 0o700); err != nil {
		t.Fatal(err)
	}

	sh := newP7W18bRealFSShell(t, remoteRoot, shellRemotePOSIXPath(workDir), localDir, true)
	if err := sh.handlePut(t.Context(), []string{"mydir"}); err != nil {
		t.Fatalf("1-arg put mydir failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(existingRemoteDir, "hello.txt"))
	if err != nil || string(got) != "hello-dir" {
		t.Fatalf("uploaded dir file = (%q, %v), want %q", string(got), err, "hello-dir")
	}
	if _, err := os.Lstat(filepath.Join(existingRemoteDir, "mydir")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("1-arg put directory double-nested into mydir/mydir: err=%v", err)
	}
}
