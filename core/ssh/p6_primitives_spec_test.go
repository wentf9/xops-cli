package ssh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
	cryptoSSH "golang.org/x/crypto/ssh"
)

const (
	p6HelperModeEnv = "XOPS_P6_LOCK_HELPER_MODE"
	p6HelperPathEnv = "XOPS_P6_LOCK_HELPER_PATH"
	p6HelperHostEnv = "XOPS_P6_LOCK_HELPER_HOST"
	p6HelperCntEnv  = "XOPS_P6_LOCK_HELPER_COUNT"
)

func p6NewTestKey(t *testing.T) cryptoSSH.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	key, err := cryptoSSH.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("cryptoSSH.NewPublicKey: %v", err)
	}
	return key
}

// TestP6Helper_CrossProcessLockWorker is invoked as a subprocess by P6 cross-process
// lock tests on Unix to exercise real OS-level flock(2) contention across processes.
func TestP6Helper_CrossProcessLockWorker(t *testing.T) {
	mode := os.Getenv(p6HelperModeEnv)
	if mode == "" {
		return
	}
	targetPath := os.Getenv(p6HelperPathEnv)
	if targetPath == "" {
		t.Fatalf("missing %s", p6HelperPathEnv)
	}

	switch mode {
	case "hold_kh_ex":
		lf, err := fsx.OpenLocked(targetPath, fsx.LockExclusive, false, fsx.OwnerOnlyPerm)
		if err != nil {
			t.Fatalf("fsx.OpenLocked(known_hosts): %v", err)
		}
		_, _ = fmt.Fprintln(os.Stdout, "LOCKED")
		// Wait for parent to close stdin before writing and unlocking.
		_, _ = io.ReadAll(os.Stdin)
		host := os.Getenv(p6HelperHostEnv)
		if host != "" {
			key := p6NewTestKey(t)
			line := fmt.Sprintf("%s %s", host, strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(key))))
			if _, seekErr := lf.Seek(0, io.SeekEnd); seekErr != nil {
				_ = lf.Close()
				t.Fatalf("seek known_hosts: %v", seekErr)
			}
			if _, err := lf.Write([]byte(line + "\n")); err != nil {
				_ = lf.Close()
				t.Fatalf("write known_hosts: %v", err)
			}
		}
		if err := lf.Close(); err != nil {
			t.Fatalf("close known_hosts lock: %v", err)
		}

	case "append_kh_batch":
		count, err := strconv.Atoi(os.Getenv(p6HelperCntEnv))
		if err != nil || count <= 0 {
			t.Fatalf("invalid count %q: %v", os.Getenv(p6HelperCntEnv), err)
		}
		prefix := os.Getenv(p6HelperHostEnv)
		key := p6NewTestKey(t)
		for i := range count {
			host := fmt.Sprintf("%s-%d.example.test:22", prefix, i)
			if err := appendKnownHost(targetPath, host, key, false); err != nil {
				t.Fatalf("appendKnownHost(%s): %v", host, err)
			}
		}

	case "hold_sock_dir":
		err := holdSocketDirLockForTest(targetPath, func() error {
			_, _ = fmt.Fprintln(os.Stdout, "LOCKED")
			_, _ = io.ReadAll(os.Stdin)
			return nil
		})
		if err != nil {
			t.Fatalf("holdSocketDirLockForTest: %v", err)
		}

	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

func startP6LockHelper(t *testing.T, mode, targetPath, host string) (*exec.Cmd, io.WriteCloser, *bufio.Reader) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestP6Helper_CrossProcessLockWorker$")
	cmd.Env = append(os.Environ(),
		p6HelperModeEnv+"="+mode,
		p6HelperPathEnv+"="+targetPath,
		p6HelperHostEnv+"="+host,
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper (%s): %v", mode, err)
	}
	reader := bufio.NewReader(stdout)
	lineCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		line, rErr := reader.ReadString('\n')
		if rErr != nil {
			errCh <- rErr
			return
		}
		lineCh <- strings.TrimSpace(line)
	}()
	select {
	case line := <-lineCh:
		if line != "LOCKED" {
			_ = stdin.Close()
			_ = cmd.Wait()
			t.Fatalf("helper(%s) printed %q, want LOCKED (stderr=%s)", mode, line, stderr.String())
		}
	case rErr := <-errCh:
		_ = stdin.Close()
		_ = cmd.Wait()
		t.Fatalf("helper(%s) failed before LOCKED: %v (stderr=%s)", mode, rErr, stderr.String())
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("helper(%s) timed out waiting for LOCKED (stderr=%s)", mode, stderr.String())
	}
	return cmd, stdin, reader
}

// --- Deliverable 1 (R6 / Finding 3.3): known_hosts cross-process lock, O_NOFOLLOW, regular-file, bounded read ---

func TestP6_3_3_KnownHosts_DevNullAndNonRegularRejection(t *testing.T) {
	t.Parallel()

	t.Run("dev_null_allowed_as_empty", p6TestKnownHostsDevNullEmpty)
	t.Run("directory_rejected_strict_and_lenient", p6TestKnownHostsDirectoryRejected)
	t.Run("dev_zero_rejected_without_hang_or_oom", p6TestKnownHostsDevZeroRejected)
	t.Run("fifo_rejected_without_blocking", p6TestKnownHostsFIFORejected)
	t.Run("symlinks_rejected_dangling_and_live", p6TestKnownHostsSymlinksRejected)
}

func p6TestKnownHostsDevNullEmpty(t *testing.T) {
	for _, devNull := range []string{os.DevNull, "/dev/null"} {
		db := newKnownHostsDB()
		if err := db.parseFileStrict(devNull); err != nil {
			t.Fatalf("parseFileStrict(%q) failed: %v", devNull, err)
		}
		if len(db.lines) != 0 {
			t.Fatalf("parseFileStrict(%q) loaded %d lines, want 0", devNull, len(db.lines))
		}
		db.parseFileLenient(devNull, nil)
		if len(db.lines) != 0 {
			t.Fatalf("parseFileLenient(%q) loaded %d lines, want 0", devNull, len(db.lines))
		}
	}
}

func p6TestKnownHostsDirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	db := newKnownHostsDB()
	if err := db.parseFileStrict(dir); err == nil {
		t.Fatalf("parseFileStrict(dir) unexpectedly succeeded")
	}
	db.parseFileLenient(dir, nil)
	if len(db.lines) != 0 {
		t.Fatalf("parseFileLenient(dir) loaded %d lines, want 0", len(db.lines))
	}
	if err := appendKnownHost(dir, "example.com:22", p6NewTestKey(t), false); err == nil {
		t.Fatalf("appendKnownHost(dir) unexpectedly succeeded")
	}
}

func p6TestKnownHostsDevZeroRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/dev/zero is Unix-specific")
	}
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skipf("/dev/zero unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		db := newKnownHostsDB()
		done <- db.parseFileStrict("/dev/zero")
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("parseFileStrict(/dev/zero) unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parseFileStrict(/dev/zero) hung")
	}

	lenientDone := make(chan struct{})
	go func() {
		defer close(lenientDone)
		db := newKnownHostsDB()
		db.parseFileLenient("/dev/zero", nil)
	}()
	select {
	case <-lenientDone:
	case <-time.After(2 * time.Second):
		t.Fatal("parseFileLenient(/dev/zero) hung")
	}

	env := fixtureEnvironment()
	env.HomeDir = t.TempDir()
	env.KnownHostsFile = filepath.Join(env.HomeDir, "known_hosts")
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })
	cfg := &ClientConfig{
		NodeID:  "zero",
		Address: "example.com",
		Port:    22,
		User:    "alice",
		Options: MustOptions(OptionUserKnownHostsFile, "/dev/zero", OptionGlobalKnownHostsFile, "none"),
	}
	if _, _, _, err := conn.openKnownHostsCallback("/dev/zero", cfg); err == nil {
		t.Fatal("openKnownHostsCallback(/dev/zero) unexpectedly succeeded")
	}
}

func p6TestKnownHostsFIFORejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mkfifo is Unix-specific")
	}
	mkfifoBin, lookErr := exec.LookPath("mkfifo")
	if lookErr != nil {
		t.Skipf("mkfifo binary unavailable: %v", lookErr)
	}
	fifoPath := filepath.Join(t.TempDir(), "kh.fifo")
	if out, err := exec.Command(mkfifoBin, "-m", "0600", fifoPath).CombinedOutput(); err != nil {
		t.Skipf("mkfifo unsupported (%v): %s", err, out)
	}
	key := p6NewTestKey(t)

	done := make(chan error, 1)
	go func() {
		db := newKnownHostsDB()
		if err := db.parseFileStrict(fifoPath); err == nil {
			done <- errors.New("parseFileStrict unexpectedly succeeded on FIFO")
			return
		}
		db.parseFileLenient(fifoPath, nil)
		if err := appendKnownHost(fifoPath, "fifo.example:22", key, false); err == nil {
			done <- errors.New("appendKnownHost unexpectedly succeeded on FIFO")
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO known_hosts operations blocked instead of failing immediately")
	}
}

func p6TestKnownHostsSymlinksRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
	dir := t.TempDir()
	key := p6NewTestKey(t)
	cfg := &ClientConfig{NodeID: "n", Address: "host.example", Port: 22, User: "u"}

	// Dangling symlink: must fail closed and never create target.
	danglingTarget := filepath.Join(dir, "dangling-target")
	danglingLink := filepath.Join(dir, "known_hosts_dangling")
	if err := os.Symlink(danglingTarget, danglingLink); err != nil {
		t.Skipf("os.Symlink unsupported: %v", err)
	}
	if err := appendKnownHost(danglingLink, "host.example:22", key, false); err == nil {
		t.Fatal("appendKnownHost succeeded on dangling symlink")
	}
	if _, err := os.Lstat(danglingTarget); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling symlink target was created (err=%v)", err)
	}
	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = danglingLink
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })
	if _, _, _, err := conn.openKnownHostsCallback("", cfg); err == nil {
		t.Fatal("openKnownHostsCallback succeeded on default dangling symlink known_hosts")
	}
	if _, err := os.Lstat(danglingTarget); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loadUserKnownHosts created dangling symlink target (err=%v)", err)
	}

	// Live symlink: must fail closed and never modify target.
	liveTarget := filepath.Join(dir, "victim.txt")
	orig := []byte("sensitive-original\n")
	if err := os.WriteFile(liveTarget, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	liveLink := filepath.Join(dir, "known_hosts_live")
	if err := os.Symlink(liveTarget, liveLink); err != nil {
		t.Fatal(err)
	}
	if err := appendKnownHost(liveLink, "host.example:22", key, false); err == nil {
		t.Fatal("appendKnownHost succeeded on live symlink")
	}
	if err := newKnownHostsDB().parseFileStrict(liveLink); err == nil {
		t.Fatal("parseFileStrict succeeded on live symlink")
	}
	env.KnownHostsFile = liveLink
	conn2 := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn2.CloseAll() })
	if _, _, _, err := conn2.openKnownHostsCallback("", cfg); err == nil {
		t.Fatal("openKnownHostsCallback succeeded on live default symlink known_hosts")
	}
	if _, _, _, err := conn2.openKnownHostsCallback(liveLink, cfg); err == nil {
		t.Fatal("openKnownHostsCallback succeeded on live UserKnownHostsFile symlink")
	}
	got, err := os.ReadFile(liveTarget)
	if err != nil || !bytes.Equal(got, orig) {
		t.Fatalf("live symlink target was modified: got=%q err=%v", got, err)
	}
}

type p6InfiniteCommentReader struct {
	chunk []byte
	pos   int
	reads int
}

func (r *p6InfiniteCommentReader) Read(p []byte) (int, error) {
	r.reads++
	n := 0
	for n < len(p) {
		copied := copy(p[n:], r.chunk[r.pos:])
		n += copied
		r.pos = (r.pos + copied) % len(r.chunk)
	}
	return n, nil
}

func p6WritePaddedKnownHostsFile(t *testing.T, path, header string, totalBytes int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(header); err != nil {
		t.Fatal(err)
	}
	padLine := []byte("#" + strings.Repeat("a", 1022) + "\n")
	remaining := int(totalBytes) - len(header)
	for remaining >= len(padLine) {
		if _, err := f.Write(padLine); err != nil {
			t.Fatal(err)
		}
		remaining -= len(padLine)
	}
	if remaining > 0 {
		tail := bytes.Repeat([]byte("a"), remaining)
		tail[0] = '#'
		if remaining > 1 {
			tail[remaining-1] = '\n'
		}
		if _, err := f.Write(tail); err != nil {
			t.Fatal(err)
		}
	}
}

func TestP6_3_3_KnownHosts_BoundedRead16MiB(t *testing.T) {
	t.Parallel()

	if maxKnownHostsFileBytes != 16<<20 {
		t.Fatalf("maxKnownHostsFileBytes = %d, want %d (16 MiB)", maxKnownHostsFileBytes, 16<<20)
	}

	dir := t.TempDir()
	key := p6NewTestKey(t)
	validLine := fmt.Sprintf("bounded.example %s\n", strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(key))))

	// 1. Exact 16 MiB regular file succeeds.
	exactPath := filepath.Join(dir, "exact_16mib")
	p6WritePaddedKnownHostsFile(t, exactPath, validLine, maxKnownHostsFileBytes)
	st, err := os.Stat(exactPath)
	if err != nil || st.Size() != maxKnownHostsFileBytes {
		t.Fatalf("exact file size = %d (err=%v), want %d", st.Size(), err, maxKnownHostsFileBytes)
	}
	dbExact := newKnownHostsDB()
	if err := dbExact.parseFileStrict(exactPath); err != nil {
		t.Fatalf("parseFileStrict(exact 16 MiB) failed: %v", err)
	}
	if err := dbExact.check("bounded.example:22", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, key); err != nil {
		t.Fatalf("expected valid host entry in exact 16 MiB file: %v", err)
	}

	// 2. 16 MiB + 1 byte regular file fails closed in strict mode and is skipped in lenient mode.
	overPath := filepath.Join(dir, "over_16mib")
	if err := os.WriteFile(overPath, []byte(validLine), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(overPath, maxKnownHostsFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := newKnownHostsDB().parseFileStrict(overPath); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("parseFileStrict(16 MiB+1) = %v, want exceeds maximum size error", err)
	}
	dbLenient := newKnownHostsDB()
	dbLenient.parseFileLenient(overPath, nil)
	if len(dbLenient.lines) != 0 {
		t.Fatalf("parseFileLenient(16 MiB+1) parsed %d lines, want 0 (skipped)", len(dbLenient.lines))
	}

	// 3. Streaming reader cap (LimitReader): infinite stream stops strictly at limit+1.
	const smallCap int64 = 4096
	inf := &p6InfiniteCommentReader{chunk: []byte("# comment line\n")}
	bounded := newBoundedKnownHostsReader(inf, smallCap)
	dbInf := newKnownHostsDB()
	if err := dbInf.readLines(bounded, "infinite", nil); err != nil {
		t.Fatalf("readLines on bounded infinite comments returned unexpected error: %v", err)
	}
	if !bounded.exceeded() || bounded.read != smallCap+1 {
		t.Fatalf("bounded reader read=%d exceeded=%v, want read=%d exceeded=true", bounded.read, bounded.exceeded(), smallCap+1)
	}
}

func TestP6_3_3_KnownHosts_CrossProcessFlockSerialization(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix flock(2) cross-process contention test")
	}

	t.Run("reader_waits_for_cross_process_writer_flock", func(t *testing.T) {
		dir := t.TempDir()
		khPath := filepath.Join(dir, "known_hosts")
		if err := os.WriteFile(khPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}

		cmd, stdin, _ := startP6LockHelper(t, "hold_kh_ex", khPath, "from-child.example")
		defer func() {
			_ = stdin.Close()
			_ = cmd.Wait()
		}()

		parseDone := make(chan error, 1)
		db := newKnownHostsDB()
		go func() {
			parseDone <- db.parseFileStrict(khPath)
		}()

		// While child process holds LOCK_EX, parent's LOCK_SH in parseFileStrict must block.
		select {
		case err := <-parseDone:
			t.Fatalf("parseFileStrict completed while child still held LOCK_EX (err=%v)", err)
		case <-time.After(120 * time.Millisecond):
		}

		// Signal child to write its host entry and release LOCK_EX.
		if err := stdin.Close(); err != nil {
			t.Fatalf("close helper stdin: %v", err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("helper failed: %v", err)
		}

		select {
		case err := <-parseDone:
			if err != nil {
				t.Fatalf("parseFileStrict failed after child released lock: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("parseFileStrict did not unblock after child released LOCK_EX")
		}

		if len(db.lines) != 1 {
			t.Fatalf("expected 1 entry written by child before unlock, got %d", len(db.lines))
		}
		if _, pinned := db.matchingHostKeyTypes(khAddr{host: "from-child.example", port: "22"}); len(pinned) != 1 {
			t.Fatalf("child entry not visible after flock handoff: pinned=%v", pinned)
		}
	})

	t.Run("concurrent_multi_process_appendKnownHost_no_corruption", func(t *testing.T) {
		dir := t.TempDir()
		khPath := filepath.Join(dir, "known_hosts")
		// Seed with a line missing a trailing newline to exercise re-stat under LOCK_EX.
		seedKey := p6NewTestKey(t)
		seedLine := fmt.Sprintf("seed.example %s", strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(seedKey))))
		if err := os.WriteFile(khPath, []byte(seedLine), 0o600); err != nil {
			t.Fatal(err)
		}

		exe, err := os.Executable()
		if err != nil {
			t.Fatalf("os.Executable: %v", err)
		}
		const procs = 4
		const perProc = 8
		var wg sync.WaitGroup
		errCh := make(chan error, procs)
		for p := range procs {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				cmd := exec.Command(exe, "-test.run=^TestP6Helper_CrossProcessLockWorker$")
				cmd.Env = append(os.Environ(),
					p6HelperModeEnv+"=append_kh_batch",
					p6HelperPathEnv+"="+khPath,
					fmt.Sprintf("%s=proc%d", p6HelperHostEnv, idx),
					fmt.Sprintf("%s=%d", p6HelperCntEnv, perProc),
				)
				if out, runErr := cmd.CombinedOutput(); runErr != nil {
					errCh <- fmt.Errorf("proc %d failed (%w): %s", idx, runErr, out)
				}
			}(p)
		}
		wg.Wait()
		close(errCh)
		for e := range errCh {
			t.Fatal(e)
		}

		db := newKnownHostsDB()
		if err := db.parseFileStrict(khPath); err != nil {
			t.Fatalf("parseFileStrict after concurrent multi-process appends failed: %v", err)
		}
		wantLines := 1 + procs*perProc
		if len(db.lines) != wantLines {
			t.Fatalf("got %d valid lines after concurrent appends, want %d", len(db.lines), wantLines)
		}
	})
}

func TestP6_3_3_WindowsKnownHostsLock_StructuralInvariants(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "../fsx/fsx_windows.go", nil, 0)
	if err != nil {
		t.Fatalf("parse ../fsx/fsx_windows.go: %v", err)
	}
	funcs := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
			funcs[fn.Name.Name] = fn
		}
	}

	assertCalls := func(fnName string, required ...string) {
		t.Helper()
		fn := funcs[fnName]
		if fn == nil || fn.Body == nil {
			t.Fatalf("missing function %s in core/fsx/fsx_windows.go", fnName)
		}
		seen := make(map[string]bool)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				seen[fun.Name] = true
			case *ast.SelectorExpr:
				if pkg, ok := fun.X.(*ast.Ident); ok {
					seen[pkg.Name+"."+fun.Sel.Name] = true
				}
			}
			return true
		})
		for _, req := range required {
			if !seen[req] {
				t.Errorf("%s in core/fsx/fsx_windows.go must call %s (seen: %v)", fnName, req, seen)
			}
		}
	}

	assertCalls("openExistingRegularForLockOS", "windows.CreateFile", "validateWindowsRegularHandle")
	assertCalls("validateWindowsRegularHandle", "windows.GetFileType", "windows.GetFileInformationByHandle")
	assertCalls("createExclusiveOS", "winsec.NewOwnerOnlySecurityDescriptor", "windows.CreateFile")
	assertCalls("lockFileOS", "windows.LockFileEx")
	assertCalls("unlockFileOS", "windows.UnlockFileEx")
}

// --- Deliverable 2 (R6 / Finding 4.6): Cross-process lock around stale Unix control socket replacement ---

func TestP6_4_6_ControlSocketDirLock_CrossProcessContention(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory flock(2) test")
	}

	sockDir := shortSocketDir(t)
	sockPath := filepath.Join(sockDir, "cm.sock")

	// Create a stale socket at sockPath.
	staleLn, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen stale socket: %v", err)
	}
	if unixLn, ok := staleLn.(*net.UnixListener); ok {
		unixLn.SetUnlinkOnClose(false)
	}
	if err := staleLn.Close(); err != nil {
		t.Fatalf("close stale socket: %v", err)
	}
	origFi, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatalf("Lstat stale socket: %v", err)
	}

	// Child holds exclusive flock on sockDir.
	cmd, stdin, _ := startP6LockHelper(t, "hold_sock_dir", sockPath, "")
	defer func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	}()

	// handleStaleControlSocket must block until child releases the directory lock.
	conn := newTestConnector(&testMuxProvider{})
	t.Cleanup(func() { _ = conn.CloseAll() })
	target := TargetContext{
		Host:    "192.0.2.1",
		Port:    22,
		User:    "alice",
		Control: &ControlConfig{Master: ControlMasterAuto, Path: sockPath},
	}
	planNode := connectionPlanNode{
		name:    "stale-lock",
		cfg:     &ClientConfig{NodeID: "stale-lock", Address: "192.0.2.1", Port: 22, User: "alice"},
		control: target.Control,
	}

	done := make(chan error, 1)
	go func() {
		_, hErr := conn.handleStaleControlSocket(t.Context(), planNode, sockPath, target, origFi)
		done <- hErr
	}()

	select {
	case hErr := <-done:
		t.Fatalf("handleStaleControlSocket returned while child still held directory lock (err=%v)", hErr)
	case <-time.After(120 * time.Millisecond):
	}

	if err := stdin.Close(); err != nil {
		t.Fatalf("close helper stdin: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper failed: %v", err)
	}

	select {
	case hErr := <-done:
		if hErr != nil {
			t.Fatalf("handleStaleControlSocket returned error: %v", hErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleStaleControlSocket did not unblock after directory lock release")
	}

	if _, statErr := os.Lstat(sockPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected stale socket to be unlinked after lock release, statErr=%v", statErr)
	}
}

func TestP6_4_6_StaleSocketConcurrentReplacement_NeverUnlinksLiveMaster(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket temp-link + directory flock replacement test")
	}

	for iter := range 8 {
		sockDir := shortSocketDir(t)
		sockPath := filepath.Join(sockDir, "race.sock")

		staleLn, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("iter %d listen stale socket: %v", iter, err)
		}
		if unixLn, ok := staleLn.(*net.UnixListener); ok {
			unixLn.SetUnlinkOnClose(false)
		}
		_ = staleLn.Close()
		origFi, err := os.Lstat(sockPath)
		if err != nil {
			t.Fatalf("iter %d Lstat stale socket: %v", iter, err)
		}

		const binders = 6
		const cleaners = 4
		start := make(chan struct{})
		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			winners   []*fsx.SocketSlot
			winnerFis []os.FileInfo
			otherErrs []error
			cleanErrs atomic.Int32
		)

		conn := newTestConnector(&testMuxProvider{})
		target := TargetContext{
			Host:    "192.0.2.1",
			Port:    22,
			User:    "alice",
			Control: &ControlConfig{Master: ControlMasterYes, Path: sockPath},
		}
		planNode := connectionPlanNode{
			name:    "race",
			cfg:     &ClientConfig{NodeID: "race", Address: "192.0.2.1", Port: 22, User: "alice"},
			control: target.Control,
		}

		for range binders {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				slot, bErr := bindAndLinkSocket(sockPath)
				mu.Lock()
				defer mu.Unlock()
				if bErr == nil {
					winners = append(winners, slot)
					winnerFis = append(winnerFis, slot.FileInfo())
				} else if !errors.Is(bErr, ErrMasterAlreadyExists) {
					otherErrs = append(otherErrs, bErr)
				}
			}()
		}
		for range cleaners {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				if _, hErr := conn.handleStaleControlSocket(ctx, planNode, sockPath, target, origFi); hErr != nil {
					cleanErrs.Add(1)
				}
			}()
		}

		close(start)
		wg.Wait()
		_ = conn.CloseAll()

		for _, slot := range winners {
			defer func(s *fsx.SocketSlot) { _ = s.Release() }(slot)
		}

		if len(otherErrs) > 0 {
			t.Fatalf("iter %d unexpected bind errors: %v", iter, otherErrs)
		}
		if cleanErrs.Load() != 0 {
			t.Fatalf("iter %d unexpected handleStaleControlSocket errors: %d", iter, cleanErrs.Load())
		}
		if len(winners) != 1 {
			t.Fatalf("iter %d expected exactly 1 winning master bind, got %d", iter, len(winners))
		}

		// The winning live socket MUST still exist on disk with matching inode and accept connections.
		currFi, statErr := os.Lstat(sockPath)
		if statErr != nil {
			t.Fatalf("iter %d winning live socket was unlinked: %v", iter, statErr)
		}
		if !os.SameFile(winnerFis[0], currFi) {
			t.Fatalf("iter %d on-disk socket inode does not match winning listener", iter)
		}
		c, dialErr := net.DialTimeout("unix", sockPath, time.Second)
		if dialErr != nil {
			t.Fatalf("iter %d winning live socket not dialable: %v", iter, dialErr)
		}
		_ = c.Close()
	}
}

// --- Deliverable 3 (R2): ParseRemoteForwardSpec colon-containing Unix sockets ---

func TestP6_R2_ParseRemoteForwardSpec_ColonUnixSocketsAndRoundTrip(t *testing.T) {
	t.Parallel()

	dynamicCases := []struct {
		name     string
		input    string
		wantPath string
		wantStr  string
	}{
		{
			name:     "quoted_colon_in_filename",
			input:    `"/tmp/app:1.sock"`,
			wantPath: "/tmp/app:1.sock",
			wantStr:  `"/tmp/app:1.sock"`,
		},
		{
			name:     "unquoted_colon_in_filename",
			input:    "/tmp/app:1.sock",
			wantPath: "/tmp/app:1.sock",
			wantStr:  `"/tmp/app:1.sock"`,
		},
		{
			name:     "quoted_colon_in_directory",
			input:    `"/tmp/a:b/c.sock"`,
			wantPath: "/tmp/a:b/c.sock",
			wantStr:  `"/tmp/a:b/c.sock"`,
		},
		{
			name:     "unquoted_colon_in_directory",
			input:    "/tmp/a:b/c.sock",
			wantPath: "/tmp/a:b/c.sock",
			wantStr:  `"/tmp/a:b/c.sock"`,
		},
		{
			name:     "unquoted_dot_relative_colon",
			input:    "./app:1.sock",
			wantPath: "./app:1.sock",
			wantStr:  `"./app:1.sock"`,
		},
		{
			name:     "unquoted_parent_relative_colon",
			input:    "../dir:2/app:3.sock",
			wantPath: "../dir:2/app:3.sock",
			wantStr:  `"../dir:2/app:3.sock"`,
		},
		{
			name:     "unquoted_tilde_colon",
			input:    "~/run:1/app:2.sock",
			wantPath: "~/run:1/app:2.sock",
			wantStr:  `"~/run:1/app:2.sock"`,
		},
		{
			name:     "unquoted_multi_colon_ipv6_name",
			input:    "/tmp/sock-2001:db8::1.sock",
			wantPath: "/tmp/sock-2001:db8::1.sock",
			wantStr:  `"/tmp/sock-2001:db8::1.sock"`,
		},
		{
			name:     "quoted_socket_resembling_sock_host_port",
			input:    `"/tmp/r.sock:127.0.0.1:80"`,
			wantPath: "/tmp/r.sock:127.0.0.1:80",
			wantStr:  `"/tmp/r.sock:127.0.0.1:80"`,
		},
		{
			name:     "quoted_socket_resembling_sock_sock",
			input:    `"/tmp/r.sock:/tmp/l.sock"`,
			wantPath: "/tmp/r.sock:/tmp/l.sock",
			wantStr:  `"/tmp/r.sock:/tmp/l.sock"`,
		},
		{
			name:     "quoted_socket_resembling_sock_port",
			input:    `"/tmp/remote.sock:1080"`,
			wantPath: "/tmp/remote.sock:1080",
			wantStr:  `"/tmp/remote.sock:1080"`,
		},
		{
			name:     "windows_drive_no_extra_colon_unquoted",
			input:    `C:\temp\a.sock`,
			wantPath: `C:\temp\a.sock`,
			wantStr:  `C:\temp\a.sock`,
		},
		{
			name:     "windows_drive_with_extra_colon_quoted",
			input:    `"C:\\temp\\app:1.sock"`,
			wantPath: `C:\temp\app:1.sock`,
			wantStr:  `"C:\\temp\\app:1.sock"`,
		},
		{
			name:     "unquoted_unclosed_bracket_with_colon",
			input:    "/tmp/a[b:1.sock",
			wantPath: "/tmp/a[b:1.sock",
			wantStr:  `"/tmp/a[b:1.sock"`,
		},
	}

	for _, tc := range dynamicCases {
		t.Run("dynamic_"+tc.name, func(t *testing.T) {
			spec, err := ParseRemoteForwardSpec(tc.input)
			if err != nil {
				t.Fatalf("ParseRemoteForwardSpec(%q) failed: %v", tc.input, err)
			}
			want := ForwardSpec{
				Bind:      ForwardEndpoint{SocketPath: tc.wantPath},
				IsDynamic: true,
				BindAddr:  tc.wantPath,
				DestAddr:  "",
			}
			if spec != want {
				t.Fatalf("ParseRemoteForwardSpec(%q) = %+v, want %+v", tc.input, spec, want)
			}
			if gotStr := spec.String(); gotStr != tc.wantStr {
				t.Fatalf("spec.String() for %q = %q, want %q", tc.input, gotStr, tc.wantStr)
			}
			reparsed, err := ParseRemoteForwardSpec(spec.String())
			if err != nil {
				t.Fatalf("round-trip ParseRemoteForwardSpec(%q) failed: %v", spec.String(), err)
			}
			if reparsed != spec {
				t.Fatalf("round-trip mismatch for %q: got %+v, want %+v", spec.String(), reparsed, spec)
			}
		})
	}

	// Verify explicit ForwardSpec struct round-trip from String() and 2-endpoint parity.
	p6AssertRemoteForwardTwoEndpointAndCLIRoundTrip(t)
}

func p6AssertRemoteForwardTwoEndpointAndCLIRoundTrip(t *testing.T) {
	t.Helper()

	for _, sockPath := range []string{"/tmp/app:1.sock", "/tmp/a:b/c.sock"} {
		spec := ForwardSpec{
			Bind:      ForwardEndpoint{SocketPath: sockPath},
			IsDynamic: true,
			BindAddr:  sockPath,
		}
		reparsed, err := ParseRemoteForwardSpec(spec.String())
		if err != nil || reparsed != spec {
			t.Fatalf("struct round-trip for %q: wire=%q got=(%+v, %v) want=%+v", sockPath, spec.String(), reparsed, err, spec)
		}
	}

	twoEndpointCases := []struct {
		input    string
		wantBind ForwardEndpoint
		wantDest ForwardEndpoint
	}{
		{
			input:    "8080:127.0.0.1:80",
			wantBind: ForwardEndpoint{Port: 8080},
			wantDest: ForwardEndpoint{Host: "127.0.0.1", Port: 80, HasHost: true},
		},
		{
			input:    "/tmp/r.sock:127.0.0.1:80",
			wantBind: ForwardEndpoint{SocketPath: "/tmp/r.sock"},
			wantDest: ForwardEndpoint{Host: "127.0.0.1", Port: 80, HasHost: true},
		},
		{
			input:    "/tmp/r.sock:/tmp/l.sock",
			wantBind: ForwardEndpoint{SocketPath: "/tmp/r.sock"},
			wantDest: ForwardEndpoint{SocketPath: "/tmp/l.sock"},
		},
		{
			input:    "/tmp/r.sock:./l.sock",
			wantBind: ForwardEndpoint{SocketPath: "/tmp/r.sock"},
			wantDest: ForwardEndpoint{SocketPath: "./l.sock"},
		},
		{
			input:    "/tmp/r.sock:../l.sock",
			wantBind: ForwardEndpoint{SocketPath: "/tmp/r.sock"},
			wantDest: ForwardEndpoint{SocketPath: "../l.sock"},
		},
		{
			input:    "/tmp/r.sock:~/l.sock",
			wantBind: ForwardEndpoint{SocketPath: "/tmp/r.sock"},
			wantDest: ForwardEndpoint{SocketPath: "~/l.sock"},
		},
		{
			input:    "127.0.0.1:8080:/tmp/l.sock",
			wantBind: ForwardEndpoint{Host: "127.0.0.1", Port: 8080, HasHost: true},
			wantDest: ForwardEndpoint{SocketPath: "/tmp/l.sock"},
		},
	}
	for _, tc := range twoEndpointCases {
		t.Run("two_endpoint_"+tc.input, func(t *testing.T) {
			spec, err := ParseRemoteForwardSpec(tc.input)
			if err != nil {
				t.Fatalf("ParseRemoteForwardSpec(%q) failed: %v", tc.input, err)
			}
			if spec.IsDynamic || spec.Bind != tc.wantBind || spec.Dest != tc.wantDest {
				t.Fatalf("ParseRemoteForwardSpec(%q) = %+v, want non-dynamic bind=%+v dest=%+v", tc.input, spec, tc.wantBind, tc.wantDest)
			}
			reparsed, err := ParseRemoteForwardSpec(spec.String())
			if err != nil || reparsed != spec {
				t.Fatalf("round-trip failed for %q: wire=%q got=(%+v, %v)", tc.input, spec.String(), reparsed, err)
			}
		})
	}

	if _, err := ParseRemoteForwardSpec("/tmp/remote.sock:1080"); err == nil {
		t.Fatal("expected error for unquoted /tmp/remote.sock:1080")
	}

	for _, raw := range []string{`"/tmp/app:1.sock" 127.0.0.1:80`, `8080 "/tmp/a:b/c.sock"`} {
		spec, err := ParseForwardSpec(raw)
		if err != nil {
			t.Fatalf("ParseForwardSpec(%q) failed: %v", raw, err)
		}
		reparsed, err := ParseForwardSpec(spec.String())
		if err != nil || reparsed != spec {
			t.Fatalf("ParseForwardSpec round-trip failed for %q: wire=%q got=(%+v, %v)", raw, spec.String(), reparsed, err)
		}
	}

	opts, err := ParseCLIOptions([]string{`RemoteForward="/tmp/app:1.sock"`, `RemoteForward=/tmp/a:b/c.sock`})
	if err != nil {
		t.Fatalf("ParseCLIOptions(RemoteForward colon sockets): %v", err)
	}
	projected := ProjectCLIOptions(opts)
	reparsedOpts, err := ParseCLIOptions(projected)
	if err != nil {
		t.Fatalf("re-ParseCLIOptions(%v): %v", projected, err)
	}
	if !opts.Equal(reparsedOpts) {
		t.Fatalf("CLI round-trip mismatch: got=%v want=%v", reparsedOpts.Map(), opts.Map())
	}
}

// --- Deliverable 4 (R3 / Finding 4.1): Converge OptionSpec capability metadata ---

func TestP6_4_1_OptionSpecCapabilityMetadataConvergence(t *testing.T) {
	t.Parallel()

	wantAllowList := map[string]bool{
		OptionPreferredAuthentications: true,
		OptionHostKeyAlgorithms:        true,
		OptionCiphers:                  true,
		OptionMACs:                     true,
		OptionKexAlgorithms:            true,
	}

	for _, spec := range RegisteredOptionSpecs() {
		p6AssertOptionSpecCapabilityMetadata(t, spec, wantAllowList[spec.CanonicalKey])
	}

	prefSpec, ok := LookupOptionSpec(OptionPreferredAuthentications)
	if !ok {
		t.Fatal("LookupOptionSpec(OptionPreferredAuthentications) failed")
	}
	if !slices.Equal(prefSpec.FailClosedTokens, []string{"gssapi-with-mic", "hostbased"}) {
		t.Fatalf("PreferredAuthentications FailClosedTokens = %v, want [gssapi-with-mic hostbased]", prefSpec.FailClosedTokens)
	}
	if _, err := ParseOption("non_allow_list_option", "raw,val", OptionSourceOpenSSHConfig); err == nil {
		t.Fatal("ParseOption(unknown) unexpectedly succeeded")
	}
	if _, err := ParseOption(OptionAddressFamily, "inet,inet6", OptionSourceOpenSSHConfig); err == nil {
		t.Fatal("ParseOption(AddressFamily, inet,inet6) unexpectedly succeeded")
	}

	p6AssertNoSwitchInSupportedListTokens(t)
}

func p6AssertOptionSpecCapabilityMetadata(t *testing.T, spec OptionSpec, wantAllow bool) {
	t.Helper()

	if spec.AllowList != wantAllow {
		t.Errorf("%s: AllowList=%v, want %v", spec.CanonicalKey, spec.AllowList, wantAllow)
	}
	if spec.AllowList != (spec.SupportedTokens != nil) {
		t.Errorf("%s: AllowList=%v disagrees with SupportedTokens!=nil (%v)", spec.CanonicalKey, spec.AllowList, spec.SupportedTokens != nil)
	}
	if len(spec.FailClosedTokens) > 0 && spec.SupportedTokens == nil {
		t.Errorf("%s: FailClosedTokens set without SupportedTokens", spec.CanonicalKey)
	}

	supported, failClosed, ok := supportedListTokens(spec.CanonicalKey)
	if ok != spec.AllowList {
		t.Errorf("supportedListTokens(%q) ok=%v, want %v", spec.CanonicalKey, ok, spec.AllowList)
		return
	}
	if !ok {
		return
	}

	direct := spec.SupportedTokens()
	if len(direct) == 0 {
		t.Fatalf("%s: SupportedTokens() returned empty slice", spec.CanonicalKey)
	}
	if !slices.Equal(supported, direct) {
		t.Errorf("%s: supportedListTokens mismatch: %v vs %v", spec.CanonicalKey, supported, direct)
	}
	if !slices.Equal(failClosed, spec.FailClosedTokens) {
		t.Errorf("%s: failClosed mismatch: %v vs %v", spec.CanonicalKey, failClosed, spec.FailClosedTokens)
	}

	saved := direct[0]
	direct[0] = "mutated-token"
	if got := spec.SupportedTokens()[0]; got != saved {
		t.Errorf("%s: SupportedTokens() returned aliased mutable slice (got %q, want %q)", spec.CanonicalKey, got, saved)
	}

	p6AssertOptionSpecTokenParsing(t, spec)
}

func p6AssertOptionSpecTokenParsing(t *testing.T, spec OptionSpec) {
	t.Helper()
	for _, tok := range spec.SupportedTokens() {
		if _, err := spec.Normalize(tok); err != nil {
			t.Errorf("%s: Normalize(%q) failed for declared SupportedToken: %v", spec.CanonicalKey, tok, err)
		}
		if parsed, err := ParseOption(spec.CanonicalKey, tok+",definitely-unsupported-openssh-token", OptionSourceOpenSSHConfig); err != nil || parsed.Normalized != tok {
			t.Errorf("%s: ParseOption(canonical, %q) = (%q, %v), want (%q, nil)", spec.CanonicalKey, tok, parsed.Normalized, err, tok)
		}
		if parsed, err := ParseOption(spec.OpenSSHName, tok+",definitely-unsupported-openssh-token", OptionSourceOpenSSHConfig); err != nil || parsed.Normalized != tok {
			t.Errorf("%s: ParseOption(openSSHName, %q) = (%q, %v), want (%q, nil)", spec.CanonicalKey, tok, parsed.Normalized, err, tok)
		}
	}
	for _, tok := range spec.FailClosedTokens {
		if _, err := spec.Normalize(tok); err != nil {
			t.Errorf("%s: Normalize(%q) failed for declared FailClosedToken: %v", spec.CanonicalKey, tok, err)
		}
		if parsed, err := ParseOption(spec.CanonicalKey, tok+",definitely-unsupported", OptionSourceOpenSSHConfig); err != nil || parsed.Normalized != tok {
			t.Errorf("%s: ParseOption(%q) = (%q, %v), want (%q, nil)", spec.CanonicalKey, tok, parsed.Normalized, err, tok)
		}
	}
}

func p6AssertNoSwitchInSupportedListTokens(t *testing.T) {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "ssh_options.go", nil, 0)
	if err != nil {
		t.Fatalf("parse ssh_options.go: %v", err)
	}
	var foundFunc bool
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "supportedListTokens" {
			continue
		}
		foundFunc = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, isSwitch := n.(*ast.SwitchStmt); isSwitch {
				t.Error("supportedListTokens in ssh_options.go must not contain a hardcoded switch; derive from OptionSpec.SupportedTokens/FailClosedTokens")
			}
			return true
		})
	}
	if !foundFunc {
		t.Fatal("supportedListTokens function not found in ssh_options.go")
	}
}
