package sshenv

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestP1_WindowsAgentAFUnixStructuralSecurityInvariants parses agent_windows.go
// on every OS (including Linux CI) to guarantee the Windows AF_UNIX agent dial
// path cannot regress back to an unverified raw net.DialContext call.
func TestP1_WindowsAgentAFUnixStructuralSecurityInvariants(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "agent_windows.go", nil, 0)
	if err != nil {
		t.Fatalf("parse agent_windows.go failed: %v", err)
	}

	funcs := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
			funcs[fn.Name.Name] = fn
		}
	}

	collectCalls := func(fnName string) map[string]bool {
		t.Helper()
		fn := funcs[fnName]
		if fn == nil || fn.Body == nil {
			t.Fatalf("missing function %s in agent_windows.go", fnName)
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
				seen["."+fun.Sel.Name] = true
			}
			return true
		})
		return seen
	}

	platformCalls := collectCalls("platformDialAgent")
	for _, req := range []string{"dialWindowsNamedPipe", "dialWindowsAFUnixAgent"} {
		if !platformCalls[req] {
			t.Errorf("platformDialAgent must call %s (seen: %v)", req, platformCalls)
		}
	}

	dialCalls := collectCalls("dialWindowsAFUnixAgent")
	for _, req := range []string{
		"winsec.VerifyOwnerOnlySocketFile",
		".DialContext",
		"verifyWindowsAFUnixAgentPeer",
		".Close",
	} {
		if !dialCalls[req] {
			t.Errorf("dialWindowsAFUnixAgent must call %s (seen: %v)", req, dialCalls)
		}
	}

	peerCalls := collectCalls("verifyWindowsAFUnixAgentPeer")
	for _, req := range []string{
		".SyscallConn",
		".Control",
		"winsec.VerifyAFUnixPeerCurrentUser",
	} {
		if !peerCalls[req] {
			t.Errorf("verifyWindowsAFUnixAgentPeer must call %s (seen: %v)", req, peerCalls)
		}
	}
}

func TestP1_ProcessStdioConn_GracefulCloseSkipsPGIDSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix PGID signaling guard is Unix-only")
	}

	origProbe := probeControllingTTY
	probeControllingTTY = func() bool { return false }
	t.Cleanup(func() { probeControllingTTY = origProbe })

	var reapCalls atomic.Int32
	origHook := onUnixReapRemainingGroup
	onUnixReapRemainingGroup = func(int) {
		reapCalls.Add(1)
	}
	t.Cleanup(func() { onUnixReapRemainingGroup = origHook })

	// Child is actively running (blocking on stdin EOF) when Close() is invoked,
	// so alreadyExited is false at Close() entry, yet after stdin closes the child
	// exits cleanly with no surviving descendants. Close() must not signal -pgid.
	t.Setenv("XOPS_SSHENV_HELPER_MODE", "echo-with-stderr")
	rawConn, err := DialProxyCommandWithStderr(t.Context(), helperSubprocessCommand(t), io.Discard)
	if err != nil {
		t.Fatalf("DialProxyCommandWithStderr failed: %v", err)
	}
	if _, err := rawConn.Write([]byte("ping")); err != nil {
		_ = rawConn.Close()
		t.Fatalf("Write failed: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(rawConn, buf); err != nil {
		_ = rawConn.Close()
		t.Fatalf("ReadFull failed: %v", err)
	}
	if string(buf) != "ping" {
		_ = rawConn.Close()
		t.Fatalf("echoed = %q, want ping", buf)
	}

	if err := rawConn.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if got := reapCalls.Load(); got != 0 {
		t.Fatalf("reapRemainingGroup invoked %d times on graceful EOF exit (PGID reuse hazard), want 0", got)
	}
}

type cancelOnWriteWriter struct {
	cancel func()
	delay  time.Duration
	fired  atomic.Bool
}

func (w *cancelOnWriteWriter) Write(p []byte) (int, error) {
	if len(p) > 0 && w.fired.CompareAndSwap(false, true) {
		if w.delay > 0 {
			time.AfterFunc(w.delay, w.cancel)
		} else {
			w.cancel()
		}
	}
	return len(p), nil
}

func TestP1_RunLocalCommandWithIO_CanceledCleanExitSkipsPostReapPGIDSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix PGID signaling guard is Unix-only")
	}

	origProbe := probeControllingTTY
	probeControllingTTY = func() bool { return false }
	t.Cleanup(func() { probeControllingTTY = origProbe })

	var reapCalls atomic.Int32
	origHook := onUnixReapRemainingGroup
	onUnixReapRemainingGroup = func(int) {
		reapCalls.Add(1)
	}
	t.Cleanup(func() { onUnixReapRemainingGroup = origHook })

	// 1. Canceled child with NO surviving grandchildren: terminateTree kills the child,
	//    cmd.Wait() reaps it and closes the sentinel pipe, so cleanupAfterWait must NOT
	//    signal -pgid post-reap.
	ctxClean, cancelClean := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelClean()
	err := RunLocalCommandWithIO(ctxClean, `printf R; exec sleep 30`, &cancelOnWriteWriter{cancel: cancelClean, delay: 20 * time.Millisecond}, io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunLocalCommandWithIO(clean cancel) = %v, want context.Canceled", err)
	}
	if got := reapCalls.Load(); got != 0 {
		t.Fatalf("cleanupAfterWait invoked %d times when no descendants survived cancellation, want 0", got)
	}

	// 2. Canceled shell spawning a SIGTERM-ignoring grandchild that redirects stdio to /dev/null:
	//    leader exits on SIGTERM so cmd.Wait() finishes promptly while the grandchild still
	//    holds the sentinel FD open; cleanupAfterWait MUST reap the remaining process group.
	ctxOrphan, cancelOrphan := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelOrphan()
	err = RunLocalCommandWithIO(
		ctxOrphan,
		`(trap '' TERM; printf R; exec sleep 30 </dev/null >/dev/null 2>/dev/null) & exec sleep 30`,
		&cancelOnWriteWriter{cancel: cancelOrphan, delay: 30 * time.Millisecond},
		io.Discard,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunLocalCommandWithIO(orphan cancel) = %v, want context.Canceled", err)
	}
	if got := reapCalls.Load(); got != 1 {
		t.Fatalf("cleanupAfterWait invoked %d times for surviving SIGTERM-ignoring grandchild, want 1", got)
	}
}
