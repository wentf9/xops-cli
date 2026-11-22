//go:build linux

package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func openPhase2TestPTY(t *testing.T) (master *os.File, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0600)
	if err != nil {
		t.Fatalf("open /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("TIOCSPTLCK: %v", err)
	}
	ptsNum, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("TIOCGPTN: %v", err)
	}
	slave, err = os.OpenFile("/dev/pts/"+strconv.Itoa(ptsNum), os.O_RDWR|unix.O_NOCTTY, 0600)
	if err != nil {
		t.Fatalf("open /dev/pts/%d: %v", ptsNum, err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

type phase2PTYFixture struct {
	addr        string
	mu          sync.Mutex
	receivedIn  bytes.Buffer
	reqOrdersCh chan []string
	shellReady  chan struct{}
	subsysReady chan struct{}
	subsysDone  chan []byte
}

func startPhase2PTYServer(t *testing.T, ctx context.Context) *phase2PTYFixture {
	t.Helper()
	srvCtx, cancelSrv := context.WithCancel(ctx)
	listener, sshSrvCfg := startKeepAliveTestSSHServer(t)

	fix := &phase2PTYFixture{
		addr:        listener.Addr().String(),
		reqOrdersCh: make(chan []string, 8),
		shellReady:  make(chan struct{}, 4),
		subsysReady: make(chan struct{}, 4),
		subsysDone:  make(chan []byte, 2),
	}

	var serverGroup sync.WaitGroup
	t.Cleanup(func() {
		cancelSrv()
		_ = listener.Close()
		serverGroup.Wait()
	})

	serverGroup.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			serverGroup.Go(func() {
				fix.serveConn(srvCtx, conn, sshSrvCfg, &serverGroup)
			})
		}
	})
	return fix
}

func (f *phase2PTYFixture) serveConn(ctx context.Context, conn net.Conn, sshSrvCfg *cryptoSSH.ServerConfig, wg *sync.WaitGroup) {
	defer func() { _ = conn.Close() }()
	srvConn, chans, reqs, err := cryptoSSH.NewServerConn(conn, sshSrvCfg)
	if err != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = srvConn.Close() })
	defer stop()
	defer func() { _ = srvConn.Close() }()
	wg.Go(func() { cryptoSSH.DiscardRequests(reqs) })

	for newCh := range chans {
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		wg.Go(func() { f.serveChannel(ctx, ch, chReqs) })
	}
}

func (f *phase2PTYFixture) serveChannel(ctx context.Context, ch cryptoSSH.Channel, chReqs <-chan *cryptoSSH.Request) {
	var order []string
	defer func() {
		_ = ch.Close()
		select {
		case f.reqOrdersCh <- slices.Clone(order):
		case <-ctx.Done():
		}
	}()
	for req := range chReqs {
		order = append(order, req.Type)
		if f.handleChannelReq(ctx, ch, req) {
			return
		}
	}
}

func (f *phase2PTYFixture) handleChannelReq(ctx context.Context, ch cryptoSSH.Channel, req *cryptoSSH.Request) bool {
	switch req.Type {
	case "env", "pty-req", "window-change":
		replyIfWanted(req, true)
		return false
	case "shell":
		replyIfWanted(req, true)
		select {
		case f.shellReady <- struct{}{}:
		default:
		}
		f.readShellUntilExit(ch)
		return true
	case "subsystem":
		replyIfWanted(req, true)
		select {
		case f.subsysReady <- struct{}{}:
		default:
		}
		got := readChannelUntilSuffix(ch, []byte("DONE"))
		select {
		case f.subsysDone <- got:
		case <-ctx.Done():
		}
		sendExitStatus(ch, 0)
		return true
	default:
		replyIfWanted(req, false)
		return false
	}
}

func (f *phase2PTYFixture) appendReceivedIn(p []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.receivedIn.Write(p)
	return bytes.Contains(f.receivedIn.Bytes(), []byte("EXIT\n"))
}

func (f *phase2PTYFixture) resetReceivedIn() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.receivedIn.Reset()
}

func (f *phase2PTYFixture) receivedInString() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.receivedIn.String()
}

func (f *phase2PTYFixture) readShellUntilExit(ch cryptoSSH.Channel) {
	buf := make([]byte, 256)
	for {
		n, readErr := ch.Read(buf)
		if n > 0 && f.appendReceivedIn(buf[:n]) {
			sendExitStatus(ch, 0)
			return
		}
		if readErr != nil {
			return
		}
	}
}

func readChannelUntilSuffix(ch cryptoSSH.Channel, suffix []byte) []byte {
	var subBuf bytes.Buffer
	tmp := make([]byte, 256)
	for {
		n, readErr := ch.Read(tmp)
		if n > 0 {
			subBuf.Write(tmp[:n])
			if bytes.HasSuffix(subBuf.Bytes(), suffix) {
				break
			}
		}
		if readErr != nil {
			break
		}
	}
	return subBuf.Bytes()
}

func (f *phase2PTYFixture) newClient(t *testing.T, opts *Options, env Environment) *Client {
	t.Helper()
	conn, err := net.DialTimeout("tcp", f.addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw, chans, reqs, err := cryptoSSH.NewClientConn(conn, f.addr, &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password("test")},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	cli := newClient(cryptoSSH.NewClient(raw, chans, reqs), conn, &ClientConfig{
		Address: "pty-host.example",
		Options: opts,
	}, nil, "")
	cli.environment = sanitizeEnvironment(env)
	cli.handshakeTimeout = time.Second
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

func TestPhase2_PTYInteractive_EscapeCharSuspendChannelsAndEnvOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	fix := startPhase2PTYServer(t, ctx)

	t.Run("interactive shell supports ~^Z termios restore, ~# channel list, and ~. clean disconnect", func(t *testing.T) {
		assertPhase2PTYShellEscapes(t, ctx, fix)
	})
	t.Run("EscapeChar=none passes ~. through to remote PTY shell", func(t *testing.T) {
		assertPhase2PTYShellEscapeNone(t, ctx, fix)
	})
	t.Run("RunSubsystemWithIO with real TTY allocatePTY=true never filters ~.", func(t *testing.T) {
		assertPhase2PTYSubsystemTransparency(t, ctx, fix)
	})
}

func assertPhase2PTYShellEscapes(t *testing.T, ctx context.Context, fix *phase2PTYFixture) {
	master, slave := openPhase2TestPTY(t)
	origTermios, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatalf("TCGETS initial: %v", err)
	}

	var suspendChecked, suspendWasRestored atomic.Bool
	cli := fix.newClient(t, MustOptions(OptionSetEnv, "PTY_VAR=ok"), Environment{
		SuspendProcess: func() error {
			cur, gErr := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if gErr == nil && cur.Lflag == origTermios.Lflag {
				suspendWasRestored.Store(true)
			}
			suspendChecked.Store(true)
			return nil
		},
	})
	cli.trackForwardListener("local", "listening", "127.0.0.1:18080", "127.0.0.1:80")

	var localStderr bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- cli.ShellWithIO(ctx, InteractiveIO{Stdin: slave, Stdout: io.Discard, Stderr: &localStderr})
	}()

	waitSignal(t, ctx, fix.shellReady, done, "shellReady")
	waitForRawTermios(t, ctx, slave, origTermios.Lflag, done)

	if _, err := master.Write([]byte{'~', 0x1a, '~', '#', '~', '.'}); err != nil {
		t.Fatalf("master.Write: %v", err)
	}
	select {
	case shellErr := <-done:
		if !errors.Is(shellErr, ErrEscapeDisconnect) {
			t.Fatalf("ShellWithIO after ~. returned error %v, want ErrEscapeDisconnect", shellErr)
		}
	case <-ctx.Done():
		t.Fatalf("ShellWithIO did not terminate on ~.: %v", ctx.Err())
	}

	if !suspendChecked.Load() || !suspendWasRestored.Load() {
		t.Fatalf("expected ~^Z to restore termios before SuspendProcess: checked=%v restored=%v", suspendChecked.Load(), suspendWasRestored.Load())
	}
	afterTermios, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || afterTermios.Lflag != origTermios.Lflag {
		t.Fatalf("terminal state not restored after ShellWithIO: err=%v got=0x%x want=0x%x", err, afterTermios.Lflag, origTermios.Lflag)
	}
	outStr := localStderr.String()
	if !strings.Contains(outStr, "client-session (shell)") || !strings.Contains(outStr, "127.0.0.1:18080") || !strings.Contains(outStr, "Connection to pty-host.example closed.") {
		t.Fatalf("unexpected local escape output: %q", outStr)
	}

	firstOrder := waitReqOrder(t, ctx, fix.reqOrdersCh)
	if len(firstOrder) < 3 || !slices.Equal(firstOrder[:3], []string{"env", "pty-req", "shell"}) {
		t.Fatalf("unexpected PTY request order: %v", firstOrder)
	}
}

func waitSignal(t *testing.T, ctx context.Context, ch <-chan struct{}, done <-chan error, name string) {
	t.Helper()
	select {
	case <-ch:
	case err := <-done:
		t.Fatalf("session exited before %s: %v", name, err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s: %v", name, ctx.Err())
	}
}

func waitReqOrder(t *testing.T, ctx context.Context, ch <-chan []string) []string {
	t.Helper()
	select {
	case order := <-ch:
		return order
	case <-ctx.Done():
		t.Fatalf("timed out waiting for server channel request order: %v", ctx.Err())
		return nil
	}
}

func waitForRawTermios(t *testing.T, ctx context.Context, slave *os.File, origLflag uint32, done <-chan error) {
	t.Helper()
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		cur, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err == nil && cur.Lflag != origLflag &&
			cur.Lflag&(unix.ICANON|unix.ISIG|unix.ECHO) == 0 &&
			cur.Iflag&unix.ICRNL == 0 {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("session exited before raw termios: %v", err)
		case <-ctx.Done():
			t.Fatalf("timed out waiting for raw termios (origLflag=0x%x): %v", origLflag, ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertPhase2PTYShellEscapeNone(t *testing.T, ctx context.Context, fix *phase2PTYFixture) {
	master, slave := openPhase2TestPTY(t)
	if !term.IsTerminal(int(slave.Fd())) {
		t.Fatal("expected slave fd to be a terminal")
	}
	origTermios, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatalf("TCGETS initial: %v", err)
	}
	fix.resetReceivedIn()

	cli := fix.newClient(t, MustOptions(OptionEscapeChar, "none"), Environment{})
	done := make(chan error, 1)
	go func() {
		done <- cli.ShellWithIO(ctx, InteractiveIO{Stdin: slave, Stdout: io.Discard, Stderr: io.Discard})
	}()

	waitSignal(t, ctx, fix.shellReady, done, "shellReady")
	waitForRawTermios(t, ctx, slave, origTermios.Lflag, done)
	if _, err := master.Write([]byte("~.EXIT\n")); err != nil {
		t.Fatalf("master.Write: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ShellWithIO(EscapeChar=none) failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("ShellWithIO(EscapeChar=none) timed out: %v", ctx.Err())
	}
	_ = waitReqOrder(t, ctx, fix.reqOrdersCh)

	gotRemote := fix.receivedInString()
	if !strings.Contains(gotRemote, "~.EXIT") {
		t.Fatalf("expected ~. to reach remote shell under EscapeChar=none, got %q", gotRemote)
	}
}

func assertPhase2PTYSubsystemTransparency(t *testing.T, ctx context.Context, fix *phase2PTYFixture) {
	master, slave := openPhase2TestPTY(t)
	origTermios, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatalf("TCGETS initial: %v", err)
	}
	cli := fix.newClient(t, MustOptions(OptionEscapeChar, "~"), Environment{})

	done := make(chan error, 1)
	go func() {
		done <- cli.RunSubsystemWithIO(ctx, "tty-subsys", slave, io.Discard, io.Discard, true)
	}()

	waitSignal(t, ctx, fix.subsysReady, done, "subsysReady")
	waitForRawTermios(t, ctx, slave, origTermios.Lflag, done)
	payload := []byte("bin\r~.dataDONE")
	if _, err := master.Write(payload); err != nil {
		t.Fatalf("master.Write: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunSubsystemWithIO(TTY) returned error: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("RunSubsystemWithIO(TTY) timed out: %v", ctx.Err())
	}
	var got []byte
	select {
	case got = <-fix.subsysDone:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for subsystem output: %v", ctx.Err())
	}
	_ = waitReqOrder(t, ctx, fix.reqOrdersCh)
	if !bytes.Equal(got, payload) {
		t.Fatalf("TTY subsystem altered binary stream: got %q, want %q", got, payload)
	}
}
