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
	addr       string
	mu         sync.Mutex
	reqOrders  [][]string
	receivedIn bytes.Buffer
	shellReady chan struct{}
	subsysDone chan []byte
}

func startPhase2PTYServer(t *testing.T, ctx context.Context) *phase2PTYFixture {
	t.Helper()
	srvCtx, cancelSrv := context.WithCancel(ctx)
	listener, sshSrvCfg := startKeepAliveTestSSHServer(t)

	fix := &phase2PTYFixture{
		addr:       listener.Addr().String(),
		shellReady: make(chan struct{}, 4),
		subsysDone: make(chan []byte, 2),
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
		wg.Go(func() { f.serveChannel(ch, chReqs) })
	}
}

func (f *phase2PTYFixture) serveChannel(ch cryptoSSH.Channel, chReqs <-chan *cryptoSSH.Request) {
	defer func() { _ = ch.Close() }()
	var order []string
	defer func() {
		f.mu.Lock()
		f.reqOrders = append(f.reqOrders, slices.Clone(order))
		f.mu.Unlock()
	}()
	for req := range chReqs {
		order = append(order, req.Type)
		if f.handleChannelReq(ch, req) {
			return
		}
	}
}

func (f *phase2PTYFixture) handleChannelReq(ch cryptoSSH.Channel, req *cryptoSSH.Request) bool {
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
		f.subsysDone <- readChannelUntilSuffix(ch, []byte("DONE"))
		sendExitStatus(ch, 0)
		return true
	default:
		replyIfWanted(req, false)
		return false
	}
}

func (f *phase2PTYFixture) readShellUntilExit(ch cryptoSSH.Channel) {
	buf := make([]byte, 256)
	for {
		n, readErr := ch.Read(buf)
		if n > 0 {
			f.mu.Lock()
			f.receivedIn.Write(buf[:n])
			hasExit := bytes.Contains(f.receivedIn.Bytes(), []byte("EXIT\n"))
			f.mu.Unlock()
			if hasExit {
				sendExitStatus(ch, 0)
				return
			}
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
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
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

	<-fix.shellReady
	waitForRawTermios(slave, origTermios.Lflag)

	if _, err := master.Write([]byte{'~', 0x1a, '~', '#', '~', '.'}); err != nil {
		t.Fatalf("master.Write: %v", err)
	}
	select {
	case shellErr := <-done:
		if !errors.Is(shellErr, ErrEscapeDisconnect) {
			t.Fatalf("ShellWithIO after ~. returned error %v, want ErrEscapeDisconnect", shellErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ShellWithIO did not terminate on ~.")
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

	fix.mu.Lock()
	firstOrder := slices.Clone(fix.reqOrders[0])
	fix.mu.Unlock()
	if len(firstOrder) < 3 || !slices.Equal(firstOrder[:3], []string{"env", "pty-req", "shell"}) {
		t.Fatalf("unexpected PTY request order: %v", firstOrder)
	}
}

func waitForRawTermios(slave *os.File, origLflag uint32) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cur, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err == nil && cur.Lflag != origLflag {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertPhase2PTYShellEscapeNone(t *testing.T, ctx context.Context, fix *phase2PTYFixture) {
	master, slave := openPhase2TestPTY(t)
	if !term.IsTerminal(int(slave.Fd())) {
		t.Fatal("expected slave fd to be a terminal")
	}
	fix.mu.Lock()
	fix.receivedIn.Reset()
	fix.mu.Unlock()

	cli := fix.newClient(t, MustOptions(OptionEscapeChar, "none"), Environment{})
	done := make(chan error, 1)
	go func() {
		done <- cli.ShellWithIO(ctx, InteractiveIO{Stdin: slave, Stdout: io.Discard, Stderr: io.Discard})
	}()

	<-fix.shellReady
	time.Sleep(30 * time.Millisecond)
	if _, err := master.Write([]byte("~.EXIT\n")); err != nil {
		t.Fatalf("master.Write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ShellWithIO(EscapeChar=none) failed: %v", err)
	}
	fix.mu.Lock()
	gotRemote := fix.receivedIn.String()
	fix.mu.Unlock()
	if !strings.Contains(gotRemote, "~.EXIT") {
		t.Fatalf("expected ~. to reach remote shell under EscapeChar=none, got %q", gotRemote)
	}
}

func assertPhase2PTYSubsystemTransparency(t *testing.T, ctx context.Context, fix *phase2PTYFixture) {
	master, slave := openPhase2TestPTY(t)
	cli := fix.newClient(t, MustOptions(OptionEscapeChar, "~"), Environment{})

	done := make(chan error, 1)
	go func() {
		done <- cli.RunSubsystemWithIO(ctx, "tty-subsys", slave, io.Discard, io.Discard, true)
	}()

	time.Sleep(40 * time.Millisecond)
	payload := []byte("bin\r~.dataDONE")
	if _, err := master.Write(payload); err != nil {
		t.Fatalf("master.Write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("RunSubsystemWithIO(TTY) returned error: %v", err)
	}
	got := <-fix.subsysDone
	if !bytes.Equal(got, payload) {
		t.Fatalf("TTY subsystem altered binary stream: got %q, want %q", got, payload)
	}
}
