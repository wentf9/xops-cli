//go:build linux || darwin || freebsd

package ssh

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// TestReviewPass3_H4_MuxProxyMasterOnlyAgentForwarding verifies Option B on Unix:
//   - (a) Master with AllowAgentForward=true, AgentSocket="/master.sock" + Passenger via
//     MUX_C_PROXY with a DIFFERENT IdentityAgent="/attacker.sock" -> remote auth-agent@openssh.com
//     dials ONLY Master's "/master.sock" and NEVER touches Passenger's "/attacker.sock";
//     also Passenger with ForwardAgent="yes", empty SSH_AUTH_SOCK, and DialAgent=nil still
//     requests Master's agent without registering any local router/lease on Passenger's sshClient,
//     whereas IdentityAgent="none" suppresses auth-agent-req@openssh.com;
//   - (b) Master with AllowAgentForward=true, AgentSocket="" (or DialAgent=nil, or AllowAgentForward=false)
//     cleanly rejects MUX_C_PROXY auth-agent-req@openssh.com;
//   - (c) A stalled passenger MUX_C_PROXY connection does NOT block Master's own shell/exec agent requests.
func TestReviewPass3_H4_MuxProxyMasterOnlyAgentForwarding(t *testing.T) {
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	loginPriv, loginPub := writeEd25519KeyFile(t, keyPath, "")

	masterAgentSock, _ := startInMemoryAgentListener(t, loginPriv)
	attackerPriv, _ := writeEd25519KeyFile(t, filepath.Join(dir, "attacker_ed25519"), "")
	attackerAgentSock, _ := startInMemoryAgentListener(t, attackerPriv)

	state := &phase3AgentServerState{hostSigner: fix.hostSigner, clientPub: loginPub}
	port := startPhase3ForwardAgentServer(t, state)

	var masterDials, attackerDials atomic.Int32
	baseEnv := fixtureEnvironment()
	baseEnv.HomeDir = dir

	masterEnv := baseEnv
	masterEnv.AgentSocket = masterAgentSock
	origMasterDial := masterEnv.DialAgent
	masterEnv.DialAgent = func(ctx context.Context, sock string) (net.Conn, error) {
		if sock != masterAgentSock {
			t.Errorf("master DialAgent called with unexpected socket %q, want %q", sock, masterAgentSock)
		}
		masterDials.Add(1)
		return origMasterDial(ctx, sock)
	}

	sockPath := filepath.Join(shortSocketDir(t), "p3-optb-master.sock")
	masterOpts := newPhase3TrustAllOptions(t, dir)
	_ = masterOpts.Set(OptionControlMaster, "yes")
	_ = masterOpts.Set(OptionControlPath, sockPath)
	_ = masterOpts.Set(OptionControlPersist, "yes")
	_ = masterOpts.Set(OptionForwardAgent, "yes")
	_ = masterOpts.Set(OptionIdentityAgent, masterAgentSock)

	masterConn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"m": {NodeID: "m", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "key", KeyPath: keyPath, Options: masterOpts},
	}}, WithEnvironment(masterEnv))
	t.Cleanup(func() { _ = masterConn.CloseAll() })

	masterCli, err := masterConn.Connect(t.Context(), "m")
	if err != nil {
		t.Fatalf("start ControlMaster failed: %v", err)
	}

	assertPass3PassengerUsesOnlyMasterAgent(t, dir, port, keyPath, sockPath, attackerAgentSock, baseEnv, &masterDials, &attackerDials)
	assertPass3PassengerWithoutLocalAgentSucceedsAndIdentityNoneSkips(t, dir, port, keyPath, sockPath, baseEnv, &masterDials)
	assertPass3MasterEmptyAgentRejectsProxy(t, dir, port, keyPath, loginPub, fix.hostSigner, baseEnv)
	assertPass3StalledPassengerDoesNotBlockMasterAgent(t, masterCli, sockPath, &masterDials)
}

func assertPass3PassengerUsesOnlyMasterAgent(
	t *testing.T,
	dir string,
	port int,
	keyPath, sockPath, attackerAgentSock string,
	baseEnv Environment,
	masterDials, attackerDials *atomic.Int32,
) {
	t.Helper()
	passengerEnv := baseEnv
	passengerEnv.AgentSocket = attackerAgentSock
	origDial := passengerEnv.DialAgent
	passengerEnv.DialAgent = func(ctx context.Context, sock string) (net.Conn, error) {
		attackerDials.Add(1)
		return origDial(ctx, sock)
	}

	proxyOpts := newPhase3TrustAllOptions(t, dir)
	_ = proxyOpts.Set(OptionControlMaster, "no")
	_ = proxyOpts.Set(OptionControlPath, sockPath)
	_ = proxyOpts.Set(OptionForwardAgent, "yes")
	_ = proxyOpts.Set(OptionIdentityAgent, attackerAgentSock)

	proxyConn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"m": {NodeID: "m", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "key", KeyPath: keyPath, Options: proxyOpts},
	}}, WithEnvironment(passengerEnv))
	defer func() { _ = proxyConn.CloseAll() }()

	beforePassengerDials := masterDials.Load()
	proxyCli, err := proxyConn.Connect(t.Context(), "m")
	if err != nil {
		t.Fatalf("connect passenger over MUX_C_PROXY failed: %v", err)
	}
	out, err := proxyCli.Run(t.Context(), "query-agent")
	if err != nil || !strings.Contains(out, "keys=1") {
		t.Fatalf("passenger Run(query-agent) = %q, err = %v", out, err)
	}
	if attackerDials.Load() != 0 {
		t.Fatalf("passenger attacker socket was dialed %d times, want 0", attackerDials.Load())
	}
	if masterDials.Load() != beforePassengerDials+1 {
		t.Fatalf("master agent socket dials = %d, want %d", masterDials.Load(), beforePassengerDials+1)
	}
	if _, loaded := sshAgentRouters.Load(proxyCli.sshClient); loaded {
		t.Fatal("passenger multiplexed proxy sshClient must not register an unused local agent router")
	}
}

func assertPass3PassengerWithoutLocalAgentSucceedsAndIdentityNoneSkips(
	t *testing.T,
	dir string,
	port int,
	keyPath, sockPath string,
	baseEnv Environment,
	masterDials *atomic.Int32,
) {
	t.Helper()
	// Passenger with NO local SSH_AUTH_SOCK and DialAgent == nil still forwards Master's agent when -A / ForwardAgent=yes!
	noLocalAgentEnv := baseEnv
	noLocalAgentEnv.AgentSocket = ""
	noLocalAgentEnv.DialAgent = nil

	proxyOpts := newPhase3TrustAllOptions(t, dir)
	_ = proxyOpts.Set(OptionControlMaster, "no")
	_ = proxyOpts.Set(OptionControlPath, sockPath)
	_ = proxyOpts.Set(OptionForwardAgent, "yes")

	proxyConn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"m": {NodeID: "m", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "key", KeyPath: keyPath, Options: proxyOpts},
	}}, WithEnvironment(noLocalAgentEnv))
	defer func() { _ = proxyConn.CloseAll() }()

	proxyCli, err := proxyConn.Connect(t.Context(), "m")
	if err != nil {
		t.Fatalf("connect agentless passenger over MUX_C_PROXY failed: %v", err)
	}
	before := masterDials.Load()
	out, err := proxyCli.Run(t.Context(), "query-agent")
	if err != nil || !strings.Contains(out, "keys=1") {
		t.Fatalf("agentless passenger Run(query-agent) = %q, err = %v", out, err)
	}
	if masterDials.Load() != before+1 {
		t.Fatalf("masterDials = %d, want %d", masterDials.Load(), before+1)
	}

	// Passenger with ForwardAgent=yes + IdentityAgent=none must NOT request agent forwarding.
	noneOpts := newPhase3TrustAllOptions(t, dir)
	_ = noneOpts.Set(OptionControlMaster, "no")
	_ = noneOpts.Set(OptionControlPath, sockPath)
	_ = noneOpts.Set(OptionForwardAgent, "yes")
	_ = noneOpts.Set(OptionIdentityAgent, "none")

	noneConn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"m": {NodeID: "m", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "key", KeyPath: keyPath, Options: noneOpts},
	}}, WithEnvironment(baseEnv))
	defer func() { _ = noneConn.CloseAll() }()

	noneCli, err := noneConn.Connect(t.Context(), "m")
	if err != nil {
		t.Fatalf("connect IdentityAgent=none passenger failed: %v", err)
	}
	noneOut, _ := noneCli.Run(t.Context(), "query-agent")
	if !strings.Contains(noneOut, "no-agent-req") {
		t.Fatalf("expected IdentityAgent=none passenger to skip auth-agent-req, got %q", noneOut)
	}
}

func assertPass3MasterEmptyAgentRejectsProxy(
	t *testing.T,
	dir string,
	port int,
	keyPath string,
	loginPub cryptoSSH.PublicKey,
	hostSigner cryptoSSH.Signer,
	baseEnv Environment,
) {
	t.Helper()
	// Start a dedicated MuxServer with AllowAgentForward: true but AgentSocket: ""!
	privBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.ParsePrivateKey(privBytes)
	if err != nil {
		t.Fatal(err)
	}
	rawTCP, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rawTCP.Close() }()

	sshCfg := &cryptoSSH.ClientConfig{
		User:            "alice",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.PublicKeys(signer)},
		HostKeyCallback: cryptoSSH.FixedHostKey(hostSigner.PublicKey()),
	}
	cConn, chans, reqs, err := cryptoSSH.NewClientConn(rawTCP, "127.0.0.1", sshCfg)
	if err != nil {
		t.Fatal(err)
	}
	rawMasterSSH := cryptoSSH.NewClient(cConn, chans, reqs)
	defer func() { _ = rawMasterSSH.Close() }()
	_ = loginPub

	emptySockPath := filepath.Join(shortSocketDir(t), "p3-empty-agent.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:       emptySockPath,
		SSHClient:         rawMasterSSH,
		RootConn:          rawTCP,
		PersistEnabled:    true,
		PersistIndefinite: true,
		AllowAgentForward: true,
		AgentSocket:       "", // Master has AllowAgentForward=true but NO agent socket!
		DialAgent:         baseEnv.DialAgent,
	})
	if err != nil {
		t.Fatalf("NewMuxServer(empty AgentSocket): %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	go func() { _ = srv.Serve() }()

	proxySSH, _, err := DialControlProxy(t.Context(), emptySockPath, TargetContext{
		Host: "127.0.0.1",
		Port: port,
		User: "alice",
	})
	if err != nil {
		t.Fatalf("DialControlProxy: %v", err)
	}
	defer func() { _ = proxySSH.Close() }()

	sess, err := proxySSH.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = sess.Close() }()

	accepted, reqErr := sess.SendRequest(agentForwardRequestType, true, nil)
	if reqErr != nil || accepted {
		t.Fatalf("expected Master with AgentSocket=\"\" to reject MUX_C_PROXY auth-agent-req, got accepted=%v err=%v", accepted, reqErr)
	}
}

func assertPass3StalledPassengerDoesNotBlockMasterAgent(
	t *testing.T,
	masterCli *Client,
	sockPath string,
	masterDials *atomic.Int32,
) {
	t.Helper()
	// Connect a raw MUX_C_PROXY passenger that opens a session, requests auth-agent-req@openssh.com,
	// starts "hold-open", and then NEVER reads from its unix control socket again!
	stalledConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial control socket for stalled passenger: %v", err)
	}
	defer func() { _ = stalledConn.Close() }()

	if err := performClientMuxHandshake(stalledConn); err != nil {
		t.Fatalf("stalled passenger handshake: %v", err)
	}
	w := newMuxWriter()
	w.WriteUint32(77) // RequestID
	if err := WriteMuxPacket(stalledConn, MUX_C_PROXY, w.Bytes()); err != nil {
		t.Fatalf("WriteMuxPacket(MUX_C_PROXY): %v", err)
	}
	pktType, _, err := ReadMuxPacket(stalledConn)
	if err != nil || pktType != MUX_S_PROXY {
		t.Fatalf("MUX_C_PROXY reply = (0x%x, %v), want MUX_S_PROXY", pktType, err)
	}
	// Discard initial hostkeys-00@openssh.com global request packet, open a session channel,
	// send auth-agent-req@openssh.com + exec "hold-open", then stop reading stalledConn completely!
	if _, err := readUnpaddedPacket(stalledConn); err != nil {
		t.Fatalf("read initial proxy packet: %v", err)
	}
	openW := newMuxWriter()
	openW.buf = append(openW.buf, msgChannelOpen)
	openW.WriteString("session")
	openW.WriteUint32(1) // clientChID
	openW.WriteUint32(65536)
	openW.WriteUint32(32768)
	if err := writeUnpaddedPacket(stalledConn, openW.Bytes()); err != nil {
		t.Fatalf("write msgChannelOpen: %v", err)
	}
	openConf, err := readUnpaddedPacket(stalledConn)
	if err != nil || len(openConf) == 0 || openConf[0] != msgChannelOpenConfirmation {
		t.Fatalf("expected msgChannelOpenConfirmation, got pkt=%v err=%v", openConf, err)
	}
	r := newMuxReader(openConf[1:])
	_, _ = r.ReadUint32() // clientCh
	serverCh, err := r.ReadUint32()
	if err != nil {
		t.Fatalf("read serverCh: %v", err)
	}

	reqW := newMuxWriter()
	reqW.buf = append(reqW.buf, msgChannelRequest)
	reqW.WriteUint32(serverCh)
	reqW.WriteString(agentForwardRequestType)
	reqW.WriteBool(true)
	if err := writeUnpaddedPacket(stalledConn, reqW.Bytes()); err != nil {
		t.Fatalf("write auth-agent-req: %v", err)
	}
	agentReply, err := readUnpaddedPacket(stalledConn)
	if err != nil || len(agentReply) == 0 || agentReply[0] != msgChannelSuccess {
		t.Fatalf("stalled passenger auth-agent-req reply = %v, err = %v", agentReply, err)
	}

	execW := newMuxWriter()
	execW.buf = append(execW.buf, msgChannelRequest)
	execW.WriteUint32(serverCh)
	execW.WriteString("exec")
	execW.WriteBool(false)
	execW.WriteString("hold-open")
	if err := writeUnpaddedPacket(stalledConn, execW.Bytes()); err != nil {
		t.Fatalf("write exec hold-open: %v", err)
	}

	// Stalled passenger stops reading stalledConn here! Master's own Run("query-agent")
	// MUST still complete promptly using Master's local agent without blocking on stalledConn!
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	before := masterDials.Load()
	out, err := masterCli.Run(ctx, "query-agent")
	if err != nil || !strings.Contains(out, "keys=1") {
		t.Fatalf("Master Run(query-agent) while passenger stalled = %q, err = %v", out, err)
	}
	if masterDials.Load() != before+1 {
		t.Fatalf("masterDials after Master Run = %d, want %d", masterDials.Load(), before+1)
	}
}

// TestReviewPass3_H5_PrivilegeInteractiveEscapeFiltering verifies:
//   - (a) sudo/su password containing "~." at line-start ("~.s3cr3t") is NOT filtered
//     during pre-terminalReady authentication, then <Enter>~. AFTER terminalReady
//     immediately disconnects and returns ErrEscapeDisconnect (ExitCode 255, not context.Canceled)
//     across SudoModeSudo, SudoModeSu, and SudoModeSudoer;
//   - (b) EscapeChar=none passes <Enter>~. literally to the privileged shell;
//   - (c) ~~ emits single ~, ~? and ~# print locally without leaking to remote shell,
//     and ~^Z invokes SuspendProcess and restores raw mode cleanly.
func TestReviewPass3_H5_PrivilegeInteractiveEscapeFiltering(t *testing.T) {
	t.Run("password with ~. unfiltered then post-ready ~. disconnects across Sudo Su Sudoer", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			mode SudoMode
			fn   string
		}{
			{name: "sudo/RunInteractiveWithSudoIO", mode: SudoModeSudo, fn: "run"},
			{name: "sudo/ShellWithSudoIO", mode: SudoModeSudo, fn: "shell"},
			{name: "sudo/RunInteractiveWithSudoExecutionIO", mode: SudoModeSudo, fn: "exec"},
			{name: "su/RunInteractiveWithSudoIO", mode: SudoModeSu, fn: "run"},
			{name: "su/ShellWithSudoIO", mode: SudoModeSu, fn: "shell"},
			{name: "su/RunInteractiveWithSudoExecutionIO", mode: SudoModeSu, fn: "exec"},
			{name: "sudoer/RunInteractiveWithSudoIO", mode: SudoModeSudoer, fn: "run"},
			{name: "sudoer/ShellWithSudoIO", mode: SudoModeSudoer, fn: "shell"},
			{name: "sudoer/RunInteractiveWithSudoExecutionIO", mode: SudoModeSudoer, fn: "exec"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				assertPass3PrivilegeModeEscapeDisconnect(t, tc.mode, tc.fn)
			})
		}
	})

	t.Run("EscapeChar=none passes literal ~. to privileged shell", assertPass3PrivilegeEscapeCharNone)
	t.Run("~~ ~? ~# and ~^Z work locally without leaking escapes to privileged shell", assertPass3PrivilegeEscapeSequencesAndSuspend)
}

func assertPass3PrivilegeModeEscapeDisconnect(t *testing.T, mode SudoMode, entrypoint string) {
	t.Helper()
	master, slave := openPass2LinuxPTY(t)
	const linuxTCGETS = 0x5401
	origTios, err := unix.IoctlGetTermios(int(slave.Fd()), linuxTCGETS)
	if err != nil {
		t.Fatalf("TCGETS initial: %v", err)
	}

	srv := startPass3PrivilegePTYServer(t, mode, "~.s3cr3t")
	cli := newPass3PrivilegeTestClient(t, srv.addr, mode, "~.s3cr3t", nil)

	var stderrBuf bytes.Buffer
	streams := InteractiveIO{
		Stdin:  slave,
		Stdout: slave,
		Stderr: &pass2ContextBuffer{buf: &stderrBuf},
	}

	done := make(chan error, 1)
	go func() {
		switch entrypoint {
		case "shell":
			done <- cli.ShellWithSudoIO(t.Context(), streams)
		case "exec":
			done <- cli.RunInteractiveWithSudoExecutionIO(
				t.Context(),
				"top",
				&ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
				streams,
			)
		default:
			done <- cli.RunInteractiveWithSudoIO(t.Context(), "top", streams)
		}
	}()

	select {
	case <-srv.interactiveReady:
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for privileged interactive session ready")
	}
	waitPass2RawMode(slave)

	if mode == SudoModeSudo || mode == SudoModeSu {
		if gotPass := srv.gotPassword(); gotPass != "~.s3cr3t" {
			t.Fatalf("pre-ready password received by %s = %q, want %q", mode, gotPass, "~.s3cr3t")
		}
	}

	if _, err := master.Write([]byte{'\r', '~', '.'}); err != nil {
		t.Fatalf("master.Write(<Enter>~.): %v", err)
	}

	select {
	case runErr := <-done:
		if !errors.Is(runErr, ErrEscapeDisconnect) {
			t.Fatalf("%s/%s on <Enter>~. returned %v, want ErrEscapeDisconnect", mode, entrypoint, runErr)
		}
		if errors.Is(runErr, context.Canceled) {
			t.Fatalf("%s/%s must not wrap context.Canceled on <Enter>~.: %v", mode, entrypoint, runErr)
		}
		type exitCoder interface{ ExitCode() int }
		var ec exitCoder
		if !errors.As(runErr, &ec) || ec.ExitCode() != 255 {
			t.Fatalf("%s/%s ExitCode = %v, want 255", mode, entrypoint, runErr)
		}
	case <-time.After(4 * time.Second):
		t.Fatalf("%s/%s hung after <Enter>~.", mode, entrypoint)
	}

	afterTios, err := unix.IoctlGetTermios(int(slave.Fd()), linuxTCGETS)
	if err != nil {
		t.Fatalf("TCGETS after disconnect: %v", err)
	}
	if afterTios.Lflag != origTios.Lflag {
		t.Fatalf("terminal cooked Lflag not restored after ~.: got 0x%x, want 0x%x", afterTios.Lflag, origTios.Lflag)
	}
	if !strings.Contains(stderrBuf.String(), "Connection to 127.0.0.1 closed.") {
		t.Fatalf("expected disconnect banner in local stderr, got %q", stderrBuf.String())
	}
}

func assertPass3PrivilegeEscapeCharNone(t *testing.T) {
	master, slave := openPass2LinuxPTY(t)
	srv := startPass3PrivilegePTYServer(t, SudoModeSudo, "~.s3cr3t")
	opts, err := NewOptions()
	if err != nil {
		t.Fatal(err)
	}
	if err := opts.Set(OptionEscapeChar, "none"); err != nil {
		t.Fatal(err)
	}
	cli := newPass3PrivilegeTestClient(t, srv.addr, SudoModeSudo, "~.s3cr3t", opts)

	var stderrBuf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- cli.RunInteractiveWithSudoIO(t.Context(), "cat-line", InteractiveIO{
			Stdin:  slave,
			Stdout: slave,
			Stderr: &pass2ContextBuffer{buf: &stderrBuf},
		})
	}()

	<-srv.interactiveReady
	waitPass2RawMode(slave)

	if _, err := master.Write([]byte("\r~.literal\nexit\n")); err != nil {
		t.Fatalf("master.Write literal ~.: %v", err)
	}

	var sawLiteral bool
	deadline := time.After(3 * time.Second)
	for !sawLiteral {
		select {
		case line := <-srv.linesCh:
			if strings.Contains(line, "~.literal") {
				sawLiteral = true
			}
		case <-deadline:
			t.Fatal("timed out waiting for literal ~. line to reach privileged shell under EscapeChar=none")
		}
	}

	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("RunInteractiveWithSudoIO with EscapeChar=none returned %v, want nil", runErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunInteractiveWithSudoIO hung on exit")
	}
}

func assertPass3PrivilegeEscapeSequencesAndSuspend(t *testing.T) {
	master, slave := openPass2LinuxPTY(t)
	const (
		linuxTCGETS = 0x5401
		linuxTCSETS = 0x5402
	)
	origTios, err := unix.IoctlGetTermios(int(slave.Fd()), linuxTCGETS)
	if err != nil {
		t.Fatal(err)
	}
	wantPostExitEchoOff := origTios.Lflag &^ unix.ECHO

	srv := startPass3PrivilegePTYServer(t, SudoModeSudo, "~.s3cr3t")
	cli := newPass3PrivilegeTestClient(t, srv.addr, SudoModeSudo, "~.s3cr3t", nil)

	var suspendCalls atomic.Int32
	cli.environment.SuspendProcess = func() error {
		suspendCalls.Add(1)
		cur, gErr := unix.IoctlGetTermios(int(slave.Fd()), linuxTCGETS)
		if gErr == nil {
			cur.Lflag &^= unix.ECHO
			_ = unix.IoctlSetTermios(int(slave.Fd()), linuxTCSETS, cur)
		}
		return nil
	}

	stderrWrap := &pass2ContextBuffer{buf: &bytes.Buffer{}}
	done := make(chan error, 1)
	go func() {
		done <- cli.ShellWithSudoIO(t.Context(), InteractiveIO{
			Stdin:  slave,
			Stdout: slave,
			Stderr: stderrWrap,
		})
	}()

	<-srv.interactiveReady
	waitPass2RawMode(slave)

	// At line-start:
	//   ~?  -> local escape help (not sent remotely)
	//   ~#  -> local open-channels summary (not sent remotely)
	//   ~^Z -> local suspend + raw-mode re-entry (not sent remotely)
	//   ~~ok\n -> single '~' + "ok\n" sent remotely!
	payload := append([]byte{'~', '?', '~', '#', '~', 0x1a}, []byte("~~ok\n")...)
	if _, err := master.Write(payload); err != nil {
		t.Fatalf("master.Write escape sequences: %v", err)
	}

	select {
	case gotLine := <-srv.linesCh:
		if gotLine != "~ok\n" {
			t.Fatalf("remote privileged shell received %q, want %q (no ~? / ~# / ~~ leak!)", gotLine, "~ok\n")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for ~~ok line on remote privileged shell")
	}

	if suspendCalls.Load() != 1 {
		t.Fatalf("SuspendProcess calls = %d, want 1", suspendCalls.Load())
	}

	stderrWrap.mu.Lock()
	localStderr := stderrWrap.buf.String()
	stderrWrap.mu.Unlock()
	if !strings.Contains(localStderr, "Supported escape sequences:") {
		t.Fatalf("expected ~? help in local stderr, got %q", localStderr)
	}
	if !strings.Contains(localStderr, "The following connections are open:") {
		t.Fatalf("expected ~# channel summary in local stderr, got %q", localStderr)
	}

	// Terminate cleanly via ~. at line-start.
	if _, err := master.Write([]byte{'~', '.'}); err != nil {
		t.Fatalf("master.Write(~.): %v", err)
	}
	select {
	case shellErr := <-done:
		if !errors.Is(shellErr, ErrEscapeDisconnect) {
			t.Fatalf("ShellWithSudoIO returned %v, want ErrEscapeDisconnect", shellErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ShellWithSudoIO hung on ~.")
	}

	afterTios, err := unix.IoctlGetTermios(int(slave.Fd()), linuxTCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if afterTios.Lflag != wantPostExitEchoOff {
		t.Fatalf("restored Lflag = 0x%x, want updated resume Lflag 0x%x", afterTios.Lflag, wantPostExitEchoOff)
	}
}

type pass3PrivilegePTYServer struct {
	addr             string
	interactiveReady chan struct{}
	linesCh          chan string
	passMu           sync.Mutex
	receivedPass     string
}

func (s *pass3PrivilegePTYServer) gotPassword() string {
	s.passMu.Lock()
	defer s.passMu.Unlock()
	return s.receivedPass
}

func startPass3PrivilegePTYServer(t *testing.T, mode SudoMode, wantPassword string) *pass3PrivilegePTYServer {
	t.Helper()
	cfg := &cryptoSSH.ServerConfig{
		PasswordCallback: func(_ cryptoSSH.ConnMetadata, pass []byte) (*cryptoSSH.Permissions, error) {
			if string(pass) == "login" {
				return nil, nil
			}
			return nil, errors.New("bad login")
		},
	}
	cfg.AddHostKey(newAuthTestSigner(t))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &pass3PrivilegePTYServer{
		addr:             ln.Addr().String(),
		interactiveReady: make(chan struct{}, 1),
		linesCh:          make(chan string, 16),
	}

	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			raw, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = raw.Close() }()
				sConn, chans, reqs, hsErr := cryptoSSH.NewServerConn(raw, cfg)
				if hsErr != nil {
					return
				}
				defer func() { _ = sConn.Close() }()
				go cryptoSSH.DiscardRequests(reqs)
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, chErr := newCh.Accept()
					if chErr != nil {
						continue
					}
					wg.Go(func() {
						srv.handleSession(ch, chReqs, mode, wantPassword)
					})
				}
			})
		}
	})
	return srv
}

func (s *pass3PrivilegePTYServer) handleSession(
	ch cryptoSSH.Channel,
	reqs <-chan *cryptoSSH.Request,
	mode SudoMode,
	wantPassword string,
) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "pty-req", "window-change", "env":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go drainPass3ChannelRequests(reqs)
			s.streamInteractiveLines(ch)
			return
		case "exec":
			var payload struct{ Command string }
			_ = cryptoSSH.Unmarshal(req.Payload, &payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go drainPass3ChannelRequests(reqs)
			s.handleExecCommand(ch, payload.Command, mode, wantPassword)
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func drainPass3ChannelRequests(reqs <-chan *cryptoSSH.Request) {
	for req := range reqs {
		if req.WantReply {
			_ = req.Reply(req.Type == "window-change", nil)
		}
	}
}

func (s *pass3PrivilegePTYServer) handleExecCommand(ch cryptoSSH.Channel, cmd string, mode SudoMode, wantPassword string) {
	readyTok := protocolToken(cmd, "[xops-ready-")
	if readyTok == "" {
		// Non-exchange probe or direct SudoModeSudoer exec (`sudo -i ...`).
		if strings.Contains(cmd, "sudo -i") {
			s.streamInteractiveLines(ch)
			return
		}
		_, _ = io.WriteString(ch, "/bin/sh\n")
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		return
	}

	promptOut := ch.Stderr()
	if mode == SudoModeSu {
		promptOut = ch
	}
	reader := bufio.NewReader(ch)

	if mode == SudoModeSudo || mode == SudoModeSu {
		promptText := "Password: "
		if mode == SudoModeSudo {
			promptText = protocolToken(cmd, "[xops-password-")
		}
		_, _ = io.WriteString(promptOut, promptText)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		pass := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		s.passMu.Lock()
		s.receivedPass = pass
		s.passMu.Unlock()
		if pass != wantPassword {
			_, _ = io.WriteString(promptOut, "su: Authentication failure\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
			return
		}
	}

	_, _ = io.WriteString(promptOut, readyTok)
	ackLine, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(ackLine) != protocolToken(cmd, "[xops-continue-") {
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{125}))
		return
	}
	if termTok := protocolToken(cmd, "[xops-terminal-"); termTok != "" {
		_, _ = io.WriteString(promptOut, termTok)
	}
	s.streamInteractiveLinesFromReader(ch, reader)
}

func (s *pass3PrivilegePTYServer) streamInteractiveLines(ch cryptoSSH.Channel) {
	s.streamInteractiveLinesFromReader(ch, bufio.NewReader(ch))
}

func (s *pass3PrivilegePTYServer) streamInteractiveLinesFromReader(ch cryptoSSH.Channel, reader *bufio.Reader) {
	select {
	case s.interactiveReady <- struct{}{}:
	default:
	}
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			select {
			case s.linesCh <- line:
			default:
			}
			if strings.TrimSpace(line) == "exit" {
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func newPass3PrivilegeTestClient(t *testing.T, addr string, mode SudoMode, sudoPassword string, opts *Options) *Client {
	t.Helper()
	setTestHome(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	ui := &recoveryTestUI{values: []string{sudoPassword}}
	cfg := &ClientConfig{
		NodeID:   "priv-node",
		Address:  host,
		Port:     port,
		User:     "alice",
		AuthType: "password",
		Password: "login",
		SudoMode: mode,
		Options:  opts,
		Execution: &ExecutionConfig{
			Interpreter:   InterpreterBash,
			LaunchDialect: LaunchPOSIX,
		},
	}
	conn := newTestConnector(&trackingProvider{cfg: cfg}, WithInteractionHandler(ui))
	t.Cleanup(func() { _ = conn.CloseAll() })

	cli, err := conn.Connect(t.Context(), "priv-node")
	if err != nil {
		t.Fatalf("Connect(priv-node): %v", err)
	}
	cli.handshakeTimeout = 2 * time.Second
	return cli
}

// TestReviewPass3_M2_StreamLocalBindUnlinkPreBindConflictAndDuplicate verifies on Unix:
//   - (a) StreamLocalBindUnlink=yes with active -L /tmp/a.sock:hostA:80 + second
//     -O forward -L /tmp/a.sock:hostB:80 (or -D /tmp/a.sock) fails with
//     "port forwarding conflict on listen endpoint" WITHOUT unlinking /tmp/a.sock,
//     and active listener still forwards to hostA:80;
//   - (b) duplicate -O forward -L /tmp/a.sock:hostA:80 (sequential and concurrent)
//     succeeds WITHOUT unlinking /tmp/a.sock; after CloseForward, /tmp/a.sock can bind hostB:80.
func TestReviewPass3_M2_StreamLocalBindUnlinkPreBindConflictAndDuplicate(t *testing.T) {
	dialConn := &pass3MuxForwardDialSSHConn{}
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	rawCli := cryptoSSH.NewClient(dialConn, chans, reqs)
	defer func() {
		close(chans)
		close(reqs)
		_ = rawCli.Close()
	}()

	sockDir := shortSocketDir(t)
	ctrlSock := filepath.Join(sockDir, "m2-ctrl.sock")
	fwdSock := filepath.Join(sockDir, "a.sock")

	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:           ctrlSock,
		SSHClient:             rawCli,
		PersistEnabled:        true,
		PersistIndefinite:     true,
		StreamLocalBindUnlink: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	go func() { _ = srv.Serve() }()

	muxCli, err := DialMuxClient(t.Context(), ctrlSock)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	reqHostA := ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  fwdSock,
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: "hostA",
		ConnectPort: 80,
	}
	if _, err := muxCli.OpenForward(t.Context(), reqHostA); err != nil {
		t.Fatalf("initial OpenForward(hostA:80): %v", err)
	}

	origFi, err := os.Lstat(fwdSock)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", fwdSock, err)
	}

	// (a) Conflicting -L /tmp/a.sock:hostB:80 and -D /tmp/a.sock MUST fail without unlinking fwdSock!
	conflictLocal := ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  fwdSock,
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: "hostB",
		ConnectPort: 80,
	}
	if _, err := muxCli.OpenForward(t.Context(), conflictLocal); err == nil || !strings.Contains(err.Error(), "port forwarding conflict on listen endpoint") {
		t.Fatalf("conflicting -L hostB:80 err = %v, want 'port forwarding conflict on listen endpoint'", err)
	}

	conflictDynamic := ForwardRequest{
		Type:       ForwardDynamic,
		ListenHost: fwdSock,
		ListenPort: MUX_SPECIAL_PORT_UNIX,
	}
	if _, err := muxCli.OpenForward(t.Context(), conflictDynamic); err == nil || !strings.Contains(err.Error(), "port forwarding conflict on listen endpoint") {
		t.Fatalf("conflicting -D err = %v, want 'port forwarding conflict on listen endpoint'", err)
	}

	afterConflictFi, err := os.Lstat(fwdSock)
	if err != nil || !os.SameFile(origFi, afterConflictFi) {
		t.Fatalf("conflicting OpenForward unlinked or replaced active socket %q (statErr=%v)", fwdSock, err)
	}
	assertPass3UnixForwardTarget(t, fwdSock, "target=hostA:80")

	// (b) Duplicate -L /tmp/a.sock:hostA:80 (sequential + concurrent) MUST succeed without unlinking fwdSock!
	if _, err := muxCli.OpenForward(t.Context(), reqHostA); err != nil {
		t.Fatalf("duplicate OpenForward(hostA:80): %v", err)
	}
	var dupWG sync.WaitGroup
	for range 4 {
		dupWG.Go(func() {
			c, dErr := DialMuxClient(t.Context(), ctrlSock)
			if dErr != nil {
				t.Errorf("DialMuxClient: %v", dErr)
				return
			}
			defer func() { _ = c.Close() }()
			if _, oErr := c.OpenForward(t.Context(), reqHostA); oErr != nil {
				t.Errorf("concurrent duplicate OpenForward: %v", oErr)
			}
		})
	}
	dupWG.Wait()

	afterDupFi, err := os.Lstat(fwdSock)
	if err != nil || !os.SameFile(origFi, afterDupFi) {
		t.Fatalf("duplicate OpenForward unlinked or replaced active socket %q (statErr=%v)", fwdSock, err)
	}
	assertPass3UnixForwardTarget(t, fwdSock, "target=hostA:80")

	// After CloseForward, endpoint reservation is cleaned up so hostB:80 can bind fwdSock cleanly!
	if err := muxCli.CloseForward(t.Context(), reqHostA); err != nil {
		t.Fatalf("CloseForward(hostA:80): %v", err)
	}
	if _, err := muxCli.OpenForward(t.Context(), conflictLocal); err != nil {
		t.Fatalf("OpenForward(hostB:80) after CloseForward failed: %v", err)
	}
	assertPass3UnixForwardTarget(t, fwdSock, "target=hostB:80")
}

func assertPass3UnixForwardTarget(t *testing.T, sockPath, wantBanner string) {
	t.Helper()
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial unix forward %q: %v", sockPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read from unix forward %q: %v", sockPath, err)
	}
	if string(got) != wantBanner {
		t.Fatalf("unix forward %q banner = %q, want %q", sockPath, string(got), wantBanner)
	}
}

// TestReviewPass3_M3_PassengerStdioFwdStreamLocalIPv6AndPortValidation verifies:
//   - MUX_C_NEW_STDIO_FWD with MUX_SPECIAL_PORT_UNIX opens direct-streamlocal@openssh.com;
//   - bracketed "[::1]" host strips brackets before net.JoinHostPort in direct-tcpip;
//   - invalid ports 0 and 70000 (and empty host / empty streamlocal path) fail with MUX_S_FAILURE.
func TestReviewPass3_M3_PassengerStdioFwdStreamLocalIPv6AndPortValidation(t *testing.T) {
	dialConn := &pass3MuxForwardDialSSHConn{}
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	rawCli := cryptoSSH.NewClient(dialConn, chans, reqs)
	defer func() {
		close(chans)
		close(reqs)
		_ = rawCli.Close()
	}()

	ctrlSock := filepath.Join(shortSocketDir(t), "m3-stdio.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:       ctrlSock,
		SSHClient:         rawCli,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	go func() { _ = srv.Serve() }()

	// 1. StreamLocal (MUX_SPECIAL_PORT_UNIX) -> direct-streamlocal@openssh.com
	gotUnix := runPass3StdioFwdSuccess(t, srv, ctrlSock, MuxNewStdioFwdRequest{
		RequestID:   1,
		ConnectHost: "/var/run/remote-app.sock",
		ConnectPort: MUX_SPECIAL_PORT_UNIX,
	})
	if gotUnix != "streamlocal=/var/run/remote-app.sock" {
		t.Fatalf("StreamLocal stdio fwd output = %q, want %q", gotUnix, "streamlocal=/var/run/remote-app.sock")
	}

	// 2. Bracketed IPv6 "[::1]" -> direct-tcpip with Host="::1", Port=8443
	gotIPv6 := runPass3StdioFwdSuccess(t, srv, ctrlSock, MuxNewStdioFwdRequest{
		RequestID:   2,
		ConnectHost: "[::1]",
		ConnectPort: 8443,
	})
	if gotIPv6 != "target=::1:8443" {
		t.Fatalf("IPv6 stdio fwd output = %q, want %q", gotIPv6, "target=::1:8443")
	}

	// 3. Invalid ports 0 and 70000, empty host, and empty streamlocal socket path MUST fail closed!
	beforeOpens := dialConn.openCalls.Load()
	for _, badReq := range []MuxNewStdioFwdRequest{
		{RequestID: 10, ConnectHost: "127.0.0.1", ConnectPort: 0},
		{RequestID: 11, ConnectHost: "127.0.0.1", ConnectPort: 70000},
		{RequestID: 12, ConnectHost: "   ", ConnectPort: 443},
		{RequestID: 13, ConnectHost: "   ", ConnectPort: MUX_SPECIAL_PORT_UNIX},
	} {
		c, dErr := net.Dial("unix", ctrlSock)
		if dErr != nil {
			t.Fatalf("Dial control socket: %v", dErr)
		}
		if hErr := performClientMuxHandshake(c); hErr != nil {
			_ = c.Close()
			t.Fatalf("handshake: %v", hErr)
		}
		if wErr := WriteMuxPacket(c, MUX_C_NEW_STDIO_FWD, EncodeMuxNewStdioFwd(badReq)); wErr != nil {
			_ = c.Close()
			t.Fatalf("WriteMuxPacket: %v", wErr)
		}
		sendStdioPipeFDs(t, c)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		pktType, _, rErr := ReadMuxPacket(c)
		_ = c.Close()
		if rErr != nil || pktType != MUX_S_FAILURE {
			t.Fatalf("bad stdio fwd %+v -> (0x%x, %v), want MUX_S_FAILURE", badReq, pktType, rErr)
		}
	}
	if afterOpens := dialConn.openCalls.Load(); afterOpens != beforeOpens {
		t.Fatalf("invalid stdio fwd requests opened %d upstream SSH channels, want 0", afterOpens-beforeOpens)
	}
	if got := srv.ActiveSessions(); got != 0 {
		t.Fatalf("ActiveSessions after rejected stdio fwd = %d, want 0", got)
	}
}

func runPass3StdioFwdSuccess(t *testing.T, srv *MuxServer, ctrlSock string, req MuxNewStdioFwdRequest) string {
	t.Helper()
	c, err := net.Dial("unix", ctrlSock)
	if err != nil {
		t.Fatalf("Dial(%q): %v", ctrlSock, err)
	}
	defer func() { _ = c.Close() }()
	if err := performClientMuxHandshake(c); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := WriteMuxPacket(c, MUX_C_NEW_STDIO_FWD, EncodeMuxNewStdioFwd(req)); err != nil {
		t.Fatalf("WriteMuxPacket: %v", err)
	}
	inR, inW, outR, outW := sendKeepOpenStdioPipes(t, c)
	// Close our copies of the remote ends immediately so EOF propagates cleanly.
	_ = inR.Close()
	_ = outW.Close()
	defer func() {
		_ = inW.Close()
		_ = outR.Close()
	}()

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	pktType, _, err := ReadMuxPacket(c)
	if err != nil || pktType != MUX_S_SESSION_OPENED {
		t.Fatalf("ReadMuxPacket(stdio fwd) = (0x%x, %v), want MUX_S_SESSION_OPENED", pktType, err)
	}
	_ = inW.Close()

	data, err := io.ReadAll(outR)
	if err != nil {
		t.Fatalf("ReadAll(stdio stdout): %v", err)
	}
	// Drain MUX_S_EXIT_MESSAGE and wait for handlePassengerStdioFwd's deferred
	// releaseSession() to decrement ActiveSessions back to 0 before returning.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	exitPkt, exitPayload, err := ReadMuxPacket(c)
	if err != nil || exitPkt != MUX_S_EXIT_MESSAGE {
		t.Fatalf("ReadMuxPacket(stdio fwd exit) = (0x%x, %v), want MUX_S_EXIT_MESSAGE", exitPkt, err)
	}
	if _, exitVal, decErr := DecodeMuxExitMessage(exitPayload); decErr != nil || exitVal != 0 {
		t.Fatalf("DecodeMuxExitMessage = (status=%d, err=%v), want (0, nil)", exitVal, decErr)
	}
	_ = c.Close()
	waitServerActiveSessionsZero(t, srv)
	return string(data)
}

type pass3MuxForwardDialSSHConn struct {
	dummyMuxGateConn
	openCalls atomic.Int32
}

func (m *pass3MuxForwardDialSSHConn) OpenChannel(name string, extra []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	m.openCalls.Add(1)
	reqs := make(chan *cryptoSSH.Request)
	close(reqs)

	var banner string
	switch name {
	case "direct-tcpip":
		var msg struct {
			Host       string
			Port       uint32
			OriginAddr string
			OriginPort uint32
		}
		if err := cryptoSSH.Unmarshal(extra, &msg); err != nil {
			return nil, nil, err
		}
		banner = fmt.Sprintf("target=%s:%d", msg.Host, msg.Port)
	case "direct-streamlocal@openssh.com":
		var msg struct {
			SocketPath string
			Reserved0  string
			Reserved1  uint32
		}
		if err := cryptoSSH.Unmarshal(extra, &msg); err != nil {
			return nil, nil, err
		}
		banner = "streamlocal=" + msg.SocketPath
	default:
		return nil, nil, errors.New("unsupported channel type: " + name)
	}
	return &pass3BannerChannel{reader: strings.NewReader(banner)}, reqs, nil
}

type pass3BannerChannel struct {
	reader *strings.Reader
}

func (c *pass3BannerChannel) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *pass3BannerChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *pass3BannerChannel) CloseWrite() error           { return nil }
func (c *pass3BannerChannel) Close() error                { return nil }
func (c *pass3BannerChannel) Stderr() io.ReadWriter       { return &nopRW{} }
func (c *pass3BannerChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
