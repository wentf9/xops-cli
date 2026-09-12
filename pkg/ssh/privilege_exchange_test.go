package ssh

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

type privilegeServerOptions struct {
	mode             SudoMode
	password         string
	noPrompt         bool
	status           uint32
	blockExecReply   bool
	banner           string
	withholdTerminal bool
	inputBytes       int
}
type privilegeServerEvidence struct {
	commands         atomic.Int32
	attempts         atomic.Int32
	input            chan string
	execRequests     atomic.Int32
	execStarted      chan struct{}
	ptyEchoOff       atomic.Bool
	terminalSignaled chan struct{}
}

func startPrivilegeExchangeServer(t *testing.T, opts privilegeServerOptions) (string, *privilegeServerEvidence) {
	t.Helper()
	config := &cryptoSSH.ServerConfig{PasswordCallback: func(_ cryptoSSH.ConnMetadata, value []byte) (*cryptoSSH.Permissions, error) {
		if string(value) == "login" {
			return nil, nil
		}
		return nil, errors.New("login rejected")
	}}
	config.AddHostKey(newAuthTestSigner(t))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	evidence := &privilegeServerEvidence{input: make(chan string, 4), execStarted: make(chan struct{}, 1), terminalSignaled: make(chan struct{}, 1)}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var active net.Conn
	wg.Go(func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		active = conn
		mu.Unlock()
		defer closePrivilegeTestResource(t, conn)
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		server, channels, requests, err := cryptoSSH.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer func() {
			if err := closeResource(server, "test SSH server"); err != nil {
				t.Error(err)
			}
		}()
		wg.Go(func() {
			for request := range requests {
				if err := request.Reply(false, nil); err != nil && ctx.Err() == nil {
					t.Error(err)
				}
			}
		})
		for {
			select {
			case <-ctx.Done():
				return
			case request, ok := <-channels:
				if !ok {
					return
				}
				channel, reqs, err := request.Accept()
				if err != nil {
					return
				}
				wg.Go(func() { servePrivilegeExchange(t, channel, reqs, opts, evidence) })
			}
		}
	})
	t.Cleanup(func() {
		cancel()
		closePrivilegeTestResource(t, listener)
		mu.Lock()
		conn := active
		mu.Unlock()
		closePrivilegeTestResource(t, conn)
		wg.Wait()
	})
	return listener.Addr().String(), evidence
}

func protocolToken(command, prefix string) string {
	at := strings.Index(command, prefix)
	if at >= 0 && strings.HasPrefix(command[at:], prefix+"%s]") {
		nonce := regexp.MustCompile(`[A-Z2-7]{26,}`).FindString(command[at:])
		if nonce != "" {
			return prefix + nonce + "]"
		}
	}
	if at < 0 {
		return ""
	}
	end := strings.Index(command[at:], "]")
	if end < 0 {
		return ""
	}
	return command[at : at+end+1]
}

func servePrivilegeExchange(t *testing.T, channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request, opts privilegeServerOptions, evidence *privilegeServerEvidence) {
	t.Helper()
	defer func() {
		if err := channel.Close(); err != nil && !errors.Is(err, io.EOF) {
			t.Error(err)
		}
	}()
	for req := range requests {
		if req.Type == "pty-req" {
			var pty struct {
				Term                                   string
				Columns, Rows, PixelWidth, PixelHeight uint32
				Modes                                  string
			}
			if err := cryptoSSH.Unmarshal(req.Payload, &pty); err != nil {
				t.Error(err)
				return
			}
			evidence.ptyEchoOff.Store(pty.Modes == string([]byte{byte(cryptoSSH.ECHO), 0, 0, 0, 0, 0}))
			if err := req.Reply(true, nil); err != nil {
				t.Error(err)
				return
			}
			continue
		}
		if req.Type != "exec" {
			if err := req.Reply(false, nil); err != nil {
				t.Error(err)
			}
			continue
		}
		var payload struct{ Command string }
		if err := cryptoSSH.Unmarshal(req.Payload, &payload); err != nil {
			t.Error(err)
			return
		}
		evidence.execRequests.Add(1)
		if opts.blockExecReply {
			select {
			case evidence.execStarted <- struct{}{}:
			default:
			}
			if _, err := io.Copy(io.Discard, channel); err != nil && !errors.Is(err, io.EOF) {
				t.Error(err)
			}
			return
		}
		if err := req.Reply(true, nil); err != nil {
			t.Error(err)
			return
		}
		servePrivilegeCommand(t, channel, payload.Command, opts, evidence)
		return
	}
}
func servePrivilegeCommand(t *testing.T, channel cryptoSSH.Channel, command string, opts privilegeServerOptions, evidence *privilegeServerEvidence) {
	t.Helper()
	ready := protocolToken(command, "[xops-ready-")
	if ready == "" {
		t.Error("missing command-start protocol")
		return
	}
	target := channel.Stderr()
	if opts.mode == SudoModeSu {
		target = channel
	}
	reader := bufio.NewReader(channel)
	if opts.banner != "" {
		if _, err := io.WriteString(target, opts.banner); err != nil {
			return
		}
	}
	if !servePrivilegeAuthentication(t, channel, reader, target, command, opts, evidence) {
		return
	}

	if _, err := io.WriteString(target, ready); err != nil {
		return
	}
	ack, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(ack) != protocolToken(command, "[xops-continue-") {
		sendPrivilegeStatus(t, channel, 125)
		return
	}
	if terminal := protocolToken(command, "[xops-terminal-"); terminal != "" {
		if opts.withholdTerminal {
			if _, err := io.Copy(io.Discard, reader); err != nil && !errors.Is(err, io.EOF) {
				t.Error(err)
			}
			return
		}
		if _, err := io.WriteString(target, terminal); err != nil {
			return
		}
		select {
		case evidence.terminalSignaled <- struct{}{}:
		default:
		}
	}
	evidence.commands.Add(1)
	var data []byte
	if opts.inputBytes > 0 {
		data = make([]byte, opts.inputBytes)
		_, err = io.ReadFull(reader, data)
	} else {
		data, err = io.ReadAll(reader)
	}
	if err != nil {
		return
	}
	evidence.input <- string(data)
	if _, err := io.WriteString(channel, "command output: su: Authentication failure\n"); err != nil {
		return
	}
	sendPrivilegeStatus(t, channel, opts.status)
}
func sendPrivilegeStatus(t *testing.T, channel cryptoSSH.Channel, status uint32) {
	t.Helper()
	if _, err := channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{status})); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Error(err)
	}
}

func exchangeTestClient(t *testing.T, addr string, mode SudoMode, ui InteractionHandler, recorder CredentialRecorder) *Client {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	provider := &trackingProvider{cfg: &ClientConfig{NodeID: "node", Address: host, Port: port, User: "user", AuthType: "password", Password: "login", SudoMode: mode, SudoUpdateToken: "sudo"}}
	connector := NewConnector(provider, WithInteractionHandler(ui), WithCredentialRecorder(recorder))
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	client, err := connector.Connect(t.Context(), "node")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestPrivilegeExchangeRetriesBeforeCommandOnly(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSu, SudoModeSudo} {
		t.Run(string(mode), func(t *testing.T) {
			setTestHome(t)
			addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: mode, password: "valid", status: 7})
			ui := &recoveryTestUI{values: []string{"wrong", "valid"}}
			recorder := &testRecorder{}
			client := exchangeTestClient(t, addr, mode, ui, recorder)
			var output bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err := client.runPrivilegeOperation(ctx, mode, "user-command", strings.NewReader("script-input"), &output, &output)
			var exitErr *cryptoSSH.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 7 {
				t.Fatalf("command exit status lost: %v", err)
			}
			if evidence.commands.Load() != 1 || evidence.attempts.Load() != 2 {
				t.Fatalf("commands=%d attempts=%d", evidence.commands.Load(), evidence.attempts.Load())
			}
			if got := <-evidence.input; got != "script-input" {
				t.Fatalf("credential leaked into stdin: %q", got)
			}
			if strings.Contains(output.String(), "xops-ready-") || strings.Contains(output.String(), "xops-password-") {
				t.Fatal("protocol frames leaked")
			}
			if recorder.sudoCalls != 1 || recorder.lastSuPass != "valid" {
				t.Fatal("verified password not saved for nonzero command exit")
			}
		})
	}
}

func TestPrivilegeExchangePasswordlessDoesNotConsumeCredential(t *testing.T) {
	setTestHome(t)
	addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, noPrompt: true})
	ui := &recoveryTestUI{values: []string{"must-not-be-read"}}
	recorder := &testRecorder{}
	client := exchangeTestClient(t, addr, SudoModeSudo, ui, recorder)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := client.runPrivilegeOperation(ctx, SudoModeSudo, "script", strings.NewReader("only-script"), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := <-evidence.input; got != "only-script" {
		t.Fatal("unexpected command input")
	}
	if ui.prompts != 0 || recorder.sudoCalls != 0 {
		t.Fatal("passwordless command used a credential")
	}
}

func TestPrivilegeExchangeCancellationJoinsWorkers(t *testing.T) {
	setTestHome(t)
	addr, _ := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSu, password: "valid"})
	client := exchangeTestClient(t, addr, SudoModeSu, &recoveryTestUI{}, &testRecorder{})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := client.runPrivilegeOperation(ctx, SudoModeSu, "command", nil, io.Discard, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

type blockingPrivilegeUI struct {
	recoveryTestUI
	entered chan struct{}
	once    sync.Once
}

func (h *blockingPrivilegeUI) PromptSecret(ctx context.Context, _ SecretRequest) (string, error) {
	h.once.Do(func() { close(h.entered) })
	<-ctx.Done()
	return "", ctx.Err()
}
func TestPrivilegeExchangeCancelDuringPrompt(t *testing.T) {
	setTestHome(t)
	addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSu, password: "valid"})
	ui := &blockingPrivilegeUI{entered: make(chan struct{})}
	client := exchangeTestClient(t, addr, SudoModeSu, ui, &testRecorder{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- client.runPrivilegeOperation(ctx, SudoModeSu, "command", nil, io.Discard, io.Discard) }()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	select {
	case <-ui.entered:
	case <-ctx.Done():
		t.Fatal("prompt did not start")
	}
	cancel()
	err := <-done
	joined = true
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled prompt: %v", err)
	}
	if evidence.commands.Load() != 0 {
		t.Fatal("command started before authentication")
	}
}

func TestPrivilegeFramesDoNotInterpretCommandOutput(t *testing.T) {
	for split := 0; split <= len("bannerPassword: [ready]Password: [ready]"); split++ {
		exchange := &privilegeExchange{mode: SudoModeSu, readyToken: "[ready]", ready: make(chan struct{}), prompts: make(chan struct{}, 3)}
		var target bytes.Buffer
		writer := &privilegeFrameWriter{exchange: exchange, target: &target, prompt: regexp.MustCompile("Password: ")}
		value := []byte("bannerPassword: [ready]Password: [ready]")
		for _, chunk := range [][]byte{value[:split], value[split:]} {
			if _, err := writer.Write(chunk); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.flush(); err != nil {
			t.Fatal(err)
		}
		if !exchange.started() || len(exchange.prompts) != 1 || target.String() != "bannerPassword: [ready]" {
			t.Fatalf("split %d changed output: %q", split, target.String())
		}
	}
}

func TestPrivilegeReadyFrameIsNotLiteralInCommand(t *testing.T) {
	exchange := newPrivilegeExchange(nil, SudoModeSu, false)
	if strings.Contains(exchange.command("echo user-command"), exchange.readyToken) {
		t.Fatal("shell command echo can impersonate command readiness")
	}
}
func TestPrivilegeFrameIgnoresXtracePromptArgument(t *testing.T) {
	exchange := &privilegeExchange{readyToken: "[ready]", ready: make(chan struct{}), prompts: make(chan struct{}, 3)}
	var output bytes.Buffer
	writer := &privilegeFrameWriter{exchange: exchange, target: &output, prompt: regexp.MustCompile(regexp.QuoteMeta("[prompt]"))}
	if _, err := writer.Write([]byte("+ sudo -p '[prompt]' command\n[prompt]")); err != nil {
		t.Fatal(err)
	}
	if len(exchange.prompts) != 1 {
		t.Fatal("xtrace argument treated as a password challenge")
	}
}

func closePrivilegeTestResource(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closeResource(closer, "test resource"); err != nil {
		t.Error(err)
	}
}

func TestPrivilegeExchangeRetryLimitLeavesCommandInputUntouched(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu} {
		t.Run(string(mode), func(t *testing.T) {
			setTestHome(t)
			addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: mode, password: "valid"})
			ui := &recoveryTestUI{values: []string{"wrong-one", "wrong-two", "wrong-three", "must-not-be-read"}}
			recorder := &testRecorder{}
			client := exchangeTestClient(t, addr, mode, ui, recorder)
			input := bytes.NewReader([]byte("untouched-script"))
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := client.runPrivilegeOperation(ctx, mode, "user-command", input, io.Discard, io.Discard); err == nil {
				t.Fatal("rejected credentials succeeded")
			}
			if evidence.commands.Load() != 0 || evidence.attempts.Load() != 3 || ui.prompts != 3 {
				t.Fatal("retry limit or command-start boundary violated")
			}
			if input.Len() != len("untouched-script") || recorder.sudoCalls != 0 {
				t.Fatal("failed authentication consumed input or saved a secret")
			}
		})
	}
}

func TestPrivilegeExchangeExecRequestCanBeCanceled(t *testing.T) {
	setTestHome(t)
	addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSu, blockExecReply: true})
	client := exchangeTestClient(t, addr, SudoModeSu, &recoveryTestUI{}, &testRecorder{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- client.runPrivilegeOperation(ctx, SudoModeSu, "command", nil, io.Discard, io.Discard) }()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	select {
	case <-evidence.execStarted:
	case <-ctx.Done():
		t.Fatal("exec request did not reach server")
	}
	cancel()
	err := <-done
	joined = true
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("exec request cancellation lost: %v", err)
	}
	if evidence.execRequests.Load() != 1 || evidence.commands.Load() != 0 {
		t.Fatal("exec request was not bounded before command start")
	}
}

type privilegeFailingOutput struct{ err error }

func (w privilegeFailingOutput) Write([]byte) (int, error) { return 0, w.err }
func TestPrivilegeExchangeOutputFailureStopsBeforeInput(t *testing.T) {
	setTestHome(t)
	addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSu, password: "valid", banner: "banner\n"})
	ui := &recoveryTestUI{values: []string{"must-not-be-read"}}
	client := exchangeTestClient(t, addr, SudoModeSu, ui, &testRecorder{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	outputErr := errors.New("output unavailable")
	target := privilegeFailingOutput{err: outputErr}
	err := client.runPrivilegeOperation(ctx, SudoModeSu, "command", nil, target, target)
	if !errors.Is(err, outputErr) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("output failure did not abort promptly: %v", err)
	}
	if evidence.commands.Load() != 0 || evidence.attempts.Load() != 0 || ui.prompts != 0 {
		t.Fatal("output failure consumed input or started command")
	}
}

func servePrivilegeAuthentication(t *testing.T, channel cryptoSSH.Channel, reader *bufio.Reader, target io.Writer, command string, opts privilegeServerOptions, evidence *privilegeServerEvidence) bool {
	t.Helper()
	if opts.noPrompt {
		return true
	}
	for attempt := 0; attempt < 3; attempt++ {
		prompt := protocolToken(command, "[xops-password-")
		if opts.mode == SudoModeSu {
			prompt = "Password: "
		}
		if _, err := io.WriteString(target, prompt); err != nil {
			return false
		}
		value, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		evidence.attempts.Add(1)
		if strings.TrimSpace(value) == opts.password {
			return true
		}
		if opts.mode == SudoModeSu || attempt == 2 {
			if _, err := io.WriteString(target, "su: Authentication failure\n"); err != nil {
				return false
			}
			sendPrivilegeStatus(t, channel, 1)
			return false
		}
	}
	return false
}
