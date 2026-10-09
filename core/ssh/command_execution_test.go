package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type commandFixture struct {
	blockClose                                                                       bool
	suspendReads                                                                     atomic.Bool
	hangPTY, terminal                                                                bool
	requestTypes                                                                     chan string
	reject, hangRequest, hangCommand, missing, signal, malformed, noClose, stallOpen bool
	status                                                                           uint32
	output                                                                           string
	commands                                                                         chan string
	inputs                                                                           chan string
	attempts                                                                         atomic.Int32
}

func commandTestClient(t *testing.T, scenario *commandFixture) *Client {
	t.Helper()
	listener, config := startKeepAliveTestSSHServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	var workers sync.WaitGroup
	var client *Client
	var conn net.Conn
	t.Cleanup(func() {
		cancel()
		if client != nil {
			if err := client.Interrupt(); err != nil {
				t.Error(err)
			}
		} else if conn != nil {
			if err := closeResource(conn, "fixture client transport"); err != nil {
				t.Error(err)
			}
		}
		if err := closeResource(listener, "fixture listener"); err != nil {
			t.Error(err)
		}
		workers.Wait()
	})
	workers.Go(func() {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				t.Error(err)
			}
			return
		}
		conn = &heldReadConn{Conn: conn, held: &scenario.suspendReads, release: ctx.Done()}
		defer func() {
			if err := closeResource(conn, "fixture transport"); err != nil {
				t.Error(err)
			}
		}()
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		server, channels, requests, err := cryptoSSH.NewServerConn(conn, config)
		if err != nil {
			t.Error(err)
			return
		}
		stop := context.AfterFunc(ctx, func() {
			if err := closeResource(server, "fixture SSH server"); err != nil {
				t.Error(err)
			}
		})
		defer stop()
		defer func() {
			if err := closeResource(server, "fixture SSH server"); err != nil {
				t.Error(err)
			}
		}()
		workers.Go(func() { cryptoSSH.DiscardRequests(requests) })
		for newChannel := range channels {
			if scenario.stallOpen {
				<-ctx.Done()
				return
			}
			channel, incoming, err := newChannel.Accept()
			if err != nil {
				if ctx.Err() == nil {
					t.Log(err)
				}
				return
			}
			workers.Go(func() { serveCommandFixture(t, ctx, channel, incoming, scenario) })
		}
	})
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, channels, requests, err := cryptoSSH.NewClientConn(conn, listener.Addr().String(), &cryptoSSH.ClientConfig{
		User: "test", Auth: []cryptoSSH.AuthMethod{cryptoSSH.Password("test")}, HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	client = newClient(cryptoSSH.NewClient(raw, channels, requests), conn, &ClientConfig{}, nil, "")
	client.handshakeTimeout = 300 * time.Millisecond
	return client
}

func serveCommandFixture(t *testing.T, ctx context.Context, channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request, scenario *commandFixture) {
	t.Helper()
	defer func() {
		if err := closeResource(channel, "fixture command channel"); err != nil && ctx.Err() == nil {
			t.Log(err)
		}
	}()
	request := nextCommandFixtureRequest(t, ctx, channel, requests, scenario)
	if request == nil {
		return
	}
	if request.Type != "exec" && request.Type != "shell" {
		t.Errorf("unexpected request %s", request.Type)
		return
	}
	scenario.attempts.Add(1)
	var payload struct{ Command string }
	if request.Type == "exec" {
		if err := cryptoSSH.Unmarshal(request.Payload, &payload); err != nil {
			t.Error(err)
			return
		}
	}
	if scenario.commands != nil {
		scenario.commands <- payload.Command
	}
	if scenario.hangRequest {
		<-ctx.Done()
		return
	}
	scenario.suspendReads.Store(scenario.blockClose)
	if err := request.Reply(!scenario.reject, nil); err != nil {
		t.Log(err)
		return
	}
	if scenario.reject {
		return
	}
	if scenario.hangCommand {
		<-ctx.Done()
		return
	}
	if !scenario.terminal {
		input, err := io.ReadAll(channel)
		if err != nil {
			t.Log(err)
			return
		}
		if scenario.inputs != nil {
			scenario.inputs <- string(input)
		}
	}
	if _, err := io.WriteString(channel, scenario.output); err != nil {
		t.Log(err)
		return
	}
	if _, err := io.WriteString(channel.Stderr(), "stderr"); err != nil {
		t.Log(err)
		return
	}
	if err := sendCommandFixtureStatus(channel, scenario); err != nil {
		t.Log(err)
	}
	if scenario.noClose {
		<-ctx.Done()
	}
}

func nextCommandFixtureRequest(t *testing.T, ctx context.Context, channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request, scenario *commandFixture) *cryptoSSH.Request {
	t.Helper()
	for request := range requests {
		if scenario.requestTypes != nil {
			scenario.requestTypes <- request.Type
		}
		if request.Type != "pty-req" {
			return request
		}
		if scenario.hangPTY {
			<-ctx.Done()
			return nil
		}
		if err := request.Reply(true, nil); err != nil {
			t.Log(err)
			return nil
		}
	}
	return nil
}

func sendCommandFixtureStatus(channel cryptoSSH.Channel, scenario *commandFixture) error {
	if scenario.missing {
		return nil
	}
	request := "exit-status"
	payload := cryptoSSH.Marshal(struct{ Status uint32 }{scenario.status})
	if scenario.signal {
		request = "exit-signal"
		payload = cryptoSSH.Marshal(struct {
			Signal            string
			CoreDumped        bool
			Message, Language string
		}{"TERM", false, "", ""})
	}
	if scenario.malformed {
		payload = []byte{0}
	}
	_, err := channel.SendRequest(request, false, payload)
	return err
}

func TestExecuteCommandWireAndInput(t *testing.T) {
	scenario := &commandFixture{commands: make(chan string, 2), inputs: make(chan string, 2), output: "stdout"}
	client := commandTestClient(t, scenario)
	command := " \r\n雪 '%PATH%' & echo $(id) \"$HOME\"\\\xff"
	input := []byte("\x00\xffdata\n")
	for _, options := range []CommandOptions{{Stdin: input}, {Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX, Login: LoginEnabled, Stdin: input}} {
		plan, err := PlanCommand(command, options)
		if err != nil {
			t.Fatal(err)
		}
		result := client.ExecuteCommand(t.Context(), plan)
		if result.Err() != nil || result.Outcome != ExecutionCompleted || result.ExitCode == nil || *result.ExitCode != 0 || result.PlanDigest != plan.Digest() {
			t.Fatalf("unexpected result: %+v, %v", result, result.Err())
		}
		if !strings.Contains(result.Output, "stdout") || !strings.Contains(result.Output, "stderr") {
			t.Fatalf("lost output: %q", result.Output)
		}
		if got := <-scenario.commands; got != plan.Payload() {
			t.Fatalf("payload %q, want %q", got, plan.Payload())
		}
		if got := <-scenario.inputs; got != string(input) {
			t.Fatalf("stdin %q", got)
		}
	}
	if scenario.attempts.Load() != 2 {
		t.Fatal("unexpected replay")
	}
}

func TestExecuteCommandResults(t *testing.T) {
	for name, scenario := range map[string]*commandFixture{
		"nonzero": {status: 127}, "signal": {signal: true}, "missing": {missing: true}, "malformed": {malformed: true}, "rejected": {reject: true},
	} {
		t.Run(name, func(t *testing.T) {
			client := commandTestClient(t, scenario)
			plan, err := PlanCommand("side-effect", CommandOptions{})
			if err != nil {
				t.Fatal(err)
			}
			result := client.ExecuteCommand(t.Context(), plan)
			if result.Err() == nil {
				t.Fatalf("failure reported success: %+v", result)
			}
			want := ExecutionCompleted
			if scenario.missing || scenario.malformed {
				want = ExecutionUnknown
			}
			if scenario.reject {
				want = ExecutionNotStarted
			}
			if result.Outcome != want || scenario.attempts.Load() != 1 {
				t.Fatalf("unexpected outcome/replay: %+v", result)
			}
			if scenario.signal && (result.Signal != "TERM" || result.ExitCode != nil) {
				t.Fatalf("lost signal: %+v", result)
			}
			if scenario.status == 127 && (result.ExitCode == nil || *result.ExitCode != 127) {
				t.Fatalf("lost exit code: %+v", result)
			}
		})
	}
}

func TestExecuteCommandCancellationAndTruncation(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, scenario := range []*commandFixture{{hangRequest: true}, {hangCommand: true}, {noClose: true}, {output: strings.Repeat("data", 1024)}} {
		t.Run(fmt.Sprintf("%+v", scenario), func(t *testing.T) {
			client := commandTestClient(t, scenario)
			plan, err := PlanCommand("side-effect", CommandOptions{Timeout: 150 * time.Millisecond, OutputLimit: 64})
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			result := client.ExecuteCommand(t.Context(), plan)
			if time.Since(start) > 3*time.Second {
				t.Fatal("command cancellation was not bounded")
			}
			if scenario.hangRequest || scenario.hangCommand || scenario.noClose {
				if !errors.Is(result.Err(), context.DeadlineExceeded) {
					t.Fatalf("lost timeout: %+v", result)
				}
				want := ExecutionUnknown
				if scenario.noClose {
					want = ExecutionCompleted
				}
				if result.Outcome != want {
					t.Fatalf("incorrect timeout outcome: %+v", result)
				}
			} else if result.Err() != nil || !result.Truncated || len(result.Output) > 160 {
				t.Fatalf("output not bounded: %+v", result)
			}
			if scenario.attempts.Load() != 1 {
				t.Fatal("command was replayed")
			}
		})
	}
}

func TestExecuteCommandRejectsBeforeDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, work := range []context.Context{nil, ctx, t.Context()} {
		result := (*Client)(nil).ExecuteCommand(work, CommandPlan{})
		if result.Err() == nil || result.Outcome != ExecutionNotStarted {
			t.Fatalf("invalid call accepted: %+v", result)
		}
	}
}

func TestExecuteCommandOpenTimeout(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	// Fixture cleanup runs first, so the peer waiting for its test context is
	// not mistaken for a leaked production worker.
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	scenario := &commandFixture{stallOpen: true}
	client := commandTestClient(t, scenario)
	client.handshakeTimeout = 30 * time.Millisecond
	plan, err := PlanCommand("must-not-start", CommandOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result := client.ExecuteCommand(t.Context(), plan)
	if result.Outcome != ExecutionNotStarted || !errors.Is(result.Err(), context.DeadlineExceeded) || scenario.attempts.Load() != 0 {
		t.Fatalf("channel-open timeout incorrectly classified: %+v", result)
	}
}

func TestExecuteCommandCallerCancellation(t *testing.T) {
	scenario := &commandFixture{hangCommand: true, commands: make(chan string, 1)}
	client := commandTestClient(t, scenario)
	plan, err := PlanCommand("side-effect", CommandOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	t.Cleanup(func() { cancel(); workers.Wait() })
	done := make(chan CommandResult, 1)
	workers.Go(func() { done <- client.ExecuteCommand(ctx, plan) })
	select {
	case <-scenario.commands:
	case <-time.After(3 * time.Second):
		t.Fatal("command was not dispatched")
	}
	cancel()
	result := <-done
	if result.Outcome != ExecutionUnknown || !errors.Is(result.Err(), context.Canceled) || scenario.attempts.Load() != 1 {
		t.Fatalf("cancellation lost state or replayed command: %+v", result)
	}
}

func TestCommandTerminationDoesNotOverwriteConfirmedResult(t *testing.T) {
	observation := &commandObservation{result: CommandResult{Outcome: ExecutionUnknown}}
	for _, status := range []uint32{127, 0} {
		request := &cryptoSSH.Request{Type: "exit-status", Payload: cryptoSSH.Marshal(struct{ Status uint32 }{status})}
		if _, err := observeCommandTermination(request, observation); err != nil {
			t.Fatal(err)
		}
	}
	result := observation.snapshot()
	if result.Outcome != ExecutionCompleted || result.ExitCode == nil || *result.ExitCode != 127 || result.IOErr == nil {
		t.Fatalf("contradictory status overwrote confirmed termination: %+v", result)
	}
}

// Hold transport reads after exec acceptance, including reads already in
// progress. The peer cannot consume/acknowledge SSH_MSG_CHANNEL_CLOSE. Fixture
// cancellation releases this gate and joins all server workers.
type heldReadConn struct {
	net.Conn
	held    *atomic.Bool
	release <-chan struct{}
}

func (c *heldReadConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if c.held.Load() {
		<-c.release
	}
	return n, err
}
