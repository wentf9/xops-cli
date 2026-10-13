package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func executionProbeClient(t *testing.T, version string, handler func(context.Context, string, cryptoSSH.Channel)) (*Client, *sshfixture.Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ServerVersion: version,
		ExecHandler:   func(command string, channel cryptoSSH.Channel) { handler(ctx, command, channel) },
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", server.Address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	sshConn, channels, requests, err := cryptoSSH.NewClientConn(conn, server.Address, &cryptoSSH.ClientConfig{
		User: "probe-test", Auth: []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(server.HostKey), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{sshClient: cryptoSSH.NewClient(sshConn, channels, requests), rootConn: conn}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client, server
}

func replyExecutionProbe(t *testing.T, ctx context.Context, channel cryptoSSH.Channel, output string, status uint32) {
	t.Helper()
	if _, err := io.WriteString(channel, output); err != nil {
		if ctx.Err() == nil && !errors.Is(err, io.EOF) {
			t.Error(err)
		}
		return
	}
	if _, err := channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{status})); err != nil && ctx.Err() == nil && !errors.Is(err, io.EOF) {
		t.Error(err)
	}
}

func TestProbeExecutionConfigDialects(t *testing.T) {
	for _, tt := range []struct {
		name, version, detection, frame, interpreters string
		dialect                                       LaunchDialect
		want                                          Interpreter
		commands                                      int32
	}{
		{"Linux", "", probePOSIX, "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n", "bash\nsh\npwsh", LaunchPOSIX, InterpreterBash, 2},
		{"fish outer shell", "", probeFish, "__XOPS_DIALECT_FISH__:4.9.3\n__XOPS_FISH_OS__:Linux\n__XOPS_FISH_SHELL__:/usr/bin/fish\n", "bash\nsh\nfish", LaunchFish, InterpreterFish, 5},
		{"fish only", "", probeFish, "__XOPS_DIALECT_FISH__:3.6.0\n__XOPS_FISH_OS__:Darwin\n__XOPS_FISH_SHELL__:\n", "fish", LaunchFish, InterpreterFish, 5},
		{"zsh default shell", "", probePOSIX, "__XOPS_DIALECT_POSIX__:Darwin:/bin/zsh\n", "bash\nsh\nzsh", LaunchPOSIX, InterpreterZsh, 2},
		{"zsh only", "", probePOSIX, "__XOPS_DIALECT_POSIX__:Linux:/usr/bin/zsh\n", "zsh", LaunchPOSIX, InterpreterZsh, 2},
		{"Alpine ash", "", probePOSIX, "__XOPS_DIALECT_POSIX__:Linux:/bin/ash\n", "sh", LaunchPOSIX, InterpreterSh, 2},
		{"Darwin empty SHELL", "", probePOSIX, "__XOPS_DIALECT_POSIX__:Darwin:\n", "bash\nsh", LaunchPOSIX, InterpreterBash, 2},
		{"CMD priority", "SSH-2.0-OpenSSH_for_Windows_9.5", probeCmd, "__XOPS_DIALECT_CMD__:C:\\Windows\\system32\\cmd.exe\r\n", "powershell\ncmd", LaunchCmd, InterpreterServer, 2},
		{"CMD only", "", probeCmd, "__XOPS_DIALECT_CMD__:C:\\Windows\\system32\\cmd.exe\n", "cmd", LaunchCmd, InterpreterCmd, 3},
		{"PowerShell", "SSH-2.0-Microsoft:Windows", probePowerShell, "__XOPS_DIALECT_POWERSHELL__:5.1.19041.1\n", "powershell\npwsh\ncmd", LaunchPowerShell, InterpreterPowerShell, 3},
		{"pwsh DefaultShell", "", probePowerShell, "__XOPS_DIALECT_POWERSHELL__:7.5.0\n", "pwsh", LaunchPowerShell, InterpreterPwsh, 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			enumeration, err := probeInterpreterCommand(tt.dialect)
			if err != nil {
				t.Fatal(err)
			}
			client, server := executionProbeClient(t, tt.version, func(ctx context.Context, command string, channel cryptoSSH.Channel) {
				switch command {
				case tt.detection:
					replyExecutionProbe(t, ctx, channel, "Welcome\r\nLast login: yesterday\n"+tt.frame, 0)
				case enumeration:
					frames := "MOTD: hello\n__XOPS_INTERP__:" + strings.ReplaceAll(tt.interpreters, "\n", "\n__XOPS_INTERP__:") + "\n__XOPS_INTERP_END__\n"
					replyExecutionProbe(t, ctx, channel, frames, 0)
				default:
					// CMD's percent expansion stays literal under PowerShell.
					if command == probeCmd && tt.dialect == LaunchPowerShell {
						replyExecutionProbe(t, ctx, channel, "__XOPS_DIALECT_CMD__:%COMSPEC%\n", 0)
					} else {
						replyExecutionProbe(t, ctx, channel, "syntax error\n", 127)
					}
				}
			})
			result, err := client.ProbeExecutionConfig(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if result.DetectedDialect != tt.dialect || result.RecommendedInterpreter != tt.want {
				t.Fatalf("result = %+v", result)
			}
			assertProbeMetadata(t, result)
			if got := server.Executed.Load(); got != tt.commands {
				t.Fatalf("exec requests = %d, want %d", got, tt.commands)
			}
			if client.Execution() != nil {
				t.Fatal("probe must not change the live execution configuration")
			}
		})
	}
}

func TestProbeExecutionConfigConcurrentCache(t *testing.T) {
	client, server := executionProbeClient(t, "", func(ctx context.Context, command string, channel cryptoSSH.Channel) {
		output := "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n"
		if command != probePOSIX {
			output = "__XOPS_INTERP__:bash\n__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n"
		}
		replyExecutionProbe(t, ctx, channel, output, 0)
	})
	var workers sync.WaitGroup
	for range 32 {
		// All callers finish when the bounded probe finishes or ctx cancels.
		workers.Go(func() {
			result, err := client.ProbeExecutionConfig(t.Context())
			if err != nil {
				t.Error(err)
				return
			}
			result.AvailableInterpreters[0] = InterpreterCmd
			*result.SuggestedConfig.Login = true
			result.SuggestedConfig.Interpreter = InterpreterCmd
		})
	}
	workers.Wait()
	result, err := client.ProbeExecutionConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.AvailableInterpreters[0] != InterpreterBash || *result.SuggestedConfig.Login || result.SuggestedConfig.Interpreter != InterpreterBash || server.Executed.Load() != 2 {
		t.Fatalf("mutable or repeated cache: %+v, requests %d", result, server.Executed.Load())
	}
}

func TestProbeExecutionConfigFailureCache(t *testing.T) {
	for _, tt := range []struct {
		name, output string
		status       uint32
	}{
		{"unsupported shell", "Welcome\n", 0},
		{"syntax errors", "not allowed\n", 1},
		{"nonzero frame", "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := executionProbeClient(t, "", func(ctx context.Context, _ string, channel cryptoSSH.Channel) {
				replyExecutionProbe(t, ctx, channel, tt.output, tt.status)
			})
			for range 2 {
				result, err := client.ProbeExecutionConfig(t.Context())
				if !errors.Is(err, ErrExecutionProbe) || result.DetectedDialect != LaunchUnknown || result.SuggestedConfig.Interpreter != InterpreterServer {
					t.Fatalf("result = %+v, err = %v", result, err)
				}
			}
			if server.Executed.Load() != 4 {
				t.Fatalf("failed probe repeated: %d requests", server.Executed.Load())
			}
		})
	}
}

func TestProbeExecutionConfigIncompleteEnumeration(t *testing.T) {
	for _, output := range []string{"noise\n", "__XOPS_INTERP_END__\n", "__XOPS_INTERP__:bash\n", strings.Repeat("noise", probeOutputLimit) + "\n__XOPS_INTERP__:bash\n__XOPS_INTERP_END__\n"} {
		t.Run(output[:min(len(output), 20)], func(t *testing.T) {
			client, server := executionProbeClient(t, "", func(ctx context.Context, command string, channel cryptoSSH.Channel) {
				if command == probePOSIX {
					replyExecutionProbe(t, ctx, channel, "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n", 0)
					return
				}
				replyExecutionProbe(t, ctx, channel, output, 0)
			})
			result, err := client.ProbeExecutionConfig(t.Context())
			if !errors.Is(err, ErrExecutionProbe) || result.SuggestedConfig.Interpreter != InterpreterServer || server.Executed.Load() != 2 {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
		})
	}
}

func TestProbeExecutionConfigCancellationAndDeadline(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, timeout := range []time.Duration{40 * time.Millisecond, 3 * time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			client := commandTestClient(t, &commandFixture{hangCommand: true})
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			started := time.Now()
			_, err := client.ProbeExecutionConfig(ctx)
			if !errors.Is(err, ErrExecutionProbe) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err = %v", err)
			}
			if time.Since(started) > min(timeout, probeCommandTimeout)+sessionShutdownTimeout+500*time.Millisecond {
				t.Fatal("probe exceeded bounded deadline and shutdown grace")
			}
		})
	}
}

func TestProbeExecutionConfigWaiterCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	client, server := executionProbeClient(t, "", func(ctx context.Context, command string, channel cryptoSSH.Channel) {
		if command == probePOSIX {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return
			}
			replyExecutionProbe(t, ctx, channel, "__XOPS_DIALECT_POSIX__:Linux:/bin/sh\n", 0)
			return
		}
		replyExecutionProbe(t, ctx, channel, "__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n", 0)
	})
	done := make(chan error, 1)
	// Initiator exits on release or its bounded probe timeout; joined below.
	go func() { _, err := client.ProbeExecutionConfig(t.Context()); done <- err }()
	<-started
	if _, ready := client.CachedExecutionProbe(); ready {
		t.Fatal("running probe was exposed as a completed cache entry")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, err := client.ProbeExecutionConfig(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter err = %v", err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if server.Executed.Load() != 2 {
		t.Fatal("waiter cancellation interrupted or repeated shared probe")
	}
}

func TestProbeExecutionConfigInitiatorCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var posixAttempts atomic.Int32
	client, server := executionProbeClient(t, "", func(ctx context.Context, command string, channel cryptoSSH.Channel) {
		if command == probePOSIX {
			if posixAttempts.Add(1) == 1 {
				close(started)
				select {
				case <-release:
				case <-ctx.Done():
				}
				return
			}
			replyExecutionProbe(t, ctx, channel, "__XOPS_DIALECT_POSIX__:Linux:/bin/sh\n", 0)
			return
		}
		replyExecutionProbe(t, ctx, channel, "__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n", 0)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	// The caller exits on cancellation, and is joined before retrying.
	go func() { _, err := client.ProbeExecutionConfig(ctx); done <- err }()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("initiator error = %v", err)
	}
	if _, cached := client.CachedExecutionProbe(); cached {
		t.Fatal("canceled attempt appeared successful")
	}
	const waiters = 8
	results := make(chan error, waiters)
	// Each retry exits on the probe's bounded timeout; all are joined below.
	for range waiters {
		go func() {
			result, err := client.ProbeExecutionConfig(t.Context())
			if err == nil && result.RecommendedInterpreter != InterpreterSh {
				err = errors.New("retry did not discover sh")
			}
			results <- err
		}()
	}
	for range waiters {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	if server.Executed.Load() != 3 {
		t.Fatalf("retries did not share one new attempt: requests=%d", server.Executed.Load())
	}
	if _, cached := client.CachedExecutionProbe(); !cached {
		t.Fatal("successful retry was not cached")
	}
}

func TestProbeExecutionConfigTotalDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		execute := func(ctx context.Context, _ string) (string, error) {
			attempts++
			if attempts < 3 {
				time.Sleep(4200 * time.Millisecond)
				return "unsupported shell\n", nil
			}
			// This is durable blocking in the bubble, so the virtual clock advances
			// directly to the production overall deadline without wall-clock sleeps.
			<-ctx.Done()
			return "", ctx.Err()
		}
		started := time.Now()
		result, err := probeExecutionWithExecutor(t.Context(), "SSH-2.0-test", execute)
		if !errors.Is(err, ErrExecutionProbe) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("probe total deadline error = %v", err)
		}
		if elapsed := time.Since(started); elapsed != probeWorkTimeout || result.Duration != probeWorkTimeout {
			t.Fatalf("overall budget was not applied: elapsed=%s snapshot=%s", elapsed, result.Duration)
		}
		if attempts != 3 {
			t.Fatalf("timeout did not stop the current dialect attempt: requests=%d", attempts)
		}
	})
}

func TestProbeExecutionConfigValidation(t *testing.T) {
	var client *Client
	if _, err := client.ProbeExecutionConfig(t.Context()); !errors.Is(err, ErrExecutionProbe) {
		t.Fatal(err)
	}
	var noContext context.Context
	if _, err := NewTestClient(ConnectionConfig{}).ProbeExecutionConfig(noContext); !errors.Is(err, ErrExecutionProbe) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := client.ProbeExecutionConfig(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestProbeFrameParsing(t *testing.T) {
	for _, tt := range []struct{ output, command string }{
		{"prefix __XOPS_DIALECT_POSIX__:Linux:/bin/sh\n", probePOSIX},
		{"__XOPS_DIALECT_POSIX__:Linux:/bin/sh\n__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n", probePOSIX},
		{"__XOPS_DIALECT_POSIX__:Linux:$SHELL\n", probePOSIX},
		{"__XOPS_DIALECT_POSIX__::/bin/sh\n", probePOSIX},
		{"__XOPS_DIALECT_CMD__:%COMSPEC%\n", probeCmd},
		{"__XOPS_DIALECT_CMD__:cmd.exe\n", probeCmd},
		{"__XOPS_DIALECT_POWERSHELL__:1..2\n", probePowerShell},
		{"__XOPS_DIALECT_POWERSHELL__:...\n", probePowerShell},
		{"__XOPS_DIALECT_POWERSHELL__:5.1\x00\n", probePowerShell},
		{"__XOPS_DIALECT_POSIX__:Linux:/" + strings.Repeat("a", 1024) + "\n", probePOSIX},
	} {
		if dialect, _, _ := parseProbeDialect(tt.output, tt.command); dialect != LaunchUnknown {
			t.Errorf("accepted malformed frame %q", tt.output)
		}
	}
	for _, output := range []string{
		"__XOPS_INTERP__:python3\n__XOPS_INTERP_END__\n",
		"__XOPS_INTERP__:sh\n__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n",
		"__XOPS_INTERP_END__\n__XOPS_INTERP_END__\n",
		"__XOPS_INTERP_END__\n__XOPS_INTERP__:bash\n",
	} {
		if _, err := parseProbeInterpreters(output); err == nil {
			t.Errorf("accepted invalid interpreter output %q", output)
		}
	}
	got, err := parseProbeInterpreters("MOTD\r\n__XOPS_INTERP__:bash\r\n__XOPS_INTERP__:sh\r\n__XOPS_INTERP_END__\r\ntrailer\n")
	if err != nil || !reflect.DeepEqual(got, []Interpreter{InterpreterBash, InterpreterSh}) {
		t.Fatalf("interpreters = %v, err = %v", got, err)
	}
}

func TestProbeStopsOnTransportFailures(t *testing.T) {
	for _, scenario := range []*commandFixture{{reject: true}, {missing: true}, {malformed: true}, {signal: true}} {
		client := commandTestClient(t, scenario)
		if _, err := client.ProbeExecutionConfig(t.Context()); !errors.Is(err, ErrExecutionProbe) {
			t.Fatalf("err = %v", err)
		}
		if scenario.attempts.Load() != 1 {
			t.Fatalf("retried invalid command outcome: %d", scenario.attempts.Load())
		}
	}
}

func TestProbeConnectionCachesAreIndependent(t *testing.T) {
	var attempts atomic.Int32
	for range 2 {
		client, _ := executionProbeClient(t, "", func(ctx context.Context, _ string, channel cryptoSSH.Channel) {
			attempts.Add(1)
			replyExecutionProbe(t, ctx, channel, "restricted\n", 1)
		})
		if _, err := client.ProbeExecutionConfig(t.Context()); !errors.Is(err, ErrExecutionProbe) {
			t.Fatal(err)
		}
	}
	if attempts.Load() != 8 {
		t.Fatal("new connection reused an earlier connection's failed cache")
	}
}

func assertProbeMetadata(t *testing.T, result *ProbeResult) {
	t.Helper()
	if err := result.SuggestedConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	if result.DetectedDialect == LaunchPOSIX && (result.SuggestedConfig.Login == nil || *result.SuggestedConfig.Login) {
		t.Fatal("POSIX recommendation must disable login")
	}
	// Fast fixture commands may complete within the Windows clock's resolution.
	if result.Duration < 0 || result.ProbedAt.IsZero() || result.ServerVersion == "" {
		t.Fatalf("missing metadata: %+v", result)
	}
	if result.DetectedDialect == LaunchPowerShell && (result.RemoteOS != "" || result.RemoteShellPath != "") {
		t.Fatal("PowerShell language version must not imply Windows OS or shell path")
	}
}
