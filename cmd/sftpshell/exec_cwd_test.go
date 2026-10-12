package sftpshell

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func startMockSSHListener(t *testing.T, onExec func(cmd string)) (string, int, func()) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey failed: %v", err)
	}
	serverConfig := &cryptoSSH.ServerConfig{
		NoClientAuth: true,
		PasswordCallback: func(_ cryptoSSH.ConnMetadata, _ []byte) (*cryptoSSH.Permissions, error) {
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	addr := listener.Addr().(*net.TCPAddr)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				sConn, chans, reqs, err := cryptoSSH.NewServerConn(c, serverConfig)
				if err != nil {
					return
				}
				defer func() { _ = sConn.Close() }()
				wg.Add(1)
				go func() {
					defer wg.Done()
					cryptoSSH.DiscardRequests(reqs)
				}()
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unknown channel type")
						continue
					}
					ch, requests, err := newChan.Accept()
					if err != nil {
						return
					}
					wg.Add(1)
					go func(channel cryptoSSH.Channel, in <-chan *cryptoSSH.Request) {
						defer wg.Done()
						defer func() { _ = channel.Close() }()
						for req := range in {
							switch req.Type {
							case "exec":
								var payload struct{ Command string }
								if err := cryptoSSH.Unmarshal(req.Payload, &payload); err == nil && onExec != nil {
									onExec(payload.Command)
								}
								_ = req.Reply(true, nil)
								_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
								return
							case "pty-req":
								_ = req.Reply(true, nil)
							default:
								_ = req.Reply(false, nil)
							}
						}
					}(ch, requests)
				}
			}(conn)
		}
	}()

	cleanup := func() {
		_ = listener.Close()
		wg.Wait()
	}
	return addr.IP.String(), addr.Port, cleanup
}

func startMockSSHExecServer(t *testing.T, onExec func(cmd string)) (*cryptoSSH.Client, func()) {
	t.Helper()
	host, port, stopServer := startMockSSHListener(t, onExec)
	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	clientConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		stopServer()
		t.Fatalf("dial mock ssh server failed: %v", err)
	}
	cConn, chans, reqs, err := cryptoSSH.NewClientConn(clientConn, targetAddr, &cryptoSSH.ClientConfig{
		User:            "test",
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		_ = clientConn.Close()
		stopServer()
		t.Fatalf("client handshake failed: %v", err)
	}
	rawClient := cryptoSSH.NewClient(cConn, chans, reqs)

	cleanup := func() {
		_ = rawClient.Close()
		stopServer()
	}
	return rawClient, cleanup
}

func decodePowerShellBase64(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64 failed: %v", err)
	}
	if len(raw)%2 != 0 {
		t.Fatalf("invalid UTF-16LE length: %d", len(raw))
	}
	u16 := make([]uint16, len(raw)/2)
	for i := range u16 {
		u16[i] = uint16(raw[i*2]) | uint16(raw[i*2+1])<<8
	}
	return string(utf16.Decode(u16))
}

func TestHandleExec_ServerInterpreterCwdRejection(t *testing.T) {
	connCfg := ssh.ConnectionConfig{
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterServer,
			LaunchDialect: ssh.LaunchPOSIX,
		},
	}
	client := ssh.NewTestClient(connCfg)
	var stdout, stderr bytes.Buffer

	for _, tc := range []struct {
		name string
		cwd  string
	}{
		{name: "root slash rejected", cwd: "/"},
		{name: "non-root cwd rejected", cwd: "/remote/dir"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Shell{
				batch:     true,
				cwd:       tc.cwd,
				sshClient: client,
				stdout:    &stdout,
				stderr:    &stderr,
			}

			err := s.handleExec(context.Background(), []string{"ls", "-la"})
			if err == nil {
				t.Fatalf("expected handleExec to reject cwd %q with server interpreter, got nil", tc.cwd)
			}
			if !strings.Contains(err.Error(), "server interpreter does not support inheriting working directory") {
				t.Errorf("error %q does not mention server interpreter inheritance", err.Error())
			}
		})
	}
}

func TestHandleExec_CmdWorkingDirRejection(t *testing.T) {
	connCfg := ssh.ConnectionConfig{
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		},
	}
	client := ssh.NewTestClient(connCfg)
	var stdout, stderr bytes.Buffer

	for _, tc := range []struct {
		name string
		cwd  string
	}{
		{name: "percent expansion", cwd: `C:\Users\%USERNAME%`},
		{name: "delayed expansion", cwd: `C:\path!name`},
		{name: "caret escape", cwd: `C:\path^name`},
		{name: "double quotes", cwd: `C:\path"name`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Shell{
				batch:     true,
				cwd:       tc.cwd,
				sshClient: client,
				stdout:    &stdout,
				stderr:    &stderr,
			}

			err := s.handleExec(context.Background(), []string{"dir"})
			if err == nil {
				t.Fatalf("expected handleExec to reject cwd %q with cmd interpreter, got nil", tc.cwd)
			}
			if !errors.Is(err, ssh.ErrExecutionValidation) {
				t.Errorf("expected ErrExecutionValidation, got: %v", err)
			}
		})
	}
}

func TestHandleExec_EmptyArgsError(t *testing.T) {
	initTestI18n(t)
	s := &Shell{}
	err := s.handleExec(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on empty args, got nil")
	}
}

func TestHandleExec_InteractiveMode_RequiresFileStdin(t *testing.T) {
	for _, tc := range []struct {
		name      string
		execution *ssh.ExecutionConfig
	}{
		{
			name:      "unconfigured execution",
			execution: nil,
		},
		{
			name: "configured execution",
			execution: &ssh.ExecutionConfig{
				Interpreter:   ssh.InterpreterSh,
				LaunchDialect: ssh.LaunchPOSIX,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connCfg := ssh.ConnectionConfig{
				Execution: tc.execution,
			}
			client := ssh.NewTestClient(connCfg)
			var stdout, stderr bytes.Buffer
			s := &Shell{
				batch:     false,
				cwd:       "",
				sshClient: client,
				stdin:     strings.NewReader("echo test"),
				stdout:    &stdout,
				stderr:    &stderr,
			}

			err := s.handleExec(context.Background(), []string{"echo", "hi"})
			if err == nil {
				t.Fatal("expected error when interactive stdin is not an *os.File, got nil")
			}
			if !strings.Contains(err.Error(), "interactive SFTP shell stdin must be an *os.File") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestHandleExec_BatchExecution_InterpretersEndToEnd(t *testing.T) {
	initTestI18n(t)

	tests := []struct {
		name          string
		execution     *ssh.ExecutionConfig
		cwd           string
		args          []string
		wantErr       string
		verifyPayload func(t *testing.T, payload string)
	}{
		{
			name:      "unconfigured execution fails safely when cwd probe has no valid response",
			execution: nil,
			cwd:       "/var/log",
			args:      []string{"ls", "-la"},
			wantErr:   "SSH execution probe failed",
		},
		{
			name:      "unconfigured execution with empty cwd runs server command directly",
			execution: nil,
			cwd:       "",
			args:      []string{"uptime"},
			verifyPayload: func(t *testing.T, payload string) {
				expected := "uptime"
				if payload != expected {
					t.Errorf("expected payload %q, got %q", expected, payload)
				}
			},
		},
		{
			name: "explicit bash execution in batch without login defaults to non-login",
			execution: &ssh.ExecutionConfig{
				Interpreter:   ssh.InterpreterBash,
				LaunchDialect: ssh.LaunchPOSIX,
			},
			cwd:  "/var/log",
			args: []string{"ls", "-la"},
			verifyPayload: func(t *testing.T, payload string) {
				expected := "bash -c 'cd -- '\\''/var/log'\\'' && ls -la'"
				if payload != expected {
					t.Errorf("expected payload %q, got %q", expected, payload)
				}
			},
		},
		{
			name: "explicit bash execution in batch with login enabled",
			execution: func() *ssh.ExecutionConfig {
				loginTrue := true
				return &ssh.ExecutionConfig{
					Interpreter:   ssh.InterpreterBash,
					LaunchDialect: ssh.LaunchPOSIX,
					Login:         &loginTrue,
				}
			}(),
			cwd:  "/var/log",
			args: []string{"ls", "-la"},
			verifyPayload: func(t *testing.T, payload string) {
				expected := "bash -l -c 'cd -- '\\''/var/log'\\'' && ls -la'"
				if payload != expected {
					t.Errorf("expected payload %q, got %q", expected, payload)
				}
			},
		},
		{
			name: "sh interpreter with working directory",
			execution: &ssh.ExecutionConfig{
				Interpreter:   ssh.InterpreterSh,
				LaunchDialect: ssh.LaunchPOSIX,
			},
			cwd:  "/var/log",
			args: []string{"ls", "-la"},
			verifyPayload: func(t *testing.T, payload string) {
				expected := "sh -c 'cd -- '\\''/var/log'\\'' && ls -la'"
				if payload != expected {
					t.Errorf("expected payload %q, got %q", expected, payload)
				}
			},
		},
		{
			name: "powershell interpreter with cmd launch dialect",
			execution: &ssh.ExecutionConfig{
				Interpreter:   ssh.InterpreterPowerShell,
				LaunchDialect: ssh.LaunchCmd,
			},
			cwd:  `C:\Temp`,
			args: []string{"Get-Date"},
			verifyPayload: func(t *testing.T, payload string) {
				prefix := "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
				if !strings.HasPrefix(payload, prefix) {
					t.Fatalf("expected payload to start with %q, got %q", prefix, payload)
				}
				encoded := strings.TrimPrefix(payload, prefix)
				decoded := decodePowerShellBase64(t, encoded)
				if !strings.Contains(decoded, `Set-Location -LiteralPath 'C:\Temp' -ErrorAction Stop; Get-Date`) {
					t.Errorf("decoded PowerShell script %q does not contain expected location command", decoded)
				}
			},
		},
		{
			name: "pwsh interpreter with posix launch dialect",
			execution: &ssh.ExecutionConfig{
				Interpreter:   ssh.InterpreterPwsh,
				LaunchDialect: ssh.LaunchPOSIX,
			},
			cwd:  "/opt/app",
			args: []string{"./start.ps1"},
			verifyPayload: func(t *testing.T, payload string) {
				prefix := "pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
				if !strings.HasPrefix(payload, prefix) {
					t.Fatalf("expected payload to start with %q, got %q", prefix, payload)
				}
				encoded := strings.TrimPrefix(payload, prefix)
				decoded := decodePowerShellBase64(t, encoded)
				if !strings.Contains(decoded, `Set-Location -LiteralPath '/opt/app' -ErrorAction Stop; ./start.ps1`) {
					t.Errorf("decoded pwsh script %q does not contain expected location command", decoded)
				}
			},
		},
		{
			name: "cmd interpreter with cmd launch dialect",
			execution: &ssh.ExecutionConfig{
				Interpreter:   ssh.InterpreterCmd,
				LaunchDialect: ssh.LaunchCmd,
			},
			cwd:  `C:\Tools`,
			args: []string{"dir", "/b"},
			verifyPayload: func(t *testing.T, payload string) {
				expected := `cmd.exe /d /s /c "cd /d "C:\Tools" && dir /b"`
				if payload != expected {
					t.Errorf("expected payload %q, got %q", expected, payload)
				}
			},
		},
		{
			name: "cmd interpreter with quotes and operators inside arguments",
			execution: &ssh.ExecutionConfig{
				Interpreter:   ssh.InterpreterCmd,
				LaunchDialect: ssh.LaunchCmd,
			},
			cwd:  `C:\Tools`,
			args: []string{"echo", `"A&B"`},
			verifyPayload: func(t *testing.T, payload string) {
				expected := `cmd.exe /d /s /c "cd /d "C:\Tools" && echo "A^&B""`
				if payload != expected {
					t.Errorf("expected payload %q, got %q", expected, payload)
				}
			},
		},
		{
			name: "server interpreter with empty cwd",
			execution: &ssh.ExecutionConfig{
				Interpreter:   ssh.InterpreterServer,
				LaunchDialect: ssh.LaunchPOSIX,
			},
			cwd:  "",
			args: []string{"uptime"},
			verifyPayload: func(t *testing.T, payload string) {
				expected := "uptime"
				if payload != expected {
					t.Errorf("expected payload %q, got %q", expected, payload)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var recordedCommand string
			var mu sync.Mutex

			rawClient, cleanup := startMockSSHExecServer(t, func(cmd string) {
				mu.Lock()
				defer mu.Unlock()
				recordedCommand = cmd
			})
			defer cleanup()

			connCfg := ssh.ConnectionConfig{
				Execution: tc.execution,
			}
			client := ssh.NewTestClientWithRaw(rawClient, connCfg)
			var stdout, stderr bytes.Buffer
			s := &Shell{
				batch:     true,
				cwd:       tc.cwd,
				sshClient: client,
				stdout:    &stdout,
				stderr:    &stderr,
			}

			err := s.handleExec(context.Background(), tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("handleExec failed: %v", err)
			}

			mu.Lock()
			cmd := recordedCommand
			mu.Unlock()

			tc.verifyPayload(t, cmd)
		})
	}
}

func TestHandleExec_ConnectorIntegration_WithNodeExecution(t *testing.T) {
	initTestI18n(t)

	var recordedCommand string
	var mu sync.Mutex

	host, port, stopServer := startMockSSHListener(t, func(cmd string) {
		mu.Lock()
		defer mu.Unlock()
		recordedCommand = cmd
	})
	defer stopServer()

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id1", models.Identity{User: "test", AuthType: "password", Password: "pwd"})

	// Node 1: server interpreter
	cfg.Nodes.Set("node-server", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterServer,
			LaunchDialect: ssh.LaunchPOSIX,
		},
	})

	// Node 2: powershell interpreter
	cfg.Nodes.Set("node-ps", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterPowerShell,
			LaunchDialect: ssh.LaunchCmd,
		},
	})

	connector := adapter.NewConnectorWithAdapterOptions(
		config.NewProviderWithoutOpenSSH(cfg),
		[]adapter.Option{
			adapter.WithSessionAuthOverride("node-server", adapter.SessionAuth{Password: "pwd"}),
			adapter.WithSessionAuthOverride("node-ps", adapter.SessionAuth{Password: "pwd"}),
		},
	)
	connector.AcceptNewHostKey.Store(true)

	t.Run("server node rejects non-empty cwd and executes verbatim with empty cwd", func(t *testing.T) {
		client, err := connector.Connect(context.Background(), "node-server")
		if err != nil {
			t.Fatalf("connector.Connect failed: %v", err)
		}
		defer func() { _ = client.Interrupt() }()

		if client.Execution() == nil || client.Execution().Interpreter != ssh.InterpreterServer {
			t.Fatalf("expected client Execution with server interpreter, got: %+v", client.Execution())
		}

		var stdout, stderr bytes.Buffer
		s := &Shell{
			batch:     true,
			cwd:       "/var/log",
			sshClient: client,
			stdout:    &stdout,
			stderr:    &stderr,
		}

		// Non-empty cwd must fail
		err = s.handleExec(context.Background(), []string{"uptime"})
		if err == nil {
			t.Fatal("expected handleExec to reject non-empty cwd with server interpreter, got nil")
		}

		// Empty cwd must succeed and dispatch verbatim command
		s.cwd = ""
		err = s.handleExec(context.Background(), []string{"uptime"})
		if err != nil {
			t.Fatalf("handleExec with empty cwd failed: %v", err)
		}

		mu.Lock()
		cmd := recordedCommand
		mu.Unlock()
		if cmd != "uptime" {
			t.Errorf("expected verbatim payload %q, got %q", "uptime", cmd)
		}
	})

	t.Run("powershell node wraps command with powershell adapter", func(t *testing.T) {
		client, err := connector.Connect(context.Background(), "node-ps")
		if err != nil {
			t.Fatalf("connector.Connect failed: %v", err)
		}
		defer func() { _ = client.Interrupt() }()

		if client.Execution() == nil || client.Execution().Interpreter != ssh.InterpreterPowerShell {
			t.Fatalf("expected client Execution with powershell interpreter, got: %+v", client.Execution())
		}

		var stdout, stderr bytes.Buffer
		s := &Shell{
			batch:     true,
			cwd:       `C:\Temp`,
			sshClient: client,
			stdout:    &stdout,
			stderr:    &stderr,
		}

		err = s.handleExec(context.Background(), []string{"Get-Date"})
		if err != nil {
			t.Fatalf("handleExec failed: %v", err)
		}

		mu.Lock()
		cmd := recordedCommand
		mu.Unlock()

		prefix := "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
		if !strings.HasPrefix(cmd, prefix) {
			t.Fatalf("expected payload to start with %q, got %q", prefix, cmd)
		}
		encoded := strings.TrimPrefix(cmd, prefix)
		decoded := decodePowerShellBase64(t, encoded)
		if !strings.Contains(decoded, `Set-Location -LiteralPath 'C:\Temp' -ErrorAction Stop; Get-Date`) {
			t.Errorf("decoded PowerShell script %q does not contain expected location command", decoded)
		}
	})
}
