package ssh

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestGetSudoParams(t *testing.T) {
	tests := []struct {
		name        string
		mode        SudoMode
		password    string
		suPwd       string
		expectedCmd string
		expectedPwd string
	}{
		{"sudo mode", SudoModeSudo, "mypass", "", "sudo -i", "mypass"},
		{"sudoer mode", SudoModeSudoer, "mypass", "", "sudo -i", ""},
		{"su mode", SudoModeSu, "", "rootpass", "su -", "rootpass"},
		{"root mode", SudoModeRoot, "", "", "", ""},
		{"invalid mode", SudoMode("unknown"), "", "", "", ""},
		{"empty mode", SudoModeNone, "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				cfg: &ClientConfig{
					SudoMode: tt.mode,
					SuPwd:    tt.suPwd,
					Password: tt.password,
				},
			}

			cmd, pwd := c.getSudoParams()
			if cmd != tt.expectedCmd {
				t.Errorf("expected cmd %q, got %q", tt.expectedCmd, cmd)
			}
			if pwd != tt.expectedPwd {
				t.Errorf("expected pwd %q, got %q", tt.expectedPwd, pwd)
			}
		})
	}
}

func TestPasswordPromptRegex_TwoLayerFallback(t *testing.T) {
	// 1. 节点级正则优先
	c := newClient(nil, nil, &ClientConfig{PasswordPromptPattern: `(?i)custom:`}, nil, `(?i)global:`)
	re := c.passwordPromptRegex()
	if !re.MatchString("Custom: ") {
		t.Errorf("node-level pattern should have priority")
	}
	if re.MatchString("Global: ") {
		t.Errorf("connector-level pattern should be overridden by node-level")
	}

	// 2. 节点级为空时回落到 Connector 全局级
	c2 := newClient(nil, nil, &ClientConfig{}, nil, `(?i)global:`)
	re2 := c2.passwordPromptRegex()
	if !re2.MatchString("Global: ") {
		t.Errorf("connector-level pattern should be used when node-level is empty")
	}

	// 3. 两者均为空时回落到内置默认
	c3 := newClient(nil, nil, &ClientConfig{}, nil, "")
	re3 := c3.passwordPromptRegex()
	if !re3.MatchString("Password: ") {
		t.Errorf("default pattern should match 'Password:'")
	}
	if !re3.MatchString("密码：") {
		t.Errorf("default pattern should match Chinese prompt")
	}

	// 4. 节点级正则无效时静默降级
	c4 := newClient(nil, nil, &ClientConfig{PasswordPromptPattern: `[invalid`}, nil, "")
	re4 := c4.passwordPromptRegex()
	if !re4.MatchString("Password: ") {
		t.Errorf("should fall back to default when node-level pattern is invalid")
	}
}

func TestRunCommandWithIO_ErrorBranches(t *testing.T) {
	ctx := t.Context()

	// 1. None 模式报错
	cNone := &Client{cfg: &ClientConfig{SudoMode: SudoModeNone}}
	err := cNone.RunCommandWithIO(ctx, "ls", true, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "privilege escalation is not supported") {
		t.Errorf("expected privilege escalation not supported error, got %v", err)
	}

	// 2. Sudo 模式且无密码报错
	cSudoNoPwd := &Client{cfg: &ClientConfig{SudoMode: SudoModeSudo, Password: ""}}
	err = cSudoNoPwd.RunCommandWithIO(ctx, "ls", true, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "sudo password is required") {
		t.Errorf("expected sudo password required error, got %v", err)
	}

	// 3. 未知模式报错
	cUnknown := &Client{cfg: &ClientConfig{SudoMode: SudoMode("unknown_mode")}}
	err = cUnknown.RunCommandWithIO(ctx, "ls", true, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown sudo mode") {
		t.Errorf("expected unknown sudo mode error, got %v", err)
	}
}

type mockExecRecord struct {
	cmd      string
	stdin    string
	stdinEOF bool
}

func handleMockSSHSession(channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request, recordedCh chan<- mockExecRecord) {
	defer func() {
		if err := channel.Close(); err != nil {
			fmt.Printf("Close failed: %v", err)
		}
	}()
	var rec mockExecRecord
	for req := range requests {
		if req.Type == "pty-req" {
			_ = req.Reply(true, nil)
			continue
		}
		if req.Type == "exec" {
			if len(req.Payload) >= 4 {
				cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
				if len(req.Payload) >= 4+cmdLen {
					rec.cmd = string(req.Payload[4 : 4+cmdLen])
				}
			}
			_ = req.Reply(true, nil)

			readDone := make(chan struct{})
			go func() {
				var buf bytes.Buffer
				stdinBuf := make([]byte, 1024)
				for {
					n, err := channel.Read(stdinBuf)
					if n > 0 {
						buf.Write(stdinBuf[:n])
					}
					if err != nil {
						rec.stdinEOF = true
						break
					}
				}
				rec.stdin = buf.String()
				close(readDone)
			}()
			select {
			case <-readDone:
			case <-time.After(2 * time.Second):
			}
			recordedCh <- rec

			_, _ = channel.Write([]byte("mock_output\n"))
			_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			return
		}
		_ = req.Reply(false, nil)
	}
}

func startMockSSHCommandServer(t *testing.T, recordedCh chan<- mockExecRecord) (net.Listener, *cryptoSSH.Client) {
	t.Helper()
	listener, serverConfig := startKeepAliveTestSSHServer(t)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sConn, chans, reqs, err := cryptoSSH.NewServerConn(c, serverConfig)
				if err != nil {
					if err := c.Close(); err != nil {
						fmt.Printf("Close failed: %v", err)
					}
					return
				}
				defer func() {
					if err := sConn.Close(); err != nil {
						fmt.Printf("Close failed: %v", err)
					}
				}()
				go cryptoSSH.DiscardRequests(reqs)

				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(cryptoSSH.UnknownChannelType, "unknown channel type")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						return
					}
					go handleMockSSHSession(channel, requests, recordedCh)
				}
			}(conn)
		}
	}()

	rawClient := dialKeepAliveTestClient(t, listener.Addr().String())
	return listener, rawClient
}

//nolint:gocyclo // The subtests intentionally cover every sudo mode in one shared mock-server lifecycle.
func TestRunCommandWithIO_MockServer(t *testing.T) {
	recordedCh := make(chan mockExecRecord, 10)
	listener, rawClient := startMockSSHCommandServer(t, recordedCh)
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Errorf("unexpected listener close error: %v", err)
		}
	})
	t.Cleanup(func() {
		if err := rawClient.Close(); err != nil {
			t.Errorf("unexpected rawClient close error: %v", err)
		}
	})

	ctx := t.Context()

	// 1. 测试普通非 sudo 执行
	t.Run("NonSudoCommand", func(t *testing.T) {
		c := newClient(rawClient, nil, &ClientConfig{SudoMode: SudoModeNone}, nil, "")
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "echo hello", false, nil, &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO failed: %v", err)
		}
		if stdout.String() != "mock_output\n" {
			t.Errorf("expected stdout 'mock_output\\n', got %q", stdout.String())
		}
		rec := <-recordedCh
		expectedCmd := "bash -c 'echo hello'"
		if rec.cmd != expectedCmd {
			t.Errorf("expected command %q, got %q", expectedCmd, rec.cmd)
		}
		if !rec.stdinEOF {
			t.Error("expected command stdin EOF")
		}
	})

	// 2. 测试 Sudoer 模式执行（免密）
	t.Run("SudoerCommand", func(t *testing.T) {
		c := newClient(rawClient, nil, &ClientConfig{SudoMode: SudoModeSudoer}, nil, "")
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "ls /root", true, nil, &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO failed: %v", err)
		}
		rec := <-recordedCh
		expectedCmd := "sudo -S -p '' bash -c 'ls /root'"
		if rec.cmd != expectedCmd {
			t.Errorf("expected command %q, got %q", expectedCmd, rec.cmd)
		}
		if !rec.stdinEOF {
			t.Error("expected sudoer stdin EOF")
		}
	})

	// 3. 测试 Sudo 密码模式执行
	t.Run("SudoPasswordCommand", func(t *testing.T) {
		c := newClient(rawClient, nil, &ClientConfig{SudoMode: SudoModeSudo, Password: "secret_password"}, nil, "")
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "ls /root", true, strings.NewReader("extra_stdin\n"), &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO failed: %v", err)
		}
		rec := <-recordedCh
		expectedCmd := "sudo -S -p '' bash -c 'ls /root'"
		if rec.cmd != expectedCmd {
			t.Errorf("expected command %q, got %q", expectedCmd, rec.cmd)
		}
		if !strings.HasPrefix(rec.stdin, "secret_password\n") {
			t.Errorf("expected stdin to start with password, got %q", rec.stdin)
		}
		if !rec.stdinEOF {
			t.Error("expected sudo stdin EOF")
		}
	})

	// 4. 测试 Root 模式执行
	t.Run("RootCommand", func(t *testing.T) {
		c := newClient(rawClient, nil, &ClientConfig{SudoMode: SudoModeRoot}, nil, "")
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "ls /root", true, nil, &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO failed: %v", err)
		}
		rec := <-recordedCh
		expectedCmd := "bash -c 'ls /root'"
		if rec.cmd != expectedCmd {
			t.Errorf("expected command %q, got %q", expectedCmd, rec.cmd)
		}
		if !rec.stdinEOF {
			t.Error("expected root stdin EOF")
		}
	})

	// 5. 测试 Su 模式执行（命令只执行一次，stdin 严格等于 password + payload 串行传输）
	t.Run("SuCommand", func(t *testing.T) {
		c := newClient(rawClient, nil, &ClientConfig{SudoMode: SudoModeSu, SuPwd: "root_password"}, nil, "")
		var stdout, stderr bytes.Buffer
		err := c.RunCommandWithIO(ctx, "cat /etc/shadow", true, strings.NewReader("user_payload\n"), &stdout, &stderr)
		if err != nil {
			t.Fatalf("RunCommandWithIO failed: %v", err)
		}
		rec := <-recordedCh
		expectedCmd := "export LC_ALL=C; su - root -c 'cat /etc/shadow'"
		if rec.cmd != expectedCmd {
			t.Errorf("expected command %q, got %q", expectedCmd, rec.cmd)
		}
		expectedStdin := "root_password\nuser_payload\n"
		if rec.stdin != expectedStdin {
			t.Errorf("expected stdin strictly %q, got %q", expectedStdin, rec.stdin)
		}
		if !rec.stdinEOF {
			t.Error("expected su stdin EOF")
		}
	})
}
