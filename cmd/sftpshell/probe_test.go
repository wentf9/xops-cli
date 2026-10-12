package sftpshell

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func lazySFTPClient(t *testing.T, dialect ssh.LaunchDialect, execution *ssh.ExecutionConfig, handler func(string, cryptoSSH.Channel)) (*ssh.Client, *sshfixture.Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	options := sshfixture.Options{ExecHandler: handler}
	if dialect == ssh.LaunchCmd {
		options.ServerVersion = "SSH-2.0-OpenSSH_for_Windows_9.5"
	}
	server, err := sshfixture.NewWithOptions(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
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
	connection, channels, requests, err := cryptoSSH.NewClientConn(conn, server.Address, &cryptoSSH.ClientConfig{
		User: "fixture", Auth: []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(server.HostKey), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewTestClientWithRaw(cryptoSSH.NewClient(connection, channels, requests), ssh.ConnectionConfig{Execution: execution.Clone()})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client, server
}

func writeSFTPProbeResult(t *testing.T, ch cryptoSSH.Channel, output string) {
	t.Helper()
	if _, err := io.WriteString(ch, output); err != nil {
		t.Error(err)
	}
	if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
		t.Error(err)
	}
}

func TestSFTPCwdLazyProbeAndCommandIsolation(t *testing.T) {
	for _, dialect := range []ssh.LaunchDialect{ssh.LaunchPOSIX, ssh.LaunchCmd, ssh.LaunchPowerShell} {
		t.Run(string(dialect), func(t *testing.T) {
			client, server := lazySFTPClient(t, dialect, nil, func(command string, ch cryptoSSH.Channel) {
				handleLazySFTPExec(t, dialect, command, ch)
			})
			var output bytes.Buffer
			cwd := "/srv/app"
			if dialect != ssh.LaunchPOSIX {
				cwd = "/C:/Temp"
			}
			shell := &Shell{batch: true, cwd: cwd, sshClient: client, stdout: &output, stderr: &output}
			for range 2 {
				if err := shell.handleExec(t.Context(), []string{"echo", "hi"}); err != nil {
					t.Fatal(err)
				}
			}
			shell.cwd = ""
			if err := shell.handleExec(t.Context(), []string{"echo", "plain"}); err != nil {
				t.Fatal(err)
			}
			wantRequests := int32(5)
			if dialect == ssh.LaunchPowerShell {
				wantRequests = 7
			}
			if server.Executed.Load() != wantRequests || client.Execution() != nil {
				t.Fatal("cwd probe repeated or changed ordinary command defaults")
			}
		})
	}
}

func TestSFTPCwdProbeFailureIsCached(t *testing.T) {
	client, server := lazySFTPClient(t, ssh.LaunchPOSIX, nil, func(_ string, ch cryptoSSH.Channel) {
		writeSFTPProbeResult(t, ch, "restricted\n")
	})
	shell := &Shell{batch: true, cwd: "/srv/app", sshClient: client, stdout: io.Discard, stderr: io.Discard}
	for range 2 {
		if err := shell.handleExec(t.Context(), []string{"must-not-run"}); err == nil {
			t.Fatal("failed probe authorized user command")
		}
	}
	if server.Executed.Load() != 3 {
		t.Fatal("failed cwd probe repeated or executed user work")
	}
}

func TestSFTPExplicitPwshColdConnectionUsesRuntimePlatform(t *testing.T) {
	execution := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPwsh, LaunchDialect: ssh.LaunchPowerShell}
	client, server := lazySFTPClient(t, ssh.LaunchPowerShell, execution, func(command string, ch cryptoSSH.Channel) {
		const prefix = "& pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
		if !strings.HasPrefix(command, prefix) {
			t.Errorf("explicit pwsh was replaced or probed: %q", command)
			return
		}
		decoded := decodePowerShellBase64(t, strings.TrimSuffix(strings.TrimPrefix(command, prefix), "; exit $LASTEXITCODE"))
		if !strings.Contains(decoded, "$IsWindows") || !strings.Contains(decoded, "'C:/Temp'") || !strings.Contains(decoded, "'/C:/Temp'") {
			t.Errorf("cold connection did not preserve both platform path forms: %q", decoded)
		}
		writeSFTPProbeResult(t, ch, "done")
	})
	shell := &Shell{batch: true, cwd: "/C:/Temp", sshClient: client, stdout: io.Discard, stderr: io.Discard}
	if err := shell.handleExec(t.Context(), []string{"echo", "hi"}); err != nil {
		t.Fatal(err)
	}
	if _, cached := client.CachedExecutionProbe(); cached || server.Executed.Load() != 1 || client.Execution().Interpreter != ssh.InterpreterPwsh {
		t.Fatal("explicit pwsh cwd execution started a probe or changed interpreter")
	}
}

func handleLazySFTPExec(t *testing.T, dialect ssh.LaunchDialect, command string, ch cryptoSSH.Channel) {
	t.Helper()
	output, code := "done", uint32(0)
	switch {
	case strings.Contains(command, "__XOPS_DIALECT_POSIX__"):
		output = "__XOPS_DIALECT_POSIX__:Linux:/bin/ash\n"
		if dialect == ssh.LaunchPowerShell {
			code = 1
			output = "syntax error"
		}
	case strings.HasPrefix(command, "echo __XOPS_DIALECT_CMD__:"):
		output = "__XOPS_DIALECT_CMD__:C:\\Windows\\system32\\cmd.exe\n"
		if dialect == ssh.LaunchPowerShell {
			output = "__XOPS_DIALECT_CMD__:%COMSPEC%\n"
		}
	case strings.Contains(command, "__XOPS_DIALECT_POWERSHELL__"):
		output = "__XOPS_DIALECT_POWERSHELL__:7.4.6\n__XOPS_PLATFORM__:Win32NT\n"
	case strings.Contains(command, "__XOPS_INTERP__"):
		output = "__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n"
		if dialect == ssh.LaunchCmd {
			output = "__XOPS_INTERP__:powershell\n__XOPS_INTERP__:cmd\n__XOPS_INTERP_END__\n"
		}
		if dialect == ssh.LaunchPowerShell {
			output = "__XOPS_INTERP__:pwsh\n__XOPS_INTERP_END__\n"
		}
	case command == "echo plain":
	default:
		verifyLazySFTPCwdPayload(t, dialect, command)
	}
	if _, err := io.WriteString(ch, output); err != nil {
		t.Error(err)
	}
	if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{code})); err != nil {
		t.Error(err)
	}
}

func verifyLazySFTPCwdPayload(t *testing.T, dialect ssh.LaunchDialect, command string) {
	t.Helper()
	if dialect == ssh.LaunchPOSIX {
		if !strings.HasPrefix(command, "sh -c ") || !strings.Contains(command, "cd --") || !strings.Contains(command, "/srv/app") {
			t.Errorf("cwd not applied through detected sh: %q", command)
		}
		return
	}
	prefix := "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
	if dialect == ssh.LaunchPowerShell {
		prefix = "& pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
	}
	if !strings.HasPrefix(command, prefix) {
		t.Errorf("cwd did not select controlled Windows adapter: %q", command)
		return
	}
	decoded := decodePowerShellBase64(t, strings.TrimSuffix(strings.TrimPrefix(command, prefix), "; exit $LASTEXITCODE"))
	if dialect == ssh.LaunchPowerShell {
		if !strings.Contains(decoded, "$IsWindows") || !strings.Contains(decoded, "'C:/Temp'") || !strings.Contains(decoded, "'/C:/Temp'") {
			t.Errorf("pwsh payload did not retain platform-specific cwd forms: %q", decoded)
		}
	} else if !strings.Contains(decoded, "Set-Location -LiteralPath 'C:/Temp'") {
		t.Errorf("cwd missing from PowerShell payload: %q", decoded)
	}
}
