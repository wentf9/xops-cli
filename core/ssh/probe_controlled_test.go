package ssh

import (
	"context"
	"reflect"
	"strings"
	"testing"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestNeedsExecutionProbePreservesExplicitChoices(t *testing.T) {
	login := false
	for _, tt := range []struct {
		execution *ExecutionConfig
		want      bool
	}{
		{nil, true}, {&ExecutionConfig{}, true}, {&ExecutionConfig{LaunchDialect: LaunchUnknown}, true},
		{&ExecutionConfig{Interpreter: InterpreterServer}, false},
		{&ExecutionConfig{Interpreter: InterpreterServer, LaunchDialect: LaunchUnknown}, false},
		{&ExecutionConfig{LaunchDialect: LaunchPOSIX}, false},
		{&ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX}, false},
		{&ExecutionConfig{Login: &login}, false},
	} {
		if got := NeedsExecutionProbe(tt.execution); got != tt.want {
			t.Errorf("NeedsExecutionProbe(%+v) = %v", tt.execution, got)
		}
	}
}

func TestProbeControlledExecutionWindowsAndCache(t *testing.T) {
	client, server := executionProbeClient(t, "SSH-2.0-OpenSSH_for_Windows_9.5", func(ctx context.Context, command string, channel cryptoSSH.Channel) {
		output := "__XOPS_INTERP__:powershell\n__XOPS_INTERP__:cmd\n__XOPS_INTERP_END__\n"
		if command == probeCmd {
			output = "__XOPS_DIALECT_CMD__:C:\\Windows\\system32\\cmd.exe\r\n"
		}
		replyExecutionProbe(t, ctx, channel, output, 0)
	})
	for range 2 {
		execution, err := client.ProbeControlledExecution(t.Context(), nil)
		if err != nil || execution.Interpreter != InterpreterPowerShell || execution.LaunchDialect != LaunchCmd {
			t.Fatalf("controlled Windows execution = %+v, %v", execution, err)
		}
	}
	if server.Executed.Load() != 2 || client.Execution() != nil {
		t.Fatal("controlled probe repeated requests or changed ordinary command defaults")
	}
	result, err := client.ProbeExecutionConfig(t.Context())
	if err != nil || result.RecommendedInterpreter != InterpreterServer {
		t.Fatal("controlled adapter selection changed the ordinary recommendation")
	}
}

func TestProbeCacheSharedAcrossPooledWrappers(t *testing.T) {
	owner, server := executionProbeClient(t, "", func(ctx context.Context, command string, channel cryptoSSH.Channel) {
		output := "__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n"
		if command == probePOSIX {
			output = "__XOPS_DIALECT_POSIX__:Linux:/bin/sh\n"
		}
		replyExecutionProbe(t, ctx, channel, output, 0)
	})
	pool := &PooledClient{SSHClient: owner.sshClient, RootConn: owner.rootConn}
	connector := &Connector{}
	first := connector.wrapCachedClient(&ClientConfig{}, pool)
	second := connector.wrapCachedClient(&ClientConfig{}, pool)
	a, err := first.ProbeExecutionConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.ProbeExecutionConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || server.Executed.Load() != 2 {
		t.Fatal("pooled wrappers repeated the transport's execution probe")
	}
}

func TestPowerShellProbeUsesExplicitPlatformMetadata(t *testing.T) {
	for _, tt := range []struct{ platform, want string }{{"Win32NT", "Windows_NT"}, {"Unix", "Unix"}, {"MacOSX", "Darwin"}, {"", ""}} {
		output := "__XOPS_DIALECT_POWERSHELL__:7.4.6\n"
		if tt.platform != "" {
			output += "__XOPS_PLATFORM__:" + tt.platform + "\n"
		}
		dialect, remoteOS, shell := parseProbeDialect(output, probePowerShell)
		if dialect != LaunchPowerShell || remoteOS != tt.want || shell != "" {
			t.Fatalf("platform %q parsed as %q/%q/%q", tt.platform, dialect, remoteOS, shell)
		}
	}
}

func TestWindowsSFTPDrivePathsPreservePOSIXSemantics(t *testing.T) {
	for _, tt := range []struct {
		interpreter Interpreter
		dialect     LaunchDialect
		want        string
	}{
		{InterpreterCmd, LaunchCmd, `cd /d "C:/Users/fixture" || exit /b & echo ok`},
		{InterpreterPowerShell, LaunchPowerShell, "Set-Location -LiteralPath 'C:/Users/fixture' -ErrorAction Stop; echo ok"},
		{InterpreterPwsh, LaunchCmd, "Set-Location -LiteralPath 'C:/Users/fixture' -ErrorAction Stop; echo ok"},
		{InterpreterPwsh, LaunchPOSIX, "Set-Location -LiteralPath $(if ($IsWindows) { 'C:/Users/fixture' } else { '/C:/Users/fixture' }) -ErrorAction Stop; echo ok"},
		{InterpreterPwsh, LaunchPowerShell, "Set-Location -LiteralPath $(if ($IsWindows) { 'C:/Users/fixture' } else { '/C:/Users/fixture' }) -ErrorAction Stop; echo ok"},
		{InterpreterSh, LaunchPOSIX, "cd -- '/C:/Users/fixture' && {\necho ok\n}"},
	} {
		got, err := FormatWorkingDirCommand("/C:/Users/fixture", "echo ok", &ExecutionConfig{Interpreter: tt.interpreter, LaunchDialect: tt.dialect})
		if err != nil || got != tt.want {
			t.Fatalf("%s/%s cwd = %q, %v", tt.interpreter, tt.dialect, got, err)
		}
	}
	if got := NormalizeWindowsSFTPWorkingDir("//server/share"); !strings.HasPrefix(got, "//") {
		t.Fatal("UNC path was changed")
	}
	if got := NormalizeWindowsSFTPWorkingDir("/C:"); got != "C:/" {
		t.Fatalf("drive root became a relative path: %q", got)
	}
}

func TestWorkingDirectoryExecutionPreservesNativeCMD(t *testing.T) {
	for _, interpreter := range []Interpreter{InterpreterServer, ""} {
		execution := &ExecutionConfig{Interpreter: interpreter, LaunchDialect: LaunchCmd}
		client := NewTestClient(ConnectionConfig{Execution: execution.Clone()})
		resolved, err := client.ResolveWorkingDirectoryExecution(t.Context(), execution)
		if err != nil || resolved.Interpreter != InterpreterCmd || resolved.LaunchDialect != LaunchCmd {
			t.Fatalf("known CMD cwd adapter = %+v, %v", resolved, err)
		}
		if !reflect.DeepEqual(execution, client.Execution()) || resolved == execution {
			t.Fatal("cwd adapter mutated connection or caller configuration")
		}
		if _, cached := client.CachedExecutionProbe(); cached {
			t.Fatal("known CMD cwd adapter started a probe")
		}
		for _, cwd := range []string{"/C:", "/C:/", "/C:/Windows"} {
			command, err := FormatWorkingDirCommand(cwd, "dir", resolved)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(command, "/C:") || !strings.HasPrefix(command, `cd /d "C:/`) {
				t.Fatalf("Windows cwd was not normalized: %q", command)
			}
			if _, err := PlanCommand(command, resolved.CommandOptions()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestWorkingDirectoryExecutionDoesNotGuessUnknownServerDialect(t *testing.T) {
	for _, dialect := range []LaunchDialect{"", LaunchUnknown, LaunchPOSIX, LaunchFish, LaunchPowerShell} {
		execution := &ExecutionConfig{Interpreter: InterpreterServer, LaunchDialect: dialect}
		client := NewTestClient(ConnectionConfig{Execution: execution})
		resolved, err := client.ResolveWorkingDirectoryExecution(t.Context(), execution)
		if err != nil || resolved.Interpreter != InterpreterServer || resolved.LaunchDialect != dialect {
			t.Fatalf("explicit server choice changed: %+v, %v", resolved, err)
		}
		if _, err := FormatWorkingDirCommand("/C:", "dir", resolved); err == nil {
			t.Fatalf("path inferred Windows semantics for dialect %q", dialect)
		}
	}
}
