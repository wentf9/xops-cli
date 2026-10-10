package ssh_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/wentf9/xops-cli/core/ssh"
)

func decodePowerShellPayload(payload string) (string, error) {
	// Look for -EncodedCommand <base64>
	idx := strings.Index(payload, "-EncodedCommand ")
	if idx < 0 {
		return "", nil
	}
	encoded := payload[idx+len("-EncodedCommand "):]
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw)%2 != 0 {
		return "", nil
	}
	u16s := make([]uint16, len(raw)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = uint16(raw[i*2]) | (uint16(raw[i*2+1]) << 8)
	}
	return string(utf16.Decode(u16s)), nil
}

func TestWindowsAdapters_PlanCommand(t *testing.T) {
	t.Run("powershell with cmd launch dialect", func(t *testing.T) {
		plan, err := ssh.PlanCommand("Get-Process", ssh.CommandOptions{
			Interpreter:   ssh.InterpreterPowerShell,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(plan.Payload(), "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ") {
			t.Errorf("unexpected payload: %s", plan.Payload())
		}
		decoded, err := decodePowerShellPayload(plan.Payload())
		if err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		if !strings.Contains(decoded, "Get-Process") {
			t.Errorf("decoded script missing command: %s", decoded)
		}
		if !strings.Contains(decoded, "$ErrorActionPreference = 'Stop'") {
			t.Errorf("decoded script missing ErrorActionPreference: %s", decoded)
		}
		if !strings.Contains(decoded, "$LASTEXITCODE") {
			t.Errorf("decoded script missing LASTEXITCODE check: %s", decoded)
		}
	})

	t.Run("powershell with powershell launch dialect uses call operator", func(t *testing.T) {
		plan, err := ssh.PlanCommand("Get-Service", ssh.CommandOptions{
			Interpreter:   ssh.InterpreterPowerShell,
			LaunchDialect: ssh.LaunchPowerShell,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(plan.Payload(), "& powershell.exe ") {
			t.Errorf("expected & prefix for powershell dialect: %s", plan.Payload())
		}
	})

	t.Run("powershell rejects posix launch dialect", func(t *testing.T) {
		_, err := ssh.PlanCommand("Get-Process", ssh.CommandOptions{
			Interpreter:   ssh.InterpreterPowerShell,
			LaunchDialect: ssh.LaunchPOSIX,
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("powershell rejects login shell", func(t *testing.T) {
		_, err := ssh.PlanCommand("Get-Process", ssh.CommandOptions{
			Interpreter:   ssh.InterpreterPowerShell,
			LaunchDialect: ssh.LaunchCmd,
			Login:         ssh.LoginEnabled,
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("pwsh with posix launch dialect", func(t *testing.T) {
		plan, err := ssh.PlanCommand("Write-Host 'hello'", ssh.CommandOptions{
			Interpreter:   ssh.InterpreterPwsh,
			LaunchDialect: ssh.LaunchPOSIX,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(plan.Payload(), "pwsh -NoProfile ") {
			t.Errorf("unexpected payload: %s", plan.Payload())
		}
	})

	t.Run("cmd with cmd launch dialect", func(t *testing.T) {
		plan, err := ssh.PlanCommand("dir /s", ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if plan.Payload() != "cmd.exe /d /c dir /s" {
			t.Errorf("unexpected payload: %s", plan.Payload())
		}
	})

	t.Run("cmd rejects posix launch dialect", func(t *testing.T) {
		_, err := ssh.PlanCommand("dir", ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchPOSIX,
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("cmd payload length limit enforced", func(t *testing.T) {
		hugeCmd := strings.Repeat("a", 8200)
		_, err := ssh.PlanCommand(hugeCmd, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err == nil {
			t.Fatal("expected payload length error for cmd, got nil")
		}
		if !strings.Contains(err.Error(), "8191") {
			t.Errorf("error %q does not mention 8191 limit", err.Error())
		}
	})

	t.Run("powershell payload length limit enforced", func(t *testing.T) {
		hugeCmd := strings.Repeat("x", 33000)
		_, err := ssh.PlanCommand(hugeCmd, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterPowerShell,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err == nil {
			t.Fatal("expected payload length error for powershell, got nil")
		}
		if !strings.Contains(err.Error(), "32767") {
			t.Errorf("error %q does not mention 32767 limit", err.Error())
		}
	})
}
