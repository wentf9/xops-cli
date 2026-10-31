package ssh_test

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
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

func TestWindowsAdapters_PlanCommand_PowerShell(t *testing.T) {
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
		if !strings.Contains(decoded, "$ProgressPreference = 'SilentlyContinue'") {
			t.Errorf("decoded script missing ProgressPreference: %s", decoded)
		}
		if !strings.Contains(decoded, "$ErrorActionPreference = 'Stop'") {
			t.Errorf("decoded script missing ErrorActionPreference: %s", decoded)
		}
		if !strings.Contains(decoded, "$LASTEXITCODE") {
			t.Errorf("decoded script missing LASTEXITCODE check: %s", decoded)
		}
	})

	t.Run("powershell with powershell launch dialect uses call operator and propagates exit code", func(t *testing.T) {
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
		if !strings.HasSuffix(plan.Payload(), "; exit $LASTEXITCODE") {
			t.Errorf("expected ; exit $LASTEXITCODE suffix for powershell dialect: %s", plan.Payload())
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
}

func TestWindowsAdapters_PlanCommand_Pwsh(t *testing.T) {
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

	t.Run("pwsh with powershell launch dialect uses call operator and propagates exit code", func(t *testing.T) {
		plan, err := ssh.PlanCommand("Get-Service", ssh.CommandOptions{
			Interpreter:   ssh.InterpreterPwsh,
			LaunchDialect: ssh.LaunchPowerShell,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(plan.Payload(), "& pwsh ") {
			t.Errorf("expected & pwsh prefix for powershell dialect: %s", plan.Payload())
		}
		if !strings.HasSuffix(plan.Payload(), "; exit $LASTEXITCODE") {
			t.Errorf("expected ; exit $LASTEXITCODE suffix for powershell dialect: %s", plan.Payload())
		}
	})
}

func TestWindowsAdapters_PlanCommand_Cmd(t *testing.T) {
	t.Run("cmd with cmd launch dialect quotes full command", func(t *testing.T) {
		plan, err := ssh.PlanCommand("dir /s", ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `cmd.exe /d /s /c "dir /s"`
		if plan.Payload() != expected {
			t.Errorf("expected payload %q, got: %s", expected, plan.Payload())
		}
	})

	t.Run("cmd with operators and quotes protects inner command", func(t *testing.T) {
		plan, err := ssh.PlanCommand(`cd /d "C:\work" && dir`, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `cmd.exe /d /s /c "cd /d "C:\work" && dir"`
		if plan.Payload() != expected {
			t.Errorf("expected payload %q, got: %s", expected, plan.Payload())
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
}

func TestWindowsAdapters_PlanCommand_CmdQuoting(t *testing.T) {
	t.Run("escapes operators inside inner quotes", func(t *testing.T) {
		plan, err := ssh.PlanCommand(`echo "A&B"`, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `cmd.exe /d /s /c "echo "A^&B""`
		if plan.Payload() != expected {
			t.Errorf("expected payload %q, got: %s", expected, plan.Payload())
		}
	})

	t.Run("escapes cwd injection ampersand inside quotes", func(t *testing.T) {
		plan, err := ssh.PlanCommand(`cd /d "C:\windows&echo OUTSIDE&rem " && dir`, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `cmd.exe /d /s /c "cd /d "C:\windows^&echo OUTSIDE^&rem " && dir"`
		if plan.Payload() != expected {
			t.Errorf("expected payload %q, got: %s", expected, plan.Payload())
		}
	})

	t.Run("escapes various metacharacters inside inner quotes", func(t *testing.T) {
		plan, err := ssh.PlanCommand(`echo "A|B" "C<D" "E>F" "G(H)" "I^J"`, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `cmd.exe /d /s /c "echo "A^|B" "C^<D" "E^>F" "G^(H^)" "I^^J""`
		if plan.Payload() != expected {
			t.Errorf("expected payload %q, got: %s", expected, plan.Payload())
		}
	})

	t.Run("rejects unbalanced double quotes", func(t *testing.T) {
		_, err := ssh.PlanCommand(`echo "unbalanced`, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err == nil {
			t.Fatal("expected error for unbalanced double quotes, got nil")
		}
		if !strings.Contains(err.Error(), "unbalanced double quotes") {
			t.Errorf("expected error to mention unbalanced double quotes, got: %v", err)
		}
	})

	t.Run("rejects newline characters", func(t *testing.T) {
		_, err := ssh.PlanCommand("dir\nwhoami", ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err == nil {
			t.Fatal("expected error for newline characters, got nil")
		}
		if !strings.Contains(err.Error(), "illegal newline") {
			t.Errorf("expected error to mention illegal newline, got: %v", err)
		}
	})
}

func TestWindowsAdapters_PlanCommand_CmdVariableExpansion(t *testing.T) {
	t.Run("rejects percent variable expansion in both quoted and unquoted contexts", func(t *testing.T) {
		for _, cmd := range []string{
			`echo "%X%"`,
			`dir "C:\Users\%USERNAME%"`,
			`echo "%1"`,
			`echo %X%`,
			`dir %TEMP%`,
			`set A=%B%`,
		} {
			_, err := ssh.PlanCommand(cmd, ssh.CommandOptions{
				Interpreter:   ssh.InterpreterCmd,
				LaunchDialect: ssh.LaunchCmd,
			})
			if err == nil {
				t.Fatalf("expected error for %q, got nil", cmd)
			}
			if !strings.Contains(err.Error(), "unsupported variable expansion") {
				t.Errorf("expected error for %q to mention unsupported variable expansion, got: %v", cmd, err)
			}
		}
	})

	t.Run("rejects exclamation variable expansion in both quoted and unquoted contexts", func(t *testing.T) {
		for _, cmd := range []string{
			`echo "!X!"`,
			`echo !X!`,
		} {
			_, err := ssh.PlanCommand(cmd, ssh.CommandOptions{
				Interpreter:   ssh.InterpreterCmd,
				LaunchDialect: ssh.LaunchCmd,
			})
			if err == nil {
				t.Fatalf("expected error for %q, got nil", cmd)
			}
			if !strings.Contains(err.Error(), "unsupported variable expansion") {
				t.Errorf("expected error for %q to mention unsupported variable expansion, got: %v", cmd, err)
			}
		}
	})
}

func TestWindowsAdapters_PlanCommand_WineProbe(t *testing.T) {
	winePath, err := exec.LookPath("wine")
	if err != nil {
		t.Skip("wine not installed, skipping wine probe")
	}

	t.Run("wine probe verifies operator protection", func(t *testing.T) {
		plan1, err := ssh.PlanCommand(`echo "A&B"`, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err != nil {
			t.Fatalf("PlanCommand failed: %v", err)
		}
		tmpDir := t.TempDir()
		batFile := filepath.Join(tmpDir, "test.bat")
		batContent := "@echo off\n" + plan1.Payload() + "\n"
		if err := os.WriteFile(batFile, []byte(batContent), 0600); err != nil {
			t.Fatalf("write test.bat failed: %v", err)
		}
		out, err := exec.Command(winePath, "cmd.exe", "/c", batFile).CombinedOutput()
		if err != nil {
			t.Fatalf("wine execution failed: %v, out: %s", err, string(out))
		}
		if !strings.Contains(string(out), `"A&B"`) {
			t.Errorf("expected wine output to contain \"A&B\", got: %s", string(out))
		}
	})

	t.Run("wine probe verifies cwd injection resistance", func(t *testing.T) {
		plan2, err := ssh.PlanCommand(`cd /d "C:\windows&echo OUTSIDE&rem " && dir`, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err != nil {
			t.Fatalf("PlanCommand failed: %v", err)
		}
		tmpDir := t.TempDir()
		batFile2 := filepath.Join(tmpDir, "test2.bat")
		batContent2 := "@echo off\n" + plan2.Payload() + "\n"
		if err := os.WriteFile(batFile2, []byte(batContent2), 0600); err != nil {
			t.Fatalf("write test2.bat failed: %v", err)
		}
		out2, _ := exec.Command(winePath, "cmd.exe", "/c", batFile2).CombinedOutput()
		if strings.Contains(string(out2), "OUTSIDE") {
			t.Errorf("wine output executed injected command: %s", string(out2))
		}
	})

	t.Run("wine probe verifies quoted env var injection is rejected before execution", func(t *testing.T) {
		// Verify that attempting to plan echo "%X%" is rejected
		_, err := ssh.PlanCommand(`echo "%X%"`, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err == nil {
			t.Fatal("expected PlanCommand to reject quoted env var expansion, got nil")
		}

		// Also verify via wine that direct execution of echo "%X%" with X=A&echo OUTSIDE&rem
		// does NOT execute OUTSIDE, confirming direct cmd behavior contrasts with unsafe nested payload.
		tmpDir := t.TempDir()
		batFile3 := filepath.Join(tmpDir, "test3.bat")
		batContent3 := "@echo off\nset \"X=A&echo OUTSIDE&rem \"\ncmd.exe /c echo \"%X%\"\n"
		if err := os.WriteFile(batFile3, []byte(batContent3), 0600); err != nil {
			t.Fatalf("write test3.bat failed: %v", err)
		}
		out3, err := exec.Command(winePath, "cmd.exe", "/c", batFile3).CombinedOutput()
		if err != nil {
			t.Fatalf("wine execution failed: %v", err)
		}
		// Direct execution should output "A&echo OUTSIDE&rem " and NOT execute OUTSIDE on its own line
		lines := strings.Split(strings.TrimSpace(string(out3)), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "OUTSIDE" {
				t.Errorf("direct execution unexpectedly executed OUTSIDE: %s", string(out3))
			}
		}
	})

	t.Run("wine probe verifies unquoted env var injection is rejected before execution", func(t *testing.T) {
		// Verify that attempting to plan echo %X% is rejected
		_, err := ssh.PlanCommand("echo %X%", ssh.CommandOptions{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err == nil {
			t.Fatal("expected PlanCommand to reject unquoted env var expansion, got nil")
		}

		// Also verify via wine that direct execution of echo %X% with X="A&echo OUTSIDE&rem "
		// outputs "A&echo OUTSIDE&rem " without executing OUTSIDE on its own line.
		tmpDir := t.TempDir()
		batFile4 := filepath.Join(tmpDir, "test4.bat")
		batContent4 := "@echo off\nset X=\"A&echo OUTSIDE&rem \"\ncmd.exe /c echo %X%\n"
		if err := os.WriteFile(batFile4, []byte(batContent4), 0600); err != nil {
			t.Fatalf("write test4.bat failed: %v", err)
		}
		out4, err := exec.Command(winePath, "cmd.exe", "/c", batFile4).CombinedOutput()
		if err != nil {
			t.Fatalf("wine execution failed: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(out4)), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "OUTSIDE" {
				t.Errorf("direct execution unexpectedly executed OUTSIDE: %s", string(out4))
			}
		}
	})
}

func TestWindowsAdapters_PlanCommand_PayloadLimits(t *testing.T) {
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

	t.Run("powershell payload length limit enforced under cmd launch dialect", func(t *testing.T) {
		hugeCmd := strings.Repeat("x", 8200)
		_, err := ssh.PlanCommand(hugeCmd, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterPowerShell,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err == nil {
			t.Fatal("expected payload length error for powershell under cmd dialect, got nil")
		}
		if !strings.Contains(err.Error(), "8191") {
			t.Errorf("error %q does not mention 8191 limit", err.Error())
		}
	})

	t.Run("powershell payload length limit enforced under powershell launch dialect", func(t *testing.T) {
		hugeCmd := strings.Repeat("x", 33000)
		_, err := ssh.PlanCommand(hugeCmd, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterPowerShell,
			LaunchDialect: ssh.LaunchPowerShell,
		})
		if err == nil {
			t.Fatal("expected payload length error for powershell under powershell dialect, got nil")
		}
		if !strings.Contains(err.Error(), "32767") {
			t.Errorf("error %q does not mention 32767 limit", err.Error())
		}
	})

	t.Run("pwsh payload length limit enforced under cmd launch dialect", func(t *testing.T) {
		hugeCmd := strings.Repeat("x", 8200)
		_, err := ssh.PlanCommand(hugeCmd, ssh.CommandOptions{
			Interpreter:   ssh.InterpreterPwsh,
			LaunchDialect: ssh.LaunchCmd,
		})
		if err == nil {
			t.Fatal("expected payload length error for pwsh under cmd dialect, got nil")
		}
		if !strings.Contains(err.Error(), "8191") {
			t.Errorf("error %q does not mention 8191 limit", err.Error())
		}
	})
}
