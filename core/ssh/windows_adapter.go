package ssh

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf16"
)

const (
	// MaxCmdPayloadBytes is the maximum command line length accepted by cmd.exe (8191 characters).
	MaxCmdPayloadBytes = 8191

	// MaxPowerShellPayloadBytes is the maximum command line length accepted by CreateProcess (32767 characters).
	MaxPowerShellPayloadBytes = 32767
)

// encodePowerShellCommand encodes a command string into UTF-16LE Base64,
// which is accepted by PowerShell's -EncodedCommand parameter without
// escaping issues across shells.
func encodePowerShellCommand(command string) string {
	runes := []rune(command)
	utf16Units := utf16.Encode(runes)
	b := make([]byte, len(utf16Units)*2)
	for i, u := range utf16Units {
		b[i*2] = byte(u)
		b[i*2+1] = byte(u >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// wrapPowerShellCommand wraps the command so terminating/non-terminating errors
// and native process exit codes ($LASTEXITCODE) are faithfully propagated to the
// PowerShell process exit code.
func wrapPowerShellCommand(command string) string {
	return "$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop'\n" + command + "\nif ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
}

// powershellCommandPayload builds the payload for Windows PowerShell (powershell.exe).
func powershellCommandPayload(command string, dialect LaunchDialect) (string, error) {
	if dialect != LaunchCmd && dialect != LaunchPowerShell {
		return "", fmt.Errorf("powershell interpreter requires cmd or powershell launch dialect, got %q", dialect)
	}

	encoded := encodePowerShellCommand(wrapPowerShellCommand(command))
	var payload string
	switch dialect {
	case LaunchCmd:
		payload = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded
	case LaunchPowerShell:
		payload = "& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded + "; exit $LASTEXITCODE"
	}

	maxLen := MaxPowerShellPayloadBytes
	if dialect == LaunchCmd {
		maxLen = MaxCmdPayloadBytes
	}
	if len(payload) > maxLen {
		return "", fmt.Errorf("powershell command payload exceeds %d bytes limit", maxLen)
	}
	return payload, nil
}

// pwshCommandPayload builds the payload for PowerShell Core (pwsh).
func pwshCommandPayload(command string, dialect LaunchDialect) (string, error) {
	if dialect != LaunchCmd && dialect != LaunchPowerShell && dialect != LaunchPOSIX && dialect != LaunchFish && dialect != LaunchCsh {
		return "", fmt.Errorf("pwsh interpreter requires cmd, powershell, posix, fish, or csh launch dialect, got %q", dialect)
	}

	encoded := encodePowerShellCommand(wrapPowerShellCommand(command))
	var payload string
	switch dialect {
	case LaunchCmd:
		payload = "pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded
	case LaunchPowerShell:
		payload = "& pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded + "; exit $LASTEXITCODE"
	case LaunchPOSIX, LaunchFish, LaunchCsh:
		payload = "pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded
	}

	maxLen := MaxPowerShellPayloadBytes
	if dialect == LaunchCmd {
		maxLen = MaxCmdPayloadBytes
	}
	if len(payload) > maxLen {
		return "", fmt.Errorf("pwsh command payload exceeds %d bytes limit", maxLen)
	}
	return payload, nil
}

// escapeCmdCommand escapes metacharacters that would be exposed to the outer cmd.exe
// when the command is wrapped in outer quotes: cmd.exe /d /s /c "<command>".
// In outer cmd, double quotes toggle quote state. When an inner double quote closes
// quote state in outer cmd, characters such as &, |, <, >, (, ), ^ fall outside quotes
// and would be parsed as operators or escape characters by outer cmd unless escaped with ^.
func escapeCmdCommand(command string) (string, error) {
	if strings.ContainsAny(command, "\r\n\x00") {
		return "", fmt.Errorf("%w: cmd command contains illegal newline or null character", ErrExecutionValidation)
	}
	if strings.Count(command, "\"")%2 != 0 {
		return "", fmt.Errorf("%w: cmd command contains unbalanced double quotes", ErrExecutionValidation)
	}
	if strings.ContainsAny(command, "%!") {
		return "", fmt.Errorf("%w: cmd command contains unsupported variable expansion: %q", ErrExecutionValidation, command)
	}

	var sb strings.Builder
	sb.Grow(len(command) + 16)

	inOuterQuote := true
	for _, r := range command {
		if r == '"' {
			inOuterQuote = !inOuterQuote
			sb.WriteRune(r)
		} else if !inOuterQuote {
			switch r {
			case '&', '|', '<', '>', '(', ')', '^':
				sb.WriteByte('^')
				sb.WriteRune(r)
			default:
				sb.WriteRune(r)
			}
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String(), nil
}

// cmdCommandPayload builds the payload for Windows Command Prompt (cmd.exe).
func cmdCommandPayload(command string, dialect LaunchDialect) (string, error) {
	if dialect != LaunchCmd {
		return "", fmt.Errorf("cmd interpreter requires cmd launch dialect, got %q", dialect)
	}

	escaped, err := escapeCmdCommand(command)
	if err != nil {
		return "", err
	}

	payload := fmt.Sprintf(`cmd.exe /d /s /c "%s"`, escaped)
	if len(payload) > MaxCmdPayloadBytes {
		return "", fmt.Errorf("cmd command payload exceeds %d bytes limit", MaxCmdPayloadBytes)
	}
	return payload, nil
}
