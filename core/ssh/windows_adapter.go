package ssh

import (
	"encoding/base64"
	"fmt"
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
	return "$ErrorActionPreference = 'Stop'\n" + command + "\nif ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
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
		payload = "& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded
	}

	if len(payload) > MaxPowerShellPayloadBytes {
		return "", fmt.Errorf("powershell command payload exceeds %d bytes limit", MaxPowerShellPayloadBytes)
	}
	return payload, nil
}

// pwshCommandPayload builds the payload for PowerShell Core (pwsh).
func pwshCommandPayload(command string, dialect LaunchDialect) (string, error) {
	if dialect != LaunchCmd && dialect != LaunchPowerShell && dialect != LaunchPOSIX {
		return "", fmt.Errorf("pwsh interpreter requires cmd, powershell, or posix launch dialect, got %q", dialect)
	}

	encoded := encodePowerShellCommand(wrapPowerShellCommand(command))
	var payload string
	switch dialect {
	case LaunchCmd:
		payload = "pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded
	case LaunchPowerShell:
		payload = "& pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded
	case LaunchPOSIX:
		payload = "pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded
	}

	if len(payload) > MaxPowerShellPayloadBytes {
		return "", fmt.Errorf("pwsh command payload exceeds %d bytes limit", MaxPowerShellPayloadBytes)
	}
	return payload, nil
}

// cmdCommandPayload builds the payload for Windows Command Prompt (cmd.exe).
func cmdCommandPayload(command string, dialect LaunchDialect) (string, error) {
	if dialect != LaunchCmd {
		return "", fmt.Errorf("cmd interpreter requires cmd launch dialect, got %q", dialect)
	}

	payload := "cmd.exe /d /c " + command
	if len(payload) > MaxCmdPayloadBytes {
		return "", fmt.Errorf("cmd command payload exceeds %d bytes limit", MaxCmdPayloadBytes)
	}
	return payload, nil
}
