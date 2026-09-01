package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"golang.org/x/term"
)

type cliInteractionHandler struct {
	stdin  *os.File
	stdout io.Writer
}

func newCLIInteractionHandler() ssh.InteractionHandler {
	return &cliInteractionHandler{stdin: os.Stdin, stdout: os.Stdout}
}

func newCLIConnector(provider config.ConfigProvider, opts ...ssh.Option) *ssh.Connector {
	return adapter.NewConnectorWithInteraction(provider, newCLIInteractionHandler(), opts...)
}

func (h *cliInteractionHandler) PromptPassword(prompt string) (password string, retErr error) {
	if h == nil || h.stdin == nil || h.stdout == nil {
		return "", fmt.Errorf("cli password prompt streams are not configured")
	}
	if _, err := fmt.Fprint(h.stdout, prompt); err != nil {
		return "", fmt.Errorf("write password prompt failed: %w", err)
	}
	defer func() {
		if _, err := fmt.Fprintln(h.stdout); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("write password prompt newline failed: %w", err))
		}
	}()
	passwordBytes, err := term.ReadPassword(int(h.stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("read password from terminal failed: %w", err)
	}
	return string(passwordBytes), nil
}

func (h *cliInteractionHandler) ConfirmHostKey(hostname, fingerprint string) (bool, error) {
	if h == nil || h.stdin == nil || h.stdout == nil {
		return false, fmt.Errorf("cli host key confirmation streams are not configured")
	}
	if _, err := fmt.Fprintf(
		h.stdout,
		"The authenticity of host '%s' can't be established.\nkey fingerprint is %s.\nAre you sure you want to continue connecting (yes/no)? ",
		hostname,
		fingerprint,
	); err != nil {
		return false, fmt.Errorf("write host key confirmation prompt failed: %w", err)
	}
	var response string
	if _, err := fmt.Fscanln(h.stdin, &response); err != nil {
		return false, fmt.Errorf("read host key confirmation failed: %w", err)
	}
	return strings.EqualFold(strings.TrimSpace(response), "yes"), nil
}
