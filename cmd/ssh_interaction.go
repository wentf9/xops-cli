package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/wentf9/xops-cli/internal/terminal"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type cliInteractionHandler struct {
	promptGate chan struct{}
	terminal   terminal.Prompter
}

var _ ssh.InteractionHandler = (*cliInteractionHandler)(nil)

func newCLIInteractionHandler() ssh.InteractionHandler {
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &cliInteractionHandler{
		promptGate: gate,
		terminal:   terminal.NewPrompter(os.Stdin, os.Stdout),
	}
}

func newCLIInteractionHandlerWithStreams(stdin io.Reader, stdout io.Writer) *cliInteractionHandler {
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &cliInteractionHandler{
		promptGate: gate,
		terminal:   terminal.NewPrompter(stdin, stdout),
	}
}

func newCLIConnector(provider config.ConfigProvider, opts ...ssh.Option) *ssh.Connector {
	opts = append([]ssh.Option{ssh.WithInteractionHandler(newCLIInteractionHandler())}, opts...)
	return adapter.NewConnector(provider, opts...)
}

func (h *cliInteractionHandler) acquireGate(ctx context.Context) (func(), error) {
	if h == nil || h.promptGate == nil {
		return nil, fmt.Errorf("cli prompt gate is not initialized")
	}
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for terminal prompt: %w", ctx.Err())
	case <-h.promptGate:
		return func() {
			h.promptGate <- struct{}{}
		}, nil
	}
}

func (h *cliInteractionHandler) PromptSecret(ctx context.Context, request ssh.SecretRequest) (string, error) {
	if h == nil || h.terminal == nil {
		return "", fmt.Errorf("cli secret prompter is not configured")
	}
	release, err := h.acquireGate(ctx)
	if err != nil {
		return "", err
	}
	defer release()

	prompt := formatSecretPrompt(request)
	secret, err := h.terminal.ReadSecret(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("read secret from terminal failed: %w", err)
	}
	return secret, nil
}

func (h *cliInteractionHandler) ConfirmHostKey(ctx context.Context, request ssh.HostKeyConfirmation) (bool, error) {
	if h == nil || h.terminal == nil {
		return false, fmt.Errorf("cli host key confirmation is not configured")
	}
	release, err := h.acquireGate(ctx)
	if err != nil {
		return false, err
	}
	defer release()

	prompt := formatHostKeyPrompt(request)
	response, err := h.terminal.ReadLine(ctx, prompt)
	if err != nil {
		return false, fmt.Errorf("read host key confirmation failed: %w", err)
	}
	return strings.EqualFold(strings.TrimSpace(response), "yes"), nil
}

func formatSecretPrompt(req ssh.SecretRequest) string {
	switch req.Kind {
	case ssh.SecretKindLoginPassword:
		if req.User != "" && req.Host != "" {
			text := i18n.Tf("prompt_enter_password_for", map[string]any{"User": req.User, "Host": req.Host})
			if text != "prompt_enter_password_for" {
				return text
			}
			return fmt.Sprintf("Enter password for %s@%s: ", req.User, req.Host)
		} else if req.User != "" {
			text := i18n.Tf("prompt_enter_user_password", map[string]any{"User": req.User})
			if text != "prompt_enter_user_password" {
				return text
			}
			return fmt.Sprintf("Enter password for user %s: ", req.User)
		}
		text := i18n.T("prompt_enter_password")
		if text != "prompt_enter_password" {
			return text
		}
		return "Enter password: "
	case ssh.SecretKindPrivateKeyPassphrase:
		text := i18n.Tf("prompt_enter_passphrase", map[string]any{"Path": req.KeyPath})
		if text != "prompt_enter_passphrase" {
			return text
		}
		return fmt.Sprintf("Enter passphrase for key '%s': ", req.KeyPath)
	case ssh.SecretKindSuPassword:
		text := i18n.Tf("prompt_su_password", map[string]any{"Node": req.NodeID})
		if text != "prompt_su_password" {
			return text
		}
		return fmt.Sprintf("Enter su root password for %s:", req.NodeID)
	default:
		return "Enter password: "
	}
}

func formatHostKeyPrompt(req ssh.HostKeyConfirmation) string {
	algo := req.Algorithm
	if algo != "" {
		algo = algo + " "
	}
	text := i18n.Tf("prompt_host_key_confirm", map[string]any{
		"Hostname":    req.Hostname,
		"Algorithm":   algo,
		"Fingerprint": req.Fingerprint,
	})
	if text == "prompt_host_key_confirm" {
		return fmt.Sprintf("The authenticity of host '%s' can't be established.\n%skey fingerprint is %s.\nAre you sure you want to continue connecting (yes/no)? ", req.Hostname, algo, req.Fingerprint)
	}
	return text
}
