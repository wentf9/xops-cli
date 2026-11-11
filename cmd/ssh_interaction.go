package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/wentf9/xops-cli/cmd/utils"
	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/terminal"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"golang.org/x/term"
)

var (
	ansiCSIFilter = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	ansiOSCFilter = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)`)
	ansiEscFilter = regexp.MustCompile(`\x1b[@-Z\\-_]`)
)

func sanitizeInteractiveText(raw string) string {
	if raw == "" {
		return ""
	}
	cleaned := ansiCSIFilter.ReplaceAllString(raw, "")
	cleaned = ansiOSCFilter.ReplaceAllString(cleaned, "")
	cleaned = ansiEscFilter.ReplaceAllString(cleaned, "")

	var b strings.Builder
	b.Grow(len(cleaned))
	for _, r := range cleaned {
		if r == '\r' {
			continue
		}
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

type cliInteractionHandler struct {
	canRemember bool
	promptGate  chan struct{}
	terminal    terminal.Prompter
	output      io.Writer
}

var _ ssh.InteractionHandler = (*cliInteractionHandler)(nil)

var commandPromptGate = func() chan struct{} { gate := make(chan struct{}, 1); gate <- struct{}{}; return gate }()

func newCLIInteractionHandler() *cliInteractionHandler {
	gate := commandPromptGate
	return &cliInteractionHandler{
		canRemember: term.IsTerminal(int(os.Stdin.Fd())),
		promptGate:  gate,
		terminal:    terminal.NewPrompter(os.Stdin, os.Stderr),
		output:      os.Stderr,
	}
}

func newCLIInteractionHandlerWithStreams(stdin io.Reader, stdout io.Writer) *cliInteractionHandler {
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &cliInteractionHandler{
		canRemember: true,
		promptGate:  gate,
		terminal:    terminal.NewPrompter(stdin, stdout),
		output:      stdout,
	}
}

// rememberOptions configures deferred confirmation; constructing a connector
// must never ask to save credentials it has not yet used or discovered.
func (h *cliInteractionHandler) rememberOptions(policy string, cfg *config.Configuration) (bool, []adapter.Option) {
	enabled := cfg.CanRememberCredentials() && (policy == "always" || (policy == "ask" && h.canRemember))
	var opts []adapter.Option
	if enabled && policy == "ask" {
		opts = append(opts, adapter.WithRememberConfirmation(h.confirmRemember))
	}
	return enabled, opts
}

// newCLIConnectorWithAdapterOptions builds the interactive CLI connector. The
// explicit handler is required: WithInteractionHandler only installs secret and
// host-key prompts, so the master connection-sharing confirmer must be wired to
// the same handler (and prompt gate) as the rest of the session.
func newCLIConnectorWithAdapterOptions(provider config.ConfigProvider, interaction *cliInteractionHandler, adpOpts []adapter.Option, opts ...ssh.Option) *ssh.Connector {
	if interaction == nil {
		interaction = newCLIInteractionHandler()
	}
	opts = append([]ssh.Option{ssh.WithInteractionHandler(interaction), ssh.WithSessionConfirmer(interaction)}, opts...)
	return adapter.NewConnectorWithAdapterOptions(provider, adpOpts, opts...)
}

// newNonInteractiveConnector 创建不安装任何交互提示器的非交互式连接器，
// 适用于 Playbook、MCP 等批处理场景，确保缺少凭据时立即 fail-closed 而非等待终端输入。
func newNonInteractiveConnector(provider config.ConfigProvider, adpOpts []adapter.Option, opts ...ssh.Option) *ssh.Connector {
	return adapter.NewConnectorWithAdapterOptions(provider, adpOpts, opts...)
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

	// 1. If server sent an instruction banner, print it first (sanitized) to output
	if request.Instruction != "" && h.output != nil {
		sanitizedInstruction := sanitizeInteractiveText(request.Instruction)
		if sanitizedInstruction != "" {
			if _, err := fmt.Fprintln(h.output, sanitizedInstruction); err != nil {
				return "", fmt.Errorf("display instruction banner failed: %w", err)
			}
		}
	}

	// 2. Format and sanitize prompt text
	prompt := formatSecretPrompt(request)

	// 3. Select input method based on Echo flag
	if request.Echo {
		line, err := h.terminal.ReadLine(ctx, prompt)
		if err != nil {
			return "", fmt.Errorf("read line from terminal failed: %w", err)
		}
		return line, nil
	}

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
	response = strings.TrimSpace(response)
	return strings.EqualFold(response, "yes") || strings.EqualFold(response, "y"), nil
}

// ConfirmSession implements ssh.SessionConfirmer for ControlMaster=ask/autoask
// (-M -M). Aligned with OpenSSH mux_master_confirm (read_passphrase with
// RP_USE_ASKPASS), confirmation is delegated exclusively to SSH_ASKPASS without
// falling back to the local terminal, supporting SSH_ASKPASS,
// SSH_ASKPASS_REQUIRE, SSH_ASKPASS_PROMPT, DISPLAY, and WAYLAND_DISPLAY.
func (h *cliInteractionHandler) ConfirmSession(ctx context.Context, action string) (bool, error) {
	if h == nil {
		return false, fmt.Errorf("cli session confirmation is not configured")
	}
	askpassProg := resolveAskpassProgram()
	if askpassProg == "" {
		return false, nil
	}
	release, err := h.acquireGate(ctx)
	if err != nil {
		return false, err
	}
	defer release()

	prompt := fmt.Sprintf("Allow connection sharing %s on this master? (yes/no) ", sanitizeInteractiveText(action))
	return confirmSessionWithAskpass(ctx, askpassProg, prompt)
}

const defaultAskpassWaitDelay = 200 * time.Millisecond

func resolveAskpassProgram() string {
	requireMode := strings.ToLower(strings.TrimSpace(os.Getenv("SSH_ASKPASS_REQUIRE")))
	if requireMode == "never" {
		return ""
	}
	hasDisplay := strings.TrimSpace(os.Getenv("DISPLAY")) != "" || strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != ""
	if !hasDisplay && requireMode != "force" && requireMode != "prefer" {
		return ""
	}
	prog := strings.TrimSpace(os.Getenv("SSH_ASKPASS"))
	if prog == "" {
		prog = findSystemAskpass()
	}
	return prog
}

func askpassCommandEnv(base []string) []string {
	const prefix = "SSH_ASKPASS_PROMPT="
	env := make([]string, 0, len(base)+1)
	for _, kv := range base {
		if len(kv) >= len(prefix) && strings.EqualFold(kv[:len(prefix)], prefix) {
			continue
		}
		env = append(env, kv)
	}
	return append(env, prefix+"confirm")
}

func isAskpassApproved(out []byte) bool {
	resp := strings.TrimSpace(string(out))
	switch strings.ToLower(resp) {
	case "", "yes", "y", "true", "ok":
		return true
	default:
		return false
	}
}

func confirmSessionWithAskpass(ctx context.Context, askpassProg, prompt string) (bool, error) {
	cmd, err := buildAskpassCommand(ctx, askpassProg, prompt)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	cmd.Stdin = nil
	cmd.Stderr = io.Discard
	cmd.Env = askpassCommandEnv(os.Environ())
	cmd.WaitDelay = defaultAskpassWaitDelay
	out, runErr := cmd.Output()
	if runErr == nil {
		return isAskpassApproved(out), nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return false, nil
}

func formatSecretPrompt(req ssh.SecretRequest) string {
	switch req.Kind {
	case ssh.SecretKindKeyboardInteractive:
		return formatKeyboardInteractivePrompt(req)
	case ssh.SecretKindOTP:
		return formatOTPPrompt(req)
	case ssh.SecretKindLoginPassword:
		return formatLoginPasswordPrompt(req)
	case ssh.SecretKindPrivateKeyPassphrase:
		text := i18n.Tf("prompt_enter_passphrase", map[string]any{"Path": req.KeyPath})
		if text != "prompt_enter_passphrase" {
			return text
		}
		return fmt.Sprintf("Enter passphrase for key '%s': ", req.KeyPath)
	case ssh.SecretKindSudoPassword:
		text := i18n.Tf("prompt_remote_sudo_password", map[string]any{"Node": req.NodeID})
		if text != "prompt_remote_sudo_password" {
			return text
		}
		return fmt.Sprintf("Enter sudo password for %s: ", req.NodeID)
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

func formatKeyboardInteractivePrompt(req ssh.SecretRequest) string {
	sanitizedPrompt := sanitizeInteractiveText(req.Prompt)
	if sanitizedPrompt == "" {
		text := i18n.T("prompt_enter_response")
		if text != "prompt_enter_response" {
			return text
		}
		return "Enter response: "
	}
	if !strings.HasSuffix(sanitizedPrompt, " ") && !strings.HasSuffix(sanitizedPrompt, "\n") {
		sanitizedPrompt += " "
	}
	return sanitizedPrompt
}

func formatOTPPrompt(req ssh.SecretRequest) string {
	if req.Prompt != "" {
		sanitizedPrompt := sanitizeInteractiveText(req.Prompt)
		if !strings.HasSuffix(sanitizedPrompt, " ") && !strings.HasSuffix(sanitizedPrompt, "\n") {
			sanitizedPrompt += " "
		}
		return sanitizedPrompt
	}
	if req.User != "" && req.Host != "" {
		text := i18n.Tf("prompt_enter_otp_for", map[string]any{"User": req.User, "Host": req.Host})
		if text != "prompt_enter_otp_for" {
			return text
		}
		return fmt.Sprintf("Enter OTP code for %s@%s: ", req.User, req.Host)
	}
	text := i18n.T("prompt_enter_otp")
	if text != "prompt_enter_otp" {
		return text
	}
	return "Enter OTP code: "
}

func formatLoginPasswordPrompt(req ssh.SecretRequest) string {
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

// confirmRemember shares the cancellable terminal prompt gate with SSH prompts.
func (h *cliInteractionHandler) confirmRemember(ctx context.Context, nodeID string) (bool, error) {
	release, err := h.acquireGate(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	answer, err := h.terminal.ReadLine(ctx, fmt.Sprintf("Save credential for %q? (yes/no): ", nodeID))
	if err != nil {
		return false, fmt.Errorf("read credential persistence decision: %w", err)
	}
	answer = strings.TrimSpace(answer)
	return strings.EqualFold(answer, "yes") || strings.EqualFold(answer, "y"), nil
}

// Password supplies only hidden terminal input, sharing the SSH prompt gate.
func (h *cliInteractionHandler) Password(ctx context.Context, id string) ([]byte, error) {
	if h == nil || !h.canRemember || credential.InteractionDisabled(ctx) {
		return nil, coreauth.ErrCredentialStoreLocked
	}
	release, err := h.acquireGate(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	value, err := h.terminal.ReadSecret(ctx, fmt.Sprintf("Master password for %s: ", id))
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

// ReportCredentialFailure keeps operational notices out of protocol stdout.
func (h *cliInteractionHandler) ReportCredentialFailure(ctx context.Context, operation string) error {
	if h == nil || !h.canRemember || h.output == nil {
		return ssh.ErrInteractionRequired
	}
	release, err := h.acquireGate(ctx)
	if err != nil {
		return err
	}
	defer release()
	key := "credential_read_retry"
	if operation == "save" {
		key = "credential_save_failed_connected"
	}
	_, err = fmt.Fprintln(h.output, i18n.T(key))
	return err
}

// CredentialRecoveryAllowed requires an actual interactive input capability.
func (h *cliInteractionHandler) CredentialRecoveryAllowed() bool { return h != nil && h.canRemember }

// automaticPersistenceOptions permits session-only interactive connections when
// the journal/service cannot be prepared. Explicitly disable recording so the
// adapter cannot fall back to legacy configuration writes without a service.
func (h *cliInteractionHandler) automaticPersistenceOptions(repo *config.Repository, cfg *config.Configuration) ([]adapter.Option, error) {
	service, err := utils.GetCredentialService(repo, cfg)
	if err == nil {
		return []adapter.Option{adapter.WithCredentialService(service)}, nil
	}
	if !h.CredentialRecoveryAllowed() || h.output == nil {
		return nil, fmt.Errorf("initialize credential persistence: %w", err)
	}
	if _, writeErr := fmt.Fprintln(h.output, i18n.T("credential_save_unavailable")); writeErr != nil {
		return nil, fmt.Errorf("report unavailable credential persistence: %w", writeErr)
	}
	return []adapter.Option{adapter.WithCredentialRecording(false)}, nil
}
