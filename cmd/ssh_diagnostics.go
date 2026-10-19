package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/pkg/i18n"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// SSH has one log level, unlike scp's independent SSH and SFTP verbosity.
type sshDiagnosticOptions struct {
	quiet   bool
	verbose bool
	seen    bool
	level   int
}

func (o *sshDiagnosticOptions) register(cmd *cobra.Command) {
	o.level = sshLogInfo
	cmd.Flags().VarP(orderedOutputFlag{&o.verbose, func(v bool) {
		if !v {
			o.seen = false
			o.level = sshLogInfo
			return
		}
		if !o.seen {
			o.seen = true
			o.level = sshLogDebug1
		} else if o.level < sshLogDebug3 {
			o.level++
		}
	}}, "verbose", "v", i18n.T("flag_ssh_verbose"))
	cmd.Flags().Lookup("verbose").NoOptDefVal = "true"
	cmd.Flags().VarP(orderedOutputFlag{&o.quiet, func(v bool) {
		if v {
			o.level = sshLogQuiet
		}
	}}, "quiet", "q", i18n.T("flag_ssh_quiet"))
	cmd.Flags().Lookup("quiet").NoOptDefVal = "true"
}

// sshDiagnostics uses the same bounded output owner as SCP. CRLF also works
// while an interactive terminal has disabled OPOST; files retain ordinary LF.
type sshDiagnostics struct {
	*diagnosticOutput
	level   int
	newline string
}

func newSSHDiagnostics(ctx context.Context, target io.Writer, level int, gates ...chan struct{}) (*sshDiagnostics, error) {
	output, err := newDiagnosticOutput(ctx, target, "stderr", "ssh", gates...)
	if err != nil {
		return nil, err
	}
	newline := "\n"
	if file, ok := target.(*os.File); ok && diagnosticTerminal(file) {
		newline = "\r\n"
	}
	return &sshDiagnostics{diagnosticOutput: output, level: level, newline: newline}, nil
}

func (d *sshDiagnostics) DiagnosticLevel() int { return d.level }
func (d *sshDiagnostics) ObserveDiagnostic(e corelog.Diagnostic) {
	if !corelog.DiagnosticEnabled(d, e.Level) {
		return
	}
	message := formatSSHDiagnostic(e)
	if message == "" {
		return
	}
	d.message(fmt.Sprintf("debug%d: %s\n", max(e.Level, 1), message))
}

// message also serves user-facing forwarding errors. They are not protocol
// metadata, but must share the same nonblocking, cancellation-aware sink.
func (d *sshDiagnostics) message(text string) {
	d.enqueue(strings.ReplaceAll(text, "\n", d.newline))
}

// startDiagnostics must be deferred before connector/client cleanup so the
// caller-owned observer outlives shared handshakes and forwarding workers.
func (o *SshOptions) startDiagnostics(ctx context.Context) (corelog.DiagnosticObserver, func() error, error) {
	if o.diagnostic.level < sshLogDebug1 {
		return nil, func() error { return nil }, nil
	}
	if o.interaction == nil {
		o.interaction = newCLIInteractionHandler()
	}
	d, err := newSSHDiagnostics(ctx, os.Stderr, o.diagnostic.level-sshLogDebug1+1, o.interaction.promptGate)
	if err != nil {
		return nil, nil, err
	}
	return d, d.finish, nil
}

// formatSSHDiagnostic renders public metadata only. In particular an exec
// request is identified by kind, never by its command, script or environment.
func formatSSHDiagnostic(e corelog.Diagnostic) string {
	q := quotedDiagnostic
	peer := q(e.NodeID)
	if e.NodeID == "" {
		peer = q(e.User + "@" + e.Host)
	}
	switch e.Kind {
	case corelog.Connecting:
		return fmt.Sprintf("Connecting to %s port %d as %s (via proxy: %t).", q(e.Host), e.Port, q(e.User), e.Proxied)
	case corelog.Connected:
		return "Connection established for " + peer + "."
	case corelog.ConnectionReused:
		return "Reusing SSH connection for " + peer + "."
	case corelog.HandshakeFailed:
		return "SSH connection/handshake failed for " + peer + "."
	case corelog.HostKeyChecked:
		return fmt.Sprintf("Server host key for %s: %s %s; verification accepted: %t.", peer, q(e.HostKey), q(e.Fingerprint), e.Accepted)
	case corelog.AuthenticationMethods:
		return "Authentications that can continue for " + peer + ": " + q(strings.Join(e.Methods, ","))
	case corelog.AuthenticationAttempt:
		return "Next authentication method for " + peer + ": " + q(e.Method)
	case corelog.Authenticated:
		return fmt.Sprintf("Authenticated to %s using %s. Local version %s; remote version %s.\ndebug1: kex: algorithm: %s; host key algorithm: %s\ndebug1: cipher server->client: %s MAC: %s; client->server: %s MAC: %s",
			peer, authenticatedMethod(e), q(e.ClientVersion), q(e.ServerVersion), q(e.KeyExchange), q(e.HostKey), q(e.ReadCipher), diagnosticMAC(e.ReadCipher, e.ReadMAC), q(e.WriteCipher), diagnosticMAC(e.WriteCipher, e.WriteMAC))
	case corelog.Negotiated:
		return fmt.Sprintf("Connection %s: local version %s; remote version %s; kex: %s; host key algorithm: %s; cipher server->client: %s MAC: %s; client->server: %s MAC: %s.",
			peer, q(e.ClientVersion), q(e.ServerVersion), q(e.KeyExchange), q(e.HostKey), q(e.ReadCipher), diagnosticMAC(e.ReadCipher, e.ReadMAC), q(e.WriteCipher), diagnosticMAC(e.WriteCipher, e.WriteMAC))
	case corelog.SubsystemStarting:
		return "Sending subsystem: sftp to " + peer
	case corelog.SubsystemReady:
		return "SFTP subsystem ready for " + peer + " (protocol version 3)."
	case corelog.SubsystemFailed:
		return "SFTP subsystem setup failed for " + peer + "."
	case corelog.SessionRequest, corelog.SessionStarted, corelog.SessionFinished, corelog.SessionCleanup:
		return formatSessionDiagnostic(e, peer)
	case corelog.PrivilegeLifecycle:
		return formatPrivilegeDiagnostic(e, peer)
	case corelog.ForwardLifecycle:
		return fmt.Sprintf("%s forwarding %s for %s: %s -> %s.", q(e.Operation), q(e.Outcome), peer, q(e.Source), q(e.Destination))
	default:
		return ""
	}
}

func formatPrivilegeDiagnostic(e corelog.Diagnostic, peer string) string {
	q := quotedDiagnostic
	switch e.Outcome {
	case "command_prepared":
		return fmt.Sprintf("Sending privilege command via %s for %s: %s.", q(e.Operation), peer, q(e.PrivilegeCommand))
	case "password_prompt_pattern", "password_prompt_fallback_pattern":
		label := strings.ReplaceAll(strings.TrimPrefix(e.Outcome, "password_prompt_"), "_", " ")
		return fmt.Sprintf("Privilege password prompt %s via %s for %s: %s.", label, q(e.Operation), peer, q(e.PrivilegePromptPattern))
	case "password_prompt_matched":
		return fmt.Sprintf("Matched privilege password prompt via %s for %s: %s.", q(e.Operation), peer, q(e.PrivilegePrompt))
	default:
		attempt := ""
		if e.Attempt > 0 {
			attempt = fmt.Sprintf(" (attempt %d)", e.Attempt)
		}
		return fmt.Sprintf("Privilege escalation via %s for %s: %s%s.", q(e.Operation), peer, q(strings.ReplaceAll(e.Outcome, "_", " ")), attempt)
	}
}

func formatSessionDiagnostic(e corelog.Diagnostic, peer string) string {
	q := quotedDiagnostic
	switch e.Kind {
	case corelog.SessionRequest:
		return fmt.Sprintf("Session request %s %s for %s.", q(e.Operation), q(e.Outcome), peer)
	case corelog.SessionStarted:
		return fmt.Sprintf("Entering %s session for %s.", q(e.Operation), peer)
	case corelog.SessionFinished:
		if e.HasExitCode {
			return fmt.Sprintf("Exit status %d for %s.", e.ExitCode, peer)
		}
		return fmt.Sprintf("Session ended for %s: %s (no confirmed exit status).", peer, q(e.Outcome))
	case corelog.SessionCleanup:
		return fmt.Sprintf("Session channel cleanup %s for %s.", q(e.Outcome), peer)
	default:
		return ""
	}
}

// Match OpenSSH's AEAD marker without treating missing metadata as AEAD.
func diagnosticMAC(cipher, mac string) string {
	if mac != "" {
		return quotedDiagnostic(mac)
	}
	switch cipher {
	case cryptoSSH.CipherAES128GCM, cryptoSSH.CipherAES256GCM, cryptoSSH.CipherChaCha20Poly1305:
		return "<implicit>"
	default:
		return "<unknown>"
	}
}

func authenticatedMethod(event corelog.Diagnostic) string {
	method := "<unknown>"
	if event.Method != "" {
		method = quotedDiagnostic(event.Method)
	}
	if len(event.Methods) > 1 {
		method += " (authentication chain: " + quotedDiagnostic(strings.Join(event.Methods, ",")) + ")"
	}
	return method
}

var _ corelog.DiagnosticObserver = (*sshDiagnostics)(nil)
