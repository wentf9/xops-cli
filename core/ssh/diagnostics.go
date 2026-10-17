package ssh

import (
	"errors"
	"net"

	corelog "github.com/wentf9/xops-cli/core/log"
	cryptossh "golang.org/x/crypto/ssh"
)

func (c *Client) observeDiagnostic(event corelog.Diagnostic) {
	if c == nil || !corelog.DiagnosticEnabled(c.diagnostics, event.Level) {
		return
	}
	c.cfgMu.RLock()
	event.NodeID, event.Host, event.User = c.connCfg.NodeID, c.connCfg.Address, c.connCfg.User
	c.cfgMu.RUnlock()
	corelog.EmitDiagnostic(c.diagnostics, event)
}

func (c *Client) observeSession(kind corelog.DiagnosticKind, level int, operation, outcome string) {
	c.observeDiagnostic(corelog.Diagnostic{Kind: kind, Level: level, Operation: operation, Outcome: outcome})
}

// waitSession observes the actual SSH termination before callers apply legacy
// shell-exit policy or join unrelated I/O/cancellation errors. No remote error
// text, command, environment or privilege framing enters a diagnostic event.
func (c *Client) waitSession(session *cryptossh.Session) error {
	err := session.Wait()
	event := corelog.Diagnostic{Kind: corelog.SessionFinished, Outcome: "unknown"}
	var exit *cryptossh.ExitError
	switch {
	case err == nil:
		event.Outcome, event.HasExitCode = "completed", true
	case errors.As(err, &exit):
		if exit.Signal() != "" {
			event.Outcome = "signaled"
		} else {
			event.Outcome, event.HasExitCode, event.ExitCode = "completed", true, int64(exit.ExitStatus())
		}
	}
	c.observeDiagnostic(event)
	return err
}

func (c *Client) observeCommandResult(result CommandResult) {
	event := corelog.Diagnostic{Kind: corelog.SessionFinished, Outcome: string(result.Outcome)}
	if result.ExitCode != nil {
		event.HasExitCode, event.ExitCode = true, int64(*result.ExitCode)
	}
	if result.Signal != "" {
		event.Outcome = "signaled"
	}
	c.observeDiagnostic(event)
}

// observedForwardHandler wraps the existing handler, without taking ownership
// of connections or introducing workers. runForwardListener remains the owner.
func (c *Client) observedForwardHandler(operation, source, destination string, handle func() error) error {
	c.observeDiagnostic(corelog.Diagnostic{Kind: corelog.ForwardLifecycle, Level: 2, Operation: operation, Outcome: "connection accepted", Source: source, Destination: destination})
	err := handle()
	outcome := "connection closed"
	if err != nil {
		outcome = "connection failed"
	}
	c.observeDiagnostic(corelog.Diagnostic{Kind: corelog.ForwardLifecycle, Level: 2, Operation: operation, Outcome: outcome, Source: source, Destination: destination})
	return err
}

func (c *Client) observeForward(operation, outcome, source, destination string) {
	c.observeDiagnostic(corelog.Diagnostic{Kind: corelog.ForwardLifecycle, Operation: operation, Outcome: outcome, Source: source, Destination: destination})
}

// forwardDiagnostics attaches metadata to the existing listener lifecycle;
// it does not acquire a connection, alter error callbacks or spawn a monitor.
func (c *Client) forwardDiagnostics(options forwardOptions, operation string, listener net.Listener, destination string) forwardOptions {
	options.observe = func(outcome string) { c.observeForward(operation, outcome, listener.Addr().String(), destination) }
	return options
}
