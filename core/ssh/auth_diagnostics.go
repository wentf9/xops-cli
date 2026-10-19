package ssh

import (
	"slices"

	corelog "github.com/wentf9/xops-cli/core/log"
	cryptossh "golang.org/x/crypto/ssh"
)

// authenticationTrace belongs to one handshake, on its authentication goroutine.
// It records callback selection, not credentials or an inferred config type.
// Success is published only after NewClientConn succeeds. x/crypto calls the
// callback again after every failed/partial attempt, but not after success.
type authenticationTrace struct {
	observer     corelog.DiagnosticObserver
	nodeID       string
	callbackSeen bool
	selected     string
	partial      []string
}

func newAuthenticationTrace(observer corelog.DiagnosticObserver, nodeID string) *authenticationTrace {
	if observer == nil {
		return nil
	}
	return &authenticationTrace{observer: observer, nodeID: nodeID}
}

func (t *authenticationTrace) DiagnosticLevel() int {
	if selected, ok := t.observer.(interface{ DiagnosticLevel() int }); ok {
		return selected.DiagnosticLevel()
	}
	return 3
}

func (t *authenticationTrace) ObserveDiagnostic(event corelog.Diagnostic) {
	if event.Kind == corelog.AuthenticationAttempt {
		t.selected = event.Method
	}
	if event.NodeID == "" {
		event.NodeID = t.nodeID
	}
	corelog.EmitDiagnostic(t.observer, event)
}

func (t *authenticationTrace) wrap(callback cryptossh.ClientAuthCallback) cryptossh.ClientAuthCallback {
	if t == nil {
		return callback
	}
	return func(ctx *cryptossh.ClientAuthContext) (cryptossh.AuthMethod, error) {
		t.callbackSeen = true
		// A new callback proves that the previous selection did NOT complete auth.
		// Only the server-confirmed partial successes survive into the next stage.
		t.selected = ""
		t.partial = slices.Clone(ctx.PartialSuccessMethods)
		if callback == nil {
			return nil, nil
		}
		return callback(ctx)
	}
}

// successfulMethods is used only after the handshake succeeds. If no callback
// ran, x/crypto's initial none exchange is the only possible successful method.
// Unknown selection stays unknown; never guess from the configured auth type.
func (t *authenticationTrace) successfulMethods() []string {
	if t == nil {
		return nil
	}
	if !t.callbackSeen {
		return []string{"none"}
	}
	if t.selected == "" {
		return nil
	}
	return append(slices.Clone(t.partial), t.selected)
}
