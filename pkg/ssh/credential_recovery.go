package ssh

import (
	"context"
	"errors"
	"sync"

	"github.com/wentf9/xops-cli/pkg/credential"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// CredentialFailureReporter opts an interactive composition root into temporary
// credential recovery. Reports contain operation names only, never backend
// errors, which may contain secrets. Returning an error aborts recovery.
type CredentialFailureReporter interface {
	CredentialRecoveryAllowed() bool
	ReportCredentialFailure(context.Context, string) error
}

var errCredentialNotSaved = errors.New("credential was not saved")

func reportCredentialFailure(ctx context.Context, prompter SecretPrompter, operation string, cause error) bool {
	if ctx.Err() != nil || errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return false
	}
	if operation == "read" && !recoverableCredentialRead(cause) {
		return false
	}
	reporter, ok := prompter.(CredentialFailureReporter)
	return ok && reporter.CredentialRecoveryAllowed() && reporter.ReportCredentialFailure(ctx, operation) == nil
}

func credentialRecoveryPrompter(prompter SecretPrompter) SecretPrompter {
	if reporter, ok := prompter.(CredentialFailureReporter); ok && reporter.CredentialRecoveryAllowed() {
		return prompter
	}
	return nil
}

func (c *Connector) recoverablePasswordAuth(ctx context.Context, cfg *ClientConfig, prompter SecretPrompter, discovered func()) cryptoSSH.AuthMethod {
	provider := &autoSecretProvider{
		lifecycleCtx: ctx, nodeID: cfg.NodeID, user: cfg.User,
		host: cfg.Address, port: cfg.Port, versionToken: cfg.AuthUpdateToken,
		resolver: c.secretResolver, prompter: prompter, recoveryPrompter: c.secretPrompter,
		handshakeTimeout: c.getHandshakeTimeout(), interactionTimeout: c.interactionTimeout,
	}
	attempts := 0
	initial := cfg.Password
	return cryptoSSH.RetryableAuthMethod(cryptoSSH.PasswordCallback(func() (string, error) {
		retry := attempts > 0
		attempts++
		password := initial
		initial = ""
		if retry || password == "" {
			var err error
			password, err = provider.resolveOrPromptAttempt(SecretRequest{Kind: SecretKindLoginPassword}, retry)
			if err != nil {
				return "", err
			}
		}
		cfg.Password = password
		cfg.Passphrase = ""
		if discovered != nil {
			discovered()
		}
		return password, nil
	}), 3)
}

func (c *Connector) recoverableKeyAuth(ctx context.Context, cfg *ClientConfig, prompter SecretPrompter, discovered func()) (cryptoSSH.AuthMethod, func(), error) {
	resolver := &initialKeySecretResolver{value: []byte(cfg.Passphrase), next: c.secretResolver}
	cfg.Passphrase = ""
	provider := &autoSecretProvider{
		lifecycleCtx: ctx, nodeID: cfg.NodeID, user: cfg.User,
		host: cfg.Address, port: cfg.Port, versionToken: cfg.AuthUpdateToken,
		resolver: resolver, prompter: prompter, recoveryPrompter: c.secretPrompter,
		handshakeTimeout: c.getHandshakeTimeout(), interactionTimeout: c.interactionTimeout,
	}
	method, err := resolveKeyAuthMethod(expandHomeDir(cfg.KeyPath), provider, func(_ string, passphrase string) {
		cfg.Passphrase, cfg.Password = passphrase, ""
		if discovered != nil {
			discovered()
		}
	}, c.getLogger())
	cleanup := func() {
		resolver.mu.Lock()
		defer resolver.mu.Unlock()
		zeroBytes(resolver.value)
		resolver.value = nil
	}
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return method, cleanup, nil
}

type initialKeySecretResolver struct {
	mu    sync.Mutex
	value []byte
	next  SecretResolver
}

func (r *initialKeySecretResolver) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if len(r.value) != 0 {
		value := r.value
		r.value = nil
		r.mu.Unlock()
		return value, nil
	}
	r.mu.Unlock()
	if r.next == nil {
		return nil, ErrInteractionRequired
	}
	return r.next.ResolveSecret(ctx, req)
}

func recoverableCredentialRead(err error) bool {
	if errors.Is(err, ErrSnapshotMismatch) || errors.Is(err, credential.ErrConfigConflict) || errors.Is(err, credential.ErrInvalidRef) {
		return false
	}
	for _, cause := range []error{credential.ErrCredentialNotFound, credential.ErrCredentialStoreLocked, credential.ErrCredentialStoreUnavailable, credential.ErrCredentialAccessDenied, credential.ErrStoreNotFound} {
		if errors.Is(err, cause) {
			return true
		}
	}
	return false
}
