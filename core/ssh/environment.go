package ssh

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"slices"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// HostKeyRequest binds trust verification to the connection being established.
type HostKeyRequest struct {
	NodeID       string
	Host         string
	Port         int
	User         string
	VersionToken string
	Hostname     string
	Remote       net.Addr
}

// HostKeyVerifier implementations must honor the handshake context and must
// not trust an unknown host implicitly.
type HostKeyVerifier interface {
	Verify(context.Context, HostKeyRequest, cryptoSSH.PublicKey) error
}

// Environment supplies explicitly selected local resources. The core never
// discovers a home directory, SSH_AUTH_SOCK, or process standard streams.
// Slices are copied by WithEnvironment; callbacks must be concurrency-safe.
type Environment struct {
	InitializationError error
	KnownHostsFile      string
	AgentSocket         string
	DefaultKeyPaths     []string
	ResolveKeyPath      func(string) string
	InteractiveIO       InteractiveIO
	InputBridge         InputBridge
}

func WithEnvironment(environment Environment) Option {
	environment.DefaultKeyPaths = slices.Clone(environment.DefaultKeyPaths)
	if nilCapability(environment.InputBridge) {
		environment.InputBridge = nil
	}
	return func(c *Connector) {
		c.environment = environment
	}
}

func WithHostKeyVerifier(verifier HostKeyVerifier) Option {
	if nilCapability(verifier) {
		verifier = nil
	}
	return func(c *Connector) {
		c.hostKeyVerifier = verifier
	}
}

// Interface-returning adapters can accidentally wrap a nil pointer. Reject it
// before invoking a lifecycle callback instead of starting a panicking worker.
func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func resolveKeyPath(path string, resolve func(string) string) string {
	if resolve != nil {
		return resolve(path)
	}
	return path
}

func (c *Connector) configureClient(client *Client) *Client {
	client.environment = c.environment
	return client
}

func (c *Client) defaultInteractiveIO() InteractiveIO {
	return c.environment.InteractiveIO
}

func validateEnvironment(environment Environment) error {
	if environment.InitializationError != nil {
		return fmt.Errorf("initialize local SSH environment: %w", environment.InitializationError)
	}
	if environment.KnownHostsFile == "" {
		return fmt.Errorf("host trust source is not configured: %w", ErrInteractionRequired)
	}
	return nil
}
