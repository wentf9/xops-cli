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

// HostKeyAlgorithmSource is an optional HostKeyVerifier capability. It selects
// host key algorithms before the handshake using the same target/trust version
// as Verify. Hostname and Remote are not available at this stage. Implementations
// must honor ctx; errors, empty lists and unsupported algorithms fail closed.
// Selection does not replace Verify or authorize a different key of that type.
type HostKeyAlgorithmSource interface {
	HostKeyAlgorithms(context.Context, HostKeyRequest) ([]string, error)
}

// SSHFPRecord represents a single DNS SSHFP resource record (RFC 4255 / RFC 6594 / RFC 7479).
type SSHFPRecord struct {
	Algorithm       uint8
	FingerprintType uint8
	Fingerprint     []byte
}

// SSHFPResult holds DNS SSHFP lookup records alongside their DNSSEC authentication state.
type SSHFPResult struct {
	Records       []SSHFPRecord
	Authenticated bool
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
	TunnelOpener        TunnelDeviceOpener

	// Multiplexing and path expansion parameters injected by host
	HomeDir   string
	LocalUser string
	LocalHost string
	LocalUID  string
	LookupEnv func(string) (string, bool)

	// GlobalKnownHostsFiles lists read-only system-wide known_hosts paths.
	GlobalKnownHostsFiles []string
	// Environ returns a snapshot of host environment variables ("KEY=VALUE") for SendEnv matching.
	Environ func() []string
	// DialAgent connects to a local SSH agent (Unix socket or Windows Named Pipe).
	DialAgent func(ctx context.Context, socket string) (net.Conn, error)
	// DialProxyCommand executes ProxyCommand and bridges its stdio as a bounded net.Conn; nil fails closed.
	DialProxyCommand func(ctx context.Context, command string) (net.Conn, error)
	// RunLocalCommand executes a foreground LocalCommand; nil fails closed.
	RunLocalCommand func(ctx context.Context, command string) error
	// LookupSSHFP performs bounded DNS SSHFP queries; nil treats no records as available.
	LookupSSHFP func(ctx context.Context, hostname string) (SSHFPResult, error)
}

func WithEnvironment(environment Environment) Option {
	environment.DefaultKeyPaths = slices.Clone(environment.DefaultKeyPaths)
	environment.GlobalKnownHostsFiles = slices.Clone(environment.GlobalKnownHostsFiles)
	if nilCapability(environment.ResolveKeyPath) {
		environment.ResolveKeyPath = nil
	}
	if nilCapability(environment.InputBridge) {
		environment.InputBridge = nil
	}
	if nilCapability(environment.TunnelOpener) {
		environment.TunnelOpener = nil
	}
	if nilCapability(environment.LookupEnv) {
		environment.LookupEnv = nil
	}
	if nilCapability(environment.Environ) {
		environment.Environ = nil
	}
	if nilCapability(environment.DialAgent) {
		environment.DialAgent = nil
	}
	if nilCapability(environment.DialProxyCommand) {
		environment.DialProxyCommand = nil
	}
	if nilCapability(environment.RunLocalCommand) {
		environment.RunLocalCommand = nil
	}
	if nilCapability(environment.LookupSSHFP) {
		environment.LookupSSHFP = nil
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
	client.diagnostics = c.diagnostics
	return client
}

func (c *Client) defaultInteractiveIO() InteractiveIO {
	if c == nil {
		return InteractiveIO{}
	}
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
