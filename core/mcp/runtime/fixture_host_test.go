package runtime

import (
	"context"
	"errors"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/sshexec"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/mcphost"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func WithConfigProvider(source ports.StateSource) Option {
	return func(cfg *serverConfig) {
		if fixture, ok := source.(interface{ Dependencies() ports.Dependencies }); ok {
			cfg.dependencies = fixture.Dependencies()
		}
	}
}

func (r *Runtime) getTestBackend() (ports.Backend, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	return r.backend, nil
}

func isolateMCPTestEnvironment(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	return home
}
func writeKnownHosts(t *testing.T, home, host, port string, key cryptossh.PublicKey) {
	t.Helper()
	directory := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	line := knownhosts.Line([]string{net.JoinHostPort(host, port)}, key) + "\n"
	if err := os.WriteFile(filepath.Join(directory, "known_hosts"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
}

func runMCPSSHTunnel(ctx context.Context, connector *ssh.Connector, spec tunnel.Spec, ready func(string) bool, report func(error)) (retErr error) {
	defer func() { retErr = errors.Join(retErr, connector.CloseAll()) }()
	client, err := connector.Connect(ctx, spec.NodeID)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("connect fixture tunnel: %w", err)
	}
	return sshexec.RunDedicatedForward(ctx, client, spec, ready, report)
}

func Serve(ctx context.Context, opts ...Option) (retErr error) {
	r, err := NewRuntime(ctx, opts...)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, r.Close()) }()
	return r.Run(&mcp.StdioTransport{})
}

func (r *Runtime) connectFixtureNode(ctx context.Context, nodeID string) (*ssh.Client, error) {
	backend, ok := r.backend.(*mcphost.Backend)
	if !ok {
		return nil, fmt.Errorf("runtime fixture backend is missing")
	}
	return backend.Connector.Connect(ctx, nodeID)
}
func (r *Runtime) getFixtureSFTPClient(ctx context.Context, nodeID string) (*sftp.Client, error) {
	client, err := r.connectFixtureNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	return sftp.NewClient(ctx, client)
}
