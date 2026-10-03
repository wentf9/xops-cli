package mcphost

import (
	"context"
	"errors"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/remotefile"
	"github.com/wentf9/xops-cli/core/mcp/sshexec"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
)

// Backend preserves the original static-fixture connection behavior, including
// direct fault-injection access. Production hosts use sshexec or a CLI adapter.
type Backend struct {
	Connector *ssh.Connector
	provider  *Provider
}

func (p *Provider) NewBackend(ctx context.Context) (ports.Backend, error) {
	connector := ssh.NewConnector(p, p.SSHOptions()...)
	connector.EnableKeepAlive(ctx, ssh.DefaultKeepAliveInterval, ssh.DefaultKeepAliveTimeout)
	return &Backend{Connector: connector, provider: p}, nil
}
func (b *Backend) Run(ctx context.Context, _ ports.Permit, node string, command ports.Command) (ports.CommandResult, error) {
	client, err := b.Connector.Connect(ctx, node)
	if err != nil {
		return ports.CommandResult{}, err
	}
	var output string
	if command.Sudo {
		output, err = client.RunWithSudo(ctx, command.Text)
	} else {
		output, err = client.Run(ctx, command.Text)
	}
	return ports.CommandResult{Output: output, Connected: true}, err
}
func (b *Backend) OpenFiles(ctx context.Context, _ ports.Permit, node string) (ports.FileSession, error) {
	client, err := b.Connector.Connect(ctx, node)
	if err != nil {
		return nil, err
	}
	return sftp.NewClient(ctx, client)
}
func (b *Backend) OpenTransfer(ctx context.Context, permit ports.Permit, node string) (ports.TransferSession, error) {
	files, err := b.OpenFiles(ctx, permit, node)
	if err != nil {
		return nil, err
	}
	return ports.GuardTransfer(context.WithoutCancel(ctx), remotefile.New(files), permit)
}
func (b *Backend) Inspect(ctx context.Context, permit ports.Permit, node string, request ports.InspectRequest) (_ remotefile.Metadata, retErr error) {
	files, err := b.OpenFiles(ctx, permit, node)
	if err != nil {
		return remotefile.Metadata{}, err
	}
	remote := remotefile.New(files)
	defer func() { retErr = errors.Join(retErr, remote.Close()) }()
	return remote.Inspect(ctx, request.Path, request.Upload, request.Overwrite)
}
func (b *Backend) Shutdown(context.Context) error { return b.Connector.CloseAll() }
func (b *Backend) RunTunnel(ctx context.Context, _ ports.Permit, spec tunnel.Spec, ready func(string) bool, report func(error)) (retErr error) {
	connector := ssh.NewConnector(b.provider, b.provider.SSHOptions()...)
	defer func() { retErr = errors.Join(retErr, connector.CloseAll()) }()
	client, err := connector.Connect(ctx, spec.NodeID)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	return sshexec.RunDedicatedForward(ctx, client, spec, ready, report)
}
