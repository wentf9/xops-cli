// Package sshexec implements the MCP execution ports using the shared SSH/SFTP
// core. It does not load inventory, secrets, trust, or defaults from CLI state.
package sshexec

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/remotefile"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
)

type Options struct {
	SSH               []ssh.Option
	Logger            corelog.DebugLogger
	KeepAliveInterval time.Duration
	KeepAliveTimeout  time.Duration
}

type Backend struct {
	ctx       context.Context
	cancel    context.CancelFunc
	connector *ssh.Connector
	options   Options
	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
}

var _ ports.Backend = (*Backend)(nil)

func New(ctx context.Context, options Options) (*Backend, error) {
	if ctx == nil {
		return nil, errors.New("SSH backend context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	options.SSH = slices.Clone(options.SSH)
	if ports.Nil(options.Logger) {
		options.Logger = corelog.NopLogger
	}
	// The owning runtime drains committed work before Shutdown. Cancelling its
	// request context alone must not interrupt an already admitted commit.
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	b := &Backend{ctx: lifetime, cancel: cancel, options: options, closed: make(chan struct{})}
	b.connector = b.newConnector()
	b.connector.EnableKeepAlive(lifetime, options.KeepAliveInterval, options.KeepAliveTimeout)
	return b, nil
}

func (b *Backend) newConnector() *ssh.Connector {
	options := append([]ssh.Option{ssh.WithLogger(b.options.Logger)}, b.options.SSH...)
	return ssh.NewConnector(nil, options...)
}

func (b *Backend) work(ctx context.Context, permit ports.Permit, phases ...ports.Phase) (context.Context, context.CancelFunc, error) {
	if err := b.ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("SSH backend stopped: %w", err)
	}
	work, cancel, err := ports.WorkContext(ctx, permit, phases...)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(b.ctx, cancel)
	if b.ctx.Err() != nil {
		cancel()
	}
	return work, func() { stop(); cancel() }, nil
}

func (b *Backend) connection(ctx context.Context, permit ports.Permit, selector string) (*ssh.PlanConnection, error) {
	view := permit.Snapshot().Clone()
	if err := permit.Binding().Validate(view); err != nil {
		return nil, err
	}
	_, target, err := view.Resolve(selector)
	if err != nil {
		return nil, err
	}
	connection, err := b.connector.ConnectPlan(ctx, target.Plan)
	if err != nil {
		return nil, fmt.Errorf("connect bound SSH target: %w", err)
	}
	return connection, nil
}

func (b *Backend) Run(ctx context.Context, permit ports.Permit, nodeID string, command ports.Command) (result ports.CommandResult, retErr error) {
	work, cancel, err := b.work(ctx, permit, ports.Execute)
	if err != nil {
		return result, err
	}
	defer cancel()
	connection, err := b.connection(work, permit, nodeID)
	if err != nil {
		return result, err
	}
	defer func() { retErr = errors.Join(retErr, connection.Close()) }()
	result.Connected = true
	if command.Sudo {
		result.Output, retErr = connection.Client.RunWithSudo(work, command.Text)
	} else {
		result.Output, retErr = connection.Client.Run(work, command.Text)
	}
	return result, retErr
}

func (b *Backend) OpenFiles(ctx context.Context, permit ports.Permit, nodeID string) (ports.FileSession, error) {
	return b.openFiles(ctx, permit, nodeID, ports.Execute)
}

func (b *Backend) openFiles(ctx context.Context, permit ports.Permit, nodeID string, phases ...ports.Phase) (*fileSession, error) {
	work, cancel, err := b.work(ctx, permit, phases...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	connection, err := b.connection(work, permit, nodeID)
	if err != nil {
		return nil, err
	}
	files, err := sftp.NewClient(work, connection.Client)
	if err != nil {
		return nil, errors.Join(err, connection.Close())
	}
	return &fileSession{Client: files, backend: b, permit: permit, phases: slices.Clone(phases), release: sync.OnceValue(func() error {
		return errors.Join(files.Close(), connection.Close())
	})}, nil
}

func (b *Backend) Inspect(ctx context.Context, permit ports.Permit, nodeID string, request ports.InspectRequest) (_ remotefile.Metadata, retErr error) {
	files, err := b.openFiles(ctx, permit, nodeID, ports.Inspect, ports.Execute, ports.TransferStart, ports.Recovery)
	if err != nil {
		return remotefile.Metadata{}, err
	}
	remote := remotefile.New(files)
	defer func() { retErr = errors.Join(retErr, remote.Close()) }()
	return remote.Inspect(ctx, request.Path, request.Upload, request.Overwrite)
}

func (b *Backend) OpenTransfer(ctx context.Context, permit ports.Permit, nodeID string) (ports.TransferSession, error) {
	files, err := b.openFiles(ctx, permit, nodeID, ports.TransferStart, ports.Commit, ports.Recovery)
	if err != nil {
		return nil, err
	}
	return ports.GuardTransfer(b.ctx, remotefile.New(&transferFiles{Client: files.Client, release: files.release}), permit)
}

// Retire drains a cached plan but never grants or revokes execution permission.
func (b *Backend) Retire(plan ssh.ConnectionPlan) error { return b.connector.RetirePlan(plan) }

// RetirePlans is a publication callback. Old admitted operations can still
// finish, but late connections for their retired snapshots are not cached.
func (b *Backend) RetirePlans(ctx context.Context, plans []ssh.ConnectionPlan) error {
	if ctx == nil {
		return errors.New("retirement context is required")
	}
	var result error
	for _, plan := range plans {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		result = errors.Join(result, b.Retire(plan))
	}
	return result
}

func (b *Backend) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return errors.New("SSH backend shutdown context is required")
	}
	b.closeOnce.Do(func() {
		b.cancel()
		// CloseAll interrupts physical transports and joins all owned workers;
		// later Shutdown calls can join a close whose caller deadline elapsed.
		go func() { b.closeErr = b.connector.CloseAll(); close(b.closed) }()
	})
	select {
	case <-b.closed:
		return b.closeErr
	case <-ctx.Done():
		return fmt.Errorf("wait for SSH backend shutdown: %w", ctx.Err())
	}
}
