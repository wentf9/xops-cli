package sftp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/ssh"
	cryptossh "golang.org/x/crypto/ssh"
)

type Option func(*Client)

const (
	defaultSubsystemSetupTimeout = 10 * time.Second
	subsystemCloseTimeout        = time.Second
)

func WithConcurrentFiles(con int) Option {
	return func(c *Client) {
		if con > 0 {
			c.config.ConcurrentFiles = con
		}
	}
}

func WithThreadsPerFile(t int) Option {
	return func(c *Client) {
		if t > 0 {
			c.config.ThreadsPerFile = t
		}
	}
}

func WithChunkSize(size int) Option {
	return func(c *Client) {
		if size > 0 {
			c.config.ChunkSize = int64(size)
		}
	}
}

func WithResume(enable bool) Option {
	return func(c *Client) {
		c.config.EnableResume = enable
	}
}

func WithResumeMinSize(size int64) Option {
	return func(c *Client) {
		if size > 0 {
			c.config.ResumeMinSize = size
		}
	}
}

func WithForce(force bool) Option {
	return func(c *Client) {
		c.config.Force = force
	}
}

// Client wraps an SFTP client and owns only file-transfer concerns. Canceling
// an in-flight operation first closes only this client's SFTP subsystem. If
// the server leaves that close blocked, the shared SSH transport is closed as
// a bounded last-resort interrupt.
type clientState struct {
	sftpClient    *sftp.Client
	interrupt     func() error
	interruptOnce sync.Once
	interruptErr  error
	closeOnce     sync.Once
	closeErr      error
}

type Client struct {
	state  *clientState
	config TransferConfig
}

// NewClient creates an SFTP subsystem on an existing SSH connection. Setup is
// bounded by ctx and an internal maximum timeout, including subsystem and
// protocol handshakes.
func NewClient(ctx context.Context, sshCli *ssh.Client, opts ...Option) (*Client, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	if sshCli == nil {
		return nil, fmt.Errorf("ssh client is nil")
	}
	setupCtx, cancelSetup := context.WithTimeout(ctx, defaultSubsystemSetupTimeout)
	defer cancelSetup()

	sftpCli := &Client{
		state:  &clientState{},
		config: DefaultConfig(),
	}
	for _, opt := range opts {
		opt(sftpCli)
	}

	client, interrupt, err := newSFTPSubsystem(
		setupCtx,
		sshCli,
		sftp.MaxConcurrentRequestsPerFile(sftpCli.config.ThreadsPerFile),
		sftp.MaxPacket(32*1024),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create sftp subsystem: %w", err)
	}
	sftpCli.state.sftpClient = client
	sftpCli.state.interrupt = interrupt

	return sftpCli, nil
}

func newSFTPSubsystem(ctx context.Context, sshCli *ssh.Client, opts ...sftp.ClientOption) (*sftp.Client, func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	session, err := newSubsystemSessionContext(ctx, sshCli)
	if err != nil {
		return nil, nil, err
	}

	closeSession := sync.OnceValues(func() (struct{}, error) {
		return struct{}{}, closeSubsystemSessionAndWait(session, sshCli)
	})
	interrupt := func() error {
		_, interruptErr := closeSession()
		return interruptErr
	}
	setupCanceled := make(chan error, 1)
	stopSetupCancellation := context.AfterFunc(ctx, func() {
		setupCanceled <- interrupt()
	})
	finishSetupCancellation := sync.OnceValues(func() (struct{}, error) {
		if stopSetupCancellation() {
			return struct{}{}, nil
		}
		return struct{}{}, errors.Join(ctx.Err(), <-setupCanceled)
	})
	finishSetup := func() error {
		_, err := finishSetupCancellation()
		return err
	}

	fail := func(operation string, operationErr error) (*sftp.Client, func() error, error) {
		return nil, nil, errors.Join(
			fmt.Errorf("%s: %w", operation, operationErr),
			finishSetup(),
			interrupt(),
		)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return fail("create SFTP subsystem stdin pipe failed", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fail("create SFTP subsystem stdout pipe failed", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return fail("create SFTP subsystem stderr pipe failed", err)
	}
	if err := session.RequestSubsystem("sftp"); err != nil {
		return fail("request SFTP subsystem failed", err)
	}

	stderrDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(io.Discard, stderr)
		if copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, net.ErrClosed) {
			copyErr = fmt.Errorf("drain SFTP subsystem stderr failed: %w", copyErr)
		} else {
			copyErr = nil
		}
		stderrDone <- copyErr
	}()

	client, err := sftp.NewClientPipe(stdout, stdin, opts...)
	if err != nil {
		return nil, nil, errors.Join(
			fmt.Errorf("initialize SFTP protocol failed: %w", err),
			finishSetup(),
			interrupt(),
			waitSubsystemStderr(stderrDone),
		)
	}
	if setupErr := finishSetup(); setupErr != nil {
		return nil, nil, errors.Join(
			setupErr,
			closeTransferResource(client, "SFTP client after canceled setup"),
			interrupt(),
			waitSubsystemStderr(stderrDone),
		)
	}

	interruptAndWait := sync.OnceValues(func() (struct{}, error) {
		return struct{}{}, errors.Join(interrupt(), waitSubsystemStderr(stderrDone))
	})
	return client, func() error {
		_, err := interruptAndWait()
		return err
	}, nil
}

type subsystemSessionResult struct {
	session *cryptossh.Session
	err     error
}

func newSubsystemSessionContext(ctx context.Context, sshCli *ssh.Client) (*cryptossh.Session, error) {
	result := make(chan subsystemSessionResult, 1)
	go func() {
		session, err := sshCli.SSHClient().NewSession()
		result <- subsystemSessionResult{session: session, err: err}
	}()

	select {
	case created := <-result:
		if created.err != nil {
			return nil, fmt.Errorf("create SSH session failed: %w", created.err)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, errors.Join(ctxErr, closeSubsystemSessionAndWait(created.session, sshCli))
		}
		return created.session, nil
	case <-ctx.Done():
		// If NewSession has already published a channel, cancellation owns and
		// closes only that channel. Otherwise closing the transport is the sole
		// protocol-level interrupt for the pending channel-open request.
		select {
		case created := <-result:
			var createErr error
			if created.err != nil {
				createErr = fmt.Errorf("create SSH session after cancellation failed: %w", created.err)
			}
			return nil, errors.Join(ctx.Err(), createErr, closeSubsystemSessionAndWait(created.session, sshCli))
		default:
		}
		interruptErr := sshCli.Interrupt()
		created := <-result
		var createErr, sessionErr error
		if created.err != nil {
			createErr = fmt.Errorf("create SSH session after transport shutdown failed: %w", created.err)
		}
		if created.session != nil {
			sessionErr = closeSubsystemSession(created.session)
		}
		return nil, errors.Join(ctx.Err(), interruptErr, createErr, sessionErr)
	}
}

func closeSubsystemSession(session *cryptossh.Session) error {
	if session == nil {
		return nil
	}
	err := session.Close()
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("close SFTP subsystem session failed: %w", err)
	}
	return nil
}

func closeSubsystemSessionAndWait(session *cryptossh.Session, sshCli *ssh.Client) error {
	if session == nil {
		return nil
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- closeSubsystemSession(session)
	}()
	timer := time.NewTimer(subsystemCloseTimeout)
	defer timer.Stop()
	select {
	case err := <-closeDone:
		return err
	case <-timer.C:
		interruptErr := sshCli.Interrupt()
		closeErr := <-closeDone
		return errors.Join(fmt.Errorf("close SFTP subsystem session timed out after %s", subsystemCloseTimeout), interruptErr, closeErr)
	}
}

func waitSubsystemStderr(done <-chan error) error {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return fmt.Errorf("wait stderr drain timed out")
	}
}

// Do runs a low-level SFTP operation with context cancellation. It deliberately
// adds no command policy or presentation concerns; callers retain ownership of
// operation-specific error context. Cancellation interrupts this SFTP
// subsystem, so the client must not be reused afterwards.
func (c *Client) Do(ctx context.Context, operation func(*sftp.Client) error) error {
	if c == nil || c.state == nil || c.state.sftpClient == nil {
		return fmt.Errorf("sftp client is nil")
	}
	if operation == nil {
		return fmt.Errorf("sftp operation is nil")
	}
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		return operation(c.state.sftpClient)
	})
}

// Config 返回当前传输配置
func (c *Client) Config() TransferConfig {
	if c == nil {
		return TransferConfig{}
	}
	return c.config
}

// SetForce 动态设置强制覆盖标志

// Close closes this SFTP subsystem. A blocked subsystem close may close the
// shared SSH transport as a bounded last-resort interrupt.
func (c *Client) Close() error {
	if c == nil || c.state == nil {
		return nil
	}
	c.state.closeOnce.Do(func() {
		c.state.closeErr = c.interruptTransfers()
		if c.state.sftpClient != nil {
			c.state.closeErr = errors.Join(
				c.state.closeErr,
				closeTransferResource(c.state.sftpClient, "SFTP client"),
			)
		}
	})
	return c.state.closeErr
}

// interruptTransfers closes this client's SFTP subsystem. It leaves the shared
// SSH transport open unless a blocked subsystem close requires the bounded
// transport fallback documented on Client.
func (c *Client) interruptTransfers() error {
	if c == nil || c.state == nil {
		return nil
	}
	c.state.interruptOnce.Do(func() {
		interrupt := c.state.interrupt
		if interrupt == nil && c.state.sftpClient != nil {
			interrupt = func() error {
				return closeTransferResource(c.state.sftpClient, "SFTP client during interruption")
			}
		}
		if interrupt == nil {
			return
		}
		if err := interrupt(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			c.state.interruptErr = fmt.Errorf("interrupt SFTP subsystem failed: %w", err)
		}
	})
	return c.state.interruptErr
}

// Cwd returns the remote working directory using the caller's cancellation boundary.
func (c *Client) Cwd(ctx context.Context) (cwd string, retErr error) {
	retErr = c.Do(ctx, func(rawClient *sftp.Client) error {
		var err error
		cwd, err = rawClient.Getwd()
		return err
	})
	return cwd, retErr
}

// JoinPath 辅助函数：处理远程路径拼接 (SFTP 协议强制使用 forward slash)
func (c *Client) JoinPath(elem ...string) string {
	if c == nil || c.state == nil || c.state.sftpClient == nil {
		return path.Join(elem...)
	}
	return c.state.sftpClient.Join(elem...)
}

// WithForce returns a new Client instance sharing the same underlying connection
// but with the specified Force configuration. This is safe for concurrent use.
func (c *Client) WithForce(force bool) *Client {
	if c == nil {
		return nil
	}
	clone := *c
	clone.config.Force = force
	return &clone
}

// SFTPClient returns the underlying *sftp.Client.
func (c *Client) SFTPClient() *sftp.Client {
	if c == nil || c.state == nil {
		return nil
	}
	return c.state.sftpClient
}
