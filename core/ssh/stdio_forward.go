package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// directTCPIPOpenMsg encodes RFC 4254 section 7.2 "direct-tcpip" channel open data.
type directTCPIPOpenMsg struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type openChannelResult struct {
	channel  cryptoSSH.Channel
	requests <-chan *cryptoSSH.Request
	err      error
}

// openChannelContext opens a raw SSH channel under a bounded timeout and
// interrupts the underlying transport if cancellation races an unresponsive peer.
func (c *Client) openChannelContext(ctx context.Context, channelType string, payload []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("open SSH channel %q context is nil", channelType)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("open SSH channel %q canceled: %w", channelType, err)
	}
	if c == nil || c.sshClient == nil {
		return nil, nil, fmt.Errorf("SSH client is not connected")
	}

	work, cancel := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
	defer cancel()

	result := make(chan openChannelResult, 1)
	go func() {
		ch, reqs, err := c.sshClient.OpenChannel(channelType, payload)
		result <- openChannelResult{channel: ch, requests: reqs, err: err}
	}()

	select {
	case opened := <-result:
		if opened.err != nil {
			return nil, nil, fmt.Errorf("open SSH channel %q failed: %w", channelType, opened.err)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, errors.Join(ctxErr, closeSSHChannel(opened.channel))
		}
		return opened.channel, opened.requests, nil
	case <-work.Done():
		select {
		case opened := <-result:
			var closeErr error
			if opened.channel != nil {
				closeErr = closeSSHChannel(opened.channel)
			}
			return nil, nil, errors.Join(work.Err(), opened.err, closeErr)
		default:
		}
		interruptErr := c.Interrupt()
		opened := <-result
		var closeErr error
		if opened.channel != nil {
			closeErr = closeSSHChannel(opened.channel)
		}
		return nil, nil, errors.Join(work.Err(), interruptErr, opened.err, closeErr)
	}
}

func closeSSHChannel(ch io.Closer) error {
	if ch == nil {
		return nil
	}
	if err := ch.Close(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}

// channelHalfCloser forwards writes to an SSH channel and sends SSH_MSG_CHANNEL_EOF
// (CloseWrite) when local input finishes, keeping the receive direction open.
type channelHalfCloser struct {
	ch      cryptoSSH.Channel
	eofOnce sync.Once
	eofDone chan struct{}
}

func newChannelHalfCloser(ch cryptoSSH.Channel) *channelHalfCloser {
	return &channelHalfCloser{
		ch:      ch,
		eofDone: make(chan struct{}),
	}
}

func (w *channelHalfCloser) Write(p []byte) (int, error) {
	return w.ch.Write(p)
}

func (w *channelHalfCloser) Close() error {
	err := w.ch.CloseWrite()
	w.eofOnce.Do(func() {
		close(w.eofDone)
	})
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}

func (c *Client) validateStdioForwardArgs(ctx context.Context, destHost string, destPort uint16, stdin io.Reader, stdout io.Writer) error {
	if ctx == nil {
		return fmt.Errorf("stdio forward context is nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("stdio forward canceled: %w", err)
	}
	if c == nil || c.sshClient == nil {
		return fmt.Errorf("SSH client is not connected")
	}
	if destHost == "" || destPort == 0 {
		return fmt.Errorf("invalid stdio forward destination %q:%d", destHost, destPort)
	}
	if stdout == nil {
		return fmt.Errorf("stdio forward stdout is nil")
	}
	return validateCommandStdin(stdin, c.environment.InputBridge)
}

func (c *Client) startStdioInputPipe(ctx context.Context, ch cryptoSSH.Channel, stdin io.Reader) (func() error, <-chan struct{}, error) {
	if stdin == nil {
		if halfErr := ch.CloseWrite(); halfErr != nil && !errors.Is(halfErr, io.EOF) {
			return nil, nil, fmt.Errorf("half-close stdio forward channel: %w", halfErr)
		}
		eofDone := make(chan struct{})
		close(eofDone)
		return func() error { return nil }, eofDone, nil
	}
	hc := newChannelHalfCloser(ch)
	stopStdin, err := pipeCommandStdin(
		stdin,
		hc,
		inputPipelineOptions{ctx: ctx, bridge: c.environment.InputBridge},
	)
	if err != nil {
		return nil, nil, err
	}
	return stopStdin, hc.eofDone, nil
}

func waitStdioForward(work context.Context, readDone <-chan error, stdinEOF <-chan struct{}, remoteClosed <-chan struct{}) (error, bool) {
	var (
		readErr          error
		readDoneReceived bool
	)
	select {
	case readErr = <-readDone:
		readDoneReceived = true
	case <-work.Done():
	}

	if readDoneReceived && readErr == nil && work.Err() == nil {
		select {
		case <-stdinEOF:
		case <-remoteClosed:
		case <-work.Done():
		}
	}
	return readErr, readDoneReceived
}

// ForwardStdio forwards caller-provided stdin and stdout to destHost:destPort
// over an SSH "direct-tcpip" channel (implementing OpenSSH -W host:port).
//
// Ownership contract: stdin and stdout are borrowed from the caller and are
// NEVER closed by ForwardStdio. Local stdin EOF sends SSH_MSG_CHANNEL_EOF via
// CloseWrite while continuing to drain remote channel data until remote EOF or
// context cancellation. Remote EOF allows remaining local stdin data to be sent
// until local EOF, remote channel close, or context cancellation.
func (c *Client) ForwardStdio(ctx context.Context, destHost string, destPort uint16, stdin io.Reader, stdout io.Writer) (retErr error) {
	if err := c.validateStdioForwardArgs(ctx, destHost, destPort, stdin, stdout); err != nil {
		return err
	}

	payload := cryptoSSH.Marshal(&directTCPIPOpenMsg{
		DestAddr:   destHost,
		DestPort:   uint32(destPort),
		OriginAddr: "127.0.0.1",
		OriginPort: 65535,
	})
	ch, reqs, err := c.openChannelContext(ctx, "direct-tcpip", payload)
	if err != nil {
		return fmt.Errorf("stdio forward to %s:%d failed: %w", destHost, destPort, err)
	}
	remoteClosed := make(chan struct{})
	go func() {
		defer close(remoteClosed)
		cryptoSSH.DiscardRequests(reqs)
	}()

	work, cancel := context.WithCancel(ctx)
	defer cancel()

	boundOut, closeOut, outCancelable, err := BindOutput(work, stdout)
	if err != nil {
		_ = closeSSHChannel(ch)
		return fmt.Errorf("bind stdio forward stdout: %w", err)
	}
	c.logUncancelableOutput(outCancelable, stdout)

	stopStdin, stdinEOF, err := c.startStdioInputPipe(work, ch, stdin)
	if err != nil {
		_ = closeSSHChannel(ch)
		return errors.Join(err, closeOut())
	}

	readDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(boundOut, ch)
		if errors.Is(copyErr, io.EOF) || errors.Is(copyErr, os.ErrClosed) {
			copyErr = nil
		}
		readDone <- copyErr
	}()

	readErr, readDoneReceived := waitStdioForward(work, readDone, stdinEOF, remoteClosed)

	wasCanceled := work.Err() != nil
	cancel()
	closeChErr := closeSSHChannel(ch)
	if !readDoneReceived {
		rErr := <-readDone
		if !wasCanceled {
			readErr = rErr
		}
	}
	stdinErr := stopStdin()
	outErr := closeOut()

	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, closeChErr, outErr)
	}
	return errors.Join(readErr, stdinErr, closeChErr, outErr)
}
