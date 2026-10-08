package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const remoteForwardRequestTimeout = 10 * time.Second

// Unlike an idle keepalive, a global forwarding request must finish even when
// unrelated channel traffic continues. x/crypto/ssh serializes these requests
// behind the pending keepalive and cannot cancel one without closing SSH.
func (c *Client) runRemoteForwardRequest(ctx context.Context, request func() error) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	interrupted := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { interrupted <- c.Interrupt() })
	defer func() {
		if !stop() {
			// Join the interrupt callback before releasing the client to callers.
			retErr = errors.Join(retErr, ctx.Err(), <-interrupted)
		} else if err := ctx.Err(); err != nil {
			// Cancellation can race with a successful request and with stopping
			// the callback. Do not publish a listener after its context expires.
			retErr = errors.Join(retErr, err, c.Interrupt())
		}
	}()
	return request()
}

func (c *Client) listenRemoteContext(ctx context.Context, addr string, timeout time.Duration) (net.Listener, error) {
	requestCtx, cancel := withTimeoutOrDefault(ctx, timeout, remoteForwardRequestTimeout)
	defer cancel()
	var listener net.Listener
	err := c.runRemoteForwardRequest(requestCtx, func() (err error) {
		listener, err = c.sshClient.Listen("tcp", addr)
		return err
	})
	if listener == nil {
		return nil, err
	}
	bounded := &remoteForwardListener{Listener: listener, client: c, timeout: timeout}
	if err != nil {
		// Listen can register a forward just after transport shutdown. Service
		// Accept while closing so queued forwarded channels cannot strand the
		// upstream forward-list lock. Never leave a late listener behind.
		return nil, errors.Join(err, bounded.closeUnpublished())
	}
	return bounded, nil
}

type remoteForwardListener struct {
	net.Listener
	client  *Client
	timeout time.Duration
	once    sync.Once
	err     error
}

func (l *remoteForwardListener) Close() error {
	l.once.Do(func() {
		// The forwarding context is normally canceled before Close. Allow a
		// bounded graceful cancel-tcpip-forward exchange on a healthy shared
		// connection; only its own expiry should force transport interruption.
		ctx, cancel := withTimeoutOrDefault(context.Background(), l.timeout, remoteForwardRequestTimeout)
		defer cancel()
		if err := l.client.runRemoteForwardRequest(ctx, func() error {
			// Normalize benign transport closure before joining timeout errors,
			// so an EOF caused by interruption cannot hide the deadline failure.
			return closeResource(l.Listener, "remote forwarding listener")
		}); err != nil {
			l.err = fmt.Errorf("stop remote forwarding listener: %w", err)
		}
	})
	return l.err
}

// An unpublished listener has no Accept loop yet. Upstream can hold its
// forward-list lock while enqueueing a channel, so Close needs a concurrent
// drain. A failed channel Accept (including EOF) does not prove the listener's
// queue is closed: keep draining until the bounded Close itself completes.
func (l *remoteForwardListener) closeUnpublished() (retErr error) {
	done := make(chan struct{})
	var closeErr error
	go func() {
		defer close(done)
		closeErr = l.Close() // Owns a timeout context and interrupts stalled I/O.
	}()
	defer func() {
		<-done
		retErr = errors.Join(retErr, closeErr)
	}()
	retry := time.NewTicker(time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-done:
			return retErr
		default:
		}
		conn, err := l.Accept()
		if err == nil {
			retErr = errors.Join(retErr, closeResource(conn, "unpublished remote forwarding connection"))
			continue
		}
		// A removed listener returns EOF immediately while the cancellation
		// reply is pending. Avoid spinning, while still draining failed opens.
		select {
		case <-done:
			return retErr
		case <-retry.C:
		}
	}
}
