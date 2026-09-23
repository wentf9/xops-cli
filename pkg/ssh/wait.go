package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// Wait monitors the SSH transport, probing idle connections to detect network
// loss. It closes the client before returning and joins its transport waiter.
// Caller cancellation returns only cleanup errors; transport loss is an error.
// Cancellation or a failed probe aborts the entire shared ProxyJump transport.
func (c *Client) Wait(ctx context.Context) error {
	return c.wait(ctx, DefaultKeepAliveInterval, DefaultKeepAliveTimeout)
}

func (c *Client) wait(ctx context.Context, interval, timeout time.Duration) (retErr error) {
	done := make(chan struct{})
	var waitErr error
	go func() {
		defer close(done)
		waitErr = c.sshClient.Wait()
	}()
	defer func() {
		select {
		case <-done:
			retErr = errors.Join(retErr, c.Close())
		default:
			// A channel Close alone cannot release a nested transport's reader.
			retErr = errors.Join(retErr, c.Interrupt())
		}
		<-done
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-done:
			if ctx.Err() != nil {
				return nil
			}
			if waitErr == nil {
				waitErr = io.EOF
			}
			return fmt.Errorf("SSH connection lost: %w", waitErr)
		case <-ticker.C:
			if err := probeWithTimeoutAndInterrupt(ctx, c.sshClient, timeout, c.Interrupt); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("SSH connection lost: %w", err)
			}
		}
	}
}
