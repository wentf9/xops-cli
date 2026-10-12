package ssh

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type confirmationProvider struct {
	mockConfigStore
	confirmErr error
	calls      atomic.Int32
}

func (p *confirmationProvider) ConfirmConnection(context.Context, string) error {
	p.calls.Add(1)
	return p.confirmErr
}

type confirmationErrorDialer struct{ err error }

type disconnectedProbeProvider struct {
	mockConfigStore
	probeErr error
}

func (p *disconnectedProbeProvider) ConfirmAuthenticatedConnection(ctx context.Context, _ string, client *Client) (*ExecutionConfig, error) {
	// Enrollment preserves authenticated node metadata even when probing fails.
	// The connector must independently reject the disconnected transport.
	_, err := client.ProbeExecutionConfig(ctx)
	p.probeErr = err
	if !errors.Is(err, ErrExecutionProbe) {
		return nil, errors.New("expected execution probe failure")
	}
	// A channel can close before its parent transport. Wait for the fixture's
	// canceled physical connection so this tests an already observed failure.
	if err := client.sshClient.Wait(); err == nil {
		return nil, errors.New("expected transport disconnection")
	}
	return nil, nil
}

func TestDisconnectedEnrollmentProbeDoesNotPublishTransport(t *testing.T) {
	setTestHome(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	peerCtx, dropPeer := context.WithCancel(ctx)
	defer dropPeer()
	server, err := sshfixture.NewWithOptions(peerCtx, sshfixture.Options{ExecHandler: func(_ string, _ cryptoSSH.Channel) { dropPeer() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, server) })
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	provider := &disconnectedProbeProvider{mockConfigStore: mockConfigStore{cfg: &ClientConfig{
		NodeID: "node", Address: host, Port: port, User: "fixture",
		AuthType: "password", Password: sshfixture.Password,
	}}}
	connector := newTestConnector(provider, WithHandshakeTimeout(time.Second))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	client, err := connector.Connect(ctx, "node")
	if client != nil {
		t.Cleanup(func() { closeTestResource(t, client) })
	}
	var connectionErr *ConnectionError
	if client != nil || !errors.As(err, &connectionErr) || connectionErr.NodeID != "node" {
		t.Fatalf("disconnected enrollment returned client=%v, error=%v, probe=%v", client != nil, err, provider.probeErr)
	}
	if _, published := connector.clients.Get("node"); published {
		t.Fatal("disconnected enrollment published a pooled transport")
	}
	if server.Authenticated.Load() != 1 || server.Executed.Load() != 1 {
		t.Fatal("disconnected enrollment retried authentication or user work")
	}
}

func (d confirmationErrorDialer) Dial(string, string) (net.Conn, error) {
	return nil, d.err
}

func (d confirmationErrorDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}

func TestConnectionConfirmationRequiresAuthentication(t *testing.T) {
	setTestHome(t)
	saveErr := errors.New("configuration save failed")
	for _, tc := range []struct {
		name       string
		password   string
		dialErr    error
		confirmErr error
		calls      int32
	}{
		{name: "authenticated_without_discovered_credentials", password: "valid", calls: 1},
		{name: "save_failure", password: "valid", confirmErr: saveErr, calls: 1},
		{name: "authentication_failure", password: "invalid"},
		{name: "connection_refused", dialErr: errors.New("connection refused")},
		{name: "connection_timeout", dialErr: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, disconnected, stop := startTestAutoSSHServer(t, "valid")
			t.Cleanup(stop)
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			provider := &confirmationProvider{
				mockConfigStore: mockConfigStore{cfg: &ClientConfig{
					NodeID: "node", Address: host, Port: port, User: "root",
					AuthType: "password", Password: tc.password,
				}},
				confirmErr: tc.confirmErr,
			}
			opts := []Option{WithHandshakeTimeout(time.Second)}
			if tc.dialErr != nil {
				opts = append(opts, WithDialer(confirmationErrorDialer{err: tc.dialErr}))
			}
			connector := newTestConnector(provider, opts...)
			connector.AcceptNewHostKey.Store(true)
			defer func() {
				if err := connector.CloseAll(); err != nil {
					t.Errorf("close connector: %v", err)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			client, err := connector.Connect(ctx, "node")
			success := tc.password == "valid" && tc.confirmErr == nil && tc.dialErr == nil
			if (err == nil) != success {
				t.Fatalf("connect error = %v, expected success = %v", err, success)
			}
			if client != nil {
				defer func() {
					if err := client.Close(); err != nil {
						t.Errorf("close client: %v", err)
					}
				}()
			}
			if provider.calls.Load() != tc.calls {
				t.Fatalf("confirmation called %d times, want %d", provider.calls.Load(), tc.calls)
			}
			if tc.confirmErr != nil {
				if !errors.Is(err, tc.confirmErr) {
					t.Fatalf("lost confirmation error: %v", err)
				}
				if _, exists := connector.clients.Get("node"); exists {
					t.Fatal("failed confirmation published an SSH client")
				}
				select {
				case <-disconnected:
				case <-ctx.Done():
					t.Fatal("failed confirmation leaked an authenticated connection")
				}
			}
		})
	}
}
