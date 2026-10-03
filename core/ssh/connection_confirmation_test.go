package ssh

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
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
