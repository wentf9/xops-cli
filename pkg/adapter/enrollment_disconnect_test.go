package adapter

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestEnrollmentProbeDisconnectPreservesNodeAndRejectsConnection(t *testing.T) {
	setTestHome(t)
	repo, store, _, _ := pendingAdapterRepository(t)
	service, secrets := pendingCredentialService(t, repo)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	peerCtx, dropPeer := context.WithCancel(ctx)
	defer dropPeer()
	server, err := sshfixture.NewWithOptions(peerCtx, sshfixture.Options{ExecHandler: func(_ string, _ cryptoSSH.Channel) { dropPeer() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{Target: config.ConnectionTarget{Selector: host, User: "fixture", HasUser: true, Port: uint16(port), HasPort: true}})
	if err != nil {
		t.Fatal(err)
	}
	var warnings atomic.Int32
	connector := NewConnectorWithAdapterOptions(repo, []Option{
		WithCredentialService(service),
		WithSessionAuthOverride(prepared.NodeID, SessionAuth{Password: sshfixture.Password, Remember: true}),
		WithEnrollmentProbing(func(string, error) { warnings.Add(1) }),
	}, ssh.WithHandshakeTimeout(time.Second))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	client, connectErr := connector.Connect(ctx, prepared.NodeID)
	if client != nil {
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	var connectionErr *ssh.ConnectionError
	if client != nil || !errors.As(connectErr, &connectionErr) {
		t.Fatalf("disconnected probe returned a usable connection: client=%v, err=%v", client != nil, connectErr)
	}
	disk, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	node, saved := disk.Nodes.Get(prepared.NodeID)
	if !saved || node.Execution != nil {
		t.Fatal("authenticated node was lost or partial probe settings persisted")
	}
	if warnings.Load() != 1 || server.Executed.Load() != 1 || server.Authenticated.Load() != 1 || len(secrets.data) != 0 {
		t.Fatal("disconnected enrollment retried, dispatched user work or recorded credentials")
	}
}
