package adapter

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestInventoryVerificationNeverPersistsDraft(t *testing.T) {
	setTestHome(t)
	host, port, stop := startAdapterPrivilegeSSHServer(t, "verified-secret", "")
	t.Cleanup(stop)
	for _, password := range []string{"verified-secret", "wrong-secret"} {
		t.Run(password, func(t *testing.T) {
			repo, _, path, before := pendingAdapterRepository(t)
			preview, err := repo.PreviewConnection("draft", models.Node{}, models.Host{Address: host, Port: uint16(port)}, models.Identity{User: "root", AuthType: "password", Password: password})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err = VerifyConnection(ctx, preview, "draft", nil)
			if (err == nil) != (password == "verified-secret") {
				t.Fatalf("verification result: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) || repo.Snapshot().Nodes.Count() != 0 {
				t.Fatal("verification saved draft metadata or credentials")
			}
		})
	}
}

// TestVerifyConnection_IgnoresActiveControlSocket verifies that VerifyConnection
// always dials a fresh SSH connection to validate credentials instead of
// attaching to an active control master socket on disk (which would report the
// wrong password as valid).
func TestVerifyConnection_IgnoresActiveControlSocket(t *testing.T) {
	setTestHome(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	host, port, stop := startAdapterPrivilegeSSHServer(t, "verified-secret", "")
	t.Cleanup(stop)

	// Start a live MuxServer on a known control socket for the same (host, port, user).
	addr := host
	fixtureClient, err := cryptoSSH.Dial("tcp", addr+":"+itoa(port), &cryptoSSH.ClientConfig{
		User:            "root",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password("verified-secret")},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial test server for master socket failed: %v", err)
	}
	t.Cleanup(func() { _ = fixtureClient.Close() })
	_ = sshfixture.Password

	sockPath := filepath.Join(t.TempDir(), "verify-bypass.sock")
	muxServer, err := ssh.NewMuxServer(ssh.MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         fixtureClient,
		Target:            ssh.TargetContext{Host: host, Port: port, User: "root"},
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	go func() { _ = muxServer.Serve() }()
	t.Cleanup(func() { _ = muxServer.Shutdown() })

	repo, _, _, _ := pendingAdapterRepository(t)
	preview, err := repo.PreviewConnection(
		"draft",
		models.Node{
			Control: &ssh.ControlConfig{
				Master:  ssh.ControlMasterAuto,
				Path:    sockPath,
				Persist: "10m",
			},
		},
		models.Host{Address: host, Port: uint16(port)},
		models.Identity{User: "root", AuthType: "password", Password: "wrong-password"},
	)
	if err != nil {
		t.Fatal(err)
	}

	// VerifyConnection MUST fail because the password is wrong, even though an
	// active control master socket exists for root@host:port at sockPath!
	if err := VerifyConnection(ctx, preview, "draft", nil); err == nil {
		t.Fatal("VerifyConnection succeeded with wrong password by reusing active control master socket")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
