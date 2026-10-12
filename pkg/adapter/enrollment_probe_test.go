package adapter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestDynamicEnrollmentProbePolicyAndAtomicPersistence(t *testing.T) {
	for _, mode := range []string{"remember", "session only", "non-interactive", "not enabled", "probe failure", "authentication failure"} {
		t.Run(mode, func(t *testing.T) {
			setTestHome(t)
			repo, store, path, before := pendingAdapterRepository(t)
			service, secrets := pendingCredentialService(t, repo)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			var userCommands atomic.Int32
			server := newEnrollmentSSHFixture(t, ctx, repo, &userCommands, mode)
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
			password := sshfixture.Password
			if mode == "authentication failure" {
				password = "wrong"
			}
			var warnings atomic.Int32
			options := []Option{WithCredentialService(service), WithSessionAuthOverride(prepared.NodeID, SessionAuth{Password: password, Remember: mode != "session only"}), WithNonInteractive(mode == "non-interactive")}
			if mode != "not enabled" {
				options = append(options, WithEnrollmentProbing(func(string, error) { warnings.Add(1) }))
			}
			connector := NewConnectorWithAdapterOptions(repo, options, ssh.WithHandshakeTimeout(time.Second))
			connector.AcceptNewHostKey.Store(true)
			t.Cleanup(func() {
				if err := connector.CloseAll(); err != nil {
					t.Error(err)
				}
			})
			client, err := connector.Connect(ctx, prepared.NodeID)
			if mode == "authentication failure" {
				if err == nil {
					t.Fatal("invalid credentials authenticated")
				}
				after, readErr := os.ReadFile(path)
				if readErr != nil || !bytes.Equal(before, after) || server.Executed.Load() != 0 || len(secrets.data) != 0 {
					t.Fatal("failed authentication probed or persisted data")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Error(err)
				}
			})
			assertDynamicEnrollment(t, ctx, mode, connector, client, server, repo, store, prepared.NodeID, &warnings, &userCommands)
		})
	}
}

func newEnrollmentSSHFixture(t *testing.T, ctx context.Context, repo *config.Repository, commands *atomic.Int32, mode string) *sshfixture.Server {
	t.Helper()
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: func(command string, ch cryptoSSH.Channel) {
		output := "done"
		if strings.Contains(command, "__XOPS_DIALECT_") || strings.Contains(command, "__XOPS_INTERP__") || strings.HasPrefix(command, "Write-Output ('__XOPS_DIALECT_") {
			if repo.Snapshot().Nodes.Count() != 0 {
				t.Error("node persisted before enrollment probe finished")
			}
			output = "restricted\n"
			if mode != "probe failure" {
				output = "__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n"
				if strings.Contains(command, "__XOPS_DIALECT_POSIX__") {
					output = "__XOPS_DIALECT_POSIX__:Linux:/bin/ash\n"
				}
			}
		} else {
			commands.Add(1)
			if repo.Snapshot().Nodes.Count() != 1 {
				t.Error("user work started before enrollment")
			}
			if mode == "remember" && !strings.HasPrefix(command, "sh -c ") {
				t.Error("first command lost the persisted execution recommendation")
			}
		}
		if _, err := io.WriteString(ch, output); err != nil {
			t.Error(err)
		}
		if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
			t.Error(err)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			if mode == "authentication failure" && expectedEnrollmentAuthFailure(err) {
				return
			}
			t.Error(err)
		}
	})
	return server
}

func expectedEnrollmentAuthFailure(err error) bool {
	var auth *cryptoSSH.ServerAuthError
	if !errors.As(err, &auth) || err.Error() != "SSH fixture failed: "+auth.Error() || len(auth.Errors) == 0 {
		return false
	}
	for _, cause := range auth.Errors {
		if !errors.Is(cause, cryptoSSH.ErrNoAuth) && cause.Error() != "fixture password rejected" {
			return false
		}
	}
	return true
}

func assertDynamicEnrollment(t *testing.T, ctx context.Context, mode string, connector *ssh.Connector, client *ssh.Client, server *sshfixture.Server, repo *config.Repository, store config.Store, nodeID string, warnings, commands *atomic.Int32) {
	t.Helper()
	disk, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	node, saved := disk.Nodes.Get(nodeID)
	if !saved || (node.Execution != nil) != (mode == "remember") {
		t.Fatalf("unexpected enrollment execution for %s: %+v", mode, node.Execution)
	}
	identity, _ := disk.Identities.Get(node.IdentityRef)
	if (identity.LoginPasswordRef != nil) != (mode != "session only" && mode != "non-interactive") {
		t.Fatal("enrollment changed credential remembering policy")
	}
	wantProbe := int32(0)
	if mode == "remember" {
		wantProbe = 2
	}
	if mode == "probe failure" {
		wantProbe = 4
	}
	if server.Executed.Load() != wantProbe || (warnings.Load() == 1) != (mode == "probe failure") {
		t.Fatal("enrollment probe policy or warnings incorrect")
	}
	if mode == "remember" || mode == "probe failure" {
		if _, err := client.ProbeExecutionConfig(ctx); (err != nil) != (mode == "probe failure") {
			t.Fatal(err)
		}
		again, err := connector.Connect(ctx, nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := again.ProbeExecutionConfig(ctx); (err != nil) != (mode == "probe failure") {
			t.Fatal(err)
		}
		if server.Executed.Load() != wantProbe {
			t.Fatal("pooled enrollment probe cache not reused")
		}
	}
	if _, err := client.Run(ctx, "echo user"); err != nil {
		t.Fatal(err)
	}
	if commands.Load() != 1 || server.Authenticated.Load() != 1 {
		t.Fatal("user command or authentication was replayed")
	}
}
