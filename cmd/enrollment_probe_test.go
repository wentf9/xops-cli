package cmd

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestEnrollmentProbeHonorsCLIExecutionOverrides(t *testing.T) {
	for _, command := range []string{"ssh", "exec"} {
		for _, tc := range []struct {
			name      string
			execution execExecutionOptions
		}{
			{name: "default"},
			{name: "server", execution: execExecutionOptions{interpreter: "server", interpreterSet: true}},
			{name: "dialect", execution: execExecutionOptions{dialect: "posix", dialectSet: true}},
			{name: "login", execution: execExecutionOptions{interpreter: "bash", interpreterSet: true, dialect: "posix", dialectSet: true, loginSet: true}},
			{name: "no-login", execution: execExecutionOptions{noLoginSet: true}},
			{name: "no-login-false", execution: execExecutionOptions{noLoginSet: true}},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				verifyCLIEnrollmentProbe(t, command, tc.execution, tc.name == "no-login")
			})
		}
	}
}

func verifyCLIEnrollmentProbe(t *testing.T, command string, execution execExecutionOptions, noLogin bool) {
	t.Helper()
	initCredentialPolicyTestI18n(t)
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	_, repo, cfg, err := utils.GetConfigStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	server := newCLIEnrollmentProbeFixture(t, ctx)
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(user string) string {
		t.Helper()
		prepared, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{Target: config.ConnectionTarget{
			Selector: host, User: user, HasUser: true, Port: uint16(port), HasPort: true,
		}})
		if err != nil {
			t.Fatal(err)
		}
		return prepared.NodeID
	}
	nodeID, otherNodeID := prepare("fixture"), prepare("other")
	ui := newCLIInteractionHandlerWithStreams(strings.NewReader("yes\n"), new(bytes.Buffer))
	base := SshOptions{Remember: "always", Password: sshfixture.Password, NoLoginShell: noLogin, interaction: ui, execution: execution}
	var options []adapter.Option
	if command == "ssh" {
		options, err = base.buildAdapterOptions(nodeID, cfg, repo)
	} else {
		o := ExecOptions{SshOptions: base, Interactive: true, interaction: ui}
		options, err = o.buildAdapterOptions([]execHostTask{{nodeID: nodeID, pass: sshfixture.Password}}, cfg, repo)
	}
	if err != nil {
		t.Fatal(err)
	}
	options = append(options, adapter.WithSessionAuthOverride(otherNodeID, adapter.SessionAuth{Password: sshfixture.Password, Remember: true}))
	connector := adapter.NewConnectorWithAdapterOptions(repo, options, ssh.WithHandshakeTimeout(time.Second),
		ssh.WithEnvironment(ssh.Environment{KnownHostsFile: filepath.Join(t.TempDir(), "known_hosts")}))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	for index, id := range []string{nodeID, otherNodeID} {
		client, err := connector.Connect(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Error(err)
			}
		})
		wantRequests := int32(2)
		if !execution.enabled() && !execution.noLoginSet {
			wantRequests = 4
		}
		if index == 0 {
			wantRequests -= 2
		}
		assertCLIEnrollmentProbe(t, client, repo, store, id, index == 1 || (!execution.enabled() && !execution.noLoginSet))
		if server.Executed.Load() != wantRequests {
			t.Fatalf("probe requests=%d, want %d", server.Executed.Load(), wantRequests)
		}
	}
}

func assertCLIEnrollmentProbe(t *testing.T, client *ssh.Client, repo *config.Repository, store config.Store, nodeID string, wantProbe bool) {
	t.Helper()
	node, saved := repo.GetNode(nodeID)
	if !saved || (node.Execution != nil) != wantProbe {
		t.Fatalf("node %s persisted execution %+v, want probe=%v", nodeID, node.Execution, wantProbe)
	}
	disk, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	savedNode, saved := disk.Nodes.Get(nodeID)
	identity, _ := disk.Identities.Get(savedNode.IdentityRef)
	if !saved || (savedNode.Execution != nil) != wantProbe || identity.LoginPasswordRef == nil {
		t.Fatal("probe exclusion changed enrollment or credential persistence")
	}
	_, cached := client.CachedExecutionProbe()
	if cached != wantProbe {
		t.Fatalf("node %s probe cache=%v, want %v", nodeID, cached, wantProbe)
	}
}

func newCLIEnrollmentProbeFixture(t *testing.T, ctx context.Context) *sshfixture.Server {
	t.Helper()
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: func(command string, channel cryptoSSH.Channel) {
		output := "__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n"
		if strings.Contains(command, "__XOPS_DIALECT_POSIX__") {
			output = "__XOPS_DIALECT_POSIX__:Linux:/bin/sh\n"
		}
		if _, err := io.WriteString(channel, output); err != nil {
			t.Error(err)
		}
		if _, err := channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
			t.Error(err)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	return server
}
