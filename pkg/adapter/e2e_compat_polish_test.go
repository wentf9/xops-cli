package adapter

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestConfirmAuthenticatedConnection_WithOpenSSHConfigOverrideDoesNotCrash(t *testing.T) {
	setTestHome(t)
	repo, _, cfgPath, before := pendingAdapterRepository(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var userCommands atomic.Int32
	server := newEnrollmentSSHFixture(t, ctx, repo, &userCommands, "probe_override")
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}

	sshCfgPath := filepath.Join(t.TempDir(), "custom_ssh_config")
	sshCfgContent := "Host custom-target\n  HostName " + host + "\n  Port " + portText + "\n  User fixture\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	overrideProvider, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride failed: %v", err)
	}
	preparer, ok := overrideProvider.(interface {
		PrepareNodeContext(context.Context, config.EnsureNodeOptions) (config.EnsureNodeResult, error)
	})
	if !ok {
		t.Fatalf("overrideProvider %T does not implement PrepareNodeContext", overrideProvider)
	}
	prepared, err := preparer.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: host, User: "fixture", HasUser: true, Port: uint16(port), HasPort: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext failed: %v", err)
	}

	adpOpts := []Option{
		WithEnrollmentProbing(nil),
		WithSessionAuthOverride(prepared.NodeID, SessionAuth{
			Password: sshfixture.Password,
			Remember: true,
		}),
	}
	adp := NewSSHAdapter(overrideProvider, adpOpts...)
	connector := NewConnectorWithAdapterOptions(overrideProvider, adpOpts, ssh.WithHandshakeTimeout(2*time.Second))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() { _ = connector.CloseAll() })

	client, err := connector.Connect(ctx, prepared.NodeID)
	if err != nil {
		t.Fatalf("Connect under WithOpenSSHConfigOverride + WithEnrollmentProbing failed: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	if _, err := adp.ConfirmAuthenticatedConnection(ctx, prepared.NodeID, client); err != nil {
		t.Fatalf("ConfirmAuthenticatedConnection returned error under -F override: %v", err)
	}

	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("expected config file on disk to remain unchanged under -F override")
	}
}

func TestSessionControlOptions_ConnectionWideOptionsIsolation(t *testing.T) {
	khFile := filepath.Join(t.TempDir(), "known_hosts")
	gkhFile := filepath.Join(t.TempDir(), "global_known_hosts")
	parsed, err := ParseOptionStrings([]string{
		"StrictHostKeyChecking=no",
		"UserKnownHostsFile=" + khFile,
		"GlobalKnownHostsFile=" + gkhFile,
		"HashKnownHosts=yes",
		"VerifyHostKeyDNS=ask",
		"ConnectTimeout=7",
		"IdentityAgent=/tmp/test-agent.sock",
		"RemoteCommand=id",
		"RequestTTY=force",
		"ForwardAgent=yes",
		"LocalCommand=echo hi",
		"PermitLocalCommand=yes",
		"ProxyCommand=nc %h %p",
		"EscapeChar=~",
		"ControlMaster=auto",
		"ControlPath=/tmp/cm-%C",
		"ControlPersist=60",
	})
	if err != nil {
		t.Fatalf("ParseOptionStrings failed: %v", err)
	}
	if err := parsed.SetAddressFamily(ssh.AddressFamilyInet); err != nil {
		t.Fatalf("SetAddressFamily failed: %v", err)
	}

	globalCtrl := parsed.ConnectionWideOptions()
	if globalCtrl.Master != nil || globalCtrl.Path != nil || globalCtrl.Persist != nil {
		t.Fatalf("expected ConnectionWideOptions to exclude ControlMaster/Path/Persist, got %+v", globalCtrl)
	}

	sshCfg := `
Host jump
    HostName 10.0.0.1
    User bastion

Host target
    HostName 10.0.0.2
    User app
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(&config.Configuration{}, store, parser)
	if err != nil {
		t.Fatal(err)
	}

	adp := NewSSHAdapter(
		repo,
		WithLocalExecution(true),
		WithGlobalSessionControl(globalCtrl),
		WithSessionControlOverride("openssh:target", parsed),
	)

	jumpCfg, err := adp.GetConfig("openssh:jump")
	if err != nil {
		t.Fatalf("GetConfig(openssh:jump) failed: %v", err)
	}
	assertJumpInheritedConnectionWide(t, jumpCfg, khFile, gkhFile)
	assertJumpExcludedTargetScoped(t, adp, jumpCfg)

	targetCfg, err := adp.GetConfig("openssh:target")
	if err != nil {
		t.Fatalf("GetConfig(openssh:target) failed: %v", err)
	}
	if targetCfg.Options.RemoteCommand() != "id" || targetCfg.Options.ForwardAgent() != "yes" {
		t.Fatalf("target lost node-scoped options: %+v", targetCfg.Options)
	}
	if targetCfg.OriginalHost != "target" || jumpCfg.OriginalHost != "jump" {
		t.Fatalf("OriginalHost failed to strip openssh: prefix: target=%q jump=%q", targetCfg.OriginalHost, jumpCfg.OriginalHost)
	}
}

func assertJumpInheritedConnectionWide(t *testing.T, jumpCfg *ssh.ClientConfig, khFile, gkhFile string) {
	t.Helper()
	opts := jumpCfg.Options
	if opts.StrictHostKeyChecking() != ssh.StrictHostKeyCheckingNo ||
		opts.UserKnownHostsFile() != khFile ||
		opts.GlobalKnownHostsFile() != gkhFile ||
		!opts.HashKnownHosts() {
		t.Fatalf("jump hop did not inherit trust options: %+v", opts)
	}
	if opts.VerifyHostKeyDNS() != ssh.VerifyHostKeyDNSAsk ||
		opts.AddressFamily() != ssh.AddressFamilyInet ||
		opts.ConnectTimeout() != 7*time.Second ||
		opts.IdentityAgent() != "/tmp/test-agent.sock" {
		t.Fatalf("jump hop did not inherit transport/agent options: %+v", opts)
	}
}

func assertJumpExcludedTargetScoped(t *testing.T, adp *SSHAdapter, jumpCfg *ssh.ClientConfig) {
	t.Helper()
	opts := jumpCfg.Options
	if opts.RemoteCommand() != "" || opts.RequestTTY() != "" || opts.ForwardAgent() != "" {
		t.Fatalf("jump hop leaked session target options: %+v", opts)
	}
	if opts.LocalCommand() != "" || opts.PermitLocalCommand() || opts.ActiveProxyCommand() != "" || opts.EscapeChar() != "" {
		t.Fatalf("jump hop leaked command/escape target options: %+v", opts)
	}
	if jumpCtrl, err := adp.GetControlConfig("openssh:jump"); err != nil || jumpCtrl != nil {
		t.Fatalf("jump hop leaked target Control* config: ctrl=%+v err=%v", jumpCtrl, err)
	}
}

func TestSSHAdapter_StripsOpenSSHPrefixFromOriginalHostOnlyForVirtualNodes(t *testing.T) {
	sshCfg := `
Host my-alias
    HostName 10.20.30.40
    User dev
    Port 2222
    ControlPath /tmp/mux-%n
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(&config.Configuration{}, store, parser)
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.CreateNodeContext(
		t.Context(),
		"ops@10.20.30.50:22",
		models.Node{HostRef: "10.20.30.50:22", IdentityRef: "ops@10.20.30.50"},
		models.Host{Address: "10.20.30.50", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	)
	if err != nil {
		t.Fatal(err)
	}

	adp := NewSSHAdapter(repo)

	vCfg, err := adp.GetConfig("openssh:my-alias")
	if err != nil {
		t.Fatal(err)
	}
	if vCfg.OriginalHost != "my-alias" {
		t.Fatalf("virtual node OriginalHost = %q, want %q", vCfg.OriginalHost, "my-alias")
	}
	sock, err := adp.ExpandControlPath("openssh:my-alias", "/tmp/mux-%n")
	if err != nil || sock != "/tmp/mux-my-alias" {
		t.Fatalf("ExpandControlPath(openssh:my-alias) = %q, err=%v, want /tmp/mux-my-alias", sock, err)
	}

	mCfg, err := adp.GetConfig("ops@10.20.30.50:22")
	if err != nil {
		t.Fatal(err)
	}
	if mCfg.OriginalHost != "" {
		t.Fatalf("managed node OriginalHost = %q, want empty so Connector uses NodeID", mCfg.OriginalHost)
	}
}
