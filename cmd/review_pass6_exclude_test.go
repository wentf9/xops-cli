package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	xssh "github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptossh "golang.org/x/crypto/ssh"
)

func newPass6TaggedExcludeFixtureRepo(t *testing.T) (*config.Repository, config.ConfigProvider, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := strings.Join([]string{
		"Host ssh-web",
		"  HostName 10.238.221.181",
		"  User iaas",
		"  Port 22",
		"Host *.corp.example.com",
		"  User ops",
		"  Port 2222",
		"Host *",
		"  ServerAliveInterval 15",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("h-web", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Hosts.Set("h-app", models.Host{Address: "10.238.221.182", Port: 22})
	cfg.Identities.Set("id-iaas", models.Identity{User: "iaas", AuthType: "auto"})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:      "h-web",
		IdentityRef:  "id-iaas",
		Alias:        []string{"prod-web"},
		Tags:         []string{"prod"},
		OpenSSHAlias: "ssh-web",
	})
	cfg.Nodes.Set("ops@10.238.221.182:22", models.Node{
		HostRef:     "h-app",
		IdentityRef: "id-ops",
		Alias:       []string{"prod-app"},
		Tags:        []string{"prod"},
	})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	savedRepo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	openSSHProv, err := config.WithOpenSSHConfigOverride(savedRepo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}
	return savedRepo, openSSHProv, sshCfgPath
}

func TestPass6_H2_ScpAndExecFailClosedExcludeWithWildcardSSHConfig(t *testing.T) {
	savedRepo, openSSHProv, sshCfgPath := newPass6TaggedExcludeFixtureRepo(t)
	unmatchedSpecs := []string{
		"typo-node",
		"openssh:typo-node",
		"openssh:ops@typo-node:22",
		"alice@typo-node",
		"typo-node:2222",
		"wild.corp.example.com",
		"openssh:wild.corp.example.com",
		"openssh:prod-app",
	}

	for _, spec := range unmatchedSpecs {
		verifyPass6ScpTagFailClosed(t, savedRepo, openSSHProv, sshCfgPath, spec)
		verifyPass6ExecFailClosed(t, sshCfgPath, spec)
	}
}

func verifyPass6ScpTagFailClosed(
	t *testing.T,
	savedRepo *config.Repository,
	openSSHProv config.ConfigProvider,
	sshCfgPath, spec string,
) {
	t.Helper()
	o := NewScpOptions()
	o.Tag = "prod"
	o.Exclude = []string{spec}
	o.Source = "./local.txt"
	o.Dest = "/tmp/remote.txt"
	o.Remember = "never"
	o.control.ConfigFile = sshCfgPath
	o.control.Options = []string{"HostName=10.0.0.99", "UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(scp %q): %v", spec, err)
	}
	if _, err := o.credentialConnector(openSSHProv, savedRepo.Snapshot()); err == nil || !strings.Contains(err.Error(), "no matching node") {
		t.Fatalf("credentialConnector(scp --tag --exclude %q) expected fail-closed error, got: %v", spec, err)
	}
	if err := o.runBatch(t.Context(), openSSHProv, nil); err == nil || !strings.Contains(err.Error(), "no matching node") {
		t.Fatalf("runBatch(scp --tag --exclude %q) expected fail-closed error, got: %v", spec, err)
	}
}

func verifyPass6ExecFailClosed(t *testing.T, sshCfgPath, spec string) {
	t.Helper()
	o := NewExecOptions()
	o.Host = "ssh-web"
	o.Exclude = []string{spec}
	o.Command = "id"
	o.Remember = "never"
	o.control.ConfigFile = sshCfgPath
	o.control.Options = []string{"UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete(exec %q): %v", spec, err)
	}
	if err := o.RunContext(t.Context()); err == nil || !strings.Contains(err.Error(), "no matching node") {
		t.Fatalf("ExecOptions.RunContext(--exclude %q) expected fail-closed error, got: %v", spec, err)
	}
}

func TestPass6_H3_ScpTagExcludeCanonicalizationWithPortLoginAndOpenSSHAlias(t *testing.T) {
	savedRepo, openSSHProv, sshCfgPath := newPass6TaggedExcludeFixtureRepo(t)

	if got := taggedNodePathInfo("iaas@10.238.221.181:22"); got != (PathInfo{Host: "iaas@10.238.221.181:22", IsRemote: true}) {
		t.Fatalf("taggedNodePathInfo = %+v, want {Host:iaas@10.238.221.181:22 IsRemote:true}", got)
	}

	verifyPass6ScpTagPortAndUserOverrides(t, savedRepo, openSSHProv, sshCfgPath)
	verifyPass6ScpTagOpenSSHAliasExcludes(t, savedRepo, openSSHProv, sshCfgPath)
	verifyPass6ScpPositionalExcludeParity(t, openSSHProv, sshCfgPath)
}

func verifyPass6ScpTagPortAndUserOverrides(
	t *testing.T,
	savedRepo *config.Repository,
	openSSHProv config.ConfigProvider,
	sshCfgPath string,
) {
	t.Helper()
	for _, ex := range []string{"iaas@prod-web", "iaas@prod-web:2222", "prod-web:2222"} {
		o := newPass6TaggedScpOptions(t, sshCfgPath, "", 2222, ex)
		assertPass6SingleRemainingTaggedHost(t, o, openSSHProv, savedRepo.Snapshot(), "10.238.221.182")
	}

	// Explicit port :22 must NOT exclude -P 2222 overridden prod-web.
	oPort22 := newPass6TaggedScpOptions(t, sshCfgPath, "", 2222, "iaas@prod-web:22")
	if got := oPort22.distinctRemoteHosts(openSSHProv); len(got) != 2 {
		t.Fatalf("distinctRemoteHosts(--exclude iaas@prod-web:22 with -P 2222) = %v, want 2 hosts", got)
	}
	if _, err := oPort22.credentialConnector(openSSHProv, savedRepo.Snapshot()); err == nil || !strings.Contains(err.Error(), "static HostName") {
		t.Fatalf("expected static HostName multi-host error when :22 exclude does not match -P 2222, got: %v", err)
	}

	// -l root override must NOT be excluded by --exclude iaas@prod-web,
	// while --exclude root@prod-web and --exclude prod-web DO exclude it.
	oLoginMismatch := newPass6TaggedScpOptions(t, sshCfgPath, "root", 2222, "iaas@prod-web")
	if got := oLoginMismatch.distinctRemoteHosts(openSSHProv); len(got) != 2 {
		t.Fatalf("distinctRemoteHosts(-l root --exclude iaas@prod-web) = %v, want 2 hosts", got)
	}
	for _, ex := range []string{"root@prod-web", "prod-web"} {
		o := newPass6TaggedScpOptions(t, sshCfgPath, "root", 2222, ex)
		assertPass6SingleRemainingTaggedHost(t, o, openSSHProv, savedRepo.Snapshot(), "10.238.221.182")
	}
}

func verifyPass6ScpTagOpenSSHAliasExcludes(
	t *testing.T,
	savedRepo *config.Repository,
	openSSHProv config.ConfigProvider,
	sshCfgPath string,
) {
	t.Helper()
	for _, ex := range []string{"ssh-web", "openssh:ssh-web", "iaas@ssh-web:2222"} {
		o := newPass6TaggedScpOptions(t, sshCfgPath, "", 2222, ex)
		assertPass6SingleRemainingTaggedHost(t, o, openSSHProv, savedRepo.Snapshot(), "10.238.221.182")
	}
}

func verifyPass6ScpPositionalExcludeParity(t *testing.T, openSSHProv config.ConfigProvider, sshCfgPath string) {
	t.Helper()
	oPos := NewScpOptions()
	oPos.Port = 2222
	oPos.Exclude = []string{"iaas@prod-web"}
	oPos.Remember = "never"
	oPos.control.ConfigFile = sshCfgPath
	oPos.control.Options = []string{"UserKnownHostsFile=none"}
	if err := oPos.Complete(NewCmdScp(), []string{"./local.txt", "prod-web:/tmp/remote.txt"}); err != nil {
		t.Fatalf("Complete(positional): %v", err)
	}
	cands := oPos.buildExcludeCandidates(openSSHProv)
	if len(cands) != 1 || cands[0].NodeID != "iaas@10.238.221.181:2222" || cands[0].BaseNodeID != "iaas@10.238.221.181:22" {
		t.Fatalf("positional buildExcludeCandidates = %+v, want canonical 2222 candidate with saved BaseNodeID", cands)
	}
	paths, err := oPos.collectTargetPaths(openSSHProv)
	if err != nil {
		t.Fatalf("collectTargetPaths(positional): %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("positional collectTargetPaths with matching --exclude = %+v, want empty", paths)
	}
}

func newPass6TaggedScpOptions(t *testing.T, sshCfgPath, user string, port uint16, exclude string) *ScpOptions {
	t.Helper()
	o := NewScpOptions()
	o.Tag = "prod"
	o.User = user
	o.Port = port
	o.Exclude = []string{exclude}
	o.Source = "./local.txt"
	o.Dest = "/tmp/remote.txt"
	o.Remember = "never"
	o.control.ConfigFile = sshCfgPath
	o.control.Options = []string{"HostName=10.0.0.99", "UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(scp %q): %v", exclude, err)
	}
	return o
}

func assertPass6SingleRemainingTaggedHost(
	t *testing.T,
	o *ScpOptions,
	prov config.ConfigProvider,
	cfg *config.Configuration,
	wantHost string,
) {
	t.Helper()
	distinct := o.distinctRemoteHosts(prov)
	if len(distinct) != 1 || distinct[0] != wantHost {
		t.Fatalf("distinctRemoteHosts(%v) = %v, want [%s]", o.Exclude, distinct, wantHost)
	}
	if _, err := o.credentialConnector(prov, cfg); err != nil {
		t.Fatalf("credentialConnector(%v) failed: %v", o.Exclude, err)
	}
}

type pass6RecordingSSHProvider struct {
	mu      sync.Mutex
	dialed  []string
	port    int
	reject  map[string]struct{}
	configs map[string]*xssh.ClientConfig
}

func (p *pass6RecordingSSHProvider) GetConfig(nodeID string) (*xssh.ClientConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dialed = append(p.dialed, nodeID)
	if _, blocked := p.reject[nodeID]; blocked {
		return nil, fmt.Errorf("excluded node %q should never be dialed", nodeID)
	}
	if cfg, ok := p.configs[nodeID]; ok {
		return cfg, nil
	}
	return &xssh.ClientConfig{
		NodeID:   nodeID,
		Address:  "127.0.0.1",
		Port:     p.port,
		User:     "test",
		AuthType: "password",
		Password: "test",
	}, nil
}

func (p *pass6RecordingSSHProvider) dialedNodes() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := slices.Clone(p.dialed)
	slices.Sort(out)
	return slices.Compact(out)
}

func startPass6SFTPServer(t *testing.T) (context.Context, int, string) {
	t.Helper()
	remoteHome := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &cryptossh.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(signer)
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	var workers sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		closeSCPTestResource(t, listener)
		workers.Wait()
	})
	deadline, _ := ctx.Deadline()
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	workers.Go(func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				if !errors.Is(acceptErr, net.ErrClosed) && ctx.Err() == nil {
					t.Errorf("accept pass6 SFTP connection: %v", acceptErr)
				}
				return
			}
			workers.Go(func() { serveSCPTestConnection(t, ctx, conn, serverCfg, remoteHome) })
		}
	})
	return ctx, listener.Addr().(*net.TCPAddr).Port, remoteHome
}

func TestPass6_H3_ScpTagEndToEndBatchTransferHonorsCanonicalizedExclude(t *testing.T) {
	savedRepo, _, sshCfgPath := newPass6TaggedExcludeFixtureRepo(t)
	ctx, fixturePort, remoteHome := startPass6SFTPServer(t)

	localSrc := filepath.Join(t.TempDir(), "payload.txt")
	writeSCPTestFile(t, localSrc, "pass6-batch-payload")

	excludedNodeID := fmt.Sprintf("iaas@10.238.221.181:%d", fixturePort)
	allowedNodeID := fmt.Sprintf("ops@10.238.221.182:%d", fixturePort)

	recProv := &pass6RecordingSSHProvider{
		port: fixturePort,
		reject: map[string]struct{}{
			"iaas@10.238.221.181:22": {},
			excludedNodeID:           {},
		},
	}
	connector := xssh.NewConnector(recProv, xssh.WithEnvironment(sshenv.Discover()))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() { _ = connector.CloseAll() })

	// 1. scp -P <fixturePort> --tag prod --exclude iaas@prod-web skips excludedNodeID and uploads to allowedNodeID.
	o := NewScpOptions()
	o.Tag = "prod"
	o.Port = uint16(fixturePort)
	o.Exclude = []string{"iaas@prod-web"}
	o.Source = localSrc
	o.Dest = "~/pass6-uploaded.txt"
	o.Remember = "never"
	o.Quiet = true
	o.control.ConfigFile = sshCfgPath
	o.control.Options = []string{"UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(batch upload): %v", err)
	}
	prov, err := config.WithOpenSSHConfigOverride(savedRepo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}
	if err := o.runTransfer(ctx, prov, connector); err != nil {
		t.Fatalf("runTransfer(--tag prod -P %d --exclude iaas@prod-web) failed: %v", fixturePort, err)
	}
	assertSCPTestFile(t, filepath.Join(remoteHome, "pass6-uploaded.txt"), "pass6-batch-payload")
	if got := recProv.dialedNodes(); !slices.Equal(got, []string{allowedNodeID}) {
		t.Fatalf("dialed nodes = %v, want [%s]", got, allowedNodeID)
	}

	// 2. With -l root -P <fixturePort>, --exclude iaas@prod-web must NOT exclude root@10.238.221.181:<fixturePort>.
	recRootProv := &pass6RecordingSSHProvider{port: fixturePort}
	rootConnector := xssh.NewConnector(recRootProv, xssh.WithEnvironment(sshenv.Discover()))
	rootConnector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() { _ = rootConnector.CloseAll() })

	oRoot := NewScpOptions()
	oRoot.Tag = "prod"
	oRoot.User = "root"
	oRoot.Port = uint16(fixturePort)
	oRoot.Exclude = []string{"iaas@prod-web"}
	oRoot.Source = localSrc
	oRoot.Dest = "~/pass6-root-uploaded.txt"
	oRoot.Remember = "never"
	oRoot.Quiet = true
	oRoot.Force = true
	oRoot.control.ConfigFile = sshCfgPath
	oRoot.control.Options = []string{"UserKnownHostsFile=none"}
	if err := oRoot.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(root batch upload): %v", err)
	}
	provRoot, err := config.WithOpenSSHConfigOverride(savedRepo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride(root): %v", err)
	}
	if err := oRoot.runTransfer(ctx, provRoot, rootConnector); err != nil {
		t.Fatalf("runTransfer(-l root -P %d --exclude iaas@prod-web) failed: %v", fixturePort, err)
	}
	wantRootDialed := []string{
		fmt.Sprintf("root@10.238.221.181:%d", fixturePort),
		fmt.Sprintf("root@10.238.221.182:%d", fixturePort),
	}
	slices.Sort(wantRootDialed)
	if got := recRootProv.dialedNodes(); !slices.Equal(got, wantRootDialed) {
		t.Fatalf("dialed nodes with -l root = %v, want %v", got, wantRootDialed)
	}
}
