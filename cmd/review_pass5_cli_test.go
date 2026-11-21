package cmd

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type pass5SpyCanonicalResolver struct {
	called bool
}

func (r *pass5SpyCanonicalResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	r.called = true
	return []string{"198.51.100.10"}, nil
}

func (r *pass5SpyCanonicalResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	r.called = true
	return host + ".", nil
}

func buildPass5SavedRepo(t *testing.T, sshConfigText string) *config.Repository {
	t.Helper()
	repo := setupTestRepository(t)
	cfg := repo.Snapshot()

	cfg.Hosts.Set("web-single", models.Host{
		Address: "10.238.221.181",
		Port:    22,
		Alias:   []string{"prod-web"},
	})
	cfg.Identities.Set("iaas-id", models.Identity{User: "iaas", AuthType: "auto"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "web-single",
		IdentityRef: "iaas-id",
		Alias:       []string{"Prod Web 01", "Prod\tWeb"},
	})

	cfg.Hosts.Set("web-shared", models.Host{
		Address: "shared-web",
		Port:    22,
	})
	cfg.Identities.Set("alice-id", models.Identity{User: "alice", AuthType: "auto"})
	cfg.Identities.Set("bob-id", models.Identity{User: "bob", AuthType: "auto"})
	cfg.Nodes.Set("alice@shared-web:22", models.Node{HostRef: "web-shared", IdentityRef: "alice-id"})
	cfg.Nodes.Set("bob@shared-web:22", models.Node{HostRef: "web-shared", IdentityRef: "bob-id"})

	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	if sshConfigText == "" {
		r, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
		if err != nil {
			t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
		}
		return r
	}
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshConfigText))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	r, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return r
}

func TestPass5_H3_SavedNodeIdentityPreservedUnderUserPortOverride(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	sshCfg := strings.Join([]string{
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
	}, "\n")
	savedRepo := buildPass5SavedRepo(t, sshCfg)

	verifyPass5H3ExecSavedOverrides(t, savedRepo)
	verifyPass5H3ScpAndSshSavedOverrides(t, savedRepo)
}

func verifyPass5H3ExecSavedOverrides(t *testing.T, savedRepo *config.Repository) {
	t.Helper()
	for _, tc := range []struct {
		selector string
		wantHost string
		wantNode string
	}{
		{selector: "Prod Web 01", wantHost: "10.238.221.181", wantNode: "root@10.238.221.181:2222"},
		{selector: "shared-web", wantHost: "shared-web", wantNode: "root@shared-web:2222"},
	} {
		oExec := NewExecOptions()
		oExec.Host = tc.selector
		oExec.User = "root"
		oExec.Port = 2222
		oExec.Command = "id"
		oExec.Remember = "never"
		oExec.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
		if err := oExec.Complete(NewCmdExec(), nil); err != nil {
			t.Fatalf("Complete(%q): %v", tc.selector, err)
		}
		tasks, hostErrs, err := oExec.buildTasksFromHosts(t.Context(), savedRepo)
		if err != nil || len(hostErrs) != 0 || len(tasks) != 1 {
			t.Fatalf("buildTasksFromHosts(%q) = (%v, %v, %v)", tc.selector, tasks, hostErrs, err)
		}
		if tasks[0].nodeID != tc.wantNode || tasks[0].originalHost != "" {
			t.Fatalf("task(%q) = (nodeID=%q, orig=%q), want (%q, empty)", tc.selector, tasks[0].nodeID, tasks[0].originalHost, tc.wantNode)
		}
		auth, err := oExec.buildTaskSessionAuth(tasks[0], nil, false, false)
		if err != nil {
			t.Fatalf("buildTaskSessionAuth(%q): %v", tc.selector, err)
		}
		if auth.OriginalHost != "" || auth.HostName != tc.wantHost+".internal" {
			t.Fatalf("auth(%q) = (OriginalHost=%q, HostName=%q), want (empty, %q)", tc.selector, auth.OriginalHost, auth.HostName, tc.wantHost+".internal")
		}
	}
}

func verifyPass5H3ScpAndSshSavedOverrides(t *testing.T, savedRepo *config.Repository) {
	t.Helper()
	oScp := NewScpOptions()
	oScp.Host = "shared-web"
	oScp.User = "root"
	oScp.Port = 2222
	oScp.Source = "./a"
	oScp.Dest = "/tmp/b"
	oScp.Remember = "never"
	oScp.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
	if err := oScp.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(scp): %v", err)
	}
	canonPath, err := oScp.canonicalizePathInfo(t.Context(), savedRepo, PathInfo{
		Host: "shared-web", User: "root", Port: 2222, IsRemote: true,
	})
	if err != nil {
		t.Fatalf("canonicalizePathInfo: %v", err)
	}
	if canonPath.OriginalHost != "" || canonPath.Host != "shared-web" {
		t.Fatalf("expected saved node override to skip canonicalization, got %+v", canonPath)
	}
	nodeIDs, originals, expandHosts := oScp.resolvedTargetNodeIDsWithHosts(savedRepo)
	if !slices.Contains(nodeIDs, "root@shared-web:2222") {
		t.Fatalf("scp nodeIDs = %v, want root@shared-web:2222", nodeIDs)
	}
	if originals["root@shared-web:2222"] != "" || expandHosts["root@shared-web:2222"] != "shared-web" {
		t.Fatalf("scp hosts = (orig=%q, expand=%q), want (empty, shared-web)", originals["root@shared-web:2222"], expandHosts["root@shared-web:2222"])
	}

	fakeResolver := &pass5SpyCanonicalResolver{}
	oSsh := NewSshOptions()
	oSsh.User = "root"
	oSsh.Port = 2222
	oSsh.Host = "prod-web"
	oSsh.Target = config.ConnectionTarget{Selector: "prod-web", User: "root", HasUser: true, Port: 2222, HasPort: true}
	if err := oSsh.applyHostnameCanonicalization(t.Context(), savedRepo, fakeResolver); err != nil {
		t.Fatalf("applyHostnameCanonicalization: %v", err)
	}
	if fakeResolver.called || oSsh.Host != "prod-web" || oSsh.originalHost != "" {
		t.Fatalf("expected saved node override to skip DNS canonicalization: called=%v Host=%q orig=%q", fakeResolver.called, oSsh.Host, oSsh.originalHost)
	}
}

func TestPass5_M4_ExecAndScpCompositeIPv6AdHocExcludesAndEarlyValidation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XOPS_CONFIG_DIR", filepath.Join(home, ".xops"))

	sshCfg := strings.Join([]string{
		"Host web",
		"  HostName 10.0.0.10",
		"  User ops",
		"  Port 22",
	}, "\n")
	repoWithSSH := buildPass5SavedRepo(t, sshCfg)
	repoNoSSH := buildPass5SavedRepo(t, "")

	verifyPass5M4ScpExcludes(t, repoWithSSH, repoNoSSH)
	verifyPass5M4ExecExcludes(t)
}

func verifyPass5M4ScpExcludes(t *testing.T, repoWithSSH, repoNoSSH *config.Repository) {
	t.Helper()
	oInvalid := NewScpOptions()
	oInvalid.Host = "prod-web,shared-web"
	oInvalid.User = "root"
	oInvalid.Exclude = []string{"nonexistent-node"}
	oInvalid.Source = "./local.txt"
	oInvalid.Dest = "/tmp/remote.txt"
	oInvalid.Remember = "never"
	oInvalid.control.Options = []string{"HostName=10.0.0.99", "UserKnownHostsFile=none"}
	if err := oInvalid.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(oInvalid): %v", err)
	}
	_, connErr := oInvalid.credentialConnector(repoNoSSH, repoNoSSH.Snapshot())
	if connErr == nil || !strings.Contains(connErr.Error(), i18n.T("scp_err_exclude")) || strings.Contains(connErr.Error(), "static HostName") {
		t.Fatalf("expected scp_err_exclude before static HostName check, got: %v", connErr)
	}

	oComp := NewScpOptions()
	oComp.Host = "alice@web,bob@web"
	oComp.Exclude = []string{"alice@web"}
	oComp.Source = "./local.txt"
	oComp.Dest = "/tmp/remote.txt"
	oComp.Remember = "never"
	oComp.control.Options = []string{"HostName=10.0.0.99", "UserKnownHostsFile=none"}
	if err := oComp.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(oComp): %v", err)
	}
	paths, err := oComp.collectTargetPaths(repoWithSSH)
	if err != nil {
		t.Fatalf("collectTargetPaths(oComp): %v", err)
	}
	if len(paths) != 1 || paths[0].User != "bob" {
		t.Fatalf("collectTargetPaths after --exclude alice@web = %+v, want [bob@web]", paths)
	}

	oAdHoc := NewScpOptions()
	oAdHoc.Host = "alice@10.0.0.77,bob@10.0.0.77,[2001:db8::1]"
	oAdHoc.Exclude = []string{"alice@10.0.0.77", "2001:db8::1"}
	oAdHoc.Source = "./local.txt"
	oAdHoc.Dest = "/tmp/remote.txt"
	adHocPaths, err := oAdHoc.collectTargetPaths(repoNoSSH)
	if err != nil {
		t.Fatalf("collectTargetPaths(oAdHoc): %v", err)
	}
	if len(adHocPaths) != 1 || adHocPaths[0].User != "bob" || adHocPaths[0].Host != "10.0.0.77" {
		t.Fatalf("collectTargetPaths(-F none ad-hoc + IPv6) = %+v, want only bob@10.0.0.77", adHocPaths)
	}
}

func verifyPass5M4ExecExcludes(t *testing.T) {
	t.Helper()
	oExecAll := NewExecOptions()
	oExecAll.Host = "alice@10.0.0.88,[2001:db8::9]"
	oExecAll.Exclude = []string{"alice@10.0.0.88", "[2001:db8::9]"}
	oExecAll.Command = "id"
	oExecAll.Remember = "never"
	oExecAll.control.ConfigFile = "none"
	if err := oExecAll.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete(oExecAll): %v", err)
	}
	errAll := oExecAll.RunContext(t.Context())
	if errAll == nil || !strings.Contains(errAll.Error(), i18n.T("err_no_nodes_found")) {
		t.Fatalf("expected err_no_nodes_found when all ad-hoc/IPv6 hosts excluded under -F none, got: %v", errAll)
	}

	oExecTypo := NewExecOptions()
	oExecTypo.Host = "alice@10.0.0.88"
	oExecTypo.Exclude = []string{"typo-node"}
	oExecTypo.Command = "id"
	oExecTypo.Remember = "never"
	oExecTypo.control.ConfigFile = "none"
	if err := oExecTypo.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete(oExecTypo): %v", err)
	}
	errTypo := oExecTypo.RunContext(t.Context())
	if errTypo == nil || !strings.Contains(errTypo.Error(), i18n.T("exec_err_exclude")) {
		t.Fatalf("expected exec_err_exclude on nonexistent exclude under -F none, got: %v", errTypo)
	}
}

func TestPass5_M5_SshSftpControlTargetExpansionAndDeferredSavedAliasHostName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	sshCfg := strings.Join([]string{
		"Host app-alias",
		"  HostName 10.0.0.5",
		"  User ops",
		"  Port 22",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-%C-%n",
	}, "\n")
	repo := buildPass5SavedRepo(t, sshCfg)

	verifyPass5M5SavedAndUnsafeHostName(t, repo)
	verifyPass5M5OpenSSHAliasParity(t, repo)
}

func verifyPass5M5SavedAndUnsafeHostName(t *testing.T, repo *config.Repository) {
	t.Helper()
	for _, savedAlias := range []string{"Prod Web 01", "Prod\tWeb"} {
		oSaved := NewSshOptions()
		cmdSaved := newCmdSshWithOptions(oSaved)
		if err := cmdSaved.ParseFlags([]string{"-o", "HostName=%h", "--host", savedAlias, "true"}); err != nil {
			t.Fatalf("ParseFlags(%q): %v", savedAlias, err)
		}
		if err := oSaved.Complete(cmdSaved, cmdSaved.Flags().Args()); err != nil {
			t.Fatalf("Complete(%q) with -o HostName=%%h must not fail early: %v", savedAlias, err)
		}
		if err := oSaved.Validate(); err != nil {
			t.Fatalf("Validate(%q): %v", savedAlias, err)
		}
		nodeID, _, err := oSaved.resolveNode(t.Context(), repo)
		if err != nil {
			t.Fatalf("resolveNode(%q): %v", savedAlias, err)
		}
		adpOpts, err := oSaved.buildAdapterOptions(nodeID, repo.Snapshot(), repo)
		if err != nil {
			t.Fatalf("buildAdapterOptions(%q): %v", savedAlias, err)
		}
		clientCfg, err := adapter.NewSSHAdapter(repo, adpOpts...).GetConfig(nodeID)
		if err != nil {
			t.Fatalf("GetConfig(%q): %v", nodeID, err)
		}
		if clientCfg.Address != "10.238.221.181" || clientCfg.OriginalHost != "" {
			t.Fatalf("saved alias %q ClientConfig = (Address=%q, OriginalHost=%q), want (10.238.221.181, empty)", savedAlias, clientCfg.Address, clientCfg.OriginalHost)
		}
		ctlTarget := controlTarget(oSaved, repo, nodeID)
		if ctlTarget.Host != "10.238.221.181" || ctlTarget.OriginalHost != "iaas@10.238.221.181:22" {
			t.Fatalf("saved alias %q controlTarget = %+v, want Host=10.238.221.181 OriginalHost=iaas@10.238.221.181:22", savedAlias, ctlTarget)
		}
	}

	oUnsafe := NewSshOptions()
	cmdUnsafe := newCmdSshWithOptions(oUnsafe)
	if err := cmdUnsafe.ParseFlags([]string{"-o", "HostName=%h", "--host", "Bad\tHost", "true"}); err != nil {
		t.Fatalf("ParseFlags(unsafe): %v", err)
	}
	if err := oUnsafe.Complete(cmdUnsafe, cmdUnsafe.Flags().Args()); err != nil {
		t.Fatalf("Complete(unsafe): %v", err)
	}
	if err := oUnsafe.Validate(); err != nil {
		t.Fatalf("Validate(unsafe): %v", err)
	}
	if _, err := oUnsafe.buildAdapterOptions("ops@Bad\tHost:22", repo.Snapshot(), repo); err == nil || !strings.Contains(err.Error(), "ASCII control") {
		t.Fatalf("expected ASCII control error for non-saved tab host with -o HostName=%%h, got: %v", err)
	}
}

func verifyPass5M5OpenSSHAliasParity(t *testing.T, repo *config.Repository) {
	t.Helper()
	oAlias := NewSshOptions()
	cmdAlias := newCmdSshWithOptions(oAlias)
	if err := cmdAlias.ParseFlags([]string{"-l", "alice", "-o", "HostName=%h.corp", "app-alias", "true"}); err != nil {
		t.Fatalf("ParseFlags(alias): %v", err)
	}
	if err := oAlias.Complete(cmdAlias, cmdAlias.Flags().Args()); err != nil {
		t.Fatalf("Complete(alias): %v", err)
	}
	if err := oAlias.Validate(); err != nil {
		t.Fatalf("Validate(alias): %v", err)
	}
	aliasNodeID, _, err := oAlias.resolveNode(t.Context(), repo)
	if err != nil {
		t.Fatalf("resolveNode(alias): %v", err)
	}
	aliasAdpOpts, err := oAlias.buildAdapterOptions(aliasNodeID, repo.Snapshot(), repo)
	if err != nil {
		t.Fatalf("buildAdapterOptions(alias): %v", err)
	}
	aliasCfg, err := adapter.NewSSHAdapter(repo, aliasAdpOpts...).GetConfig(aliasNodeID)
	if err != nil {
		t.Fatalf("GetConfig(alias): %v", err)
	}
	if aliasCfg.OriginalHost != "app-alias" || aliasCfg.Address != "app-alias.corp" {
		t.Fatalf("OpenSSH alias ClientConfig = (OriginalHost=%q, Address=%q), want (app-alias, app-alias.corp)", aliasCfg.OriginalHost, aliasCfg.Address)
	}
	aliasCtlTarget := controlTarget(oAlias, repo, aliasNodeID)
	if aliasCtlTarget.OriginalHost != "app-alias" || aliasCtlTarget.Host != "app-alias.corp" || aliasCtlTarget.User != "alice" {
		t.Fatalf("OpenSSH alias controlTarget = %+v, want OriginalHost=app-alias Host=app-alias.corp User=alice", aliasCtlTarget)
	}
	proxyCfg, _ := buildControlProxyClientConfig(aliasCtlTarget, repo, aliasNodeID, oAlias)
	if proxyCfg.OriginalHost != "app-alias" || proxyCfg.Address != "app-alias.corp" {
		t.Fatalf("buildControlProxyClientConfig = (OriginalHost=%q, Address=%q), want (app-alias, app-alias.corp)", proxyCfg.OriginalHost, proxyCfg.Address)
	}
	wantSock, err := ssh.ExpandControlPath("/tmp/cm-%C-%n", sshenv.Discover(), ssh.TargetContext{
		Host:         "app-alias.corp",
		Port:         22,
		User:         "alice",
		OriginalHost: "app-alias",
	})
	if err != nil {
		t.Fatalf("ExpandControlPath: %v", err)
	}
	gotSock, err := controlSocketPath(oAlias, repo, aliasNodeID)
	if err != nil || gotSock != wantSock {
		t.Fatalf("controlSocketPath(alice@app-alias) = %q (err=%v), want %q", gotSock, err, wantSock)
	}
}

func TestPass5_M6_ControlPersistCanonicalizedHostAndOriginalHostHandoff(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	_, portStr, _ := net.SplitHostPort(fix.Address)
	port, _ := strconv.Atoi(portStr)

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("cryptoSSH.Dial: %v", err)
	}
	defer func() { _ = rawClient.Close() }()

	sshCfg := strings.Join([]string{
		"Host app-alias",
		"  HostName 10.0.0.5",
		"  User ops",
		"  Port 22",
		"",
		"Host web",
		"  User ops",
		"",
		"Host *.corp.example.com",
		"  User ops",
	}, "\n")
	repo := buildPass5SavedRepo(t, sshCfg)

	verifyPass5M6MasterNodeIDAndDaemonArgs(t, ctx, rawClient, repo, port)
	verifyPass5M6DaemonOriginalHostEnvRestore(t, ctx, repo, port)
}

func verifyPass5M6MasterNodeIDAndDaemonArgs(t *testing.T, ctx context.Context, rawClient *cryptoSSH.Client, repo *config.Repository, port int) {
	t.Helper()
	tmpDir := shortControlTempDir(t)

	canonMaster, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: filepath.Join(tmpDir, "canon.sock"),
		Target: ssh.TargetContext{
			Host:         "web.corp.example.com",
			Port:         port,
			User:         "ops",
			OriginalHost: "web",
			Control:      &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: filepath.Join(tmpDir, "canon.sock"), Persist: "5m"},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer(canon): %v", err)
	}
	defer func() { _ = canonMaster.Shutdown() }()

	canonNodeID := resolveMasterNodeID(repo, canonMaster)
	wantComposite := config.FormatNodeID("ops", "web.corp.example.com", uint16(port))
	if canonNodeID != wantComposite {
		t.Fatalf("resolveMasterNodeID(canonicalized web) = %q, want %q", canonNodeID, wantComposite)
	}
	daemonOpts := NewSshOptions()
	canonSpec := daemonOpts.buildMuxDaemonSpec(canonNodeID, canonMaster.ControlPath(), canonMaster)
	if canonSpec.TargetHost != "web.corp.example.com" || canonSpec.OpenSSHNamespace {
		t.Fatalf("buildMuxDaemonSpec(canonicalized) = %+v, expected TargetHost=web.corp.example.com OpenSSHNamespace=false", canonSpec)
	}

	aliasMaster, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: filepath.Join(tmpDir, "alias.sock"),
		Target: ssh.TargetContext{
			Host:         "10.0.0.5",
			Port:         22,
			User:         "ops",
			OriginalHost: "app-alias",
			Control:      &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: filepath.Join(tmpDir, "alias.sock"), Persist: "5m"},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer(alias): %v", err)
	}
	defer func() { _ = aliasMaster.Shutdown() }()

	aliasNodeID := resolveMasterNodeID(repo, aliasMaster)
	if aliasNodeID != "openssh:app-alias" {
		t.Fatalf("resolveMasterNodeID(app-alias) = %q, want openssh:app-alias", aliasNodeID)
	}
	aliasSpec := daemonOpts.buildMuxDaemonSpec(aliasNodeID, aliasMaster.ControlPath(), aliasMaster)
	if aliasSpec.TargetHost != "app-alias" || !aliasSpec.OpenSSHNamespace {
		t.Fatalf("buildMuxDaemonSpec(app-alias) = %+v, expected TargetHost=app-alias OpenSSHNamespace=true", aliasSpec)
	}
}

func verifyPass5M6DaemonOriginalHostEnvRestore(t *testing.T, ctx context.Context, repo *config.Repository, port int) {
	t.Helper()
	tmpDir := shortControlTempDir(t)

	childOpts := NewSshOptions()
	spec := MuxDaemonSpec{
		Version:       muxDaemonSpecVersion,
		TargetHost:    "web.corp.example.com",
		OriginalHost:  "web",
		Port:          uint16(port),
		User:          "ops",
		ControlPath:   filepath.Join(tmpDir, "d.sock"),
		ControlMaster: ssh.ControlMasterYes,
	}
	if err := childOpts.applyMuxDaemonSpec(roundTripMuxDaemonSpecThroughPipe(t, spec)); err != nil {
		t.Fatalf("applyMuxDaemonSpec(child): %v", err)
	}
	if err := childOpts.Validate(); err != nil {
		t.Fatalf("Validate(child): %v", err)
	}
	if childOpts.originalHost != "web" {
		t.Fatalf("mux daemon child originalHost = %q, want web", childOpts.originalHost)
	}
	childNodeID, _, err := childOpts.resolveNode(ctx, repo)
	if err != nil {
		t.Fatalf("resolveNode(child): %v", err)
	}
	childAdpOpts, err := childOpts.buildAdapterOptions(childNodeID, repo.Snapshot(), repo)
	if err != nil {
		t.Fatalf("buildAdapterOptions(child): %v", err)
	}
	childCfg, err := adapter.NewSSHAdapter(repo, childAdpOpts...).GetConfig(childNodeID)
	if err != nil {
		t.Fatalf("GetConfig(child): %v", err)
	}
	if childCfg.Address != "web.corp.example.com" || childCfg.OriginalHost != "web" {
		t.Fatalf("mux daemon child ClientConfig = (Address=%q, OriginalHost=%q), want (web.corp.example.com, web)", childCfg.Address, childCfg.OriginalHost)
	}

	var stderrBuf bytes.Buffer
	ctlUnsafe := NewSshOptions()
	ctlUnsafe.control.CtlCmd = "check"
	ctlUnsafe.control.Options = []string{"HostName=%h"}
	ctlUnsafe.Host = "Bad\tHost"
	ctlUnsafe.Target = config.ConnectionTarget{Selector: "Bad\tHost"}
	var exitErr *ControlExitError
	if _, _, _, _, ctlErr := resolveControlContext(ctx, ctlUnsafe, &stderrBuf); !errors.As(ctlErr, &exitErr) || exitErr.Code != 255 {
		t.Fatalf("expected resolveControlContext to fail closed with exit 255 on non-saved control-char host with -o HostName=%%h, got: %v", ctlErr)
	}
}
