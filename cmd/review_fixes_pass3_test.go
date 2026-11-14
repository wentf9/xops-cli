package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestM4_ScpCanonicalCacheCompositeKeyAndBatchExclude(t *testing.T) {
	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("web-h", models.Host{Address: "10.0.0.5", Port: 22})
	cfg.Identities.Set("ops-i", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@web:22", models.Node{
		HostRef:     "web-h",
		IdentityRef: "ops-i",
		Alias:       []string{"web"},
	})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	savedRepo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}

	// Verify canonicalCacheKey distinguishes (host, user, port) so root@web and ops@web
	// never collide in o.canonicalCache.
	o := NewScpOptions()
	o.control.Options = []string{"CanonicalizeHostname=yes", "CanonicalDomains=corp.example.com", "UserKnownHostsFile=none"}
	kRoot := o.canonicalCacheKey(PathInfo{Host: "web", User: "root", IsRemote: true})
	kOps := o.canonicalCacheKey(PathInfo{Host: "web", User: "ops", IsRemote: true})
	kOps22 := o.canonicalCacheKey(PathInfo{Host: "web", User: "ops", Port: 22, IsRemote: true})
	if kRoot == kOps || kOps == kOps22 || kRoot == kOps22 {
		t.Fatalf("expected distinct cache keys for distinct (user, port), got %q, %q, %q", kRoot, kOps, kOps22)
	}

	// Pre-populate cache for root@web as canonicalized; ops@web must still resolve
	// as MatchedSavedNode without inheriting root@web's cached canonicalization.
	o.canonicalCache = map[string]config.CanonicalizeResult{
		kRoot: {
			OriginalHost:  "web",
			CanonicalHost: "web.corp.example.com",
			Canonicalized: true,
		},
	}
	pOps, err := o.canonicalizePathInfo(t.Context(), savedRepo, PathInfo{Host: "web", User: "ops", Port: 22, IsRemote: true})
	if err != nil {
		t.Fatalf("canonicalizePathInfo(ops@web): %v", err)
	}
	if pOps.Host != "web" {
		t.Fatalf("expected ops@web:22 to preserve saved host 'web' without cache poisoning from root@web, got %q", pOps.Host)
	}

	// Verify runBatch evaluates --exclude after canonicalization:
	// 1) Short "web" canonicalizes to "web.corp.example.com" and hits --exclude ops@web.corp.example.com:22.
	cfgCanon := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfgCanon.Hosts.Set("canon-h", models.Host{Address: "web.corp.example.com", Port: 22})
	cfgCanon.Identities.Set("canon-ops-i", models.Identity{User: "ops", AuthType: "auto"})
	cfgCanon.Nodes.Set("ops@web.corp.example.com:22", models.Node{
		HostRef:     "canon-h",
		IdentityRef: "canon-ops-i",
	})
	canonRepo, err := config.NewRepositoryWithoutOpenSSH(cfgCanon, config.NewDefaultStore(filepath.Join(t.TempDir(), "c2.yaml"), filepath.Join(t.TempDir(), "c2.key")))
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH(canon): %v", err)
	}
	oBatch := NewScpOptions()
	oBatch.Host = "web"
	oBatch.User = "ops"
	oBatch.Port = 22
	oBatch.Exclude = []string{"ops@web.corp.example.com:22"}
	oBatch.Source = "./a"
	oBatch.Dest = "/tmp/b"
	oBatch.Remember = "never"
	oBatch.control.Options = []string{"CanonicalizeHostname=yes", "CanonicalDomains=corp.example.com", "UserKnownHostsFile=none"}
	if err := oBatch.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(batch): %v", err)
	}
	kOpsBatch := oBatch.canonicalCacheKey(PathInfo{Host: "web", User: "ops", Port: 22, IsRemote: true})
	oBatch.canonicalCache = map[string]config.CanonicalizeResult{
		kOpsBatch: {
			OriginalHost:  "web",
			CanonicalHost: "web.corp.example.com",
			Canonicalized: true,
		},
	}
	if err := oBatch.runBatch(t.Context(), canonRepo, nil); err != nil {
		t.Fatalf("runBatch with canonicalized excluded host should skip cleanly without dialing, got: %v", err)
	}

	// 2) -u root on the same host must NOT be falsely excluded when --exclude ops@web.corp.example.com:22 is passed
	// (both when only ops@... is saved and when both ops@... and root@... are saved).
	excludes := map[string]struct{}{"ops@web.corp.example.com:22": {}}
	oRoot := NewScpOptions()
	oRoot.User = "root"
	oRoot.Port = 22
	excluded, err := oRoot.isBatchHostExcluded(canonRepo, excludes, "web.corp.example.com", PathInfo{Host: "web.corp.example.com", User: "root", Port: 22, IsRemote: true})
	if err != nil || excluded {
		t.Fatalf("isBatchHostExcluded(-u root, only ops saved) = (%v, %v), want (false, nil)", excluded, err)
	}
	cfgCanon.Identities.Set("canon-root-i", models.Identity{User: "root", AuthType: "auto"})
	cfgCanon.Nodes.Set("root@web.corp.example.com:22", models.Node{
		HostRef:     "canon-h",
		IdentityRef: "canon-root-i",
	})
	canonBothRepo, err := config.NewRepositoryWithoutOpenSSH(cfgCanon, config.NewDefaultStore(filepath.Join(t.TempDir(), "c3.yaml"), filepath.Join(t.TempDir(), "c3.key")))
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH(canonBoth): %v", err)
	}
	excludedBoth, err := oRoot.isBatchHostExcluded(canonBothRepo, excludes, "web.corp.example.com", PathInfo{Host: "web.corp.example.com", User: "root", Port: 22, IsRemote: true})
	if err != nil || excludedBoth {
		t.Fatalf("isBatchHostExcluded(-u root, both ops and root saved) = (%v, %v), want (false, nil)", excludedBoth, err)
	}
}

func TestM5_ExecStaticHostNameRejectedAndOriginalHostPreserved(t *testing.T) {
	// 1. Multi-host static HostName must be rejected in ExecOptions.buildAdapterOptions.
	oStatic := NewExecOptions()
	oStatic.Host = "web1,web2"
	oStatic.Command = "id"
	oStatic.Remember = "never"
	oStatic.control.Options = []string{"HostName=10.0.0.5", "UserKnownHostsFile=none"}
	if err := oStatic.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete(static): %v", err)
	}
	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	tasks, hostErrs, err := oStatic.buildTasksFromHosts(t.Context(), repo)
	if err != nil || len(hostErrs) != 0 || len(tasks) != 2 {
		t.Fatalf("buildTasksFromHosts = (%v, %v, %v), want 2 tasks", tasks, hostErrs, err)
	}
	if _, err := oStatic.buildAdapterOptions(tasks, cfg, repo); err == nil || !strings.Contains(err.Error(), "static HostName") {
		t.Fatalf("expected static HostName error for multi-host exec, got: %v", err)
	}

	// 2. Dynamic HostName=%h.internal across multiple hosts is allowed.
	oDyn := NewExecOptions()
	oDyn.Host = "web1,web2"
	oDyn.Command = "id"
	oDyn.Remember = "never"
	oDyn.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
	if err := oDyn.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete(dynamic): %v", err)
	}
	tasksDyn, hostErrsDyn, err := oDyn.buildTasksFromHosts(t.Context(), repo)
	if err != nil || len(hostErrsDyn) != 0 || len(tasksDyn) != 2 {
		t.Fatalf("buildTasksFromHosts(dynamic) = (%v, %v, %v)", tasksDyn, hostErrsDyn, err)
	}
	if _, err := oDyn.buildAdapterOptions(tasksDyn, cfg, repo); err != nil {
		t.Fatalf("expected dynamic HostName=%%h.internal to succeed, got: %v", err)
	}

	// 3. Single-target static HostName is allowed.
	oSingle := NewExecOptions()
	oSingle.Host = "web1"
	oSingle.Command = "id"
	oSingle.Remember = "never"
	oSingle.control.Options = []string{"HostName=10.0.0.5", "UserKnownHostsFile=none"}
	if err := oSingle.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete(single): %v", err)
	}
	tasksSingle, _, err := oSingle.buildTasksFromHosts(t.Context(), repo)
	if err != nil || len(tasksSingle) != 1 {
		t.Fatalf("buildTasksFromHosts(single): %v", err)
	}
	if _, err := oSingle.buildAdapterOptions(tasksSingle, cfg, repo); err != nil {
		t.Fatalf("expected single-target static HostName to succeed, got: %v", err)
	}

	// 4. --exclude filtering in RunContext runs BEFORE static HostName validation:
	// excluding all hosts with -o HostName=10.0.0.5 must return no-nodes-found, not static HostName error.
	t.Setenv("HOME", t.TempDir())
	oExcl := NewExecOptions()
	oExcl.Host = "web1,web2"
	oExcl.Exclude = []string{"web1", "web2"}
	oExcl.Command = "id"
	oExcl.Remember = "never"
	oExcl.control.Options = []string{"HostName=10.0.0.5", "UserKnownHostsFile=none"}
	if err := oExcl.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete(excl): %v", err)
	}
	if err := oExcl.RunContext(t.Context()); err == nil || strings.Contains(err.Error(), "static HostName") {
		t.Fatalf("expected --exclude to filter before static HostName check, got: %v", err)
	}
}

func TestM5_ExecOriginalHostPreservedWithoutCanonicalization(t *testing.T) {
	repo := setupTestRepository(t)
	// CanonicalizeHostname=no must still preserve task.originalHost and SessionAuth.OriginalHost (%n).
	oNoCanon := NewExecOptions()
	oNoCanon.Host = "app-alias"
	oNoCanon.Command = "uptime"
	oNoCanon.Remember = "never"
	oNoCanon.control.Options = []string{"CanonicalizeHostname=no", "UserKnownHostsFile=none"}
	if err := oNoCanon.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete(no-canon): %v", err)
	}
	tasksNoCanon, hostErrsNoCanon, err := oNoCanon.buildTasksFromHosts(t.Context(), repo)
	if err != nil || len(hostErrsNoCanon) != 0 || len(tasksNoCanon) != 1 {
		t.Fatalf("buildTasksFromHosts(no-canon) = (%v, %v, %v)", tasksNoCanon, hostErrsNoCanon, err)
	}
	if tasksNoCanon[0].originalHost != "app-alias" {
		t.Fatalf("task.originalHost = %q, want app-alias", tasksNoCanon[0].originalHost)
	}
	auth, err := oNoCanon.buildTaskSessionAuth(tasksNoCanon[0], nil, false, false)
	if err != nil {
		t.Fatalf("buildTaskSessionAuth: %v", err)
	}
	if auth.OriginalHost != "app-alias" {
		t.Fatalf("SessionAuth.OriginalHost = %q, want app-alias", auth.OriginalHost)
	}
}

func TestM6_ReadOnlyOverrideProviderDisablesProbeAndRecording(t *testing.T) {
	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(sshCfgPath, []byte("Host newhost\n  HostName 10.0.0.9\n  User ops\n"), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}
	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	overrideProv, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}

	// 1. openSSHOverrideProvider.PendingNodeExecution must always return (nil, false).
	if pne, ok := overrideProv.(interface {
		PendingNodeExecution(string) (*ssh.ExecutionConfig, bool)
	}); ok {
		if _, pending := pne.PendingNodeExecution("ops@10.0.0.9:22"); pending {
			t.Fatalf("expected openSSHOverrideProvider.PendingNodeExecution to return false")
		}
	}

	// 2. ssh.go appendRememberPersistenceOptions appends WithCredentialRecording(false)
	// and WithSuppressNodeConfirmation(true) when provider is not *config.Repository.
	sshOpt := NewSshOptions()
	sshOpt.control.ConfigFile = sshCfgPath
	sshOpt.control.Options = []string{"UserKnownHostsFile=none"}
	var sshAdpOpts []adapter.Option
	if err := sshOpt.appendRememberPersistenceOptions(&sshAdpOpts, "ops@10.0.0.9:22", cfg, overrideProv, true); err != nil {
		t.Fatalf("appendRememberPersistenceOptions: %v", err)
	}
	if len(sshAdpOpts) < 2 {
		t.Fatalf("expected WithCredentialRecording(false) + WithSuppressNodeConfirmation(true), got %d options", len(sshAdpOpts))
	}
	sshAdp := adapter.NewSSHAdapter(overrideProv, sshAdpOpts...)
	if nextVer, err := sshAdp.UpdateAuth(t.Context(), "ops@10.0.0.9:22", "", "secret", "", ""); err != nil || nextVer != "" {
		t.Fatalf("expected UpdateAuth under -F to be disabled no-op, got (%q, %v)", nextVer, err)
	}

	// 3. exec.go buildAdapterOptions disables credential recording under -F override.
	execOpt := NewExecOptions()
	execOpt.Host = "newhost"
	execOpt.Command = "id"
	execOpt.Interactive = true
	execOpt.Remember = "always"
	execOpt.control.ConfigFile = sshCfgPath
	execOpt.control.Options = []string{"UserKnownHostsFile=none"}
	if err := execOpt.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Exec Complete: %v", err)
	}
	execTasks, hostErrs, err := execOpt.buildTasksFromHosts(t.Context(), overrideProv)
	if err != nil || len(hostErrs) != 0 || len(execTasks) != 1 {
		t.Fatalf("buildTasksFromHosts = (%v, %v, %v)", execTasks, hostErrs, err)
	}
	execAdpOpts, err := execOpt.buildAdapterOptions(execTasks, cfg, overrideProv)
	if err != nil {
		t.Fatalf("buildAdapterOptions: %v", err)
	}
	execAdp := adapter.NewSSHAdapter(overrideProv, execAdpOpts...)
	if nextVer, err := execAdp.UpdateAuth(t.Context(), execTasks[0].nodeID, "", "secret", "", ""); err != nil || nextVer != "" {
		t.Fatalf("expected exec UpdateAuth under -F to be disabled no-op, got (%q, %v)", nextVer, err)
	}

	// 4. scp.go credentialConnectorWithInteraction succeeds without prompting under -F override.
	scpOpt := NewScpOptions()
	scpOpt.Remember = "always"
	scpOpt.control.ConfigFile = sshCfgPath
	scpOpt.control.Options = []string{"UserKnownHostsFile=none"}
	if err := scpOpt.Complete(NewCmdScp(), []string{"./a", "newhost:/tmp/b"}); err != nil {
		t.Fatalf("Scp Complete: %v", err)
	}
	if _, err := scpOpt.credentialConnectorWithInteraction(overrideProv, cfg, newCLIInteractionHandler()); err != nil {
		t.Fatalf("credentialConnectorWithInteraction under -F: %v", err)
	}
}
