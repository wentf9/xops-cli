package cmd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func newPass7TaggedRepo(t *testing.T) (*config.Repository, config.ConfigProvider, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := strings.Join([]string{
		"Host ssh-alpha",
		"  HostName 10.240.0.11",
		"  User iaas",
		"  Port 22",
		"Host ssh-zeta",
		"  HostName 10.240.0.13",
		"  User ops",
		"  Port 22",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("h-alpha", models.Host{Address: "10.240.0.11", Port: 22})
	cfg.Hosts.Set("h-mid", models.Host{Address: "10.240.0.12", Port: 0})
	cfg.Hosts.Set("h-zeta", models.Host{Address: "10.240.0.13", Port: 22})
	cfg.Identities.Set("id-iaas", models.Identity{User: "iaas", AuthType: "password", Password: "iaas-stored-secret"})
	cfg.Identities.Set("id-mid", models.Identity{User: "deploy", AuthType: "password", Password: "deploy-stored-secret"})
	cfg.Identities.Set("id-zeta", models.Identity{User: "ops", AuthType: "password", Password: "ops-stored-secret"})

	cfg.Nodes.Set("z-node", models.Node{
		HostRef:      "h-zeta",
		IdentityRef:  "id-zeta",
		Tags:         []string{"p7tag"},
		OpenSSHAlias: "ssh-zeta",
	})
	cfg.Nodes.Set("a-node", models.Node{
		HostRef:      "h-alpha",
		IdentityRef:  "id-iaas",
		Tags:         []string{"p7tag"},
		OpenSSHAlias: "ssh-alpha",
	})
	cfg.Nodes.Set("m-node", models.Node{
		HostRef:     "h-mid",
		IdentityRef: "id-mid",
		Tags:        []string{"p7tag"},
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

func TestPass7_H5_ExecTagParityAndOverriddenExclude(t *testing.T) {
	_, prov, sshCfgPath := newPass7TaggedRepo(t)

	verifyPass7ExecTagSortedAndNormalized(t, prov, sshCfgPath)
	verifyPass7ExecTagOverridesAndPasswordSafety(t, prov, sshCfgPath)
	verifyPass7OverriddenHostNameAndAliasExcludes(t, prov, sshCfgPath)
}

func verifyPass7ExecTagSortedAndNormalized(t *testing.T, prov config.ConfigProvider, sshCfgPath string) {
	t.Helper()
	o := NewExecOptions()
	o.Tag = "p7tag"
	o.Remember = "never"
	o.control.ConfigFile = sshCfgPath
	if err := o.withTestPendingTagTasks(t.Context(), prov, func(tasks []execHostTask, _ []config.PendingLease) error {
		if len(tasks) != 3 {
			t.Fatalf("expected 3 tasks, got %d", len(tasks))
		}
		gotIDs := []string{tasks[0].nodeID, tasks[1].nodeID, tasks[2].nodeID}
		wantIDs := []string{"a-node", "m-node", "z-node"}
		if !slices.Equal(gotIDs, wantIDs) {
			t.Fatalf("task nodeIDs = %v, want deterministic sorted %v", gotIDs, wantIDs)
		}
		if tasks[0].openSSHAlias != "ssh-alpha" || tasks[2].openSSHAlias != "ssh-zeta" {
			t.Fatalf("expected OpenSSHAlias parity on tagged tasks, got %q and %q", tasks[0].openSSHAlias, tasks[2].openSSHAlias)
		}
		if tasks[1].port != 22 {
			t.Fatalf("expected port 0 tagged host to normalize to 22, got %d", tasks[1].port)
		}
		if tasks[0].pass != "iaas-stored-secret" {
			t.Fatalf("expected default user to retain stored identity password, got %q", tasks[0].pass)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingTagTasks: %v", err)
	}

	oHost := NewExecOptions()
	oHost.Host = "m-node"
	oHost.Remember = "never"
	if err := oHost.withTestPendingHostTasks(t.Context(), prov, func(hostTasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
		if len(hostErrs) != 0 || len(hostTasks) != 1 {
			t.Fatalf("withTestPendingHostTasks(m-node): hostErrs=%v len=%d", hostErrs, len(hostTasks))
		}
		if hostTasks[0].port != 22 {
			t.Fatalf("expected withTestPendingHostTasks port 0 to normalize to 22, got %d", hostTasks[0].port)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingHostTasks(m-node): %v", err)
	}
}

func verifyPass7ExecTagOverridesAndPasswordSafety(t *testing.T, prov config.ConfigProvider, sshCfgPath string) {
	t.Helper()
	oOther := NewExecOptions()
	oOther.Tag = "p7tag"
	oOther.User = "otheruser"
	oOther.Port = 2222
	oOther.Remember = "never"
	oOther.control.ConfigFile = sshCfgPath
	if err := oOther.withTestPendingTagTasks(t.Context(), prov, func(tasks []execHostTask, _ []config.PendingLease) error {
		for _, task := range tasks {
			if task.user != "otheruser" || task.port != 2222 {
				t.Fatalf("unexpected overridden task user/port: %+v", task)
			}
			if task.pass != "" {
				t.Fatalf("expected stored password NOT to pair with -l otheruser on %s, got %q", task.rawHost, task.pass)
			}
			if task.nodeID == task.rawHost {
				t.Fatalf("expected overridden tagged task %s to prepare distinct nodeID, got %q", task.rawHost, task.nodeID)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingTagTasks(-l otheruser -p 2222): %v", err)
	}

	oExplicitPass := NewExecOptions()
	oExplicitPass.Tag = "p7tag"
	oExplicitPass.User = "otheruser"
	oExplicitPass.Password = "cli-override-secret"
	oExplicitPass.Remember = "never"
	oExplicitPass.control.ConfigFile = sshCfgPath
	if err := oExplicitPass.withTestPendingTagTasks(t.Context(), prov, func(tasksWithPass []execHostTask, _ []config.PendingLease) error {
		for _, task := range tasksWithPass {
			if task.pass != "cli-override-secret" {
				t.Fatalf("expected explicit CLI password on %s, got %q", task.rawHost, task.pass)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingTagTasks(-l otheruser with explicit password): %v", err)
	}
}

func verifyPass7OverriddenHostNameAndAliasExcludes(t *testing.T, prov config.ConfigProvider, sshCfgPath string) {
	t.Helper()
	for _, exSpec := range []string{"real-10.240.0.11.internal", "ssh-alpha", "openssh:ssh-alpha"} {
		assertPass7ExecTagExcludeFiltersAlpha(t, prov, sshCfgPath, exSpec)
		assertPass7ExecHostExcludeFiltersAlpha(t, prov, sshCfgPath, exSpec)
		assertPass7ScpTagExcludeFiltersAlpha(t, prov, sshCfgPath, exSpec)
		assertPass7ScpHostExcludeFiltersAlpha(t, prov, sshCfgPath, exSpec)
	}
}

func assertPass7ExecTagExcludeFiltersAlpha(t *testing.T, prov config.ConfigProvider, sshCfgPath, exSpec string) {
	t.Helper()
	o := NewExecOptions()
	o.Tag = "p7tag"
	o.Exclude = []string{exSpec}
	o.Command = "id"
	o.Remember = "never"
	o.control.ConfigFile = sshCfgPath
	o.control.Options = []string{"HostName=real-%h.internal", "UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete(exec --tag %s): %v", exSpec, err)
	}
	if err := o.withTestPendingTagTasks(t.Context(), prov, func(tasks []execHostTask, _ []config.PendingLease) error {
		cands := make([]utils.ExcludeTargetInfo, 0, len(tasks))
		for _, task := range tasks {
			cands = append(cands, o.execTaskExcludeInfo(task))
		}
		excludes, err := utils.ResolveExcludesForTargets(prov, utils.ParseExcludeFlag(o.Exclude), cands)
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(exec --tag %s): %v", exSpec, err)
		}
		var kept []string
		for i, task := range tasks {
			if !utils.IsTargetExcluded(excludes, cands[i]) {
				kept = append(kept, task.rawHost)
			}
		}
		if !slices.Equal(kept, []string{"m-node", "z-node"}) {
			t.Fatalf("exec --tag --exclude %q kept %v, want [m-node z-node]", exSpec, kept)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingTagTasks(%s): %v", exSpec, err)
	}
}

func assertPass7ExecHostExcludeFiltersAlpha(t *testing.T, prov config.ConfigProvider, sshCfgPath, exSpec string) {
	t.Helper()
	o := NewExecOptions()
	o.Host = "a-node,z-node"
	o.Exclude = []string{exSpec}
	o.Command = "id"
	o.Remember = "never"
	o.control.ConfigFile = sshCfgPath
	o.control.Options = []string{"HostName=real-%h.internal", "UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete(exec --host %s): %v", exSpec, err)
	}
	if err := o.withTestPendingHostTasks(t.Context(), prov, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
		if len(hostErrs) != 0 {
			t.Fatalf("withTestPendingHostTasks(%s): hostErrs=%v", exSpec, hostErrs)
		}
		cands := make([]utils.ExcludeTargetInfo, 0, len(tasks))
		for _, task := range tasks {
			cands = append(cands, o.execTaskExcludeInfo(task))
		}
		excludes, err := utils.ResolveExcludesForTargets(prov, utils.ParseExcludeFlag(o.Exclude), cands)
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(exec --host %s): %v", exSpec, err)
		}
		var kept []string
		for i, task := range tasks {
			if !utils.IsTargetExcluded(excludes, cands[i]) {
				kept = append(kept, task.rawHost)
			}
		}
		if !slices.Equal(kept, []string{"z-node"}) {
			t.Fatalf("exec --host --exclude %q kept %v, want [z-node]", exSpec, kept)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingHostTasks(%s): %v", exSpec, err)
	}
}

func assertPass7ScpTagExcludeFiltersAlpha(t *testing.T, prov config.ConfigProvider, sshCfgPath, exSpec string) {
	t.Helper()
	o := NewScpOptions()
	o.Tag = "p7tag"
	o.Exclude = []string{exSpec}
	o.Source = "./local.txt"
	o.Dest = "/tmp/remote.txt"
	o.Remember = "never"
	o.control.ConfigFile = sshCfgPath
	o.control.Options = []string{"HostName=real-%h.internal", "UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(scp --tag %s): %v", exSpec, err)
	}
	paths, err := o.collectTargetPaths(prov)
	if err != nil {
		t.Fatalf("collectTargetPaths(scp --tag %s): %v", exSpec, err)
	}
	var got []string
	for _, p := range paths {
		got = append(got, p.Host)
	}
	if !slices.Equal(got, []string{"m-node", "z-node"}) {
		t.Fatalf("scp --tag --exclude %q collected %v, want [m-node z-node]", exSpec, got)
	}
}

func assertPass7ScpHostExcludeFiltersAlpha(t *testing.T, prov config.ConfigProvider, sshCfgPath, exSpec string) {
	t.Helper()
	o := NewScpOptions()
	o.Host = "a-node,z-node"
	o.Exclude = []string{exSpec}
	o.Source = "./local.txt"
	o.Dest = "/tmp/remote.txt"
	o.Remember = "never"
	o.control.ConfigFile = sshCfgPath
	o.control.Options = []string{"HostName=real-%h.internal", "UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(scp --host %s): %v", exSpec, err)
	}
	paths, err := o.collectTargetPaths(prov)
	if err != nil {
		t.Fatalf("collectTargetPaths(scp --host %s): %v", exSpec, err)
	}
	if len(paths) != 1 || paths[0].Host != "z-node" {
		t.Fatalf("scp --host --exclude %q collected %+v, want [z-node]", exSpec, paths)
	}
}

func TestPass7_M6_OpenSSHPrecedenceMatrix(t *testing.T) {
	repo := setupTestRepository(t)

	verifyPass7SingleExecPrecedenceAndPasswordSafety(t, repo)
	verifyPass7BatchExecIFileAndMultiHostPrecedence(t, repo)
	verifyPass7ScpHelperPrecedenceUniformity(t, repo)
}

func verifyPass7SingleExecPrecedenceAndPasswordSafety(t *testing.T, repo *config.Repository) {
	t.Helper()
	// Single-target exec: -l/-p/-o User/-o Port overrides inline user@host:port,
	// and never pairs inline password meant for inline user with overridden -l user.
	ifile := filepath.Join(t.TempDir(), "single.hosts")
	oSingle := NewExecOptions()
	oSingle.Host = "inlineuser@10.238.221.181:2201"
	oSingle.User = "flaguser"
	oSingle.Port = 2299
	oSingle.Remember = "never"
	if err := oSingle.withTestPendingHostTasks(t.Context(), repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
		if len(hostErrs) != 0 || len(tasks) != 1 {
			t.Fatalf("single exec withTestPendingHostTasks: hostErrs=%v len=%d", hostErrs, len(tasks))
		}
		if tasks[0].user != "flaguser" || tasks[0].port != 2299 {
			t.Fatalf("single exec expected flaguser:2299, got %s:%d", tasks[0].user, tasks[0].port)
		}
		return nil
	}); err != nil {
		t.Fatalf("single exec withTestPendingHostTasks: %v", err)
	}

	// Verify resolveExecEntryCredentials drops inline password when single-target -l overrides inline user.
	u, hasU, p, hasP, pw := oSingle.resolveExecEntryCredentials(utils.HostInfo{
		Host:     "10.238.221.181",
		User:     "inlineuser",
		Port:     2201,
		Password: "inline-secret",
	}, false)
	if u != "flaguser" || !hasU || p != 2299 || !hasP || pw != "" {
		t.Fatalf("expected inline password dropped on single-target -l override, got u=%q p=%d pw=%q", u, p, pw)
	}
	oSingle.Password = "flag-secret"
	_, _, _, _, pw2 := oSingle.resolveExecEntryCredentials(utils.HostInfo{
		Host:     "10.238.221.181",
		User:     "inlineuser",
		Port:     2201,
		Password: "inline-secret",
	}, false)
	if pw2 != "flag-secret" {
		t.Fatalf("expected explicit CLI password on single-target -l override, got %q", pw2)
	}
	_ = ifile
}

func verifyPass7BatchExecIFileAndMultiHostPrecedence(t *testing.T, repo *config.Repository) {
	t.Helper()
	// 1. --ifile batch exec: per-row inline user/port overrides global -l/-p,
	// while rows omitting inline user/port inherit global -l/-p.
	ifile := filepath.Join(t.TempDir(), "batch.hosts")
	content := strings.Join([]string{
		"alice@10.240.1.10:2222",
		"10.240.1.11",
	}, "\n") + "\n"
	if err := os.WriteFile(ifile, []byte(content), 0o600); err != nil {
		t.Fatalf("write ifile: %v", err)
	}

	oIFile := NewExecOptions()
	oIFile.HostFile = ifile
	oIFile.User = "globaluser"
	oIFile.Port = 2200
	oIFile.Password = "global_pw"
	oIFile.Remember = "never"
	if err := oIFile.withTestPendingHostTasks(t.Context(), repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
		if len(hostErrs) != 0 || len(tasks) != 2 {
			t.Fatalf("ifile withTestPendingHostTasks: hostErrs=%v len=%d", hostErrs, len(tasks))
		}
		if tasks[0].user != "alice" || tasks[0].port != 2222 {
			t.Fatalf("row 0 expected alice@:2222, got user=%q port=%d", tasks[0].user, tasks[0].port)
		}
		if tasks[1].user != "globaluser" || tasks[1].port != 2200 || tasks[1].pass != "global_pw" {
			t.Fatalf("row 1 expected globaluser@:2200 with global_pw, got user=%q port=%d pass=%q", tasks[1].user, tasks[1].port, tasks[1].pass)
		}
		return nil
	}); err != nil {
		t.Fatalf("ifile withTestPendingHostTasks: %v", err)
	}
	// Also verify per-row HostInfo password stays paired with inline user in batch mode.
	bUser, _, bPort, _, bPw := oIFile.resolveExecEntryCredentials(utils.HostInfo{
		Host:     "10.240.1.10",
		User:     "alice",
		Port:     2222,
		Password: "alice_pw",
	}, true)
	if bUser != "alice" || bPort != 2222 || bPw != "alice_pw" {
		t.Fatalf("batch entry expected alice:2222/alice_pw, got %s:%d/%s", bUser, bPort, bPw)
	}

	// 2. Multi-host --host a,b: inline user/port beats global -l/-p; bare entry inherits global -l/-p.
	oMulti := NewExecOptions()
	oMulti.Host = "bob@10.240.1.20:2225,10.240.1.21"
	oMulti.User = "globaluser"
	oMulti.Port = 2200
	oMulti.Remember = "never"
	if err := oMulti.withTestPendingHostTasks(t.Context(), repo, func(mTasks []execHostTask, _ []config.PendingLease, mErrs []error) error {
		if len(mErrs) != 0 || len(mTasks) != 2 {
			t.Fatalf("multi --host withTestPendingHostTasks: hostErrs=%v len=%d", mErrs, len(mTasks))
		}
		if mTasks[0].user != "bob" || mTasks[0].port != 2225 {
			t.Fatalf("multi --host[0] expected bob:2225, got %s:%d", mTasks[0].user, mTasks[0].port)
		}
		if mTasks[1].user != "globaluser" || mTasks[1].port != 2200 {
			t.Fatalf("multi --host[1] expected globaluser:2200, got %s:%d", mTasks[1].user, mTasks[1].port)
		}
		return nil
	}); err != nil {
		t.Fatalf("multi --host withTestPendingHostTasks: %v", err)
	}
}

func verifyPass7ScpHelperPrecedenceUniformity(t *testing.T, repo *config.Repository) {
	t.Helper()
	o := NewScpOptions()
	o.Host = "alice@10.238.221.181:2223,10.238.221.181"
	o.User = "globaluser"
	o.Port = 2200

	inlinePath := PathInfo{Host: "10.238.221.181", User: "alice", Port: 2223, IsRemote: true}
	barePath := PathInfo{Host: "10.238.221.181", IsRemote: true}

	assertPass7ScpTargetAndCacheKey(t, o, inlinePath, "alice", 2223, "10.238.221.181\x00alice\x002223")
	assertPass7ScpTargetAndCacheKey(t, o, barePath, "globaluser", 2200, "10.238.221.181\x00globaluser\x002200")
	assertPass7ScpExcludeAndRawPaths(t, o, repo, inlinePath, barePath)
}

func assertPass7ScpTargetAndCacheKey(t *testing.T, o *ScpOptions, p PathInfo, wantUser string, wantPort uint16, wantKey string) {
	t.Helper()
	target, err := o.resolveTargetForPath(p)
	if err != nil || target.User != wantUser || !target.HasUser || target.Port != wantPort || !target.HasPort {
		t.Fatalf("resolveTargetForPath(%+v) = %+v, err=%v", p, target, err)
	}
	if got := o.canonicalCacheKey(p); got != wantKey {
		t.Fatalf("canonicalCacheKey(%+v) = %q, want %q", p, got, wantKey)
	}
}

func assertPass7ScpExcludeAndRawPaths(t *testing.T, o *ScpOptions, repo *config.Repository, inlinePath, barePath PathInfo) {
	t.Helper()
	exInline, err := o.excludeTargetInfoForPath(repo, inlinePath.Host, inlinePath)
	if err != nil || exInline.User != "alice" || exInline.Port != 2223 {
		t.Fatalf("excludeTargetInfoForPath(inline) = %+v, err=%v", exInline, err)
	}
	exBare, err := o.excludeTargetInfoForPath(repo, barePath.Host, barePath)
	if err != nil || exBare.User != "globaluser" || exBare.Port != 2200 {
		t.Fatalf("excludeTargetInfoForPath(bare) = %+v, err=%v", exBare, err)
	}

	rawPaths, err := o.rawHostTargetPaths()
	if err != nil {
		t.Fatalf("rawHostTargetPaths failed: %v", err)
	}
	if len(rawPaths) != 2 ||
		rawPaths[0].User != "alice" || rawPaths[0].Port != 2223 ||
		rawPaths[1].User != "globaluser" || rawPaths[1].Port != 2200 {
		t.Fatalf("rawHostTargetPaths = %+v, want [alice:2223, globaluser:2200]", rawPaths)
	}
}

func TestPass7_H8_HandoffFastExitAndBoundedBackoffOnStoppedOrBusyMasters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, portStr, _ := net.SplitHostPort(fix.Address)
	fixPort, _ := strconv.Atoi(portStr)

	verifyPass7H8StoppedJumpMasterFastAbort(t, ctx, fixHost, fixPort)
	verifyPass7H8BoundedBackoffUnderBusyMaster(t, ctx, fixHost, fixPort)
}

func verifyPass7H8StoppedJumpMasterFastAbort(t *testing.T, ctx context.Context, fixHost string, fixPort int) {
	t.Helper()
	tmpDir := shortControlTempDir(t)
	jumpSock := filepath.Join(tmpDir, "h8-jump.sock")
	targetSock := filepath.Join(tmpDir, "h8-target.sock")

	repo, connector := buildPass7JumpConnector(t, fixHost, fixPort, jumpSock, "5m", targetSock, "5m")
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, "p7-target")
	if err != nil {
		t.Fatalf("Connect(p7-target): %v", err)
	}
	defer func() { _ = client.Close() }()

	jumpMaster := ssh.GetActiveMuxServer(jumpSock)
	targetMaster := ssh.GetActiveMuxServer(targetSock)
	if jumpMaster == nil || targetMaster == nil {
		t.Fatalf("expected active jumpMaster (%v) and targetMaster (%v)", jumpMaster, targetMaster)
	}

	// Issue -O stop on jumpMaster via MuxClient so jumpMaster.StoppedListening() == true
	// while targetMaster's tunnel channel still keeps jumpMaster alive.
	mc, err := ssh.DialMuxClient(ctx, jumpSock)
	if err != nil {
		t.Fatalf("DialMuxClient(jump): %v", err)
	}
	stopErr := mc.StopListening(ctx)
	_ = mc.Close()
	if stopErr != nil {
		t.Fatalf("StopListening(jump): %v", stopErr)
	}
	if !jumpMaster.StoppedListening() {
		t.Fatal("expected jumpMaster.StoppedListening() == true")
	}

	ready, terminalAbort, err := releaseMastersForHandoffWithProvider(connector, repo, targetMaster, targetSock)
	if err != nil || ready || !terminalAbort {
		t.Fatalf("expected (ready=false, terminalAbort=true, err=nil) on stopped jumpMaster, got (%v, %v, %v)", ready, terminalAbort, err)
	}

	start := time.Now()
	wReady, wErr := waitAndReleaseMastersForHandoffWithProvider(ctx, connector, repo, targetMaster, targetSock)
	elapsed := time.Since(start)
	if wErr != nil || wReady {
		t.Fatalf("expected waitAndReleaseMastersForHandoffWithProvider to exit (false, nil), got (%v, %v)", wReady, wErr)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("expected fast exit without spin on stopped jumpMaster, took %v", elapsed)
	}
}

func verifyPass7H8BoundedBackoffUnderBusyMaster(t *testing.T, ctx context.Context, fixHost string, fixPort int) {
	t.Helper()
	tmpDir := shortControlTempDir(t)
	jumpSock := filepath.Join(tmpDir, "h8-busy-jump.sock")
	targetSock := filepath.Join(tmpDir, "h8-busy-target.sock")

	repo, connector := buildPass7JumpConnector(t, fixHost, fixPort, jumpSock, "5m", targetSock, "5m")
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, "p7-target")
	if err != nil {
		t.Fatalf("Connect(p7-target): %v", err)
	}
	defer func() { _ = client.Close() }()

	targetMaster := ssh.GetActiveMuxServer(targetSock)
	if targetMaster == nil {
		t.Fatal("expected active targetMaster")
	}

	muxCli, err := ssh.DialMuxClient(ctx, targetSock)
	if err != nil {
		t.Fatalf("DialMuxClient(target): %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	fwd := ssh.ForwardRequest{Type: ssh.ForwardLocal, ListenHost: "127.0.0.1", ConnectHost: "127.0.0.1", ConnectPort: uint32(fixPort)}
	if _, err := muxCli.OpenForward(ctx, fwd); err != nil {
		t.Fatalf("OpenForward(target): %v", err)
	}
	doneRelease := make(chan struct{})
	go func() {
		defer close(doneRelease)
		time.Sleep(35 * time.Millisecond)
		_ = muxCli.CloseForward(ctx, fwd)
	}()

	wReady, wErr := waitAndReleaseMastersForHandoffWithProvider(ctx, connector, repo, targetMaster, targetSock)
	<-doneRelease
	if wErr != nil || !wReady {
		t.Fatalf("expected bounded backoff to succeed once mux forward closed, got ready=%v err=%v", wReady, wErr)
	}
}

func buildPass7JumpConnector(
	t *testing.T,
	fixHost string,
	fixPort int,
	jumpSock, jumpPersist, targetSock, targetPersist string,
) (*config.Repository, *ssh.Connector) {
	t.Helper()
	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("h-p7", models.Host{Address: fixHost, Port: uint16(fixPort)})
	cfg.Identities.Set("id-p7", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("p7-jump", models.Node{
		HostRef:     "h-p7",
		IdentityRef: "id-p7",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterYes,
			Path:    jumpSock,
			Persist: jumpPersist,
		}),
	})
	cfg.Nodes.Set("p7-target", models.Node{
		HostRef:     "h-p7",
		IdentityRef: "id-p7",
		ProxyJump:   "p7-jump",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterYes,
			Path:    targetSock,
			Persist: targetPersist,
		}),
	})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	savedRepo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	adp := adapter.NewSSHAdapter(savedRepo, adapter.WithNonInteractive(true))
	connector := newPass6Connector(adp)
	return savedRepo, connector
}

func TestPass7_M3_FindOwnedMasterSkipsClosedAndSelectsNewest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, portStr, _ := net.SplitHostPort(fix.Address)
	fixPort, _ := strconv.Atoi(portStr)

	tmpDir := shortControlTempDir(t)
	sock1 := filepath.Join(tmpDir, "m3-1.sock")
	sock2 := filepath.Join(tmpDir, "m3-2.sock")

	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("h-m3", models.Host{Address: fixHost, Port: uint16(fixPort)})
	cfg.Identities.Set("id-m3", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("m3-node-1", models.Node{
		HostRef:     "h-m3",
		IdentityRef: "id-m3",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterYes,
			Path:    sock1,
			Persist: "5m",
		}),
	})
	cfg.Nodes.Set("m3-node-2", models.Node{
		HostRef:     "h-m3",
		IdentityRef: "id-m3",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterYes,
			Path:    sock2,
			Persist: "5m",
		}),
	})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	savedRepo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}

	adp := adapter.NewSSHAdapter(
		savedRepo,
		adapter.WithNonInteractive(true),
		adapter.WithSessionAuthOverride("m3-node-1", adapter.SessionAuth{OriginalHost: "shared-orig"}),
		adapter.WithSessionAuthOverride("m3-node-2", adapter.SessionAuth{OriginalHost: "shared-orig"}),
	)
	connector := newPass6Connector(adp)
	defer func() { _ = connector.CloseAll() }()

	c1, err := connector.Connect(ctx, "m3-node-1")
	if err != nil {
		t.Fatalf("Connect(m3-node-1): %v", err)
	}
	defer func() { _ = c1.Close() }()
	m1 := ssh.GetActiveMuxServer(sock1)

	c2, err := connector.Connect(ctx, "m3-node-2")
	if err != nil {
		t.Fatalf("Connect(m3-node-2): %v", err)
	}
	defer func() { _ = c2.Close() }()
	m2 := ssh.GetActiveMuxServer(sock2)

	if m1 == nil || m2 == nil || m1 == m2 {
		t.Fatalf("expected two distinct live masters, got m1=%v m2=%v", m1, m2)
	}
	// Reverse scan must select the newest live master (m2) when matching OriginalHost or empty nodeID.
	if got := findOwnedMasterForNode(connector, "shared-orig"); got != m2 {
		t.Fatalf("findOwnedMasterForNode(shared-orig) = %v, want newest m2 (%v)", got, m2)
	}
	if got := findOwnedMasterForNode(connector, ""); got != m2 {
		t.Fatalf("findOwnedMasterForNode(\"\") = %v, want newest m2 (%v)", got, m2)
	}

	// Shutting down m2 must skip closed m2 and return live m1.
	_ = m2.Shutdown()
	if got := findOwnedMasterForNode(connector, "m3-node-2"); got != nil {
		t.Fatalf("findOwnedMasterForNode(closed m3-node-2) = %v, want nil", got)
	}
	if got := findOwnedMasterForNode(connector, "shared-orig"); got != m1 {
		t.Fatalf("findOwnedMasterForNode(shared-orig after m2 closed) = %v, want live m1 (%v)", got, m1)
	}
}

func TestPass7_M7_MultiHopControlPersistHandoffCompletenessAndSpecificity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fix1, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New(1): %v", err)
	}
	defer func() { _ = fix1.Close() }()
	host1, portStr1, _ := net.SplitHostPort(fix1.Address)
	port1, _ := strconv.Atoi(portStr1)

	fix2, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New(2): %v", err)
	}
	defer func() { _ = fix2.Close() }()
	_, portStr2, _ := net.SplitHostPort(fix2.Address)
	port2, _ := strconv.Atoi(portStr2)

	verifyPass7M71TransitiveJumpAcrossNonMuxHop(t, ctx, host1, port1)
	verifyPass7M72ReserveNonPersistentJumpMaster(t, ctx, host1, port1)
	verifyPass7M73JumpDaemonConnectionWideOptions(t, ctx, fix1.Address, host1, port1)
	verifyPass7M74JumpHopUserPortSpecificity(t, ctx, host1, port1, port2)
}

func verifyPass7M71TransitiveJumpAcrossNonMuxHop(t *testing.T, ctx context.Context, fixHost string, fixPort int) {
	t.Helper()
	tmpDir := shortControlTempDir(t)
	jump0Sock := filepath.Join(tmpDir, "m71-jump0.sock")
	targetSock := filepath.Join(tmpDir, "m71-target.sock")

	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("h-m71", models.Host{Address: fixHost, Port: uint16(fixPort)})
	cfg.Identities.Set("id-m71", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("jump0", models.Node{
		HostRef:     "h-m71",
		IdentityRef: "id-m71",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterYes,
			Path:    jump0Sock,
			Persist: "5m",
		}),
	})
	nonMuxOpts := &ssh.Options{}
	_ = nonMuxOpts.Set(ssh.OptionControlMaster, "no")
	cfg.Nodes.Set("jump1", models.Node{
		HostRef:     "h-m71",
		IdentityRef: "id-m71",
		ProxyJump:   "jump0",
		SSHOptions:  nonMuxOpts,
	})
	cfg.Nodes.Set("target-m71", models.Node{
		HostRef:     "h-m71",
		IdentityRef: "id-m71",
		ProxyJump:   "jump1",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterYes,
			Path:    targetSock,
			Persist: "5m",
		}),
	})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	savedRepo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	connector := newPass6Connector(adapter.NewSSHAdapter(savedRepo, adapter.WithNonInteractive(true)))
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, "target-m71")
	if err != nil {
		t.Fatalf("Connect(target-m71): %v", err)
	}
	defer func() { _ = client.Close() }()

	jump0Master := ssh.GetActiveMuxServer(jump0Sock)
	targetMaster := ssh.GetActiveMuxServer(targetSock)
	if jump0Master == nil || targetMaster == nil {
		t.Fatalf("expected jump0Master (%v) and targetMaster (%v)", jump0Master, targetMaster)
	}

	jumps := persistentJumpHopsWithProvider(connector, savedRepo, connector.Masters())
	if !isSuppressedJumpMaster(jumps, connector.MasterNodeID(jump0Master), "jump0") {
		t.Fatalf("expected outer jump0 to be suppressed across ControlMaster=no jump1, jumps=%v", jumps)
	}
	chain := jumpChainMastersWithProvider(connector, savedRepo, targetMaster, connector.Masters())
	if len(chain) != 1 || chain[0] != jump0Master {
		t.Fatalf("jumpChainMastersWithProvider = %v, want [%v]", chain, jump0Master)
	}

	ready, abort, err := releaseMastersForHandoffWithProvider(connector, savedRepo, targetMaster, targetSock)
	if err != nil || !ready || abort {
		t.Fatalf("releaseMastersForHandoffWithProvider = (%v, %v, %v), want (true, false, nil)", ready, abort, err)
	}
	if !isMasterClosed(jump0Master) || !isMasterClosed(targetMaster) {
		t.Fatal("expected both targetMaster and transitive jump0Master to be shut down cleanly")
	}
}

func verifyPass7M72ReserveNonPersistentJumpMaster(t *testing.T, ctx context.Context, fixHost string, fixPort int) {
	t.Helper()
	tmpDir := shortControlTempDir(t)
	jumpSock := filepath.Join(tmpDir, "m72-jump.sock")
	targetSock := filepath.Join(tmpDir, "m72-target.sock")

	repo, connector := buildPass7JumpConnector(t, fixHost, fixPort, jumpSock, "no", targetSock, "5m")
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, "p7-target")
	if err != nil {
		t.Fatalf("Connect(p7-target): %v", err)
	}
	defer func() { _ = client.Close() }()

	jumpMaster := ssh.GetActiveMuxServer(jumpSock)
	targetMaster := ssh.GetActiveMuxServer(targetSock)
	if jumpMaster == nil || jumpMaster.PersistEnabled() || targetMaster == nil {
		t.Fatalf("expected non-persistent jumpMaster (%v) and persistent targetMaster (%v)", jumpMaster, targetMaster)
	}

	// Hold an active mux forward on the non-persistent jumpMaster so PrepareHandoff refuses.
	muxCli, err := ssh.DialMuxClient(ctx, jumpSock)
	if err != nil {
		t.Fatalf("DialMuxClient(jump): %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	fwd := ssh.ForwardRequest{Type: ssh.ForwardLocal, ListenHost: "127.0.0.1", ConnectHost: "127.0.0.1", ConnectPort: uint32(fixPort)}
	if _, err := muxCli.OpenForward(ctx, fwd); err != nil {
		t.Fatalf("OpenForward(jump): %v", err)
	}

	ready, abort, err := releaseMastersForHandoffWithProvider(connector, repo, targetMaster, targetSock)
	if err != nil || ready || abort {
		t.Fatalf("expected busy non-persistent jumpMaster to refuse handoff with (false, false, nil), got (%v, %v, %v)", ready, abort, err)
	}
	if isMasterClosed(jumpMaster) || isMasterClosed(targetMaster) {
		t.Fatal("busy non-persistent jumpMaster must NOT be forcefully shut down when PrepareHandoff fails")
	}
	if !connector.HasMasterSession(targetMaster) || !connector.HasMasterSession(jumpMaster) {
		t.Fatal("expected rollbackHandoffReservation to restore connector session refs on both masters")
	}

	// Close the active forward; handoff reservation & shutdown of both masters now succeeds.
	if err := muxCli.CloseForward(ctx, fwd); err != nil {
		t.Fatalf("CloseForward(jump): %v", err)
	}
	ready2, abort2, err2 := releaseMastersForHandoffWithProvider(connector, repo, targetMaster, targetSock)
	if err2 != nil || !ready2 || abort2 {
		t.Fatalf("expected handoff release to succeed once jumpMaster drained, got (%v, %v, %v)", ready2, abort2, err2)
	}
	if !isMasterClosed(jumpMaster) || !isMasterClosed(targetMaster) {
		t.Fatal("expected both targetMaster and non-persistent jumpMaster to shut down after reservation")
	}
}

func verifyPass7M73JumpDaemonConnectionWideOptions(t *testing.T, ctx context.Context, fixAddr, fixHost string, fixPort int) {
	t.Helper()
	tmpDir := shortControlTempDir(t)
	jumpSock := filepath.Join(tmpDir, "m73-jump.sock")

	_, jumpMaster := startPass7StandaloneMux(t, ctx, fixAddr, fixHost, fixPort, jumpSock, "bastion")

	opts := NewSshOptions()
	opts.Host = "target-app"
	opts.JumpHost = "bastion"
	opts.IdentityFile = "/tmp/target-only-key"
	opts.CipherSpec = "aes256-gcm@openssh.com"
	opts.GatewayPorts = true
	opts.control.ConfigFile = "/tmp/custom_ssh_config"
	opts.control.AddressFamily = "inet6"
	opts.control.Options = []string{
		"StrictHostKeyChecking=accept-new",
		"UserKnownHostsFile=/tmp/custom_kh",
		"GlobalKnownHostsFile=/tmp/global_kh",
		"HashKnownHosts=yes",
		"VerifyHostKeyDNS=ask",
		"BatchMode=yes",
		"ConnectTimeout=7",
		"IdentityAgent=/tmp/custom-agent.sock",
		"HostName=10.99.99.99",
		"ProxyCommand=sh -c true",
		"LocalCommand=echo hi",
		"PermitLocalCommand=yes",
		"RemoteCommand=uptime",
		"LocalForward=18080 127.0.0.1:80",
		"PubkeyAuthentication=no",
		"ForwardAgent=yes",
	}

	spec := opts.buildMuxDaemonSpec("bastion", jumpSock, jumpMaster)
	if spec.ConfigFile != "/tmp/custom_ssh_config" || spec.AddressFamily != "inet6" {
		t.Fatalf("expected jump daemon spec to preserve ConfigFile/AddressFamily, got %+v", spec)
	}
	joined := strings.Join(spec.Options, " ")
	for _, want := range []string{
		"StrictHostKeyChecking=accept-new",
		"UserKnownHostsFile=/tmp/custom_kh",
		"GlobalKnownHostsFile=/tmp/global_kh",
		"HashKnownHosts=yes",
		"VerifyHostKeyDNS=ask",
		"BatchMode=yes",
		"ConnectTimeout=7",
		"IdentityAgent=/tmp/custom-agent.sock",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected jump daemon spec to preserve connection-wide option %q, got %q", want, joined)
		}
	}
	if len(spec.IdentityFiles) > 0 || spec.CipherSpec != "" || spec.GatewayPorts {
		t.Fatalf("expected target-specific key/cipher/gateway-ports excluded from jump daemon spec, got %+v", spec)
	}
	for _, forbidden := range []string{
		"target-only-key",
		"aes256-gcm@openssh.com",
		"GatewayPorts",
		"10.99.99.99",
		"ProxyCommand",
		"LocalCommand",
		"RemoteCommand",
		"LocalForward",
		"PubkeyAuthentication",
		"ForwardAgent",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("expected target-specific option %q to be excluded from jump daemon spec options, got %q", forbidden, joined)
		}
	}
}

func startPass7StandaloneMux(
	t *testing.T,
	ctx context.Context,
	fixAddr, fixHost string,
	fixPort int,
	sockPath, origHost string,
) (*ssh.Client, *ssh.MuxServer) {
	t.Helper()
	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("h-sa", models.Host{Address: fixHost, Port: uint16(fixPort)})
	cfg.Identities.Set("id-sa", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set(origHost, models.Node{
		HostRef:     "h-sa",
		IdentityRef: "id-sa",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterYes,
			Path:    sockPath,
			Persist: "5m",
		}),
	})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	savedRepo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	connector := newPass6Connector(adapter.NewSSHAdapter(savedRepo, adapter.WithNonInteractive(true)))
	t.Cleanup(func() { _ = connector.CloseAll() })
	client, err := connector.Connect(ctx, origHost)
	if err != nil {
		t.Fatalf("Connect(%s at %s): %v", origHost, fixAddr, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	m := ssh.GetActiveMuxServer(sockPath)
	if m == nil {
		t.Fatalf("expected active MuxServer at %s", sockPath)
	}
	return client, m
}

func verifyPass7M74JumpHopUserPortSpecificity(t *testing.T, ctx context.Context, fixHost string, port1, port2 int) {
	t.Helper()
	tmpDir := shortControlTempDir(t)
	jumpSock := filepath.Join(tmpDir, "m74-jump.sock")
	targetSock := filepath.Join(tmpDir, "m74-target.sock")
	directSock := filepath.Join(tmpDir, "m74-direct.sock")

	sshCfg := strings.Join([]string{
		"Host shared-gw",
		"  HostName " + fixHost,
		"  User fixture",
		"  Port " + strconv.Itoa(port1),
		"Host target-behind-gw",
		"  HostName " + fixHost,
		"  User fixture",
		"  Port " + strconv.Itoa(port1),
		"  ProxyJump fixture@shared-gw:" + strconv.Itoa(port1),
	}, "\n")
	repo := buildPass6Repo(t, sshCfg)

	jumpNodeID := "openssh:fixture@shared-gw:" + strconv.Itoa(port1)
	targetNodeID := "openssh:target-behind-gw"
	directNodeID := "openssh:fixture@shared-gw:" + strconv.Itoa(port2)

	adp := adapter.NewSSHAdapter(
		repo,
		adapter.WithNonInteractive(true),
		adapter.WithSessionAuthOverride(jumpNodeID, adapter.SessionAuth{Password: sshfixture.Password, OriginalHost: "shared-gw"}),
		adapter.WithSessionControlOverride(jumpNodeID, newPass6SessionControl(t, jumpSock)),
		adapter.WithSessionAuthOverride(targetNodeID, adapter.SessionAuth{Password: sshfixture.Password, OriginalHost: "target-behind-gw"}),
		adapter.WithSessionControlOverride(targetNodeID, newPass6SessionControl(t, targetSock)),
		adapter.WithSessionAuthOverride(directNodeID, adapter.SessionAuth{Password: sshfixture.Password, OriginalHost: "shared-gw"}),
		adapter.WithSessionControlOverride(directNodeID, newPass6SessionControl(t, directSock)),
	)
	connector := newPass6Connector(adp)
	defer func() { _ = connector.CloseAll() }()

	cTarget, err := connector.Connect(ctx, targetNodeID)
	if err != nil {
		t.Fatalf("Connect(%s): %v", targetNodeID, err)
	}
	defer func() { _ = cTarget.Close() }()

	cDirect, err := connector.Connect(ctx, directNodeID)
	if err != nil {
		t.Fatalf("Connect(%s): %v", directNodeID, err)
	}
	defer func() { _ = cDirect.Close() }()

	jumpMaster := ssh.GetActiveMuxServer(jumpSock)
	targetMaster := ssh.GetActiveMuxServer(targetSock)
	directMaster := ssh.GetActiveMuxServer(directSock)
	if jumpMaster == nil || targetMaster == nil || directMaster == nil {
		t.Fatalf("expected jump (%v), target (%v), direct (%v)", jumpMaster, targetMaster, directMaster)
	}

	jumps := persistentJumpHopsWithProvider(connector, repo, connector.Masters())
	if jumps["shared-gw"] || jumps["openssh:shared-gw"] {
		t.Fatalf("explicit user/port jump hop must NOT coarsen into bare shared-gw in jumps: %v", jumps)
	}
	jumpResolved := resolveOwnedMasterNodeID(repo, connector, jumpMaster)
	directResolved := resolveOwnedMasterNodeID(repo, connector, directMaster)
	if !isSuppressedJumpMaster(jumps, connector.MasterNodeID(jumpMaster), jumpResolved) {
		t.Fatalf("expected jumpMaster (%s) to be suppressed, jumps=%v", connector.MasterNodeID(jumpMaster), jumps)
	}
	if isSuppressedJumpMaster(jumps, connector.MasterNodeID(directMaster), directResolved) {
		t.Fatalf("directMaster (%s, resolved=%s) on different port must NOT be suppressed as jump master!", connector.MasterNodeID(directMaster), directResolved)
	}

	chain := jumpChainMastersWithProvider(connector, repo, targetMaster, connector.Masters())
	if len(chain) != 1 || chain[0] != jumpMaster {
		t.Fatalf("jumpChainMastersWithProvider = %v, want ONLY [%v] (never directMaster %v)", chain, jumpMaster, directMaster)
	}
}
