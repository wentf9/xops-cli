package utils

import (
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound8_P1_8_BidirectionalHostPortExcludeSchema(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host web",
		"  HostName 10.90.0.10",
		"  User ops",
		"  Port 22",
		"",
		"Host custom-port",
		"  HostName 10.90.0.20",
		"  User ops",
		"  Port 2222",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatal(err)
	}
	prov := config.NewProviderWithOpenSSHParser(config.NewProviderWithoutOpenSSH(nil).Snapshot(), parser)

	// 1. --exclude web:22 (no candidates passed to ResolveExcludes) must exclude ANY user on web:22
	// including targets with Port: 0 (default 22) and explicit User: "alice", without excluding web:2222.
	excl, err := ResolveExcludes(prov, []string{"web:22"})
	if err != nil {
		t.Fatalf("ResolveExcludes(web:22): %v", err)
	}
	if !IsTargetExcluded(excl, ExcludeTargetInfo{OpenSSHAlias: "web", User: "alice", Port: 22}) {
		t.Fatalf("web:22 failed to exclude alice@web:22; excl=%v", excl)
	}
	if !IsTargetExcluded(excl, ExcludeTargetInfo{OpenSSHAlias: "web", User: "alice", Port: 0}) {
		t.Fatalf("web:22 failed to exclude alice@web (Port:0 -> 22); excl=%v", excl)
	}
	if !IsTargetExcluded(excl, ExcludeTargetInfo{OpenSSHAlias: "web", User: "", Port: 0}) {
		t.Fatalf("web:22 failed to exclude bare web (Port:0 -> 22); excl=%v", excl)
	}
	if IsTargetExcluded(excl, ExcludeTargetInfo{OpenSSHAlias: "web", User: "alice", Port: 2222}) {
		t.Fatalf("web:22 wrongly excluded alice@web:2222; excl=%v", excl)
	}

	// 2. --exclude custom-port:2222 must exclude bob@custom-port:2222 even when ResolveTarget defaulted User=ops.
	excl2, err := ResolveExcludes(prov, []string{"custom-port:2222"})
	if err != nil {
		t.Fatalf("ResolveExcludes(custom-port:2222): %v", err)
	}
	if !IsTargetExcluded(excl2, ExcludeTargetInfo{OpenSSHAlias: "custom-port", User: "bob", Port: 2222}) {
		t.Fatalf("custom-port:2222 failed to exclude bob@custom-port:2222; excl=%v", excl2)
	}
	if IsTargetExcluded(excl2, ExcludeTargetInfo{OpenSSHAlias: "custom-port", User: "bob", Port: 22}) {
		t.Fatalf("custom-port:2222 wrongly excluded bob@custom-port:22; excl=%v", excl2)
	}

	// 3. Unmanaged host:port exclude (e.g. "app.example.com:22") must exclude
	// unmanaged target with User="alice" and Port=0/22, without excluding Port=2222.
	unmanagedCands := []ExcludeTargetInfo{
		{UnmanagedHosts: []string{"app.example.com"}, User: "alice", Port: 22},
		{UnmanagedHosts: []string{"app.example.com"}, User: "alice", Port: 2222},
	}
	excl3, err := ResolveExcludesForTargets(prov, []string{"app.example.com:22"}, unmanagedCands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(app.example.com:22): %v", err)
	}
	if !IsTargetExcluded(excl3, ExcludeTargetInfo{UnmanagedHosts: []string{"app.example.com"}, User: "alice", Port: 22}) {
		t.Fatalf("app.example.com:22 failed to exclude unmanaged alice@app.example.com:22; excl=%v", excl3)
	}
	if !IsTargetExcluded(excl3, ExcludeTargetInfo{UnmanagedHosts: []string{"app.example.com"}, User: "alice", Port: 0}) {
		t.Fatalf("app.example.com:22 failed to exclude unmanaged alice@app.example.com (Port:0); excl=%v", excl3)
	}
	if IsTargetExcluded(excl3, ExcludeTargetInfo{UnmanagedHosts: []string{"app.example.com"}, User: "alice", Port: 2222}) {
		t.Fatalf("app.example.com:22 wrongly excluded unmanaged alice@app.example.com:2222; excl=%v", excl3)
	}
	// Direct user-less host:port exclude map must also match unmanaged targets carrying User and Port=0/22.
	directPortExcl := map[string]struct{}{"app.example.com:22": {}}
	if !IsTargetExcluded(directPortExcl, ExcludeTargetInfo{UnmanagedHosts: []string{"app.example.com"}, User: "bob", Port: 0}) {
		t.Fatalf("direct host:port exclude failed to match unmanaged bob@app.example.com (Port:0)")
	}
	if IsTargetExcluded(directPortExcl, ExcludeTargetInfo{UnmanagedHosts: []string{"app.example.com"}, User: "bob", Port: 2222}) {
		t.Fatalf("direct host:port exclude wrongly matched unmanaged bob@app.example.com:2222")
	}
}

func TestRound8_P1_9_SavedBaseGuardBlocksBareBaseExclusionWhenUnmanagedUserPortMatches(t *testing.T) {
	t.Parallel()

	// Target derived from saved node "my-box" with matching user/port in UnmanagedHosts:
	// Excluding ONLY bare "my-box" (e.g. in an override scenario where NodeID != "my-box")
	// must NOT strip "ops@my-box:22" down to canonHost="my-box" and match excludes["my-box"].
	excludes := map[string]struct{}{
		"my-box": {},
	}
	info := ExcludeTargetInfo{
		NodeID:         "ops@10.91.0.1:2222",
		BaseNodeID:     "my-box",
		User:           "ops",
		Port:           2222,
		UnmanagedHosts: []string{"ops@my-box:2222"},
	}
	if IsTargetExcluded(excludes, info) {
		t.Fatalf("bare BaseNodeID exclude %v wrongly excluded overridden saved target %+v via canonHost", excludes, info)
	}
	// Explicit matching composite exclude MUST still match.
	exactExcludes := map[string]struct{}{
		"ops@my-box:2222": {},
	}
	if !IsTargetExcluded(exactExcludes, info) {
		t.Fatalf("explicit composite exclude %v failed to exclude %+v", exactExcludes, info)
	}
}

func TestRound8_P2_14_CompositeExcludeMonotonicityAndSavedMatchedNodeID(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host ssh-alias",
		"  HostName 10.92.0.5",
		"  User ops",
		"  Port 22",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.92.0.5", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-node", models.Node{HostRef: "h1", IdentityRef: "id1"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	savedCand := ExcludeTargetInfo{
		NodeID:        "saved-node",
		MatchedNodeID: "saved-node",
		BaseNodeID:    "saved-node",
		ResolvedHost:  "10.92.0.5",
		User:          "ops",
		Port:          22,
	}
	openSSHCand := ExcludeTargetInfo{
		NodeID:        "openssh:ssh-alias",
		MatchedNodeID: "openssh:ssh-alias",
		BaseNodeID:    "openssh:ssh-alias",
		OpenSSHAlias:  "ssh-alias",
		ResolvedHost:  "10.92.0.5",
		User:          "ops",
		Port:          22,
	}
	cands := []ExcludeTargetInfo{savedCand, openSSHCand}

	// Monotonicity: bare --exclude 10.92.0.5 isolates concrete OpenSSH alias ssh-alias.
	bareExcl, err := ResolveExcludesForTargets(prov, []string{"10.92.0.5"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(bare): %v", err)
	}
	if !IsTargetExcluded(bareExcl, savedCand) {
		t.Fatalf("bare 10.92.0.5 failed to exclude saved-node; excl=%v", bareExcl)
	}
	if IsTargetExcluded(bareExcl, openSSHCand) {
		t.Fatalf("bare 10.92.0.5 wrongly excluded concrete OpenSSH alias ssh-alias; excl=%v", bareExcl)
	}

	// Narrowing to ops@10.92.0.5:22 MUST NOT suddenly widen to exclude ssh-alias!
	compExcl, err := ResolveExcludesForTargets(prov, []string{"ops@10.92.0.5:22"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(composite): %v", err)
	}
	if !IsTargetExcluded(compExcl, savedCand) {
		t.Fatalf("ops@10.92.0.5:22 failed to exclude saved-node; excl=%v", compExcl)
	}
	if IsTargetExcluded(compExcl, openSSHCand) {
		t.Fatalf("anti-monotonicity: ops@10.92.0.5:22 excluded concrete OpenSSH alias ssh-alias while bare 10.92.0.5 did not; excl=%v", compExcl)
	}

	// OpenSSH composite exclude resolving to a saved MatchedNodeID (without candidates) must record saved-node!
	aliasExcl, err := ResolveExcludes(prov, []string{"ops@ssh-alias:22"})
	if err != nil {
		t.Fatalf("ResolveExcludes(ops@ssh-alias:22): %v", err)
	}
	if !IsTargetExcluded(aliasExcl, savedCand) {
		t.Fatalf("ops@ssh-alias:22 failed to record saved MatchedNodeID saved-node; excl=%v", aliasExcl)
	}
}
