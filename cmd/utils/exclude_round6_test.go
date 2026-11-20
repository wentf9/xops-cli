package utils

import (
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound6_P1_1_CustomSavedNodeIPv6AndSharedIPExcludeSafety(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host 2001:db8::9",
		"  User v6ssh",
		"  Port 2222",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("hv6", models.Host{Address: "2001:db8::1", Port: 22})
	cfg.Hosts.Set("hv6-fmt", models.Host{Address: "2001:db8::2", Port: 22})
	cfg.Hosts.Set("hdb", models.Host{Address: "10.90.0.10", Port: 22})
	cfg.Hosts.Set("hmap", models.Host{Address: "::ffff:10.0.0.1", Port: 22})
	cfg.Hosts.Set("hzone", models.Host{Address: "fe80::1%eth0", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops"})
	cfg.Identities.Set("id-root", models.Identity{User: "root"})
	cfg.Nodes.Set("my-v6-box", models.Node{HostRef: "hv6", IdentityRef: "id-ops"})
	cfg.Nodes.Set("ops@[2001:db8::2]:22", models.Node{HostRef: "hv6-fmt", IdentityRef: "id-ops"})
	cfg.Nodes.Set("prod-db-1", models.Node{HostRef: "hdb", IdentityRef: "id-ops"})
	cfg.Nodes.Set("prod-db-2", models.Node{HostRef: "hdb", IdentityRef: "id-root"})
	cfg.Nodes.Set("v4-mapped", models.Node{HostRef: "hmap", IdentityRef: "id-ops"})
	cfg.Nodes.Set("v6-zone", models.Node{HostRef: "hzone", IdentityRef: "id-ops"})

	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	// 1. Direct Round-5 regression: custom-named saved node my-v6-box with non-canonical IPv6 target
	// (even if candidate arrived with BaseNodeID=="") MUST be excluded by --exclude 2001:0DB8::1.
	rawV6Cand := ExcludeTargetInfo{
		NodeID:         "ops@[2001:0DB8::1]:22",
		User:           "ops",
		Port:           22,
		UnmanagedHosts: []string{"2001:0DB8::1"},
	}
	excludes, err := ResolveExcludesForTargets(prov, []string{"2001:0DB8::1"}, []ExcludeTargetInfo{rawV6Cand})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(2001:0DB8::1): %v", err)
	}
	if !IsTargetExcluded(excludes, rawV6Cand) {
		t.Fatalf("P1-1 bypass: custom-named saved node target was NOT excluded; excludes=%v", excludes)
	}

	// 2. FormatNodeID saved node with user override (-l alice) on non-canonical IPv6 target.
	aliceV6Cand := ExcludeTargetInfo{
		NodeID:         "alice@[2001:0DB8::2]:22",
		User:           "alice",
		Port:           22,
		UnmanagedHosts: []string{"2001:0DB8::2"},
	}
	exFmt, err := ResolveExcludesForTargets(prov, []string{"2001:0DB8::2"}, []ExcludeTargetInfo{aliceV6Cand})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(2001:0DB8::2): %v", err)
	}
	if !IsTargetExcluded(exFmt, aliceV6Cand) {
		t.Fatalf("P1-1 bypass: FormatNodeID IPv6 user-override target NOT excluded; excludes=%v", exFmt)
	}

	// 3. Scoped exclude ops@[2001:0DB8::1]:22 must NOT falsely exclude -u root override of my-v6-box.
	rootOverrideCand := ExcludeTargetInfo{
		NodeID:         "root@[2001:db8::1]:22",
		BaseNodeID:     "my-v6-box",
		User:           "root",
		Port:           22,
		UnmanagedHosts: []string{"my-v6-box", "2001:db8::1"},
	}
	exScoped, err := ResolveExcludesForTargets(prov, []string{"ops@[2001:0DB8::1]:22"}, []ExcludeTargetInfo{rootOverrideCand})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(scoped): %v", err)
	}
	if IsTargetExcluded(exScoped, rootOverrideCand) {
		t.Fatalf("scoped exclude ops@[2001:0DB8::1]:22 falsely excluded root override; excludes=%v", exScoped)
	}

	// 4. Shared-IP custom nodes: --exclude root@prod-db-1 excludes prod-db-2 (root) without touching prod-db-1 (ops).
	dbOps := ExcludeTargetInfo{NodeID: "prod-db-1", MatchedNodeID: "prod-db-1", BaseNodeID: "prod-db-1", User: "ops", Port: 22}
	dbRootOverride := ExcludeTargetInfo{NodeID: "root@10.90.0.10:22", BaseNodeID: "prod-db-2", User: "root", Port: 22}
	exShared, err := ResolveExcludesForTargets(prov, []string{"root@prod-db-1"}, []ExcludeTargetInfo{dbOps, dbRootOverride})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(root@prod-db-1): %v", err)
	}
	if !IsTargetExcluded(exShared, dbRootOverride) || IsTargetExcluded(exShared, dbOps) {
		t.Fatalf("shared-IP custom exclude mismatch: root=%v ops=%v excludes=%v",
			IsTargetExcluded(exShared, dbRootOverride), IsTargetExcluded(exShared, dbOps), exShared)
	}

	verifyRound6IPv6VariantsAndOpenSSHExclude(t, prov)
}

func verifyRound6IPv6VariantsAndOpenSSHExclude(t *testing.T, prov config.ConfigProvider) {
	t.Helper()

	// IPv4-mapped IPv6 matches ::ffff:0a00:0001 and stays distinct from IPv4 10.0.0.1.
	v4MappedCand := ExcludeTargetInfo{NodeID: "v4-mapped", MatchedNodeID: "v4-mapped", BaseNodeID: "v4-mapped", User: "ops", Port: 22}
	v4PlainCand := ExcludeTargetInfo{NodeID: "ops@10.0.0.1:22", User: "ops", Port: 22, UnmanagedHosts: []string{"10.0.0.1"}}
	exMap, err := ResolveExcludesForTargets(prov, []string{"::ffff:0a00:0001"}, []ExcludeTargetInfo{v4MappedCand, v4PlainCand})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(::ffff:0a00:0001): %v", err)
	}
	if !IsTargetExcluded(exMap, v4MappedCand) || IsTargetExcluded(exMap, v4PlainCand) {
		t.Fatalf("IPv4-mapped IPv6 mismatch: mapped=%v plain=%v", IsTargetExcluded(exMap, v4MappedCand), IsTargetExcluded(exMap, v4PlainCand))
	}

	// Zone IDs match equivalently compressed form.
	zoneCand := ExcludeTargetInfo{NodeID: "v6-zone", MatchedNodeID: "v6-zone", BaseNodeID: "v6-zone", User: "ops", Port: 22}
	exZone, err := ResolveExcludesForTargets(prov, []string{"fe80:0::1%eth0"}, []ExcludeTargetInfo{zoneCand})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(fe80:0::1%%eth0): %v", err)
	}
	if !IsTargetExcluded(exZone, zoneCand) {
		t.Fatalf("zone-ID IPv6 target NOT excluded; excludes=%v", exZone)
	}

	// Unprefixed [2001:0DB8::9]:2222 against concrete OpenSSH IPv6 host inherits ssh_config User=v6ssh.
	openSSHV6Cand := ExcludeTargetInfo{
		NodeID:        "openssh:2001:db8::9",
		MatchedNodeID: "openssh:2001:db8::9",
		BaseNodeID:    "openssh:2001:db8::9",
		OpenSSHAlias:  "2001:db8::9",
		User:          "v6ssh",
		Port:          2222,
	}
	openSSHV6Port22 := ExcludeTargetInfo{
		NodeID:       "openssh:v6ssh@[2001:db8::9]:22",
		BaseNodeID:   "openssh:2001:db8::9",
		OpenSSHAlias: "2001:db8::9",
		User:         "v6ssh",
		Port:         22,
	}
	exOpenSSH, err := ResolveExcludesForTargets(prov, []string{"[2001:0DB8::9]:2222"}, []ExcludeTargetInfo{openSSHV6Cand, openSSHV6Port22})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets([2001:0DB8::9]:2222): %v", err)
	}
	if !IsTargetExcluded(exOpenSSH, openSSHV6Cand) || IsTargetExcluded(exOpenSSH, openSSHV6Port22) {
		t.Fatalf("unprefixed OpenSSH IPv6 port exclude mismatch: p2222=%v p22=%v excludes=%v",
			IsTargetExcluded(exOpenSSH, openSSHV6Cand), IsTargetExcluded(exOpenSSH, openSSHV6Port22), exOpenSSH)
	}
}
