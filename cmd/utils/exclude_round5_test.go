package utils

import (
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound5_P2_14_IPv6ExcludeCanonicalizationMatrix(t *testing.T) {
	t.Parallel()

	// 1. Saved IPv6 node excluded via expanded/uppercase/bracketed/composite forms.
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-v6", models.Host{Address: "2001:db8::1", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	savedID := config.FormatNodeID("ops", "2001:db8::1", 22)
	cfg.Nodes.Set(savedID, models.Node{HostRef: "h-v6", IdentityRef: "id-ops"})
	savedProv := config.NewProviderWithoutOpenSSH(cfg)

	savedCand := ExcludeTargetInfo{
		NodeID:         savedID,
		MatchedNodeID:  savedID,
		BaseNodeID:     savedID,
		User:           "ops",
		Port:           22,
		UnmanagedHosts: []string{"2001:db8::1", "[2001:0DB8::1]"},
	}

	for _, spec := range []string{
		"2001:0DB8:0000:0000:0000:0000:0000:0001",
		"[2001:0DB8::1]",
		"ops@[2001:0DB8::1]:22",
	} {
		excludes, err := ResolveExcludesForTargets(savedProv, []string{spec}, []ExcludeTargetInfo{savedCand})
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(%q): %v", spec, err)
		}
		if !IsTargetExcluded(excludes, savedCand) {
			t.Fatalf("saved IPv6 candidate not excluded by %q (excludes=%v)", spec, excludes)
		}
	}

	// Negative check: different user/port on same IPv6 address must NOT exclude saved ops@...:22.
	diffUserExcludes, err := ResolveExcludesForTargets(savedProv, []string{"alice@[2001:0DB8::1]:2222"}, []ExcludeTargetInfo{savedCand})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(diffUser): %v", err)
	}
	if IsTargetExcluded(diffUserExcludes, savedCand) {
		t.Fatalf("different user/port alice@...:2222 must not exclude saved ops@...:22")
	}

	// 2. OpenSSH concrete IPv6 node & zone-ID IPv6 excluded across forms.
	sshProv := newRound3ExcludeProvider(t, `
Host 2001:db8::9
  HostName 2001:db8::9
  User ops
  Port 2222

Host fe80::1%eth0
  HostName fe80::1%eth0
  User root
`)

	v6Cand := ExcludeTargetInfo{
		NodeID:         config.OpenSSHNodePrefix + "ops@[2001:db8::9]:2222",
		MatchedNodeID:  config.OpenSSHNodePrefix + "ops@[2001:db8::9]:2222",
		BaseNodeID:     config.OpenSSHNodePrefix + "2001:db8::9",
		OpenSSHAlias:   "2001:db8::9",
		User:           "ops",
		Port:           2222,
		UnmanagedHosts: []string{"ops@[2001:0DB8::9]:2222", "[2001:0DB8::9]"},
	}
	for _, spec := range []string{
		"[2001:0DB8:0000::9]",
		"openssh:[2001:0DB8::9]",
		"openssh:ops@[2001:0DB8::9]:2222",
	} {
		excludes, err := ResolveExcludesForTargets(sshProv, []string{spec}, []ExcludeTargetInfo{v6Cand})
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(OpenSSH %q): %v", spec, err)
		}
		if !IsTargetExcluded(excludes, v6Cand) {
			t.Fatalf("OpenSSH IPv6 candidate not excluded by %q (excludes=%v)", spec, excludes)
		}
	}

	zoneCand := ExcludeTargetInfo{
		NodeID:         config.OpenSSHNodePrefix + "root@[fe80::1%eth0]:22",
		MatchedNodeID:  config.OpenSSHNodePrefix + "root@[fe80::1%eth0]:22",
		BaseNodeID:     config.OpenSSHNodePrefix + "fe80::1%eth0",
		OpenSSHAlias:   "fe80::1%eth0",
		User:           "root",
		Port:           22,
		UnmanagedHosts: []string{"[FE80:0000::0001%eth0]"},
	}
	excludesZone, err := ResolveExcludesForTargets(sshProv, []string{"[fe80::0001%eth0]"}, []ExcludeTargetInfo{zoneCand})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(zone ID): %v", err)
	}
	if !IsTargetExcluded(excludesZone, zoneCand) {
		t.Fatalf("zone-ID IPv6 candidate not excluded by [fe80::0001%%eth0] (excludes=%v)", excludesZone)
	}

	// 3. Ad-hoc unmanaged IPv6 target excluded via bare canonical/bracketed forms.
	emptyProv := config.NewProviderWithoutOpenSSH(nil)
	adhocCand := ExcludeTargetInfo{
		NodeID:         config.FormatNodeID("bob", "2001:db8::55", 22),
		User:           "bob",
		Port:           22,
		UnmanagedHosts: []string{"bob@[2001:0DB8::55]:22", "[2001:0DB8::55]"},
	}
	excludesAdhoc, err := ResolveExcludesForTargets(emptyProv, []string{"2001:0DB8:0000::55"}, []ExcludeTargetInfo{adhocCand})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(ad-hoc IPv6): %v", err)
	}
	if !IsTargetExcluded(excludesAdhoc, adhocCand) {
		t.Fatalf("ad-hoc unmanaged IPv6 not excluded by 2001:0DB8:0000::55 (excludes=%v)", excludesAdhoc)
	}
}
