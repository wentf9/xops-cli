package utils

import (
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound7_P1_6_BuildExcludeTargetInfoAndResolvedHostSeparation(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host unrelated-alias",
		"  HostName 10.91.0.5",
		"  User ops",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-saved", models.Host{Address: "10.91.0.5", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops"})
	cfg.Nodes.Set("saved-ov", models.Node{HostRef: "h-saved", IdentityRef: "id-ops"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	savedOvCand := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID:           "saved-ov",
		MatchedNodeID:    "saved-ov",
		BaseNodeID:       "saved-ov",
		ResolvedHost:     "10.91.0.5",
		User:             "ops",
		Port:             22,
		UnmanagedHosts:   []string{"saved-ov", "override.internal"},
		HostNameOverride: "override.internal",
	})
	if savedOvCand.ResolvedHost != "10.91.0.5" || !slices.Contains(savedOvCand.UnmanagedHosts, "10.91.0.5") {
		t.Fatalf("saved candidate lost ResolvedHost in UnmanagedHosts: %+v", savedOvCand)
	}

	unrelatedOpenSSHCand := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID:         "openssh:unrelated-alias",
		MatchedNodeID:  "openssh:unrelated-alias",
		BaseNodeID:     "openssh:unrelated-alias",
		OpenSSHAlias:   "unrelated-alias",
		ResolvedHost:   "10.91.0.5",
		User:           "ops",
		Port:           22,
		UnmanagedHosts: []string{"openssh:unrelated-alias", "unrelated-alias"},
	})
	if slices.Contains(unrelatedOpenSSHCand.UnmanagedHosts, "10.91.0.5") {
		t.Fatalf("OpenSSH alias leaked ResolvedHost into UnmanagedHosts: %+v", unrelatedOpenSSHCand)
	}

	cands := []ExcludeTargetInfo{savedOvCand, unrelatedOpenSSHCand}

	// Excluding saved-ov by saved name excludes saved-ov even under -o HostName=override.internal,
	// without falsely excluding unrelated OpenSSH alias sharing the same IP.
	exBySaved, err := ResolveExcludesForTargets(prov, []string{"saved-ov"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(saved-ov): %v", err)
	}
	if !IsTargetExcluded(exBySaved, savedOvCand) || IsTargetExcluded(exBySaved, unrelatedOpenSSHCand) {
		t.Fatalf("exclude saved-ov mismatch: saved=%v unrelated=%v ex=%v",
			IsTargetExcluded(exBySaved, savedOvCand), IsTargetExcluded(exBySaved, unrelatedOpenSSHCand), exBySaved)
	}

	// Excluding explicit IP 10.91.0.5 matches saved node even under -o HostName=override.internal,
	// without pulling in an unrelated concrete OpenSSH alias when a saved node owns that IP selector.
	exByIP, err := ResolveExcludesForTargets(prov, []string{"10.91.0.5"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(10.91.0.5): %v", err)
	}
	if !IsTargetExcluded(exByIP, savedOvCand) || IsTargetExcluded(exByIP, unrelatedOpenSSHCand) {
		t.Fatalf("exclude 10.91.0.5 mismatch (saved inventory match): saved=%v unrelated=%v ex=%v",
			IsTargetExcluded(exByIP, savedOvCand), IsTargetExcluded(exByIP, unrelatedOpenSSHCand), exByIP)
	}

	// When no saved node intercepts the IP (e.g. OpenSSH aliases + un-aliased ad-hoc target with HostName override):
	// - excluding explicit IP 10.91.0.99 matches both OpenSSHAlias and ad-hoc ResolvedHost;
	// - excluding alias-a (resolvedHost=10.91.0.99) excludes alias-a and the ad-hoc IP target (OpenSSHAlias==""),
	//   while NOT falsely excluding sibling alias-b (OpenSSHAlias=="alias-b").
	sharedSSH := strings.Join([]string{
		"Host alias-a",
		"  HostName 10.91.0.99",
		"  User ops",
		"Host alias-b",
		"  HostName 10.91.0.99",
		"  User ops",
	}, "\n") + "\n"
	sharedParser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sharedSSH))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader(shared): %v", err)
	}
	sharedProv := config.NewProviderWithOpenSSHParser(nil, sharedParser)
	aliasACand := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID: "openssh:alias-a", MatchedNodeID: "openssh:alias-a", BaseNodeID: "openssh:alias-a",
		OpenSSHAlias: "alias-a", ResolvedHost: "10.91.0.99", User: "ops", Port: 22,
	})
	aliasBCand := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID: "openssh:alias-b", MatchedNodeID: "openssh:alias-b", BaseNodeID: "openssh:alias-b",
		OpenSSHAlias: "alias-b", ResolvedHost: "10.91.0.99", User: "ops", Port: 22,
	})
	adHocOvCand := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID: "ops@10.91.0.99:22", ResolvedHost: "10.91.0.99", User: "ops", Port: 22,
		UnmanagedHosts: []string{"10.91.0.99", "ov.internal"}, HostNameOverride: "ov.internal",
	})
	sharedCands := []ExcludeTargetInfo{aliasACand, aliasBCand, adHocOvCand}

	exSharedIP, err := ResolveExcludesForTargets(sharedProv, []string{"10.91.0.99"}, sharedCands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(10.91.0.99): %v", err)
	}
	if !IsTargetExcluded(exSharedIP, aliasACand) || !IsTargetExcluded(exSharedIP, aliasBCand) || !IsTargetExcluded(exSharedIP, adHocOvCand) {
		t.Fatalf("explicit IP 10.91.0.99 failed on ResolvedHost: a=%v b=%v adhoc=%v ex=%v",
			IsTargetExcluded(exSharedIP, aliasACand), IsTargetExcluded(exSharedIP, aliasBCand), IsTargetExcluded(exSharedIP, adHocOvCand), exSharedIP)
	}

	exAliasA, err := ResolveExcludesForTargets(sharedProv, []string{"alias-a"}, sharedCands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(alias-a): %v", err)
	}
	if !IsTargetExcluded(exAliasA, aliasACand) || !IsTargetExcluded(exAliasA, adHocOvCand) || IsTargetExcluded(exAliasA, aliasBCand) {
		t.Fatalf("alias-a exclude isolation failed: a=%v adhoc=%v b=%v ex=%v",
			IsTargetExcluded(exAliasA, aliasACand), IsTargetExcluded(exAliasA, adHocOvCand), IsTargetExcluded(exAliasA, aliasBCand), exAliasA)
	}
}

func TestRound7_P1_7_RecordSavedBaseCandidateMatchWildcardFallback(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host concrete-alias",
		"  HostName 10.92.0.10",
		"  User wild",
		"",
		"Host *",
		"  User wild",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-web", models.Host{Address: "10.92.0.10", Port: 22})
	cfg.Identities.Set("id-wild", models.Identity{User: "wild"})
	cfg.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-wild"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	wildcardFallback := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID:         "openssh:10.92.0.10",
		MatchedNodeID:  "openssh:10.92.0.10",
		BaseNodeID:     "openssh:10.92.0.10",
		ResolvedHost:   "10.92.0.10",
		User:           "wild",
		Port:           22,
		UnmanagedHosts: []string{"10.92.0.10"},
	})
	openSSHDerivedSaved := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID:       "custom-saved",
		BaseNodeID:   "openssh:other-alias",
		ResolvedHost: "10.92.0.10",
		User:         "wild",
		Port:         22,
	})
	concreteAlias := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID:         "openssh:concrete-alias",
		MatchedNodeID:  "openssh:concrete-alias",
		BaseNodeID:     "openssh:concrete-alias",
		OpenSSHAlias:   "concrete-alias",
		ResolvedHost:   "10.92.0.10",
		User:           "wild",
		Port:           22,
		UnmanagedHosts: []string{"concrete-alias"},
	})

	cands := []ExcludeTargetInfo{wildcardFallback, openSSHDerivedSaved, concreteAlias}
	ex, err := ResolveExcludesForTargets(prov, []string{"saved-web"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(saved-web): %v", err)
	}
	if !IsTargetExcluded(ex, wildcardFallback) {
		t.Fatalf("wildcard fallback candidate was NOT excluded by saved-web; ex=%v", ex)
	}
	if !IsTargetExcluded(ex, openSSHDerivedSaved) {
		t.Fatalf("saved candidate with openssh BaseNodeID was NOT excluded by saved-web; ex=%v", ex)
	}
	if IsTargetExcluded(ex, concreteAlias) {
		t.Fatalf("concrete OpenSSH alias was falsely excluded by saved-web; ex=%v", ex)
	}
}

func TestRound7_P1_8_CompositeExcludeNeverLeaksBareOpenSSHKey(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host app-alias",
		"  HostName 10.93.0.10",
		"  User ops",
		"  Port 22",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(nil, parser)

	opsCand := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID:        "openssh:app-alias",
		MatchedNodeID: "openssh:app-alias",
		BaseNodeID:    "openssh:app-alias",
		OpenSSHAlias:  "app-alias",
		ResolvedHost:  "10.93.0.10",
		User:          "ops",
		Port:          22,
	})
	adminPort2222Cand := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID:       "openssh:admin@app-alias:2222",
		BaseNodeID:   "openssh:app-alias",
		OpenSSHAlias: "app-alias",
		ResolvedHost: "10.93.0.10",
		User:         "admin",
		Port:         2222,
	})
	noUserPort22Cand := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID:       "openssh:app-alias",
		BaseNodeID:   "openssh:app-alias",
		OpenSSHAlias: "app-alias",
		ResolvedHost: "10.93.0.10",
		Port:         22,
	})
	noUserPort2222Cand := BuildExcludeTargetInfo(ExcludeTargetBuildInput{
		NodeID:       "openssh:app-alias",
		BaseNodeID:   "openssh:app-alias",
		OpenSSHAlias: "app-alias",
		ResolvedHost: "10.93.0.10",
		Port:         2222,
	})
	cands := []ExcludeTargetInfo{opsCand, adminPort2222Cand, noUserPort22Cand, noUserPort2222Cand}

	// 1. User-scoped composite exclude (--exclude ops@app-alias) must not leak bare openssh:app-alias.
	exUser, err := ResolveExcludesForTargets(prov, []string{"ops@app-alias"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(ops@app-alias): %v", err)
	}
	if _, bareLeaked := exUser["openssh:app-alias"]; bareLeaked {
		t.Fatalf("composite exclude ops@app-alias leaked bare openssh:app-alias: %v", exUser)
	}
	if !IsTargetExcluded(exUser, opsCand) || IsTargetExcluded(exUser, adminPort2222Cand) {
		t.Fatalf("ops@app-alias matching broken: ops=%v admin2222=%v ex=%v",
			IsTargetExcluded(exUser, opsCand), IsTargetExcluded(exUser, adminPort2222Cand), exUser)
	}

	// 2. User-less port composite exclude (--exclude app-alias:2222) excludes port 2222 (including user-less),
	// leaves port 22 (both ops@ and user-less) unexcluded, and never leaks bare openssh:app-alias.
	exPort, err := ResolveExcludesForTargets(prov, []string{"app-alias:2222"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(app-alias:2222): %v", err)
	}
	if _, bareLeaked := exPort["openssh:app-alias"]; bareLeaked {
		t.Fatalf("port composite exclude app-alias:2222 leaked bare openssh:app-alias: %v", exPort)
	}
	if !IsTargetExcluded(exPort, noUserPort2222Cand) || !IsTargetExcluded(exPort, adminPort2222Cand) {
		t.Fatalf("port 2222 candidates were NOT excluded: noUser=%v admin=%v ex=%v",
			IsTargetExcluded(exPort, noUserPort2222Cand), IsTargetExcluded(exPort, adminPort2222Cand), exPort)
	}
	if IsTargetExcluded(exPort, opsCand) || IsTargetExcluded(exPort, noUserPort22Cand) {
		t.Fatalf("port 22 candidates falsely excluded by app-alias:2222: ops=%v noUser22=%v ex=%v",
			IsTargetExcluded(exPort, opsCand), IsTargetExcluded(exPort, noUserPort22Cand), exPort)
	}
}

func TestRound7_P2_6_UnmanagedSavedBaseGuardCanonicalIPv6AndPostParseAddr(t *testing.T) {
	t.Parallel()

	// Case 1: Saved BaseNodeID is uppercase bracketed IPv6 composite, UnmanagedHosts has compressed variant.
	infoCanonical := ExcludeTargetInfo{
		NodeID:         "admin@2001:db8::1:22",
		BaseNodeID:     "ops@[2001:0DB8::1]:22",
		User:           "admin",
		Port:           22,
		UnmanagedHosts: []string{"ops@2001:db8::1:22"},
	}
	exCanon := map[string]struct{}{"ops@[2001:0DB8::1]:22": {}}
	if IsTargetExcluded(exCanon, infoCanonical) {
		t.Fatalf("savedBase guard failed to protect canonical IPv6 equivalent BaseNodeID; ex=%v", exCanon)
	}

	// Case 2: Post-ParseAddr stripping of mismatched user/port reveals bare BaseNodeID (2001:db8::1 == 2001:0DB8::1).
	infoPostParse := ExcludeTargetInfo{
		NodeID:         "admin@[2001:db8::1]:22",
		BaseNodeID:     "2001:0DB8::1",
		User:           "admin",
		Port:           22,
		UnmanagedHosts: []string{"other@[2001:db8::1]:2222"},
	}
	exBare := map[string]struct{}{"[2001:0DB8::1]": {}, "2001:db8::1": {}}
	if IsTargetExcluded(exBare, infoPostParse) {
		t.Fatalf("savedBase guard leaked after ParseAddr stripped user/port; ex=%v", exBare)
	}
}
