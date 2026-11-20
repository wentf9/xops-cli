package utils

import (
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
)

func TestRound4_P2_25_HasCompositeExcludeAddrAndIPv6MixedCase(t *testing.T) {
	t.Parallel()

	if !hasCompositeExcludeAddr("openssh:ops@[2001:db8::1]:2222") {
		t.Fatal("hasCompositeExcludeAddr(\"openssh:ops@[2001:db8::1]:2222\") = false, want true")
	}
	if !hasCompositeExcludeAddr("openssh:ops@WebHost:2222") {
		t.Fatal("hasCompositeExcludeAddr(\"openssh:ops@WebHost:2222\") = false, want true")
	}
	if hasCompositeExcludeAddr("openssh:webhost") {
		t.Fatal("hasCompositeExcludeAddr(\"openssh:webhost\") = true, want false")
	}

	prov := config.NewProviderWithoutOpenSSH(nil)
	v6Cand := ExcludeTargetInfo{
		NodeID:         "openssh:ops@[2001:db8::1]:2222",
		BaseNodeID:     "openssh:2001:db8::1",
		User:           "ops",
		Port:           2222,
		UnmanagedHosts: []string{"[2001:db8::1]"},
	}
	mixedCand := ExcludeTargetInfo{
		NodeID:         "openssh:ops@Web.Example:2222",
		BaseNodeID:     "openssh:Web.Example",
		User:           "ops",
		Port:           2222,
		UnmanagedHosts: []string{"Web.Example"},
	}

	excludes, err := ResolveExcludesForTargets(prov, []string{"ops@[2001:0db8::1]:2222", "ops@web.example:2222"}, []ExcludeTargetInfo{v6Cand, mixedCand})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets: %v", err)
	}
	if !IsTargetExcluded(excludes, v6Cand) {
		t.Fatalf("non-canonical IPv6 composite exclude missed %+v (excludes=%v)", v6Cand, excludes)
	}
	if !IsTargetExcluded(excludes, mixedCand) {
		t.Fatalf("mixed-case composite exclude missed %+v (excludes=%v)", mixedCand, excludes)
	}
}

func TestRound4_P3_10_ExcludeUnmanagedIPv6AndCLICanonicalOptions(t *testing.T) {
	t.Parallel()

	for _, unmanaged := range []string{"2001:db8::1", "[2001:db8::1]"} {
		cand := ExcludeTargetInfo{
			User:           "ops",
			Port:           2222,
			UnmanagedHosts: []string{unmanaged},
		}
		excludes := map[string]struct{}{
			config.OpenSSHNodePrefix + config.FormatNodeID("ops", "2001:db8::1", 2222): {},
		}
		if !IsTargetExcluded(excludes, cand) {
			t.Fatalf("IsTargetExcluded failed for UnmanagedHosts=%q", unmanaged)
		}
	}

	sshCfg := strings.Join([]string{
		"Host short.corp.example.com",
		"  User ops",
		"  HostName 10.60.0.10",
	}, "\n") + "\n"
	prov := newRound3ExcludeProvider(t, sshCfg)

	cand := ExcludeTargetInfo{
		NodeID:         config.OpenSSHNodePrefix + "short.corp.example.com",
		MatchedNodeID:  config.OpenSSHNodePrefix + "short.corp.example.com",
		BaseNodeID:     config.OpenSSHNodePrefix + "short.corp.example.com",
		CanonicalHost:  "short.corp.example.com",
		User:           "ops",
		Port:           22,
		UnmanagedHosts: []string{"short.corp.example.com"},
	}

	// Without CLI canonicalization options, "short" cannot expand to corp.example.com.
	if _, err := ResolveExcludesForTargetsWithOptions(prov, []string{"short"}, []ExcludeTargetInfo{cand}, nil, ""); err == nil {
		t.Fatal("expected 'short' without CLI CanonicalDomains to fail matching")
	}

	// With CLI -o CanonicalizeHostname=yes -o CanonicalDomains=corp.example.com, "short" excludes short.corp.example.com.
	excludes, err := ResolveExcludesForTargetsWithOptions(
		prov,
		[]string{"short"},
		[]ExcludeTargetInfo{cand},
		[]string{"CanonicalizeHostname=yes", "CanonicalDomains=corp.example.com"},
		"",
	)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargetsWithOptions(CLI canonical): %v", err)
	}
	if !IsTargetExcluded(excludes, cand) {
		t.Fatalf("cand was not excluded with CLI CanonicalDomains: excludes=%v", excludes)
	}

	// With explicit active CLI -J bastion (without CanonicalizeFallbackLocal), canonicalization is disabled per OpenSSH.
	if _, err := ResolveExcludesForTargetsWithOptions(
		prov,
		[]string{"short"},
		[]ExcludeTargetInfo{cand},
		[]string{"CanonicalizeHostname=yes", "CanonicalDomains=corp.example.com"},
		"bastion",
	); err == nil {
		t.Fatal("expected active CLI ProxyJump to suppress canonicalization without CanonicalizeFallbackLocal")
	}
}
