package utils

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
)

func newRound3ExcludeProvider(t *testing.T, sshCfg string) config.ConfigProvider {
	t.Helper()
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}
	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser error = %v", err)
	}
	return repo
}

func TestRound3_P1_4_CanonicalBidirectionalExcludeAndIsolation(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host short",
		"  User ops",
		"  HostName 10.200.0.10",
		"",
		"Host shared-a",
		"  User ops",
		"  HostName 10.200.0.99",
		"",
		"Host shared-b",
		"  User ops",
		"  HostName 10.200.0.99",
		"",
		"Host *.corp.example.com",
		"  User ops",
		"",
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
	}, "\n") + "\n"

	prov := newRound3ExcludeProvider(t, sshCfg)

	canonCandidateOps := ExcludeTargetInfo{
		NodeID:         config.OpenSSHNodePrefix + "short.corp.example.com",
		MatchedNodeID:  config.OpenSSHNodePrefix + "short.corp.example.com",
		BaseNodeID:     config.OpenSSHNodePrefix + "short.corp.example.com",
		OpenSSHAlias:   "short",
		CanonicalHost:  "short.corp.example.com",
		User:           "ops",
		Port:           22,
		UnmanagedHosts: []string{"short", "short.corp.example.com"},
	}
	canonCandidateRoot := ExcludeTargetInfo{
		NodeID:         config.OpenSSHNodePrefix + "root@short.corp.example.com:22",
		BaseNodeID:     config.OpenSSHNodePrefix + "short.corp.example.com",
		OpenSSHAlias:   "short",
		CanonicalHost:  "short.corp.example.com",
		User:           "root",
		Port:           22,
		UnmanagedHosts: []string{"short", "short.corp.example.com"},
	}
	canonCandidatePort2222 := ExcludeTargetInfo{
		NodeID:         config.OpenSSHNodePrefix + "ops@short.corp.example.com:2222",
		BaseNodeID:     config.OpenSSHNodePrefix + "short.corp.example.com",
		OpenSSHAlias:   "short",
		CanonicalHost:  "short.corp.example.com",
		User:           "ops",
		Port:           2222,
		UnmanagedHosts: []string{"short", "short.corp.example.com"},
	}
	sharedACandidate := ExcludeTargetInfo{
		NodeID:         config.OpenSSHNodePrefix + "shared-a",
		MatchedNodeID:  config.OpenSSHNodePrefix + "shared-a",
		BaseNodeID:     config.OpenSSHNodePrefix + "shared-a",
		OpenSSHAlias:   "shared-a",
		User:           "ops",
		Port:           22,
		UnmanagedHosts: []string{"shared-a", "10.200.0.99"},
	}
	sharedBCandidate := ExcludeTargetInfo{
		NodeID:         config.OpenSSHNodePrefix + "shared-b",
		MatchedNodeID:  config.OpenSSHNodePrefix + "shared-b",
		BaseNodeID:     config.OpenSSHNodePrefix + "shared-b",
		OpenSSHAlias:   "shared-b",
		User:           "ops",
		Port:           22,
		UnmanagedHosts: []string{"shared-b", "10.200.0.99"},
	}
	directFQDNCandidate := ExcludeTargetInfo{
		NodeID:         config.OpenSSHNodePrefix + "direct.corp.example.com",
		MatchedNodeID:  config.OpenSSHNodePrefix + "direct.corp.example.com",
		BaseNodeID:     config.OpenSSHNodePrefix + "direct.corp.example.com",
		User:           "ops",
		Port:           22,
		UnmanagedHosts: []string{"direct.corp.example.com"},
	}

	cands := []ExcludeTargetInfo{
		canonCandidateOps,
		canonCandidateRoot,
		canonCandidatePort2222,
		sharedACandidate,
		sharedBCandidate,
		directFQDNCandidate,
	}

	// 1. Canonicalized target (short -> short.corp.example.com) excluded by FQDN user@canon:port.
	exByFQDN, err := ResolveExcludesForTargets(prov, []string{"ops@short.corp.example.com:22"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(ops@short.corp.example.com:22) error = %v", err)
	}
	if !IsTargetExcluded(exByFQDN, canonCandidateOps) {
		t.Fatal("expected ops@short.corp.example.com:22 exclude to match canonicalized ops@short:22")
	}
	if IsTargetExcluded(exByFQDN, canonCandidateRoot) || IsTargetExcluded(exByFQDN, canonCandidatePort2222) {
		t.Fatal("composite :22 exclude leaked to different user or port 2222")
	}

	// 2. Canonicalized target excluded by alias ops@short:22, and direct FQDN excluded by ops@direct via CanonicalDomainCandidates.
	exByAliasAndDirect, err := ResolveExcludesForTargets(prov, []string{"ops@short:22", "ops@direct"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(ops@short:22, ops@direct) error = %v", err)
	}
	if !IsTargetExcluded(exByAliasAndDirect, canonCandidateOps) {
		t.Fatal("expected ops@short:22 exclude to match canonicalized candidate")
	}
	if !IsTargetExcluded(exByAliasAndDirect, directFQDNCandidate) {
		t.Fatal("expected ops@direct exclude to expand via CanonicalDomains and match direct.corp.example.com")
	}
	if IsTargetExcluded(exByAliasAndDirect, canonCandidateRoot) || IsTargetExcluded(exByAliasAndDirect, canonCandidatePort2222) {
		t.Fatal("expanded alias :22 exclude leaked to different user or port 2222")
	}

	// 2b. Port-less ops@short still excludes both ports while isolating user=root.
	exNoPort, err := ResolveExcludesForTargets(prov, []string{"ops@short"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(ops@short) error = %v", err)
	}
	if !IsTargetExcluded(exNoPort, canonCandidateOps) || !IsTargetExcluded(exNoPort, canonCandidatePort2222) {
		t.Fatal("expected port-less ops@short exclude to match ops on both ports")
	}
	if IsTargetExcluded(exNoPort, canonCandidateRoot) {
		t.Fatal("ops@short leaked to root user")
	}

	// 3. Shared-IP isolation: --exclude ops@shared-a excludes shared-a ONLY, never shared-b (10.200.0.99).
	exSharedA, err := ResolveExcludesForTargets(prov, []string{"ops@shared-a"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(ops@shared-a) error = %v", err)
	}
	if !IsTargetExcluded(exSharedA, sharedACandidate) {
		t.Fatal("expected ops@shared-a exclude to match shared-a")
	}
	if IsTargetExcluded(exSharedA, sharedBCandidate) {
		t.Fatal("ops@shared-a exclude leaked via shared IP 10.200.0.99 onto shared-b")
	}

	// 4. Typo under wildcard Host * + CanonicalDomains must still fail closed.
	if _, err := ResolveExcludesForTargets(prov, []string{"typo-host"}, cands); err == nil || !strings.Contains(err.Error(), "no matching node") {
		t.Fatalf("expected typo-host to fail closed even with Host * CanonicalDomains, got err=%v", err)
	}
}
