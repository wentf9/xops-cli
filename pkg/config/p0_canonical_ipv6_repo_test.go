package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP0_CanonicalizeCNAMEInjectionRejectedAndValidAccepted(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host *.b.example.com
    ConnectTimeout 11

Host *
    CanonicalizeHostname yes
    CanonicalDomains a.example.com
    CanonicalizeMaxDots 1
    CanonicalizePermittedCNAMEs *:*
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	provider := NewProviderWithOpenSSHParser(nil, parser)

	hostileCNAMEs := []string{
		"root@app.b.example.com.",
		"app.b.example.com:2222.",
		"openssh:app.b.example.com.",
		"evil/path.b.example.com.",
		`evil\path.b.example.com.`,
		"app.b.example.com\n",
		"app\x00.b.example.com.",
		"app\u2028.b.example.com.",
		"app\u2029.b.example.com.",
		"app bad.b.example.com.",
		" app.b.example.com.",
		"127.0.0.1.",
		"10.0.0.1.",
		"::1",
		"localhost.",
		"LOCALHOST.",
		"-leading.b.example.com.",
		"trailing-.b.example.com.",
		"double..dot.b.example.com.",
		"doubletrailing.b.example.com..",
		"under_score.b.example.com.",
		strings.Repeat("a", 64) + ".b.example.com.",
		strings.Repeat("a.", 127) + "example.com.",
	}

	for _, bad := range hostileCNAMEs {
		res := &fakeCanonicalResolver{
			hosts:  map[string][]string{"web.a.example.com": {"10.10.0.1"}},
			cnames: map[string]string{"web.a.example.com": bad},
		}
		out, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: provider,
			Host:     "web",
			Resolver: res,
		})
		if err != nil {
			t.Fatalf("CNAME %q returned unexpected error: %v", bad, err)
		}
		if out.CanonicalHost != "web.a.example.com" {
			t.Fatalf("hostile CNAME %q was adopted as CanonicalHost=%q, want web.a.example.com", bad, out.CanonicalHost)
		}
	}

	// Valid RFC 1123 CNAME (mixed case) is normalized and accepted.
	resOK := &fakeCanonicalResolver{
		hosts:  map[string][]string{"web.a.example.com": {"10.10.0.1"}},
		cnames: map[string]string{"web.a.example.com": "App-01.B.Example.Com."},
	}
	outOK, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
		Provider: provider,
		Host:     "web",
		Resolver: resOK,
	})
	if err != nil {
		t.Fatalf("valid CNAME error: %v", err)
	}
	if !outOK.Canonicalized || outOK.CanonicalHost != "app-01.b.example.com" {
		t.Fatalf("valid CNAME result = %+v, want CanonicalHost=app-01.b.example.com", outOK)
	}
	if outOK.Pass2Options == nil || outOK.Pass2Options.Get(ssh.OptionConnectTimeout) != "11" {
		t.Fatalf("expected Pass2Options ConnectTimeout=11, got %+v", outOK.Pass2Options)
	}
}

func TestP0_CanonicalizeMaxDotsAndTrailingDotPermittedCNAMEs(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host *.b.example.com
    ConnectTimeout 13

Host *.internal.corp
    ConnectTimeout 17

Host *
    CanonicalizeHostname yes
    CanonicalDomains corp.example.com
    CanonicalizeMaxDots 1
    CanonicalizeFallbackLocal no
    CanonicalizePermittedCNAMEs *.a.example.com:*.b.example.com *.corp:*.internal.corp
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	provider := NewProviderWithOpenSSHParser(nil, parser)

	t.Run("FQDN exceeding CanonicalizeMaxDots skips domain suffixes but follows permitted CNAME", func(t *testing.T) {
		if cands := CanonicalDomainCandidates(provider, "app.a.example.com"); len(cands) != 0 {
			t.Fatalf("CanonicalDomainCandidates(app.a.example.com) = %v, want nil", cands)
		}
		res := &fakeCanonicalResolver{
			hosts: map[string][]string{
				"app.a.example.com":                  {"10.20.0.1"},
				"app.a.example.com.corp.example.com": {"10.99.99.99"},
			},
			cnames: map[string]string{
				"app.a.example.com": "app.b.example.com.",
			},
		}
		out, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: provider,
			Host:     "app.a.example.com",
			Resolver: res,
		})
		if err != nil {
			t.Fatalf("CanonicalizeHost(app.a.example.com) error = %v", err)
		}
		if !out.Canonicalized || out.CanonicalHost != "app.b.example.com" {
			t.Fatalf("CanonicalizeHost(app.a.example.com) = %+v, want app.b.example.com", out)
		}
		if slices.Contains(res.queried, "app.a.example.com.corp.example.com") {
			t.Fatalf("CanonicalDomains suffix was probed despite exceeding CanonicalizeMaxDots: queried=%v", res.queried)
		}
		if out.Pass2Options == nil || out.Pass2Options.Get(ssh.OptionConnectTimeout) != "13" {
			t.Fatalf("expected Pass2Options ConnectTimeout=13, got %+v", out.Pass2Options)
		}
	})

	t.Run("trailing-dot FQDN skips domain suffixes and follows permitted CNAME", func(t *testing.T) {
		if cands := CanonicalDomainCandidates(provider, "web.corp."); len(cands) != 0 {
			t.Fatalf("CanonicalDomainCandidates(web.corp.) = %v, want nil", cands)
		}
		res := &fakeCanonicalResolver{
			hosts: map[string][]string{
				"web.corp.": {"10.20.0.2"},
			},
			cnames: map[string]string{
				"web.corp.": "web.internal.corp.",
			},
		}
		out, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: provider,
			Host:     "web.corp.",
			Resolver: res,
		})
		if err != nil {
			t.Fatalf("CanonicalizeHost(web.corp.) error = %v", err)
		}
		if !out.Canonicalized || out.CanonicalHost != "web.internal.corp" {
			t.Fatalf("CanonicalizeHost(web.corp.) = %+v, want web.internal.corp", out)
		}
		for _, q := range res.queried {
			if strings.Contains(q, "..") || strings.HasSuffix(q, ".corp.example.com") {
				t.Fatalf("unexpected domain suffix query for trailing-dot host: %v", res.queried)
			}
		}
		if out.Pass2Options == nil || out.Pass2Options.Get(ssh.OptionConnectTimeout) != "17" {
			t.Fatalf("expected Pass2Options ConnectTimeout=17, got %+v", out.Pass2Options)
		}
	})
}

func TestP0_IPv6OpenSSHConfigMatchingAndTargetRefHardening(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host 2001:db8::1
    User ipv6ops
    Port 2222
    ConnectTimeout 8

Host fe80::1%eth0
    User linkops
    Port 2202
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	store := NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "config.key"))
	repo, err := NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	t.Run("ipv6 selectors", func(t *testing.T) {
		assertP0IPv6OpenSSHMatching(t, parser, repo)
	})
	t.Run("target ref and virtual node hardening", func(t *testing.T) {
		assertP0TargetRefAndVirtualNodeHardening(t, parser)
	})
}

func assertP0IPv6OpenSSHMatching(t *testing.T, parser *OpenSSHParser, repo *Repository) {
	t.Helper()

	for _, tc := range []struct {
		in     string
		wantID string
		wantOK bool
	}{
		{in: "2001:db8::1", wantID: "openssh:2001:db8::1", wantOK: true},
		{in: "[2001:db8::1]", wantID: "openssh:2001:db8::1", wantOK: true},
		{in: "fe80::1%eth0", wantID: "openssh:fe80::1%eth0", wantOK: true},
		{in: "[fe80::1%eth0]", wantID: "openssh:fe80::1%eth0", wantOK: true},
		{in: "[2001:db8::1]:2222", wantOK: false},
		{in: "ipv6ops@2001:db8::1", wantOK: false},
		{in: "ipv6ops@[2001:db8::1]", wantOK: false},
		{in: "web:22", wantOK: false},
		{in: "openssh:web", wantOK: false},
	} {
		gotID, gotOK := parser.Find(tc.in)
		if gotOK != tc.wantOK || gotID != tc.wantID {
			t.Errorf("parser.Find(%q) = (%q, %v), want (%q, %v)", tc.in, gotID, gotOK, tc.wantID, tc.wantOK)
		}
	}

	for _, sel := range []string{"2001:db8::1", "[2001:db8::1]"} {
		res, err := repo.ResolveTarget(ConnectionTarget{Selector: sel})
		if err != nil {
			t.Fatalf("ResolveTarget(%q): %v", sel, err)
		}
		if res.MatchedNodeID != "openssh:2001:db8::1" || res.User != "ipv6ops" || res.Port != 2222 {
			t.Fatalf("ResolveTarget(%q) = %+v, want openssh:2001:db8::1 ipv6ops:2222", sel, res)
		}
	}

	resMatch, err := repo.ResolveTarget(ConnectionTarget{
		Selector: "2001:db8::1",
		User:     "ipv6ops",
		HasUser:  true,
		Port:     2222,
		HasPort:  true,
	})
	if err != nil || resMatch.MatchedNodeID != "openssh:2001:db8::1" || resMatch.Provenance != ProvenanceOpenSSHVirtual {
		t.Fatalf("ResolveTarget(explicit matching IPv6) = (%+v, %v), want openssh:2001:db8::1 virtual", resMatch, err)
	}

	resDerived, err := repo.ResolveTarget(ConnectionTarget{
		Selector: "[2001:db8::1]",
		User:     "altuser",
		HasUser:  true,
	})
	if err != nil || resDerived.Port != 2222 || resDerived.OpenSSHAlias != "2001:db8::1" || resDerived.Provenance != ProvenanceOpenSSHDerived {
		t.Fatalf("ResolveTarget(explicit override IPv6) = (%+v, %v), want Port=2222 OpenSSHAlias=2001:db8::1 derived", resDerived, err)
	}

	resZoned, err := repo.ResolveTarget(ConnectionTarget{Selector: "fe80::1%eth0"})
	if err != nil || resZoned.MatchedNodeID != "openssh:fe80::1%eth0" || resZoned.User != "linkops" || resZoned.Port != 2202 {
		t.Fatalf("ResolveTarget(fe80::1%%eth0) = (%+v, %v)", resZoned, err)
	}
}

func assertP0TargetRefAndVirtualNodeHardening(t *testing.T, parser *OpenSSHParser) {
	t.Helper()

	badInputs := []string{
		"web\n",
		"\rweb",
		"web\t",
		"Prod\tWeb",
		"web\x00",
		"web\u00a001",
		"web\u2028",
		"web\u2029",
		"foo bar:22",
		"bad user@10.0.0.1",
		"alice @web",
		"alice@ web",
		"web :22",
		"web: 22",
		"openssh :22",
		"openssh: web",
		"openssh:web 01",
		"[::1] :22",
		"[ ::1 ]:22",
		"alice\n@web:22",
		"alice@web:22\u2028",
	}
	for _, raw := range badInputs {
		if _, err := ParseTargetRef(raw); err == nil {
			t.Errorf("ParseTargetRef(%q) succeeded, want error", raw)
		}
		if _, _, _, err := ParseHostPort(raw); err == nil {
			t.Errorf("ParseHostPort(%q) succeeded, want error", raw)
		}
	}

	// Bare saved-node aliases containing ASCII spaces (e.g. "Prod Web 01") are accepted by
	// ParseTargetRef while still rejected by ParseHostPort and ValidateConcreteHostAddress.
	aliasRef, err := ParseTargetRef("Prod Web 01")
	if err != nil || aliasRef != (TargetRef{Host: "Prod Web 01"}) || aliasRef.NormalizedString() != "Prod Web 01" {
		t.Fatalf("ParseTargetRef(\"Prod Web 01\") = (%+v, %v), want bare alias", aliasRef, err)
	}
	if _, _, _, err := ParseHostPort("Prod Web 01"); err == nil {
		t.Error("ParseHostPort(\"Prod Web 01\") succeeded, want whitespace error")
	}
	if _, _, _, err := ParseHostPort("web 01"); err == nil {
		t.Error("ParseHostPort(\"web 01\") succeeded, want whitespace error")
	}
	if err := ValidateConcreteHostAddress("Prod Web 01"); err == nil {
		t.Error("ValidateConcreteHostAddress(\"Prod Web 01\") succeeded, want whitespace error")
	}

	ambig := TargetRef{OpenSSH: false, Host: "openssh", Port: 22, HasPort: true}
	norm := ambig.NormalizedString()
	if IsOpenSSHNodeID(norm) {
		t.Fatalf("TargetRef{OpenSSH:false, Host:openssh, Port:22}.NormalizedString() = %q must not have openssh: prefix", norm)
	}
	if reparsed, err := ParseTargetRef(norm); err == nil && reparsed.OpenSSH {
		t.Fatalf("NormalizedString() = %q was misparsed as OpenSSH: %+v", norm, reparsed)
	}

	if _, _, _, err := parser.GetVirtualNodeWithCanonical("web\n", ""); err == nil {
		t.Error("GetVirtualNodeWithCanonical accepted newline in originalAlias")
	}
	if _, _, _, err := parser.GetVirtualNodeWithCanonical("ali ce@web", ""); err == nil {
		t.Error("GetVirtualNodeWithCanonical accepted internal whitespace in user")
	}
	if _, _, _, err := parser.GetVirtualNodeWithCanonical("web", "canon\u2028.example.com"); err == nil {
		t.Error("GetVirtualNodeWithCanonical accepted U+2028 in canonicalHost")
	}
	if _, _, _, err := parser.GetVirtualNodeWithCanonical("web", "canon host"); err == nil {
		t.Error("GetVirtualNodeWithCanonical accepted internal whitespace in canonicalHost")
	}
	if _, _, _, err := parser.getVirtualNodeWithCanonical("web", "", "root\u2029", 0, "web"); err == nil {
		t.Error("getVirtualNodeWithCanonical accepted U+2029 in userOverride")
	}
	if _, _, _, err := parser.getVirtualNodeWithCanonical("web", "", "bad user", 0, "web"); err == nil {
		t.Error("getVirtualNodeWithCanonical accepted internal whitespace in userOverride")
	}
}

func TestP0_RepositoryImportSafetyCloneAndPendingSymmetry(t *testing.T) {
	t.Parallel()

	t.Run("re-import after rename disambiguates host/identity refs and checks Host.Alias", testP0RepoReimportAfterRename)
	t.Run("normalizeImportedSSHOptions deletes invalid ControlPath and ControlMaster=no imports cleanly with global ControlPersist", testP0RepoImportControlSanitization)
	t.Run("identity and host writes clone caller-owned pointers and slices", testP0RepoCloneIsolation)
	t.Run("Set/Clear OpenSSHOrigin updates active pending provider and ConfirmNodeContext cleans disambiguated openssh pending entry", testP0RepoPendingOriginSymmetryAndCleanup)
}

func testP0RepoReimportAfterRename(t *testing.T) {
	store := NewDefaultStore(filepath.Join(t.TempDir(), "cfg.yaml"), filepath.Join(t.TempDir(), "cfg.key"))
	repo, err := NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatal(err)
	}

	res1, err := repo.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{{
		Name:     "web",
		Host:     models.Host{Address: "10.0.0.1", Port: 22, Alias: []string{"h-alias-1"}},
		Identity: models.Identity{User: "orig-user", AuthType: "auto", KeyPath: "/keys/orig"},
		Node:     models.Node{Alias: []string{"web"}, Tags: []string{"openssh"}},
	}})
	if err != nil || res1.Imported != 1 {
		t.Fatalf("initial import = (%+v, %v)", res1, err)
	}

	view := repo.View()
	ref := view.NodeRefs["web"]
	n, _ := view.Configuration.Nodes.Get("web")
	h, _ := view.Configuration.Hosts.Get(n.HostRef)
	id, _ := view.Configuration.Identities.Get(n.IdentityRef)
	n.Alias = []string{"prod-web"}
	if err := repo.ReplaceNodeAtRefContext(t.Context(), ref, "prod-web", n, h, id); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext rename: %v", err)
	}

	res2, err := repo.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{
		{
			Name:     "web",
			Host:     models.Host{Address: "10.0.0.99", Port: 2222, Alias: []string{"batch-dup"}},
			Identity: models.Identity{User: "new-user", AuthType: "auto", KeyPath: "/keys/new"},
			Node:     models.Node{Alias: []string{"web"}, Tags: []string{"openssh"}},
		},
		{
			Name:     "conflict-existing-host-alias",
			Host:     models.Host{Address: "10.0.0.2", Port: 22, Alias: []string{"h-alias-1"}},
			Identity: models.Identity{User: "u2", AuthType: "auto"},
			Node:     models.Node{Alias: []string{"c1"}},
		},
		{
			Name:     "conflict-batch-host-alias",
			Host:     models.Host{Address: "10.0.0.3", Port: 22, Alias: []string{"batch-dup"}},
			Identity: models.Identity{User: "u3", AuthType: "auto"},
			Node:     models.Node{Alias: []string{"c2"}},
		},
	})
	if err != nil || res2.Imported != 1 || res2.Skipped != 2 || len(res2.Issues) != 2 {
		t.Fatalf("re-import = (%+v, %v), want Imported=1 Skipped=2 Issues=2", res2, err)
	}

	_, prodHost, prodIdent, err := repo.Resolve("prod-web")
	if err != nil || prodHost.Address != "10.0.0.1" || prodHost.Port != 22 || prodIdent.User != "orig-user" || prodIdent.KeyPath != "/keys/orig" {
		t.Fatalf("prod-web was corrupted by re-import: host=%+v ident=%+v err=%v", prodHost, prodIdent, err)
	}

	webNode, webHost, webIdent, err := repo.Resolve("web")
	if err != nil {
		t.Fatalf("Resolve(web): %v", err)
	}
	if webNode.HostRef == "openssh-host:web" || webNode.IdentityRef == "openssh-identity:web" {
		t.Fatalf("re-imported web reused existing refs: %+v", webNode)
	}
	if webHost.Address != "10.0.0.99" || webHost.Port != 2222 || webIdent.User != "new-user" {
		t.Fatalf("re-imported web mismatch: host=%+v ident=%+v", webHost, webIdent)
	}
}

func testP0RepoImportControlSanitization(t *testing.T) {
	badCtrlOpts := ssh.OptionsFromControl(&ssh.ControlConfig{
		Master:  ssh.ControlMasterAuto,
		Path:    "/tmp/bad-%z",
		Persist: "5m",
	})
	norm := normalizeImportedSSHOptions(badCtrlOpts)
	if norm != nil && (norm.ControlPath() != "" || norm.ControlMaster() != "" || norm.ControlPersist() != "") {
		t.Fatalf("normalizeImportedSSHOptions retained invalid ControlPath/Master/Persist: %+v", norm)
	}

	globalOpts := ssh.MustOptions(
		ssh.OptionControlMaster, "auto",
		ssh.OptionControlPath, "~/.ssh/global-%C",
		ssh.OptionControlPersist, "10m",
	)
	baseCfg := NewProviderWithoutOpenSSH(nil).Snapshot()
	baseCfg.SSHOptions = globalOpts
	store := NewDefaultStore(filepath.Join(t.TempDir(), "cfg.yaml"), filepath.Join(t.TempDir(), "cfg.key"))
	if err := store.Save(baseCfg); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	repo, err := NewRepositoryWithoutOpenSSH(baseCfg, store)
	if err != nil {
		t.Fatal(err)
	}

	nodeNoMasterOpts := ssh.MustOptions(
		ssh.OptionControlMaster, "no",
		ssh.OptionControlPath, "~/.ssh/node-%C",
	)
	res, err := repo.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{{
		Name:     "nomaster",
		Host:     models.Host{Address: "10.1.0.1", Port: 22},
		Identity: models.Identity{User: "ops", AuthType: "auto"},
		Node:     models.Node{Alias: []string{"nomaster"}, SSHOptions: nodeNoMasterOpts},
	}})
	if err != nil || res.Imported != 1 {
		t.Fatalf("ImportOpenSSHHostsContext(control_master:no + global control_persist) = (%+v, %v)", res, err)
	}
	snap := repo.Snapshot()
	if snap.SSHOptions == nil || snap.SSHOptions.ControlPersist() != "10m" {
		t.Fatalf("expected global ControlPersist=10m preserved, got %+v", snap.SSHOptions)
	}
	importedNode, ok := snap.Nodes.Get("nomaster")
	if !ok || importedNode.SSHOptions == nil || importedNode.SSHOptions.ControlMaster() != ssh.ControlMasterNo || importedNode.SSHOptions.ControlPersist() != "no" {
		t.Fatalf("expected sanitized ControlMaster=no ControlPersist=no on imported node, got %+v", importedNode.SSHOptions)
	}
	if _, err := snap.ToV2(); err != nil {
		t.Fatalf("ToV2 validation failed after import: %v", err)
	}
}

func testP0RepoCloneIsolation(t *testing.T) {
	store := NewDefaultStore(filepath.Join(t.TempDir(), "cfg.yaml"), filepath.Join(t.TempDir(), "cfg.key"))
	baseCfg := NewProviderWithoutOpenSSH(nil).Snapshot()
	baseCfg.Credential = &CredentialConfig{
		DefaultStore: "s1",
		Stores:       map[string]StoreConfig{"s1": {Type: StoreTypeNone}},
	}
	if err := store.Save(baseCfg); err != nil {
		t.Fatalf("seed credential store config: %v", err)
	}
	repo, err := NewRepositoryWithoutOpenSSH(baseCfg, store)
	if err != nil {
		t.Fatal(err)
	}

	makeIdent := func(itemID string) models.Identity {
		return models.Identity{
			User:             "ops",
			AuthType:         "password",
			LoginPasswordRef: &credential.Ref{StoreID: "s1", ItemID: itemID},
			OTP:              &models.OTPConfig{Command: "oathtool", Args: []string{"--totp", "orig"}},
		}
	}

	id1 := makeIdent("item1")
	if _, err := repo.CreateIdentityContext(t.Context(), "id1", id1); err != nil {
		t.Fatalf("CreateIdentityContext: %v", err)
	}
	id1.LoginPasswordRef.ItemID = "mutated"
	id1.OTP.Args[1] = "mutated"
	got1, _ := repo.Snapshot().Identities.Get("id1")
	if got1.LoginPasswordRef.ItemID != "item1" || got1.OTP.Args[1] != "orig" {
		t.Fatalf("CreateIdentityContext aliased caller pointers: %+v", got1)
	}

	id2 := makeIdent("item2")
	if _, err := repo.ReplaceIdentityAtRefContext(t.Context(), repo.View().IdentityRefs["id1"], id2); err != nil {
		t.Fatalf("ReplaceIdentityAtRefContext: %v", err)
	}
	id2.LoginPasswordRef.ItemID = "mutated"
	id2.OTP.Args[1] = "mutated"
	got2, _ := repo.Snapshot().Identities.Get("id1")
	if got2.LoginPasswordRef.ItemID != "item2" || got2.OTP.Args[1] != "orig" {
		t.Fatalf("ReplaceIdentityAtRefContext aliased caller pointers: %+v", got2)
	}

	assertP0NodeAndImportCloneIsolation(t, repo, makeIdent)
}

func assertP0NodeAndImportCloneIsolation(t *testing.T, repo *Repository, makeIdent func(string) models.Identity) {
	t.Helper()

	id3 := makeIdent("item3")
	if _, err := repo.CreateNodeContext(t.Context(), "n1",
		models.Node{HostRef: "h1", IdentityRef: "id3"},
		models.Host{Address: "10.2.0.1", Port: 22},
		id3,
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}
	id3.LoginPasswordRef.ItemID = "mutated"
	if got3, _ := repo.GetIdentity("n1"); got3.LoginPasswordRef.ItemID != "item3" {
		t.Fatalf("CreateNodeContext aliased caller identity: %+v", got3)
	}

	id4 := makeIdent("item4")
	if err := repo.ReplaceNodeAtRefContext(t.Context(), repo.View().NodeRefs["n1"], "n1",
		models.Node{HostRef: "h1", IdentityRef: "id3"},
		models.Host{Address: "10.2.0.1", Port: 22},
		id4,
	); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext: %v", err)
	}
	id4.LoginPasswordRef.ItemID = "mutated"
	if got4, _ := repo.GetIdentity("n1"); got4.LoginPasswordRef.ItemID != "item4" {
		t.Fatalf("ReplaceNodeAtRefContext aliased caller identity: %+v", got4)
	}

	id5 := makeIdent("item5")
	if _, err := repo.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{{
		Name:     "imp1",
		Host:     models.Host{Address: "10.2.0.2", Port: 22},
		Identity: id5,
		Node:     models.Node{Alias: []string{"imp1"}},
	}}); err != nil {
		t.Fatalf("ImportOpenSSHHostsContext: %v", err)
	}
	id5.LoginPasswordRef.ItemID = "mutated"
	if got5, _ := repo.GetIdentity("imp1"); got5.LoginPasswordRef.ItemID != "item5" {
		t.Fatalf("ImportOpenSSHHostsContext aliased caller identity: %+v", got5)
	}

	cfg := NewProviderWithoutOpenSSH(nil).Snapshot()
	h6 := models.Host{Address: "10.2.0.6", Port: 22, Alias: []string{"h6-orig"}}
	id6 := makeIdent("item6")
	if err := mergeConfirmedNodeConfig(cfg, "n6", models.Node{HostRef: "h6", IdentityRef: "id6"}, h6, id6); err != nil {
		t.Fatalf("mergeConfirmedNodeConfig: %v", err)
	}
	h6.Alias[0] = "mutated"
	id6.LoginPasswordRef.ItemID = "mutated"
	gotH6, _ := cfg.Hosts.Get("h6")
	gotID6, _ := cfg.Identities.Get("id6")
	if gotH6.Alias[0] != "h6-orig" || gotID6.LoginPasswordRef.ItemID != "item6" {
		t.Fatalf("mergeConfirmedNodeConfig aliased caller host/identity: host=%+v ident=%+v", gotH6, gotID6)
	}
}

func testP0RepoPendingOriginSymmetryAndCleanup(t *testing.T) {
	const sshCfg = `
Host role-a
    HostName 10.50.0.1
    User reader

Host role-b
    HostName 10.50.0.1
    User writer
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatal(err)
	}
	store := NewDefaultStore(filepath.Join(t.TempDir(), "cfg.yaml"), filepath.Join(t.TempDir(), "cfg.key"))
	repo, err := NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatal(err)
	}

	prepA, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "role-a", User: "ops", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(role-a): %v", err)
	}
	prepB, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "role-b", User: "ops", HasUser: true},
	})
	if err != nil || !IsOpenSSHNodeID(prepB.NodeID) {
		t.Fatalf("PrepareNodeContext(role-b) = (%+v, %v), want disambiguated openssh: ID", prepB, err)
	}

	repo.SetNodeOpenSSHOrigin(prepA.NodeID, OpenSSHOrigin{Alias: "custom-a", CanonicalHost: "a.corp.example.com"})
	if got := repo.NodeOpenSSHOrigin(prepA.NodeID); got != (OpenSSHOrigin{Alias: "custom-a", CanonicalHost: "a.corp.example.com"}) {
		t.Fatalf("NodeOpenSSHOrigin after Set = %+v", got)
	}
	repo.SetNodeCanonicalHost(prepA.NodeID, "a2.corp.example.com")
	if got := repo.NodeCanonicalHost(prepA.NodeID); got != "a2.corp.example.com" {
		t.Fatalf("NodeCanonicalHost after Set = %q", got)
	}
	repo.SetNodeOpenSSHAlias(prepA.NodeID, "alias-a2")
	if got := repo.NodeOpenSSHAlias(prepA.NodeID); got != "alias-a2" {
		t.Fatalf("NodeOpenSSHAlias after Set = %q", got)
	}
	repo.ClearNodeOpenSSHOrigin(prepA.NodeID)
	if got := repo.NodeOpenSSHOrigin(prepA.NodeID); !got.IsZero() {
		t.Fatalf("NodeOpenSSHOrigin after Clear = %+v, want zero", got)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 20 {
			repo.SetNodeOpenSSHOrigin(prepA.NodeID, OpenSSHOrigin{Alias: "race-a", CanonicalHost: "race.corp"})
			_ = repo.NodeOpenSSHOrigin(prepA.NodeID)
			_, _ = repo.ResolveConnection(prepA.NodeID)
		}
	}()
	go func() {
		defer wg.Done()
		for range 20 {
			repo.SetNodeOpenSSHOrigin(prepB.NodeID, OpenSSHOrigin{Alias: "race-b", CanonicalHost: "race-b.corp"})
			_ = repo.NodeOpenSSHOrigin(prepB.NodeID)
		}
	}()
	wg.Wait()

	if err := repo.ConfirmNodeContext(t.Context(), prepB.NodeID); err != nil {
		t.Fatalf("ConfirmNodeContext(prepB): %v", err)
	}
	repo.pendingMu.RLock()
	_, stillPendingB := repo.pending[prepB.NodeID]
	repo.pendingMu.RUnlock()
	if stillPendingB {
		t.Fatalf("disambiguated pending entry %q leaked in r.pending after ConfirmNodeContext", prepB.NodeID)
	}

	if err := repo.ConfirmNodeContext(t.Context(), prepA.NodeID); err != nil {
		t.Fatalf("ConfirmNodeContext(prepA): %v", err)
	}
	repo.pendingMu.RLock()
	remaining := len(repo.pending)
	repo.pendingMu.RUnlock()
	if remaining != 0 {
		t.Fatalf("expected 0 remaining pending entries, got %d", remaining)
	}
}

func TestP0_AllowListOnEmptyRejectFailClosed(t *testing.T) {
	t.Parallel()

	rejectCases := []struct {
		name string
		line string
		want string
	}{
		{name: "Ciphers", line: "Ciphers unsupported-cipher@example.com", want: "no supported Ciphers"},
		{name: "MACs", line: "MACs unsupported-mac@example.com", want: "no supported MACs"},
		{name: "KexAlgorithms", line: "KexAlgorithms sntrup761x25519-sha512@openssh.com", want: "no supported KexAlgorithms"},
		{name: "HostKeyAlgorithms", line: "HostKeyAlgorithms unsupported-key@example.com", want: "no supported HostKeyAlgorithms"},
		{name: "PreferredAuthentications bogus", line: "PreferredAuthentications totally-unknown-auth", want: "no supported PreferredAuthentications"},
	}

	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			cfgText := "Host target\n  HostName 10.0.0.1\n  " + tc.line + "\n"
			parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfgText))
			if err != nil {
				t.Fatalf("NewOpenSSHParserFromReader: %v", err)
			}
			_, err = parser.GetSSHOptions("target")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("GetSSHOptions() err = %v, want substring %q", err, tc.want)
			}
		})
	}

	t.Run("PreferredAuthentications gssapi-with-mic and hostbased retained fail-closed", func(t *testing.T) {
		cfgText := "Host krb\n  HostName 10.0.0.2\n  PreferredAuthentications gssapi-with-mic,hostbased\n"
		parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfgText))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		opts, err := parser.GetSSHOptions("krb")
		if err != nil {
			t.Fatalf("GetSSHOptions(krb) unexpected error: %v", err)
		}
		if got := opts.Get(ssh.OptionPreferredAuthentications); got != "gssapi-with-mic,hostbased" {
			t.Fatalf("PreferredAuthentications = %q, want gssapi-with-mic,hostbased", got)
		}
	})

	t.Run("modifiers +/^ with unsupported algorithms remain lenient no-op", func(t *testing.T) {
		cfgText := strings.Join([]string{
			"Host modhost",
			"  HostName 10.0.0.3",
			"  KexAlgorithms +sntrup761x25519-sha512@openssh.com",
			"  Ciphers ^unsupported-cipher@example.com",
			"  MACs -unsupported-mac@example.com",
		}, "\n") + "\n"
		parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfgText))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		opts, err := parser.GetSSHOptions("modhost")
		if err != nil {
			t.Fatalf("GetSSHOptions(modhost) unexpected error: %v", err)
		}
		if opts != nil && (opts.KexAlgorithms() != "" || opts.Ciphers() != "") {
			t.Fatalf("expected unsupported +/^ modifiers to keep defaults unset, got %+v", opts)
		}
	})
}

func TestP0_IncludeNonRegularFileAndDAGBudgetBounds(t *testing.T) {
	t.Run("exponential Include DAG hits maxIncludeFileLoads budget without hanging", testP0IncludeExponentialDAG)
	t.Run("non-regular included files (FIFO and char device) fail closed without blocking", testP0IncludeNonRegularFiles)
}

func testP0IncludeExponentialDAG(t *testing.T) {
	dir := t.TempDir()
	const levels = 10
	for lvl := levels; lvl >= 1; lvl-- {
		for branch := range 2 {
			content := "Host leaf\n  HostName 10.0.0.1\n"
			if lvl < levels {
				next0 := filepath.Join(dir, fmt.Sprintf("l%d_0.conf", lvl+1))
				next1 := filepath.Join(dir, fmt.Sprintf("l%d_1.conf", lvl+1))
				content = fmt.Sprintf("Include %s %s\n", next0, next1)
			}
			p := filepath.Join(dir, fmt.Sprintf("l%d_%d.conf", lvl, branch))
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := filepath.Join(dir, "config")
	rootContent := fmt.Sprintf("Include %s %s\n", filepath.Join(dir, "l1_0.conf"), filepath.Join(dir, "l1_1.conf"))
	if err := os.WriteFile(root, []byte(rootContent), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := NewOpenSSHParserFromPath(root)
	if err == nil || !strings.Contains(err.Error(), "load limit") {
		t.Fatalf("expected include load limit error on exponential DAG, got %v", err)
	}
}

func testP0IncludeNonRegularFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FIFO/char device test is Unix-only")
	}
	dir := t.TempDir()

	devCfg := filepath.Join(dir, "dev.conf")
	if err := os.WriteFile(devCfg, []byte("Include /dev/null\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOpenSSHParserFromPath(devCfg); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected non-regular file error for /dev/null Include, got %v", err)
	}

	assertP0FIFOIncludeRejectedWithoutBlocking(t, dir)
	assertP0SymlinkRegularIncludeAccepted(t, dir)
}

func assertP0FIFOIncludeRejectedWithoutBlocking(t *testing.T, dir string) {
	t.Helper()
	mkfifoPath, err := exec.LookPath("mkfifo")
	if err != nil || mkfifoPath == "" {
		return
	}
	fifoPath := filepath.Join(dir, "hang.fifo")
	if out, mkErr := exec.CommandContext(t.Context(), mkfifoPath, fifoPath).CombinedOutput(); mkErr != nil {
		t.Fatalf("mkfifo failed: %v (%s)", mkErr, string(out))
	}
	fifoCfg := filepath.Join(dir, "fifo.conf")
	if err := os.WriteFile(fifoCfg, []byte("Include "+fifoPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, parseErr := NewOpenSSHParserFromPath(fifoCfg)
		done <- parseErr
	}()
	select {
	case parseErr := <-done:
		if parseErr == nil || !strings.Contains(parseErr.Error(), "not a regular file") {
			t.Fatalf("expected non-regular file error for FIFO Include, got %v", parseErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("NewOpenSSHParserFromPath blocked on FIFO Include instead of rejecting non-regular file")
	}
}

func assertP0SymlinkRegularIncludeAccepted(t *testing.T, dir string) {
	t.Helper()
	targetFile := filepath.Join(dir, "real.conf")
	if err := os.WriteFile(targetFile, []byte("Host linked\n  HostName 10.7.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkFile := filepath.Join(dir, "link.conf")
	if err := os.Symlink(targetFile, linkFile); err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(dir, "link_root.conf")
	if err := os.WriteFile(linkRoot, []byte("Include "+linkFile+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parser, err := NewOpenSSHParserFromPath(linkRoot)
	if err != nil {
		t.Fatalf("symlink to regular included file failed: %v", err)
	}
	if !parser.HasHost("linked") {
		t.Fatal("expected Host linked from symlinked regular Include file")
	}
}

func TestP0_OverrideProviderCleansDisambiguatedOpenSSHPending(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sshCfgPath := filepath.Join(dir, "ssh_config")
	const sshCfg = `
Host a1
    HostName 10.60.0.1
    User u1

Host a2
    HostName 10.60.0.1
    User u2
`
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewDefaultStore(filepath.Join(dir, "cfg.yaml"), filepath.Join(dir, "cfg.key"))
	repo, err := NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatal(err)
	}
	ov, err := WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ovProv := ov.(*openSSHOverrideProvider)
	if _, err := ovProv.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "a1", User: "ops", HasUser: true},
	}); err != nil {
		t.Fatal(err)
	}
	res2, err := ovProv.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "a2", User: "ops", HasUser: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !IsOpenSSHNodeID(res2.NodeID) {
		t.Fatalf("expected openssh: disambiguated ID, got %q", res2.NodeID)
	}
	if err := ovProv.ConfirmNodeContext(t.Context(), res2.NodeID); err != nil {
		t.Fatal(err)
	}
	ovProv.repo.pendingMu.RLock()
	_, stillPresent := ovProv.repo.pending[res2.NodeID]
	ovProv.repo.pendingMu.RUnlock()
	if stillPresent {
		t.Fatalf("override provider leaked pending entry %q", res2.NodeID)
	}
	// Verify errors.Is sanity for ErrCanonicalizeFailed.
	if !errors.Is(fmt.Errorf("%w: x", ErrCanonicalizeFailed), ErrCanonicalizeFailed) {
		t.Fatal("ErrCanonicalizeFailed wrap check failed")
	}
}
