package config

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/kevinburke/ssh_config"
	"github.com/wentf9/xops-cli/core/ssh"
)

type pass7IncludeFixture struct {
	home     string
	rootConf string
	parser   *OpenSSHParser
	provider *Provider
}

func setupPass7IncludeFixture(t *testing.T) pass7IncludeFixture {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	sshDir := filepath.Join(home, ".ssh")
	confDir := filepath.Join(sshDir, "conf.d")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", confDir, err)
	}

	const canonConf = `
Host *.corp.example.com
    ConnectTimeout 19

Host *
    CanonicalizeHostname yes
    CanonicalDomains dev.example.com corp.example.com
    CanonicalizeMaxDots 1
    CanonicalizeFallbackLocal yes
    SendEnv LANG LC_*
    SetEnv APP_ENV=included-default
`
	const hostsConf = `
Host included-app
    HostName 10.77.0.10
    User inc-user
    Port 2222
    ProxyJump inc-bastion
    ProxyCommand nc %h %p
    IdentityFile ~/.ssh/id_inc_primary
    IdentityFile ~/.ssh/id_inc_secondary
    LocalForward 18080 127.0.0.1:80
    SendEnv -LC_*
    SetEnv APP_ENV=included-prod

Host included-cmd
    HostName 10.77.0.11
    User cmd-user
    Port 2201
    ProxyCommand ssh -W %h:%p inc-bastion
    ProxyJump ignored-jump

Host inc-bastion
    HostName 10.77.0.1
    User jump-ops
    Port 22
`
	const rootConf = `
Include conf.d/*.conf

Host *
    User fallback-user
    ProxyCommand fallback-nc %h %p
    IdentityFile ~/.ssh/id_root_fallback
    SetEnv APP_ENV=root-fallback
`

	writeSSHTestFile(t, filepath.Join(confDir, "10-hosts.conf"), hostsConf)
	writeSSHTestFile(t, filepath.Join(confDir, "20-canonical.conf"), canonConf)
	rootCfgPath := filepath.Join(sshDir, "config")
	writeSSHTestFile(t, rootCfgPath, rootConf)

	parser, err := NewOpenSSHParserFromPath(rootCfgPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath() error = %v", err)
	}
	return pass7IncludeFixture{
		home:     home,
		rootConf: rootConf,
		parser:   parser,
		provider: NewProviderWithOpenSSHParser(nil, parser),
	}
}

func writeSSHTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

func TestPass7_H3_IncludeASTTraversalParity(t *testing.T) {
	fx := setupPass7IncludeFixture(t)

	t.Run("HasHost and FindConcreteHostsByAddress", func(t *testing.T) {
		assertPass7IncludedHostLookup(t, fx.parser)
	})
	t.Run("ResolveConnection options env and proxy precedence", func(t *testing.T) {
		assertPass7IncludedConnectionOptions(t, fx)
	})
	t.Run("ParseOpenSSHHosts and Gate3", func(t *testing.T) {
		assertPass7IncludedImport(t, fx.rootConf)
	})
	t.Run("CanonicalizeHost across Included directives", func(t *testing.T) {
		assertPass7IncludedCanonicalize(t, fx.provider)
	})
}

func assertPass7IncludedHostLookup(t *testing.T, parser *OpenSSHParser) {
	t.Helper()
	for _, wantTrue := range []string{"included-app", "openssh:included-app", "included-cmd", "inc-bastion"} {
		if !parser.HasHost(wantTrue) {
			t.Fatalf("HasHost(%q) = false, want true", wantTrue)
		}
	}
	if parser.HasHost("nonexistent-included") {
		t.Fatal("HasHost(nonexistent-included) = true, want false")
	}
	if got := parser.FindConcreteHostsByAddress("10.77.0.10", 2222); !slices.Equal(got, []string{"included-app"}) {
		t.Fatalf("FindConcreteHostsByAddress(10.77.0.10, 2222) = %v, want [included-app]", got)
	}
	if got := parser.FindConcreteHostsByAddress("10.77.0.10", 22); len(got) != 0 {
		t.Fatalf("FindConcreteHostsByAddress(10.77.0.10, 22) = %v, want empty", got)
	}
	if got := parser.FindConcreteHostsByAddress("10.77.0.11", 2201); !slices.Equal(got, []string{"included-cmd"}) {
		t.Fatalf("FindConcreteHostsByAddress(10.77.0.11, 2201) = %v, want [included-cmd]", got)
	}
}

func assertPass7IncludedConnectionOptions(t *testing.T, fx pass7IncludeFixture) {
	t.Helper()
	snapApp, err := fx.provider.ResolveConnection(OpenSSHNodePrefix + "included-app")
	if err != nil {
		t.Fatalf("ResolveConnection(openssh:included-app) error = %v", err)
	}
	wantKey := filepath.Join(fx.home, ".ssh", "id_inc_primary")
	if snapApp.Host.Address != "10.77.0.10" || snapApp.Host.Port != 2222 || snapApp.Identity.User != "inc-user" || snapApp.Identity.KeyPath != wantKey {
		t.Fatalf("unexpected included-app snapshot: %+v", snapApp)
	}
	if snapApp.Node.ProxyJump != OpenSSHNodePrefix+"inc-bastion" {
		t.Fatalf("included-app ProxyJump = %q, want %q", snapApp.Node.ProxyJump, OpenSSHNodePrefix+"inc-bastion")
	}
	assertPass7AppSSHOptions(t, snapApp.Node.SSHOptions)

	snapCmd, err := fx.provider.ResolveConnection(OpenSSHNodePrefix + "included-cmd")
	if err != nil {
		t.Fatalf("ResolveConnection(openssh:included-cmd) error = %v", err)
	}
	if snapCmd.Node.ProxyJump != "" {
		t.Fatalf("included-cmd ProxyJump = %q, want empty", snapCmd.Node.ProxyJump)
	}
	if snapCmd.Node.SSHOptions == nil || snapCmd.Node.SSHOptions.ActiveProxyCommand() != "ssh -W %h:%p inc-bastion" {
		t.Fatalf("included-cmd ActiveProxyCommand() = %v, want ssh -W %%h:%%p inc-bastion", snapCmd.Node.SSHOptions)
	}
}

func assertPass7AppSSHOptions(t *testing.T, opts *ssh.Options) {
	t.Helper()
	if opts == nil {
		t.Fatal("expected included-app SSHOptions to be non-nil")
	}
	if got := opts.ActiveProxyCommand(); got != "" {
		t.Fatalf("included-app ActiveProxyCommand() = %q, want empty", got)
	}
	wantIDs := []string{"~/.ssh/id_inc_primary", "~/.ssh/id_inc_secondary", "~/.ssh/id_root_fallback"}
	if got := opts.IdentityFiles(); !slices.Equal(got, wantIDs) {
		t.Fatalf("included-app IdentityFiles() = %v, want %v", got, wantIDs)
	}
	if got := opts.LocalForwards(); !slices.Equal(got, []string{"18080 127.0.0.1:80"}) {
		t.Fatalf("included-app LocalForwards() = %v, want [18080 127.0.0.1:80]", got)
	}
	envVars, err := ssh.ResolveSessionEnv(opts, func() []string {
		return []string{"LANG=en_US.UTF-8", "LC_ALL=C", "LC_CTYPE=UTF-8"}
	})
	if err != nil {
		t.Fatalf("ResolveSessionEnv() error = %v", err)
	}
	envMap := make(map[string]string, len(envVars))
	for _, ev := range envVars {
		envMap[ev.Name] = ev.Value
	}
	// Under native OpenSSH_10.6p2 top-to-bottom SendEnv evaluation:
	// 10-hosts.conf has `SendEnv -LC_*` BEFORE 20-canonical.conf's `SendEnv LANG LC_*`,
	// so `-LC_*` only clears earlier entries and both LANG and LC_* remain active.
	if envMap["LANG"] != "en_US.UTF-8" || envMap["LC_ALL"] != "C" || envMap["LC_CTYPE"] != "UTF-8" || envMap["APP_ENV"] != "included-prod" {
		t.Fatalf("unexpected resolved session env: %+v", envMap)
	}
}

func assertPass7IncludedImport(t *testing.T, rootConf string) {
	t.Helper()
	imported, err := ParseOpenSSHHosts(strings.NewReader(rootConf), "local-default")
	if err != nil {
		t.Fatalf("ParseOpenSSHHosts() error = %v", err)
	}
	byName := make(map[string]OpenSSHHost, len(imported))
	for _, h := range imported {
		byName[h.Name] = h
	}
	if len(byName) != 3 {
		t.Fatalf("ParseOpenSSHHosts() returned %d hosts, want 3", len(byName))
	}
	impApp, ok := byName["included-app"]
	if !ok || impApp.Host.Address != "10.77.0.10" || impApp.Host.Port != 2222 || impApp.Identity.User != "inc-user" || impApp.Node.ProxyJump != "inc-bastion" {
		t.Fatalf("unexpected imported included-app: %+v (ok=%v)", impApp, ok)
	}
	impCmd, ok := byName["included-cmd"]
	if !ok || impCmd.Node.ProxyJump != "" {
		t.Fatalf("unexpected imported included-cmd: %+v (ok=%v)", impCmd, ok)
	}
	if impCmd.Node.SSHOptions != nil && impCmd.Node.SSHOptions.Get(ssh.OptionProxyCommand) != "" {
		t.Fatalf("Gate 3 violation: ProxyCommand leaked into imported SSHOptions: %+v", impCmd.Node.SSHOptions)
	}
}

func assertPass7IncludedCanonicalize(t *testing.T, provider *Provider) {
	t.Helper()
	resSkipped := &fakeCanonicalResolver{
		hosts: map[string][]string{"included-cmd.corp.example.com": {"10.77.0.11"}},
	}
	outSkipped, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
		Provider: provider,
		Host:     "included-cmd",
		Resolver: resSkipped,
	})
	if err != nil || outSkipped.Canonicalized || len(resSkipped.queried) != 0 {
		t.Fatalf("expected ProxyCommand in Included file to skip CanonicalizeHost(yes), got out=%+v err=%v queried=%v", outSkipped, err, resSkipped.queried)
	}

	resCanon := &fakeCanonicalResolver{
		hosts: map[string][]string{"portal.corp.example.com": {"10.77.0.50"}},
	}
	outCanon, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
		Provider:      provider,
		Host:          "portal",
		RawCLIOptions: []string{"ProxyCommand=none"},
		Resolver:      resCanon,
	})
	if err != nil || !outCanon.Canonicalized || outCanon.CanonicalHost != "portal.corp.example.com" {
		t.Fatalf("CanonicalizeHost(portal) = %+v, err = %v", outCanon, err)
	}
	if want := []string{"portal.dev.example.com", "portal.corp.example.com"}; !slices.Equal(resCanon.queried, want) {
		t.Fatalf("CanonicalizeHost queried = %v, want %v", resCanon.queried, want)
	}
	if outCanon.Pass2Options == nil || outCanon.Pass2Options.Get(ssh.OptionConnectTimeout) != "19" {
		t.Fatalf("expected Pass2Options ConnectTimeout=19 from included Host *.corp.example.com, got %+v", outCanon.Pass2Options)
	}
}

func TestPass7_H3_ConditionalIncludeAndLexicalOrder(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	prodDir := filepath.Join(home, ".ssh", "conf.d", "prod")
	nestedDir := filepath.Join(prodDir, "nested")
	if err := os.MkdirAll(nestedDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	const secondConf = `
Host db.prod.corp.example.com
    HostName 10.80.0.2
    User second-user
    Port 2202
    IdentityFile ~/.ssh/id_second

Host leaked-outside-prod
    HostName 10.99.99.99
    User leaked-user
    ProxyCommand evil-command %h %p
`
	const firstConf = `
Host db.prod.corp.example.com
    HostName 10.80.0.1
    User first-user
    IdentityFile ~/.ssh/id_first
    Include conf.d/prod/nested/*.conf
`
	const nestedConf = "Port 2299\nProxyJump prod-jump\n"
	const rootConf = "Host *.prod.corp.example.com\n    Include conf.d/prod/*.conf\n\nHost *\n    User global-default\n"

	writeSSHTestFile(t, filepath.Join(prodDir, "02-second.conf"), secondConf)
	writeSSHTestFile(t, filepath.Join(prodDir, "01-first.conf"), firstConf)
	writeSSHTestFile(t, filepath.Join(nestedDir, "10-port.conf"), nestedConf)

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(rootConf))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}

	assertConditionalIncludeMatching(t, parser)
	assertConditionalIncludeIsolation(t, parser, rootConf)
}

func assertConditionalIncludeMatching(t *testing.T, parser *OpenSSHParser) {
	t.Helper()
	if !parser.HasHost("db.prod.corp.example.com") {
		t.Fatal("expected db.prod.corp.example.com inside matching conditional Include to be found")
	}
	if got := parser.FindConcreteHostsByAddress("10.80.0.1", 2299); !slices.Equal(got, []string{"db.prod.corp.example.com"}) {
		t.Fatalf("FindConcreteHostsByAddress(10.80.0.1, 2299) = %v, want [db.prod.corp.example.com]", got)
	}
	node, host, ident, err := parser.GetVirtualNode("db.prod.corp.example.com")
	if err != nil {
		t.Fatalf("GetVirtualNode(db.prod.corp.example.com) error = %v", err)
	}
	if host.Address != "10.80.0.1" || host.Port != 2299 || ident.User != "first-user" || node.ProxyJump != OpenSSHNodePrefix+"prod-jump" {
		t.Fatalf("unexpected resolved db.prod.corp.example.com: node=%+v host=%+v ident=%+v", node, host, ident)
	}
	wantIDs := []string{"~/.ssh/id_first", "~/.ssh/id_second"}
	if got := node.SSHOptions.IdentityFiles(); !slices.Equal(got, wantIDs) {
		t.Fatalf("IdentityFiles() = %v, want %v", got, wantIDs)
	}
}

func assertConditionalIncludeIsolation(t *testing.T, parser *OpenSSHParser, rootConf string) {
	t.Helper()
	if parser.HasHost("leaked-outside-prod") {
		t.Fatal("HasHost(leaked-outside-prod) = true, want false")
	}
	if got := parser.FindConcreteHostsByAddress("10.99.99.99", 22); len(got) != 0 {
		t.Fatalf("FindConcreteHostsByAddress leaked conditional host: %v", got)
	}
	leakNode, leakHost, leakIdent, err := parser.GetVirtualNode("leaked-outside-prod")
	if err != nil {
		t.Fatalf("GetVirtualNode(leaked-outside-prod) error = %v", err)
	}
	if leakHost.Address != "leaked-outside-prod" || leakIdent.User != "global-default" {
		t.Fatalf("leaked-outside-prod inherited gated Include directives: host=%+v ident=%+v", leakHost, leakIdent)
	}
	if leakNode.SSHOptions != nil && leakNode.SSHOptions.ActiveProxyCommand() != "" {
		t.Fatalf("leaked-outside-prod inherited gated ProxyCommand: %q", leakNode.SSHOptions.ActiveProxyCommand())
	}
	imported, err := ParseOpenSSHHosts(strings.NewReader(rootConf), "fallback")
	if err != nil {
		t.Fatalf("ParseOpenSSHHosts() error = %v", err)
	}
	if len(imported) != 1 || imported[0].Name != "db.prod.corp.example.com" {
		t.Fatalf("ParseOpenSSHHosts() = %+v, want only [db.prod.corp.example.com]", imported)
	}
}

func TestPass7_H3_IncludeCycleDepthAndConcurrencySafety(t *testing.T) {
	parser := setupCyclicAndDeepIncludeParser(t)

	if !parser.HasHost("cycle-a") || !parser.HasHost("cycle-b") {
		t.Fatal("expected cycle-a and cycle-b to resolve cleanly across cyclic Include")
	}
	if !parser.HasHost("depth-16") {
		t.Fatalf("expected depth-16 (at maxIncludeDepth=%d) to be reachable", maxIncludeDepth)
	}
	if parser.HasHost("depth-17") {
		t.Fatalf("expected depth-17 (> maxIncludeDepth=%d) to be bounded", maxIncludeDepth)
	}

	assertInMemoryASTCycleGuard(t)
	assertConcurrentOpenSSHReads(parser)
}

func setupCyclicAndDeepIncludeParser(t *testing.T) *OpenSSHParser {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	sshDir := filepath.Join(home, ".ssh")
	confDir := filepath.Join(sshDir, "conf.d")
	chainDir := filepath.Join(sshDir, "chain")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(chainDir, 0o700); err != nil {
		t.Fatal(err)
	}

	writeSSHTestFile(t, filepath.Join(confDir, "a.conf"), "Include conf.d/b.conf\nHost cycle-a\n    HostName 10.66.0.1\n    User user-a\n")
	writeSSHTestFile(t, filepath.Join(confDir, "b.conf"), "Include conf.d/a.conf\nInclude config\nHost cycle-b\n    HostName 10.66.0.2\n    User user-b\n")

	for i := 1; i <= 20; i++ {
		var sb strings.Builder
		if i < 20 {
			sb.WriteString("Include chain/d" + twoDigit(i+1) + ".conf\n")
		}
		sb.WriteString("Host depth-" + twoDigit(i) + "\n    HostName 10.55.0." + strconv.Itoa(i) + "\n")
		writeSSHTestFile(t, filepath.Join(chainDir, "d"+twoDigit(i)+".conf"), sb.String())
	}

	rootPath := filepath.Join(sshDir, "config")
	writeSSHTestFile(t, rootPath, "Include conf.d/a.conf\nInclude chain/d01.conf\n")

	parser, err := NewOpenSSHParserFromPath(rootPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath(cyclic) error = %v", err)
	}
	return parser
}

func assertInMemoryASTCycleGuard(t *testing.T) {
	t.Helper()
	cfg1, err := ssh_config.DecodeBytes([]byte("Host mem-1\n    HostName 10.1.1.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg2, err := ssh_config.DecodeBytes([]byte("Host mem-2\n    HostName 10.1.1.2\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg1.Hosts[0].Nodes = append(cfg1.Hosts[0].Nodes, &openSSHIncludeNode{
		files: map[string]*ssh_config.Config{"cfg2": cfg2},
	})
	cfg2.Hosts[0].Nodes = append(cfg2.Hosts[0].Nodes, &openSSHIncludeNode{
		files: map[string]*ssh_config.Config{"cfg1": cfg1},
	})
	memParser := &OpenSSHParser{cfg: cfg1}
	if !memParser.HasHost("mem-1") || !memParser.HasHost("mem-2") || memParser.HasHost("missing") {
		t.Fatal("unexpected HasHost result on cyclic in-memory AST")
	}
	if got := memParser.FindConcreteHostsByAddress("10.1.1.2", 22); !slices.Equal(got, []string{"mem-2"}) {
		t.Fatalf("unexpected FindConcreteHostsByAddress on cyclic in-memory AST: %v", got)
	}
}

func assertConcurrentOpenSSHReads(parser *OpenSSHParser) {
	prov := NewProviderWithOpenSSHParser(nil, parser)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				_ = parser.HasHost("cycle-a")
				_ = parser.FindConcreteHostsByAddress("10.66.0.2", 22)
				_, _, _, _ = parser.GetVirtualNode("cycle-b")
				_, _ = prov.GetOpenSSHOptions("cycle-a")
			}
		}()
	}
	wg.Wait()
}

func TestPass7_H4_HasHostRequiresConcretePatternMatch(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	confDir := filepath.Join(home, ".ssh", "conf.d")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSSHTestFile(t, filepath.Join(confDir, "mixed.conf"), "Host inc-bastion *.inc.example.com\n    HostName 10.44.0.1\n")

	const sshCfg = `
Include conf.d/*.conf

Host bastion *.corp.example.com
    HostName 10.10.0.1
    User ops

Host localhost *
    ServerAliveInterval 30

Host app !app
    HostName 10.10.0.2

Host !denied.example.com denied.example.com allowed.example.com
    HostName 10.10.0.3
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}

	cases := []struct {
		alias string
		want  bool
	}{
		{alias: "bastion", want: true},
		{alias: "openssh:bastion", want: true},
		{alias: "deploy@bastion:2222", want: true},
		{alias: "localhost", want: true},
		{alias: "typo.corp.example.com", want: false},
		{alias: "openssh:deploy@typo.corp.example.com:2222", want: false},
		{alias: "random", want: false},
		{alias: "app", want: false},
		{alias: "denied.example.com", want: false},
		{alias: "allowed.example.com", want: true},
		{alias: "inc-bastion", want: true},
		{alias: "typo.inc.example.com", want: false},
	}

	for _, tc := range cases {
		if got := parser.HasHost(tc.alias); got != tc.want {
			t.Errorf("HasHost(%q) = %v, want %v", tc.alias, got, tc.want)
		}
	}

	prov := NewProviderWithOpenSSHParser(nil, parser)
	if _, err := prov.ResolveProxyJumpChain("random"); err == nil {
		t.Fatal("expected ResolveProxyJumpChain(\"random\") to fail closed despite `Host localhost *`")
	}
	gotJump, err := prov.ResolveProxyJumpChain("bastion")
	if err != nil || gotJump != OpenSSHNodePrefix+"bastion" {
		t.Fatalf("ResolveProxyJumpChain(\"bastion\") = (%q, %v), want (%q, nil)", gotJump, err, OpenSSHNodePrefix+"bastion")
	}
}

func twoDigit(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
