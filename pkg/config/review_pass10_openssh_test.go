package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestPass10_H2_OpenSSHConfigHashCommentAndQuoteLexing(t *testing.T) {
	dir := t.TempDir()
	incUnquotedDir := filepath.Join(dir, "inc#1")
	incQuotedDir := filepath.Join(dir, "inc # 2")
	for _, d := range []string{incUnquotedDir, incQuotedDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(incUnquotedDir, "a.conf"), []byte("Host app#1\n  Port 2201 # port comment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incQuotedDir, "b.conf"), []byte("Match host match#1,*.example#1.com # match comment\n  User alice#1 # inline comment\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	mainPath := filepath.Join(dir, "ssh_config")
	mainCfg := strings.Join([]string{
		"Include " + incUnquotedDir + "/*.conf # unquoted hash dir include",
		`Include "` + incQuotedDir + `/*.conf" # quoted hash dir include`,
		"",
		"Host app#1 # trailing host comment",
		"  HostName host#1.example.com # hn comment",
		`  User "alice # 1" # user comment`,
		"  IdentityFile /tmp/key#1 # unquoted key comment",
		`  IdentityFile "/tmp/key # 2" # dq key comment`,
		"  IdentityFile '/tmp/key # 3' # sq key comment",
		`  CertificateFile "/tmp/cert # 1.pub" # cert comment`,
		`  IdentityAgent "/tmp/agent # 1" # ia comment`,
		`  ControlPath "/tmp/mux # 1" # cp comment`,
		`  SetEnv A=foo#bar B="x # y" C='p # q' # setenv comment`,
		`  SendEnv LANG "LC_*" -FOO_* # sendenv comment`,
		"  LocalCommand echo \"hi # 1\" # trailing local",
		"  RemoteCommand echo 'rc # 1' # trailing remote",
		"",
		"Host proxy#cmd",
		"  HostName 10.0.0.77",
		"  ProxyCommand sh -c 'echo #1' # trailing proxy",
		"",
		"Host pj-compat",
		"  HostName 10.0.0.88",
		`  ProxyJump "jump#1"`,
	}, "\n") + "\n"
	if err := os.WriteFile(mainPath, []byte(mainCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	parser, err := NewOpenSSHParserFromPath(mainPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath: %v", err)
	}
	if !parser.HasHost("app#1") {
		t.Fatal("expected HasHost(app#1) == true after Include inc#1")
	}

	assertPass10App1Node(t, parser)
	assertPass10MatchAndProxyNodes(t, parser)
}

func assertPass10App1Node(t *testing.T, parser *OpenSSHParser) {
	t.Helper()
	node, host, ident, err := parser.GetVirtualNode("app#1")
	if err != nil {
		t.Fatalf("GetVirtualNode(app#1): %v", err)
	}
	if host.Address != "host#1.example.com" || host.Port != 2201 || ident.User != "alice # 1" {
		t.Fatalf("app#1 target = host:%q port:%d user:%q", host.Address, host.Port, ident.User)
	}
	opts := node.SSHOptions
	if opts == nil {
		t.Fatal("expected non-nil SSHOptions for app#1")
	}
	wantIDs := []string{"/tmp/key#1", "/tmp/key # 2", "/tmp/key # 3"}
	if !slices.Equal(opts.IdentityFiles(), wantIDs) {
		t.Errorf("IdentityFiles = %#v, want %#v", opts.IdentityFiles(), wantIDs)
	}
	if got := opts.CertificateFiles(); !slices.Equal(got, []string{"/tmp/cert # 1.pub"}) {
		t.Errorf("CertificateFiles = %#v, want [/tmp/cert # 1.pub]", got)
	}
	if opts.IdentityAgent() != "/tmp/agent # 1" || opts.ControlPath() != "/tmp/mux # 1" {
		t.Errorf("IdentityAgent=%q ControlPath=%q", opts.IdentityAgent(), opts.ControlPath())
	}
	assertPass10App1SessionAndEnvOptions(t, opts)
}

func assertPass10App1SessionAndEnvOptions(t *testing.T, opts *ssh.Options) {
	t.Helper()
	if got := opts.Get(ssh.OptionLocalCommand); got != `echo "hi # 1" # trailing local` {
		t.Errorf("LocalCommand = %q, want whole line with # preserved", got)
	}
	if got := opts.RemoteCommand(); got != `echo 'rc # 1' # trailing remote` {
		t.Errorf("RemoteCommand = %q, want whole line with # preserved", got)
	}
	if got := opts.SendEnvPatterns(); !slices.Equal(got, []string{"LANG", "LC_*", "-FOO_*"}) {
		t.Errorf("SendEnvPatterns = %#v, want [LANG LC_* -FOO_*]", got)
	}
	envVars, err := ssh.ResolveSessionEnv(opts, func() []string { return nil })
	if err != nil {
		t.Fatalf("ResolveSessionEnv: %v", err)
	}
	wantEnv := []ssh.EnvVar{
		{Name: "A", Value: "foo#bar"},
		{Name: "B", Value: "x # y"},
		{Name: "C", Value: "p # q"},
	}
	if !slices.Equal(envVars, wantEnv) {
		t.Errorf("SetEnv resolved = %#v, want %#v", envVars, wantEnv)
	}
}

func assertPass10MatchAndProxyNodes(t *testing.T, parser *OpenSSHParser) {
	t.Helper()
	// Match host pattern with # from quoted Include dir.
	_, _, matchIdent, err := parser.GetVirtualNode("match#1")
	if err != nil {
		t.Fatalf("GetVirtualNode(match#1): %v", err)
	}
	if matchIdent.User != "alice#1" {
		t.Errorf("Match host match#1 User = %q, want alice#1", matchIdent.User)
	}

	// ProxyCommand keeps whole line including # after quoted segment.
	proxyNode, _, _, err := parser.GetVirtualNode("proxy#cmd")
	if err != nil {
		t.Fatalf("GetVirtualNode(proxy#cmd): %v", err)
	}
	if got := proxyNode.SSHOptions.ActiveProxyCommand(); got != "sh -c 'echo #1' # trailing proxy" {
		t.Errorf("ActiveProxyCommand = %q, want %q", got, "sh -c 'echo #1' # trailing proxy")
	}

	// Match exec still fails closed even if it contains quotes and #.
	if _, err := NewOpenSSHParserFromReader(strings.NewReader("Match exec \"echo #1\"\n  User bad\n")); err == nil {
		t.Fatal("expected Match exec with # to still be rejected")
	}
}

func TestPass10_M1_RepositoryRejectsReservedOpenSSHAliases(t *testing.T) {
	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "xops.key"))
	repo, err := NewRepositoryWithoutOpenSSH(NewProviderWithoutOpenSSH(nil).Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}

	host := models.Host{Address: "10.0.0.10", Port: 22}
	ident := models.Identity{User: "ops", AuthType: "auto"}

	for _, badAlias := range []string{"openssh", "OPENSSH", "openssh:prod", "OpenSSH:web"} {
		node := models.Node{HostRef: "h-bad", IdentityRef: "id-bad", Alias: []string{badAlias}}
		if _, err := repo.CreateNodeContext(t.Context(), "node-bad", node, host, ident); err == nil {
			t.Errorf("CreateNodeContext allowed reserved alias %q", badAlias)
		}
		if _, err := repo.CreateNodeContext(t.Context(), badAlias, models.Node{HostRef: "h-bad", IdentityRef: "id-bad"}, host, ident); err == nil {
			t.Errorf("CreateNodeContext allowed reserved nodeID %q", badAlias)
		}
		upd := repo.NodeCredentialCreate("node-cred-bad", node, host, ident)
		if _, _, err := upd.ApplyCredentialRefAtVersion(t.Context(), credential.Target{NodeID: "node-cred-bad", Kind: credential.KindLoginPassword}, "", &credential.Ref{StoreID: "file", ItemID: "i1"}); err == nil {
			t.Errorf("NodeCredentialCreate allowed reserved alias %q", badAlias)
		}
	}

	// Create valid node, then attempt ReplaceNodeAtRefContext with reserved alias.
	validNode := models.Node{HostRef: "h-good", IdentityRef: "id-good", Alias: []string{"good"}}
	mut, err := repo.CreateNodeContext(t.Context(), "node-good", validNode, host, ident)
	if err != nil {
		t.Fatalf("CreateNodeContext(valid): %v", err)
	}
	edited := validNode
	edited.Alias = []string{"openssh:hijack"}
	if err := repo.ReplaceNodeAtRefContext(t.Context(), mut.Ref, "node-good", edited, host, ident); err == nil {
		t.Fatal("ReplaceNodeAtRefContext allowed updating alias to openssh:hijack")
	}

	// ImportOpenSSHHostsContext skips invalid names/aliases while importing valid siblings.
	res, err := repo.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{
		{
			Name:     "openssh",
			Host:     models.Host{Address: "10.0.0.1", Port: 22},
			Identity: ident,
			Node:     models.Node{Alias: []string{"openssh"}},
		},
		{
			Name:     "bad-alias-host",
			Host:     models.Host{Address: "10.0.0.2", Port: 22},
			Identity: ident,
			Node:     models.Node{Alias: []string{"openssh:alias"}},
		},
		{
			Name:     "good-import",
			Host:     models.Host{Address: "10.0.0.3", Port: 22},
			Identity: ident,
			Node:     models.Node{Alias: []string{"good-import"}},
		},
	})
	if err != nil {
		t.Fatalf("ImportOpenSSHHostsContext: %v", err)
	}
	if res.Imported != 1 || res.Skipped != 2 || len(res.Issues) != 2 {
		t.Errorf("ImportResult = %+v, want Imported=1 Skipped=2 Issues=2", res)
	}
	if _, ok := repo.GetNode("openssh"); ok {
		t.Error("reserved node 'openssh' was persisted")
	}
	if _, ok := repo.GetNode("bad-alias-host"); ok {
		t.Error("node with reserved alias 'openssh:alias' was persisted")
	}
	if _, ok := repo.GetNode("good-import"); !ok {
		t.Error("valid sibling 'good-import' was not imported")
	}
}
