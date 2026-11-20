package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestOpenSSHWildcardMatchingSemantics(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		want    bool
	}{
		{"*", "anything", true},
		{"*", "", true},
		{"?", "a", true},
		{"?", "", false},
		{"?", "ab", false},
		{"web-??.prod", "web-01.prod", true},
		{"web-??.prod", "web-1.prod", false},
		{"a*b*c", "axxxbyyyc", true},
		{"a*b*c", "abbc", true},
		{"a*b*c", "ac", false},
		{"*bad", "abadbad", true},
		{"HASH-CASE", "HASH-CASE", true},
		{"HASH-CASE", "hash-case", false},
		// '[' and '\' are literal in OpenSSH match_pattern, not glob/escape metacharacters.
		{"[a-z]", "[a-z]", true},
		{"[a-z]", "b", false},
		{`a\b`, `a\b`, true},
		{`a\b`, "ab", false},
	}

	for _, tc := range tests {
		if got := matchSSHWildcard(tc.pattern, tc.input); got != tc.want {
			t.Errorf("matchSSHWildcard(%q, %q) = %v, want %v", tc.pattern, tc.input, got, tc.want)
		}
	}
}

func TestOpenSSHBlockPatternNegationAndEmptyHost(t *testing.T) {
	if _, err := NewOpenSSHParserFromReader(strings.NewReader("Host\n  User empty-host-user\n")); err == nil {
		t.Fatal("expected bare empty Host directive to fail closed, got nil")
	}

	cfg := strings.Join([]string{
		"Host !",
		"  User bare-bang-user",
		"",
		"Host !*.internal.example *.example",
		"  User ext-user",
		"",
		"Host web.internal.example",
		"  User int-user",
		"",
		"Host *.example !blocked.example",
		"  User wildcard-user",
	}, "\n") + "\n"

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}

	if parser.HasHost("foo.example") {
		t.Fatal("HasHost(foo.example) = true for wildcard pattern, want false")
	}
	if !parser.HasHost("web.internal.example") {
		t.Fatal("HasHost(web.internal.example) = false, want true")
	}

	_, _, extIdent, err := parser.GetVirtualNode("api.example")
	if err != nil {
		t.Fatalf("GetVirtualNode(api.example): %v", err)
	}
	if extIdent.User != "ext-user" {
		t.Errorf("api.example User = %q, want ext-user", extIdent.User)
	}

	_, _, intIdent, err := parser.GetVirtualNode("web.internal.example")
	if err != nil {
		t.Fatalf("GetVirtualNode(web.internal.example): %v", err)
	}
	if intIdent.User != "int-user" {
		t.Errorf("web.internal.example User = %q, want int-user", intIdent.User)
	}

	_, _, blockedIdent, err := parser.GetVirtualNode("blocked.example")
	if err != nil {
		t.Fatalf("GetVirtualNode(blocked.example): %v", err)
	}
	if blockedIdent.User == "wildcard-user" || blockedIdent.User == "empty-host-user" || blockedIdent.User == "bare-bang-user" {
		t.Errorf("blocked.example unexpectedly matched negated/empty block user %q", blockedIdent.User)
	}
}

func TestOpenSSHParserMatchAllAndMatchHost(t *testing.T) {
	cfg := strings.Join([]string{
		"Match host comma-a,comma-b,!comma-bad # inline comment",
		"  User comma-user",
		"",
		"Match host=eq-a,eq-b",
		"  User eq-user",
		"",
		"Match host tag",
		"  User tag-user",
		"",
		"Match host command",
		"  User cmd-user",
		"",
		"Match host user",
		"  User user-kw-user",
		"",
		"Match host !all",
		"  User bang-only-user",
		"",
		"Match host *,!all,!comma-bad",
		"  User bang-all-user",
		"",
		"Match all",
		"  User all-fallback",
	}, "\n") + "\n"

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}

	// Match blocks never count as concrete Host declarations in HasHost or inventory import.
	for _, alias := range []string{"comma-a", "eq-a", "tag", "command", "user"} {
		if parser.HasHost(alias) {
			t.Errorf("HasHost(%q) = true for Match host block, want false", alias)
		}
	}

	wantUsers := map[string]string{
		"comma-a":   "comma-user",
		"comma-b":   "comma-user",
		"comma-bad": "all-fallback",
		"eq-a":      "eq-user",
		"eq-b":      "eq-user",
		"tag":       "tag-user",
		"command":   "cmd-user",
		"user":      "user-kw-user",
		"all":       "all-fallback",
		"other":     "bang-all-user",
	}
	for host, want := range wantUsers {
		_, _, ident, err := parser.GetVirtualNode(host)
		if err != nil {
			t.Fatalf("GetVirtualNode(%q) error = %v", host, err)
		}
		if ident.User != want {
			t.Errorf("GetVirtualNode(%q).User = %q, want %q", host, ident.User, want)
		}
	}
}

func TestOpenSSHParserMatchUnsupportedFailsClosed(t *testing.T) {
	invalidCases := []string{
		"Match\n  User bad\n",
		"Match exec \"echo #1\"\n  User bad\n",
		"Match host app exec \"false\"\n  User bad\n",
		"Match host space-a space-b # inline comment\n  User space-user\n",
		"Match user alice\n  User bad\n",
		"Match originalhost app\n  User bad\n",
		"Match canonical host app\n  User bad\n",
		"Match final all\n  User bad\n",
		"Match !host app\n  User bad\n",
		"Match host *.corp version 1.0\n  User bad\n",
		"Match host *.corp tag ops\n  User bad\n",
		"Match host *.corp unknownfuturecriterion\n  User bad\n",
		"Match host=a extra\n  User bad\n",
		"Match host=\n  User bad\n",
		"Match host , \n  User bad\n",
	}

	for _, raw := range invalidCases {
		if _, err := NewOpenSSHParserFromReader(strings.NewReader(raw)); err == nil {
			t.Errorf("expected NewOpenSSHParserFromReader(%q) to fail closed, got nil", raw)
		}
	}
}

func TestOpenSSHParserProxyJumpQuotesCommentsBOMAndCRLF(t *testing.T) {
	raw := "\xEF\xBB\xBF" + strings.Join([]string{
		"Host pj-quoted",
		`  ProxyJump "jump#1" # trailing comment`,
		"",
		"Host pj-list",
		"  ProxyJump jump-a, ops@jump-b:2222 # trailing comment",
	}, "\r\n") + "\r\n"

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}

	nodeQ, _, _, err := parser.GetVirtualNode("pj-quoted")
	if err != nil {
		t.Fatalf("GetVirtualNode(pj-quoted) error = %v", err)
	}
	if nodeQ.ProxyJump != "openssh:jump#1" {
		t.Errorf("pj-quoted ProxyJump = %q, want %q", nodeQ.ProxyJump, "openssh:jump#1")
	}

	nodeL, _, _, err := parser.GetVirtualNode("pj-list")
	if err != nil {
		t.Fatalf("GetVirtualNode(pj-list) error = %v", err)
	}
	if nodeL.ProxyJump != "openssh:jump-a,openssh:ops@jump-b:2222" {
		t.Errorf("pj-list ProxyJump = %q, want %q", nodeL.ProxyJump, "openssh:jump-a,openssh:ops@jump-b:2222")
	}

	if got := parser.FindConcreteHostsByAddress("pj-quoted", 0); !slices.Equal(got, []string{"pj-quoted"}) {
		t.Errorf("FindConcreteHostsByAddress(pj-quoted) = %v, want [pj-quoted]", got)
	}
}

func TestOpenSSHParser_DynamicEffectiveHostTwoPassAndSyntaxStrictness(t *testing.T) {
	t.Run("Match host sees expanded HostName from earlier block", func(t *testing.T) {
		cfg := strings.Join([]string{
			"Host db-alias",
			"  HostName 10.20.0.5",
			"  User dbuser",
			"",
			"Match host 10.20.0.5",
			"  Port 2222",
			"  ServerAliveInterval 15",
		}, "\n") + "\n"
		parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		_, host, ident, err := parser.GetVirtualNode("db-alias")
		if err != nil {
			t.Fatalf("GetVirtualNode(db-alias): %v", err)
		}
		if host.Address != "10.20.0.5" || host.Port != 2222 || ident.User != "dbuser" {
			t.Fatalf("unexpected virtual resolution: host=%+v ident=%+v", host, ident)
		}
		opts, err := parser.GetSSHOptions("db-alias")
		if err != nil {
			t.Fatalf("GetSSHOptions(db-alias): %v", err)
		}
		if opts.Get("server_alive_interval") != "15" {
			t.Fatalf("expected Match host 10.20.0.5 ServerAliveInterval=15, got %q", opts.Get("server_alive_interval"))
		}
	})

	t.Run("two-pass canonical preserves Pass 1 options and deduplicates wildcard identities", func(t *testing.T) {
		cfg := strings.Join([]string{
			"Host short",
			"  User alice",
			"  Port 2201",
			"  IdentityFile /tmp/id_short",
			"  SendEnv LANG",
			"",
			"Host *.corp.example.com",
			"  User bob",
			"  ProxyJump bastion",
			"  ServerAliveInterval 20",
			"",
			"Host *",
			"  IdentityFile /tmp/id_shared",
		}, "\n") + "\n"
		parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		node, host, ident, err := parser.GetVirtualNodeWithCanonical("short", "short.corp.example.com")
		if err != nil {
			t.Fatalf("GetVirtualNodeWithCanonical: %v", err)
		}
		if host.Address != "short.corp.example.com" || host.Port != 2201 || ident.User != "alice" {
			t.Fatalf("unexpected two-pass virtual target: host=%+v ident=%+v", host, ident)
		}
		if node.ProxyJump != "openssh:bastion" {
			t.Fatalf("ProxyJump = %q, want openssh:bastion", node.ProxyJump)
		}
		opts, err := parser.GetSSHOptionsWithCanonical("short", "short.corp.example.com")
		if err != nil {
			t.Fatalf("GetSSHOptionsWithCanonical: %v", err)
		}
		if opts.Get("server_alive_interval") != "20" {
			t.Fatalf("ServerAliveInterval = %q, want 20", opts.Get("server_alive_interval"))
		}
		wantIDs := []string{"/tmp/id_short", "/tmp/id_shared"}
		if gotIDs := opts.IdentityFiles(); !slices.Equal(gotIDs, wantIDs) {
			t.Fatalf("IdentityFiles = %v, want deduplicated %v", gotIDs, wantIDs)
		}
	})
}

func TestOpenSSHParser_SyntaxStrictnessAndPercentJ(t *testing.T) {
	t.Run("rejects unclosed quotes and extra scalar args while unquoting multi-token lists and skipping %j include", func(t *testing.T) {
		for _, bad := range []string{
			"Host badq\n  IdentitiesOnly \"yes\n",
			"Host extra\n  User alice bob\n",
			"Host extra2\n  IdentitiesOnly yes no\n",
		} {
			if _, err := NewOpenSSHParserFromReader(strings.NewReader(bad)); err == nil {
				t.Errorf("expected error parsing %q, got nil", bad)
			}
		}

		valid := strings.Join([]string{
			"Include /nonexistent/%j.conf",
			"Host multi",
			`  CanonicalDomains "dev.example" "corp.example"`,
			`  UserKnownHostsFile "/tmp/kh 1" "/tmp/kh 2"`,
		}, "\n") + "\n"
		parser, err := NewOpenSSHParserFromReader(strings.NewReader(valid))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader(valid) error = %v", err)
		}
		opts, err := parser.GetSSHOptions("multi")
		if err != nil {
			t.Fatalf("GetSSHOptions(multi): %v", err)
		}
		if got := opts.CanonicalDomains(); !slices.Equal(got, []string{"dev.example", "corp.example"}) {
			t.Fatalf("CanonicalDomains = %v, want [dev.example corp.example]", got)
		}
	})
}

func TestOpenSSHParser_MatchEqualsFailClosed_AndPass2HostNameSendEnv(t *testing.T) {
	t.Run("match criterion equals syntax and rdomain/address fail closed", func(t *testing.T) {
		badCases := []string{
			"Match host *.corp exec=\"false\"\n  User root\n",
			"Match host * user=alice\n  Port 2222\n",
			"Match host * !user=root\n  Port 2222\n",
			"Match host * rdomain=foo\n  Port 2222\n",
			"Match host * rdomain foo\n  Port 2222\n",
			"Match host * address 10.0.0.0/8\n  Port 2222\n",
		}
		for _, raw := range badCases {
			if _, err := NewOpenSSHParserFromReader(strings.NewReader(raw)); err == nil {
				t.Fatalf("expected Match block %q to fail closed, got nil error", raw)
			}
		}
	})

	t.Run("pass2 preserves pass1 sawHostName and deduplicates SendEnv across passes without breaking -PATTERN", func(t *testing.T) {
		raw := strings.Join([]string{
			"Host short",
			"  User alice",
			"  HostName short.corp.example.com",
			"",
			"Host short.corp.example.com",
			"  SendEnv -FOO",
			"",
			"Host *",
			"  HostName %h.fallback.example.com",
			"  SendEnv FOO BAR",
			"",
			"Match host short.corp.example.com",
			"  Port 2299",
			"",
			"Match host short.corp.example.com.fallback.example.com",
			"  Port 2399",
		}, "\n") + "\n"
		p, err := NewOpenSSHParserFromReader(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		_, host, ident, err := p.GetVirtualNodeWithCanonical("short", "short.corp.example.com")
		if err != nil {
			t.Fatalf("GetVirtualNodeWithCanonical: %v", err)
		}
		if host.Address != "short.corp.example.com" || host.Port != 2299 || ident.User != "alice" {
			t.Fatalf("Pass 2 HostName/Match leak: host=%+v ident=%+v", host, ident)
		}
		opts, err := p.GetSSHOptionsWithCanonical("short", "short.corp.example.com")
		if err != nil {
			t.Fatalf("GetSSHOptionsWithCanonical: %v", err)
		}
		resolved, rErr := ssh.ResolveSessionEnv(opts, func() []string { return []string{"FOO=1", "BAR=2"} })
		if rErr != nil {
			t.Fatalf("ResolveSessionEnv: %v", rErr)
		}
		if len(resolved) != 1 || resolved[0].Name != "BAR" {
			t.Fatalf("resolved SendEnv = %+v, want [BAR=2] (Host * FOO must not repeat after Pass-2 -FOO)", resolved)
		}
	})

	t.Run("pass1 without HostName allows pass2 concrete HostName and within-pass SendEnv re-enable works", func(t *testing.T) {
		raw := strings.Join([]string{
			"Host web",
			"  SendEnv FOO",
			"  SendEnv -FOO",
			"  SendEnv FOO",
			"",
			"Host web.corp.example.com",
			"  HostName 10.0.0.5",
			"  Port 2205",
		}, "\n") + "\n"
		p, err := NewOpenSSHParserFromReader(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		_, host, _, err := p.GetVirtualNodeWithCanonical("web", "web.corp.example.com")
		if err != nil {
			t.Fatalf("GetVirtualNodeWithCanonical: %v", err)
		}
		if host.Address != "10.0.0.5" || host.Port != 2205 {
			t.Fatalf("Pass 2 concrete HostName lost: host=%+v", host)
		}
		opts, err := p.GetSSHOptions("web")
		if err != nil {
			t.Fatalf("GetSSHOptions: %v", err)
		}
		resolved, rErr := ssh.ResolveSessionEnv(opts, func() []string { return []string{"FOO=1"} })
		if rErr != nil {
			t.Fatalf("ResolveSessionEnv: %v", rErr)
		}
		if len(resolved) != 1 || resolved[0].Name != "FOO" {
			t.Fatalf("within-pass SendEnv re-enable resolved = %+v, want [FOO=1]", resolved)
		}
		_ = slices.Clone(resolved)
	})
}
