package config

import (
	"slices"
	"strings"
	"testing"
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
	cfg := strings.Join([]string{
		"Host",
		"  User empty-host-user",
		"",
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
		"Match host comma-a,comma-b,!comma-bad",
		"  User comma-user",
		"",
		"Match host space-a space-b # inline comment",
		"  User space-user",
		"",
		"Match all",
		"  User all-fallback",
	}, "\n") + "\n"

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}

	// Match blocks never count as concrete Host declarations in HasHost or inventory import.
	for _, alias := range []string{"comma-a", "space-a"} {
		if parser.HasHost(alias) {
			t.Errorf("HasHost(%q) = true for Match host block, want false", alias)
		}
	}

	wantUsers := map[string]string{
		"comma-a":   "comma-user",
		"comma-b":   "comma-user",
		"comma-bad": "all-fallback",
		"space-a":   "space-user",
		"space-b":   "space-user",
		"other":     "all-fallback",
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
		"Match user alice\n  User bad\n",
		"Match originalhost app\n  User bad\n",
		"Match canonical host app\n  User bad\n",
		"Match final all\n  User bad\n",
		"Match !host app\n  User bad\n",
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
