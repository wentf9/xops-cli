package cmd

import (
	"strings"
	"testing"

	corelog "github.com/wentf9/xops-cli/core/log"
	cryptossh "golang.org/x/crypto/ssh"
)

func TestSSHAuthenticatedMethodRendering(t *testing.T) {
	for _, test := range []struct {
		method string
		chain  []string
		want   string
	}{
		{"password", []string{"password"}, `using "password"`},
		{"publickey", []string{"publickey"}, `using "publickey"`},
		{"none", []string{"none"}, `using "none"`},
		{"password", []string{"publickey", "password"}, `using "password" (authentication chain: "publickey,password")`},
		{"", nil, "using <unknown>"},
	} {
		text := formatSSHDiagnostic(corelog.Diagnostic{Kind: corelog.Authenticated, NodeID: "fixture", Method: test.method, Methods: test.chain})
		if !strings.Contains(text, test.want) {
			t.Fatalf("missing final method/chain: %s", text)
		}
	}
}

func TestSSHDiagnosticMACRendering(t *testing.T) {
	for _, kind := range []corelog.DiagnosticKind{corelog.Negotiated, corelog.Authenticated} {
		for _, test := range []struct{ cipher, mac, want string }{
			{cryptossh.CipherAES128GCM, "", "<implicit>"},
			{cryptossh.CipherAES256GCM, "", "<implicit>"},
			{cryptossh.CipherChaCha20Poly1305, "", "<implicit>"},
			{cryptossh.CipherAES128CTR, cryptossh.HMACSHA256, `"hmac-sha2-256"`},
			{cryptossh.CipherAES128CTR, "", "<unknown>"},
			{"unrecognized-cipher", "", "<unknown>"},
			{"", "", "<unknown>"},
		} {
			text := formatSSHDiagnostic(corelog.Diagnostic{Kind: kind, ReadCipher: test.cipher, ReadMAC: test.mac, WriteCipher: cryptossh.CipherAES128CTR, WriteMAC: cryptossh.HMACSHA512ETM})
			if !strings.Contains(text, "MAC: "+test.want+"; client->server:") || !strings.Contains(text, `MAC: "hmac-sha2-512-etm@openssh.com"`) || strings.Contains(text, `MAC: ""`) {
				t.Fatalf("MAC not rendered by direction/cipher: %s", text)
			}
		}
	}
}
