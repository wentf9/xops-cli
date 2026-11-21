package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func newPhase4HostKey(t *testing.T) cryptoSSH.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cryptoSSH.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func sshfpSHA256(key cryptoSSH.PublicKey) []byte {
	sum := sha256.Sum256(key.Marshal())
	return sum[:]
}

func TestPhase4_OptionRegistryNormalizationAndAccessors(t *testing.T) {
	assertPhase4Specs(t)
	assertPhase4Normalization(t)
	assertPhase4NilAccessors(t)
	assertPhase4Accessors(t)
}

func assertPhase4Specs(t *testing.T) {
	t.Helper()
	specs := []struct {
		name  string
		key   string
		class OptionClass
	}{
		{"GlobalKnownHostsFile", OptionGlobalKnownHostsFile, OptionClassTrust},
		{"HashKnownHosts", OptionHashKnownHosts, OptionClassTrust},
		{"VerifyHostKeyDNS", OptionVerifyHostKeyDNS, OptionClassTrust},
		{"CanonicalizeHostname", OptionCanonicalizeHostname, OptionClassTransport},
		{"CanonicalDomains", OptionCanonicalDomains, OptionClassTransport},
		{"CanonicalizeMaxDots", OptionCanonicalizeMaxDots, OptionClassTransport},
		{"CanonicalizeFallbackLocal", OptionCanonicalizeFallbackLocal, OptionClassTransport},
		{"CanonicalizePermittedCNAMEs", OptionCanonicalizePermittedCNAMEs, OptionClassTransport},
	}
	for _, s := range specs {
		spec, ok := LookupOptionSpec(s.name)
		if !ok || spec.CanonicalKey != s.key || spec.Class != s.class || spec.MultiValue {
			t.Fatalf("unexpected spec for %s: ok=%v %+v", s.name, ok, spec)
		}
	}
}

func assertPhase4Normalization(t *testing.T) {
	t.Helper()
	valid := []struct{ key, raw, want string }{
		{OptionGlobalKnownHostsFile, "  /etc/a   ~/b/%h ", "/etc/a ~/b/%h"},
		{OptionGlobalKnownHostsFile, "NONE", "none"},
		{OptionHashKnownHosts, "True", "yes"},
		{OptionVerifyHostKeyDNS, "true", "yes"},
		{OptionVerifyHostKeyDNS, "FALSE", "no"},
		{OptionVerifyHostKeyDNS, "Ask", "ask"},
		{OptionCanonicalizeHostname, "ALWAYS", "always"},
		{OptionCanonicalizeHostname, "true", "yes"},
		{OptionCanonicalDomains, "Example.COM. corp.example.com example.com", "example.com corp.example.com"},
		{OptionCanonicalDomains, "none", "none"},
		{OptionCanonicalizeMaxDots, " 0 ", "0"},
		{OptionCanonicalizeMaxDots, "64", "64"},
		{OptionCanonicalizeFallbackLocal, "no", "no"},
		{OptionCanonicalizePermittedCNAMEs, "*.A.example.com:*.B.example.com,*.c.net  *.x:*.y", "*.a.example.com:*.b.example.com,*.c.net *.x:*.y"},
		{OptionCanonicalizePermittedCNAMEs, "None", "none"},
	}
	for _, tc := range valid {
		spec, _ := LookupOptionSpec(tc.key)
		got, err := spec.Normalize(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("Normalize(%s, %q) = %q, %v; want %q", tc.key, tc.raw, got, err, tc.want)
		}
	}

	invalid := []struct{ key, raw string }{
		{OptionGlobalKnownHostsFile, "   "},
		{OptionGlobalKnownHostsFile, "none /etc/a"},
		{OptionGlobalKnownHostsFile, "/etc/%z"},
		{OptionHashKnownHosts, "maybe"},
		{OptionVerifyHostKeyDNS, "always"},
		{OptionCanonicalizeHostname, "ask"},
		{OptionCanonicalDomains, ".example.com"},
		{OptionCanonicalDomains, "exa mple..com"},
		{OptionCanonicalDomains, "bad/domain"},
		{OptionCanonicalizeMaxDots, "-1"},
		{OptionCanonicalizeMaxDots, "65"},
		{OptionCanonicalizeMaxDots, "x"},
		{OptionCanonicalizePermittedCNAMEs, "*.a.example.com"},
		{OptionCanonicalizePermittedCNAMEs, ":*.b"},
		{OptionCanonicalizePermittedCNAMEs, "*.a:*.b:*.c"},
		{OptionCanonicalizePermittedCNAMEs, "*.a:,*.b"},
		{OptionCanonicalizePermittedCNAMEs, "none *.a:*.b"},
	}
	for _, tc := range invalid {
		spec, _ := LookupOptionSpec(tc.key)
		if got, err := spec.Normalize(tc.raw); err == nil {
			t.Fatalf("Normalize(%s, %q) = %q, want error", tc.key, tc.raw, got)
		}
	}
}

func assertPhase4NilAccessors(t *testing.T) {
	t.Helper()
	var nilOpts *Options
	if nilOpts.GlobalKnownHostsFile() != "" || nilOpts.HashKnownHosts() || nilOpts.VerifyHostKeyDNS() != "" ||
		nilOpts.CanonicalizeHostname() != "" || nilOpts.CanonicalDomains() != nil || nilOpts.CanonicalizePermittedCNAMEs() != nil {
		t.Fatal("nil Options accessors must return zero values")
	}
	if n, set := nilOpts.CanonicalizeMaxDots(); n != DefaultCanonicalizeMaxDots || set {
		t.Fatalf("CanonicalizeMaxDots default = %d,%v", n, set)
	}
	if v, set := nilOpts.CanonicalizeFallbackLocal(); !v || set {
		t.Fatalf("CanonicalizeFallbackLocal default = %v,%v", v, set)
	}
}

func assertPhase4Accessors(t *testing.T) {
	t.Helper()
	opts := MustOptions(
		OptionHashKnownHosts, "yes",
		OptionCanonicalDomains, "a.example b.example",
		OptionCanonicalizeMaxDots, "0",
		OptionCanonicalizeFallbackLocal, "no",
		OptionCanonicalizePermittedCNAMEs, "*.a:*.b",
	)
	if !opts.HashKnownHosts() || strings.Join(opts.CanonicalDomains(), ",") != "a.example,b.example" {
		t.Fatalf("unexpected accessors: %v %v", opts.HashKnownHosts(), opts.CanonicalDomains())
	}
	if n, set := opts.CanonicalizeMaxDots(); n != 0 || !set {
		t.Fatalf("CanonicalizeMaxDots = %d,%v", n, set)
	}
	if v, set := opts.CanonicalizeFallbackLocal(); v || !set {
		t.Fatalf("CanonicalizeFallbackLocal = %v,%v", v, set)
	}
	if got := opts.CanonicalizePermittedCNAMEs(); len(got) != 1 || got[0] != "*.a:*.b" {
		t.Fatalf("CanonicalizePermittedCNAMEs = %v", got)
	}
}

func TestPhase4_EvaluateSSHFPMatrix(t *testing.T) {
	key := newPhase4HostKey(t)
	good := sshfpSHA256(key)
	bad := make([]byte, 32)
	sha1Len := make([]byte, 20)

	cases := []struct {
		name   string
		result SSHFPResult
		want   SSHFPVerifyStatus
	}{
		{"no records", SSHFPResult{}, SSHFPStatusNone},
		{"verified match", SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{4, 2, good}}}, SSHFPStatusMatchedVerified},
		{"unverified match", SSHFPResult{Records: []SSHFPRecord{{4, 2, good}}}, SSHFPStatusMatchedUnverified},
		{"match among mismatches", SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{4, 2, bad}, {4, 2, good}}}, SSHFPStatusMatchedVerified},
		{"mismatch", SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{4, 2, bad}}}, SSHFPStatusMismatch},
		{"sha1 ignored", SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{4, 1, sha1Len}}}, SSHFPStatusNone},
		{"sha256 wrong length ignored", SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{4, 2, good[:31]}}}, SSHFPStatusNone},
		{"other algorithm authenticated mismatches", SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{1, 2, good}}}, SSHFPStatusMismatch},
		{"other algorithm unauthenticated ignored", SSHFPResult{Authenticated: false, Records: []SSHFPRecord{{1, 2, good}}}, SSHFPStatusNone},
	}
	for _, tc := range cases {
		if got := EvaluateSSHFP(tc.result, key); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
	if EvaluateSSHFP(SSHFPResult{Records: []SSHFPRecord{{4, 2, good}}}, nil) != SSHFPStatusNone {
		t.Fatal("nil key must yield none")
	}

	for host, want := range map[string]string{
		"example.com":      "example.com",
		"example.com.":     "example.com",
		"example.com:2222": "example.com",
		"192.0.2.1":        "",
		"[2001:db8::1]":    "",
		"fe80::1%eth0":     "",
		"":                 "",
	} {
		if got := sshfpLookupHost(host); got != want {
			t.Fatalf("sshfpLookupHost(%q) = %q want %q", host, got, want)
		}
	}
}

func TestPhase4_AppendKnownHostHashing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "known_hosts")
	key := newPhase4HostKey(t)
	if err := appendKnownHost(file, "secret.example.com:22", key, true); err != nil {
		t.Fatal(err)
	}
	if err := appendKnownHost(file, "secret.example.com:2222", key, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret.example.com") {
		t.Fatalf("hashed known_hosts leaked plaintext hostname:\n%s", data)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if !strings.HasPrefix(line, "|1|") {
			t.Fatalf("expected hashed entry, got %q", line)
		}
	}
	cb, err := knownhosts.New(file)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	for _, host := range []string{"secret.example.com:22", "secret.example.com:2222"} {
		if err := cb(host, addr, key); err != nil {
			t.Fatalf("hashed entry for %s must verify: %v", host, err)
		}
	}
	if err := cb("secret.example.com:2200", addr, key); err == nil {
		t.Fatal("hashed [host]:2222 entry must not match port 2200")
	}

	plain := filepath.Join(dir, "plain")
	if err := appendKnownHost(plain, "plain.example.com:2222", key, false); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(plain); !strings.HasPrefix(string(data), "[plain.example.com]:2222 ") {
		t.Fatalf("unexpected plain entry %q", data)
	}
}

func writePhase4KnownHosts(t *testing.T, path, host string, key cryptoSSH.PublicKey) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(host)}, key) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPhase4_GlobalKnownHostsFiles(t *testing.T) {
	dir := t.TempDir()
	key := newPhase4HostKey(t)
	otherKey := newPhase4HostKey(t)
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}

	globalFile := filepath.Join(dir, "etc", "ssh_known_hosts")
	writePhase4KnownHosts(t, globalFile, "global.example.com:22", key)
	missingGlobal := filepath.Join(dir, "etc", "missing_known_hosts")

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = filepath.Join(dir, ".ssh", "known_hosts")
	env.GlobalKnownHostsFiles = []string{missingGlobal, globalFile, filepath.Join(dir, "etc")}
	conn := NewConnector(nil, WithEnvironment(env))
	cfg := &ClientConfig{NodeID: "n", Address: "global.example.com", Port: 22, User: "alice"}

	// Default user file + environment globals: verified via global, user file is the only write target.
	primary, noWrite, cb, err := conn.openKnownHostsCallback("", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if primary != env.KnownHostsFile || noWrite {
		t.Fatalf("primary=%q noWrite=%v", primary, noWrite)
	}
	if err := cb("global.example.com:22", addr, key); err != nil {
		t.Fatalf("global known host must verify: %v", err)
	}
	var keyErr *knownhosts.KeyError
	if err := cb("global.example.com:22", addr, otherKey); !errors.As(err, &keyErr) || len(keyErr.Want) == 0 {
		t.Fatalf("conflicting key in global file must report Want, got %v", err)
	}
	if _, err := os.Stat(missingGlobal); !os.IsNotExist(err) {
		t.Fatal("missing global known_hosts file must not be created")
	}
	assertPhase4GlobalNoneModes(t, conn, cfg, key)
	assertPhase4CustomGlobal(t, conn, dir, key)
}

func assertPhase4GlobalNoneModes(t *testing.T, conn *Connector, cfg *ClientConfig, key cryptoSSH.PublicKey) {
	t.Helper()
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	var keyErr *knownhosts.KeyError
	// UserKnownHostsFile=none: no write target, globals still verify.
	primary, noWrite, cb, err := conn.openKnownHostsCallback("none", cfg)
	if err != nil || primary != "" || !noWrite {
		t.Fatalf("none: primary=%q noWrite=%v err=%v", primary, noWrite, err)
	}
	if err := cb("global.example.com:22", addr, key); err != nil {
		t.Fatalf("UserKnownHostsFile=none must still verify against globals: %v", err)
	}

	// GlobalKnownHostsFile=none disables globals.
	cfgNone := *cfg
	cfgNone.Options = MustOptions(OptionGlobalKnownHostsFile, "none")
	_, _, cb, err = conn.openKnownHostsCallback("none", &cfgNone)
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("global.example.com:22", addr, key); !errors.As(err, &keyErr) || len(keyErr.Want) != 0 {
		t.Fatalf("GlobalKnownHostsFile=none must leave host unknown, got %v", err)
	}
}

func assertPhase4CustomGlobal(t *testing.T, conn *Connector, dir string, key cryptoSSH.PublicKey) {
	t.Helper()
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	// Custom GlobalKnownHostsFile with ~ and %h tokens overrides environment defaults.
	customGlobal := filepath.Join(dir, "global-custom.example.com.hosts")
	writePhase4KnownHosts(t, customGlobal, "custom.example.com:22", key)
	cfgCustom := ClientConfig{NodeID: "n", Address: "global-custom.example.com", Port: 22, User: "alice",
		Options: MustOptions(OptionGlobalKnownHostsFile, "~/%h.hosts ~/does-not-exist")}
	customUser := filepath.Join(dir, "custom_user_known_hosts")
	primary, noWrite, cb, err := conn.openKnownHostsCallback(customUser, &cfgCustom)
	if err != nil || primary != customUser || noWrite {
		t.Fatalf("custom: primary=%q noWrite=%v err=%v", primary, noWrite, err)
	}
	if err := cb("custom.example.com:22", addr, key); err != nil {
		t.Fatalf("custom global must verify: %v", err)
	}
	if err := cb("global.example.com:22", addr, key); err == nil {
		t.Fatal("custom GlobalKnownHostsFile must replace environment defaults")
	}
	if _, err := os.Stat(customUser); !os.IsNotExist(err) {
		t.Fatal("custom user known_hosts must not be created on open")
	}
}

type phase4Confirmer struct {
	calls  atomic.Int32
	status atomic.Value
	accept bool
}

func (p *phase4Confirmer) ConfirmHostKey(_ context.Context, req HostKeyConfirmation) (bool, error) {
	p.calls.Add(1)
	p.status.Store(req.SSHFPStatus)
	return p.accept, nil
}

func (p *phase4Confirmer) lastStatus() SSHFPVerifyStatus {
	v, _ := p.status.Load().(SSHFPVerifyStatus)
	return v
}

func TestPhase4_VerifyHostKeyDNSFailClosedMatrix(t *testing.T) {
	key := newPhase4HostKey(t)
	good := sshfpSHA256(key)
	bad := make([]byte, 32)

	verified := SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{4, 2, good}}}
	unverified := SSHFPResult{Records: []SSHFPRecord{{4, 2, good}}}
	mismatch := SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{4, 2, bad}}}

	type tc struct {
		name           string
		strict         string
		dns            string
		batch          bool
		acceptFlag     bool
		conflict       bool
		address        string
		result         SSHFPResult
		lookupErr      error
		confirm        bool
		wantErr        error
		wantPrompt     bool
		wantStatus     SSHFPVerifyStatus
		wantWritten    bool
		wantNoLookup   bool
		hashKnownHosts bool
	}
	cases := []tc{
		{name: "conflict beats verified DNS", strict: "ask", dns: "yes", conflict: true, result: verified, wantErr: ErrHostKeyMismatch, wantNoLookup: true},
		{name: "strict yes beats verified DNS", strict: "yes", dns: "yes", result: verified, wantErr: ErrHostKeyMismatch, wantNoLookup: true},
		{name: "strict no opts out of SSHFP lookup even on mismatch", strict: "no", dns: "yes", result: mismatch, wantWritten: true, wantNoLookup: true},
		{name: "ask + verified + dns yes accepts without prompt or write", strict: "ask", dns: "yes", result: verified},
		{name: "ask + batch + verified + dns yes accepts", strict: "ask", dns: "yes", batch: true, result: verified},
		{name: "accept-new + verified writes", strict: "accept-new", dns: "yes", result: verified, wantWritten: true},
		{name: "accept-new + verified writes hashed", strict: "accept-new", dns: "yes", result: verified, wantWritten: true, hashKnownHosts: true},
		{name: "accept-new + unverified writes", strict: "accept-new", dns: "yes", result: unverified, wantWritten: true},
		{name: "accept-new + mismatch + batch fails closed", strict: "accept-new", dns: "yes", batch: true, result: mismatch, wantErr: ErrHostKeyMismatch},
		{name: "accept-new + mismatch prompts", strict: "accept-new", dns: "yes", result: mismatch, confirm: true, wantPrompt: true, wantStatus: SSHFPStatusMismatch, wantWritten: true},
		{name: "accept-new + mismatch prompt rejected", strict: "accept-new", dns: "yes", result: mismatch, wantErr: ErrHostKeyMismatch, wantPrompt: true, wantStatus: SSHFPStatusMismatch},
		{name: "ask + mismatch + AcceptNewHostKey fails closed", strict: "ask", dns: "yes", acceptFlag: true, result: mismatch, wantErr: ErrHostKeyMismatch},
		{name: "ask + unverified prompts", strict: "ask", dns: "yes", result: unverified, confirm: true, wantPrompt: true, wantStatus: SSHFPStatusMatchedUnverified, wantWritten: true},
		{name: "ask + unverified + batch requires interaction", strict: "ask", dns: "yes", batch: true, result: unverified, wantErr: ErrInteractionRequired},
		{name: "dns ask + verified still prompts", strict: "ask", dns: "ask", result: verified, confirm: true, wantPrompt: true, wantStatus: SSHFPStatusMatchedVerified, wantWritten: true},
		{name: "dns no skips lookup", strict: "ask", dns: "no", result: verified, confirm: true, wantPrompt: true, wantWritten: true, wantNoLookup: true},
		{name: "lookup error degrades to prompt", strict: "ask", dns: "yes", lookupErr: errors.New("servfail"), confirm: true, wantPrompt: true, wantWritten: true},
		{name: "IP literal skips lookup", strict: "ask", dns: "yes", address: "192.0.2.10", result: verified, confirm: true, wantPrompt: true, wantWritten: true, wantNoLookup: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			khFile := filepath.Join(dir, "known_hosts")
			var lookups atomic.Int32
			env := fixtureEnvironment()
			env.HomeDir = dir
			env.LookupSSHFP = func(_ context.Context, host string) (SSHFPResult, error) {
				lookups.Add(1)
				if host != "dns.example.com" {
					t.Errorf("unexpected SSHFP lookup host %q", host)
				}
				return c.result, c.lookupErr
			}
			confirmer := &phase4Confirmer{accept: c.confirm}
			conn := NewConnector(nil, WithEnvironment(env), WithHostKeyConfirmer(confirmer))
			conn.AcceptNewHostKey.Store(c.acceptFlag)

			address := c.address
			if address == "" {
				address = "dns.example.com"
			}
			opts := MustOptions(OptionVerifyHostKeyDNS, c.dns)
			if c.hashKnownHosts {
				_ = opts.Set(OptionHashKnownHosts, "yes")
			}
			cfg := &ClientConfig{NodeID: "n", Address: address, Port: 22, User: "alice", Options: opts}
			keyErr := &knownhosts.KeyError{}
			if c.conflict {
				keyErr.Want = []knownhosts.KnownKey{{Key: newPhase4HostKey(t), Filename: khFile, Line: 1}}
			}
			hostname := address + ":22"
			err := conn.handleKnownHostsKeyError(t.Context(), nil, cfg, keyErr, c.strict, c.batch, false, khFile, hostname, nil, key, nil)

			if c.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("error = %v, want %v", err, c.wantErr)
			}
			if got := confirmer.calls.Load() > 0; got != c.wantPrompt {
				t.Fatalf("prompted = %v, want %v", got, c.wantPrompt)
			}
			if c.wantPrompt && confirmer.lastStatus() != c.wantStatus {
				t.Fatalf("prompt SSHFPStatus = %q, want %q", confirmer.lastStatus(), c.wantStatus)
			}
			if c.wantNoLookup && lookups.Load() != 0 {
				t.Fatalf("expected no SSHFP lookup, got %d", lookups.Load())
			}
			data, readErr := os.ReadFile(khFile)
			written := readErr == nil && len(data) > 0
			if written != c.wantWritten {
				t.Fatalf("known_hosts written = %v, want %v (%q)", written, c.wantWritten, data)
			}
			if written && c.hashKnownHosts && !strings.HasPrefix(string(data), "|1|") {
				t.Fatalf("expected hashed entry, got %q", data)
			}
		})
	}
}

func TestPhase4_SSHFPLookupBoundedByConnectTimeout(t *testing.T) {
	key := newPhase4HostKey(t)
	var deadline atomic.Value
	env := fixtureEnvironment()
	env.LookupSSHFP = func(ctx context.Context, _ string) (SSHFPResult, error) {
		d, ok := ctx.Deadline()
		if !ok {
			t.Error("SSHFP lookup context has no deadline")
		}
		deadline.Store(d)
		return SSHFPResult{}, nil
	}
	conn := NewConnector(nil, WithEnvironment(env))
	cfg := &ClientConfig{NodeID: "n", Address: "dns.example.com", Port: 22, User: "u",
		Options: MustOptions(OptionVerifyHostKeyDNS, "yes", OptionConnectTimeout, "1")}
	start := time.Now()
	conn.lookupSSHFPStatus(t.Context(), nil, cfg, key)
	d, _ := deadline.Load().(time.Time)
	if remaining := d.Sub(start); remaining > 1500*time.Millisecond || remaining <= 0 {
		t.Fatalf("lookup deadline %s, want <= ConnectTimeout(1s)", remaining)
	}

	cfg.Options = MustOptions(OptionVerifyHostKeyDNS, "yes", OptionConnectTimeout, "60")
	start = time.Now()
	conn.lookupSSHFPStatus(t.Context(), nil, cfg, key)
	d, _ = deadline.Load().(time.Time)
	if remaining := d.Sub(start); remaining > sshfpLookupTimeout+500*time.Millisecond {
		t.Fatalf("lookup deadline %s, want capped at %s", remaining, sshfpLookupTimeout)
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	env.LookupSSHFP = func(ctx context.Context, _ string) (SSHFPResult, error) {
		return SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{4, 2, sshfpSHA256(key)}}}, ctx.Err()
	}
	conn = NewConnector(nil, WithEnvironment(env))
	if got := conn.lookupSSHFPStatus(canceled, nil, cfg, key); got != SSHFPStatusNone {
		t.Fatalf("canceled lookup status = %q, want none", got)
	}
}

func TestPhase4_OriginalHostPropagatesToTokenExpansion(t *testing.T) {
	cfg := &ClientConfig{NodeID: "web", OriginalHost: " web-alias ", Address: "web.corp.example.com", Port: 22, User: "alice", ProxyJump: ""}
	conn := NewConnector(nil, WithEnvironment(fixtureEnvironment()))

	if got := knownHostsTarget(cfg); got.OriginalHost != "web-alias" || got.Host != "web.corp.example.com" {
		t.Fatalf("knownHostsTarget = %+v", got)
	}
	if got := conn.authTargetContext(cfg); got.OriginalHost != "web-alias" {
		t.Fatalf("authTargetContext OriginalHost = %q", got.OriginalHost)
	}
	if got := conn.buildTargetContext(connectionPlanNode{name: "web", cfg: cfg}); got.OriginalHost != "web-alias" {
		t.Fatalf("buildTargetContext OriginalHost = %q", got.OriginalHost)
	}
	expanded, err := ExpandControlPath("/tmp/%n-%h", fixtureEnvironment(), conn.authTargetContext(cfg))
	if err != nil || expanded != "/tmp/web-alias-web.corp.example.com" {
		t.Fatalf("ExpandControlPath = %q, %v", expanded, err)
	}

	noAlias := &ClientConfig{NodeID: "web", Address: "web.corp.example.com", Port: 22, User: "alice"}
	if got := knownHostsTarget(noAlias); got.OriginalHost != "web" {
		t.Fatalf("fallback OriginalHost = %q, want NodeID", got.OriginalHost)
	}

	connCfg := cfg.ToConnectionConfig()
	if connCfg.OriginalHost != "web-alias" {
		t.Fatalf("ToConnectionConfig OriginalHost = %q, want %q", connCfg.OriginalHost, "web-alias")
	}
	if back := clientConfigFromPlan(connCfg); back.OriginalHost != connCfg.OriginalHost {
		t.Fatalf("clientConfigFromPlan OriginalHost = %q", back.OriginalHost)
	}
	k1, err := ConnectionKey(ConnectionPlan{Scope: "s", Hops: []ConnectionConfig{connCfg}})
	if err != nil {
		t.Fatal(err)
	}
	other := connCfg.Clone()
	other.OriginalHost = "other-alias"
	k2, err := ConnectionKey(ConnectionPlan{Scope: "s", Hops: []ConnectionConfig{other}})
	if err != nil {
		t.Fatal(err)
	}
	if k1 == k2 {
		t.Fatal("OriginalHost (%n) must isolate ConnectionKey")
	}
}
