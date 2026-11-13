package ssh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type testDebugLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *testDebugLogger) Debug(msg string, args ...any) {
	l.Debugf("%s %v", msg, args)
}

func (l *testDebugLogger) Debugf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, fmt.Sprintf(format, args...))
}

func (l *testDebugLogger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.msgs)
}

func TestPhase2_OptionSpecsAndAccessors(t *testing.T) {
	assertPhase2NilOptionAccessors(t)
	assertPhase2OptionRegistrySpecs(t)
	opts := buildPopulatedPhase2Options(t)
	assertPhase2OptionSerializationRoundTrip(t, opts)
	assertPhase2SessionOptionsStrippedFromPlan(t, opts)
}

func assertPhase2NilOptionAccessors(t *testing.T) {
	t.Helper()
	var nilOpts *Options
	if nilOpts.SendEnvPatterns() != nil || nilOpts.SetEnvDirectives() != nil {
		t.Fatal("expected nil slice accessors on nil *Options")
	}
	if nilOpts.RemoteCommand() != "" || nilOpts.EscapeChar() != "" {
		t.Fatal("expected empty string accessors on nil *Options")
	}
}

func assertPhase2OptionRegistrySpecs(t *testing.T) {
	t.Helper()
	checks := []struct {
		key         string
		openSSHName string
		multi       bool
	}{
		{OptionSendEnv, "SendEnv", true},
		{OptionSetEnv, "SetEnv", true},
		{OptionRemoteCommand, "RemoteCommand", false},
		{OptionEscapeChar, "EscapeChar", false},
	}
	for _, tc := range checks {
		spec, ok := LookupOptionSpec(tc.openSSHName)
		if !ok || spec.CanonicalKey != tc.key || spec.OpenSSHName != tc.openSSHName || spec.Class != OptionClassSession || spec.MultiValue != tc.multi {
			t.Fatalf("unexpected OptionSpec for %q: %+v (ok=%v)", tc.openSSHName, spec, ok)
		}
	}
}

func buildPopulatedPhase2Options(t *testing.T) *Options {
	t.Helper()
	opts := &Options{}
	if err := opts.Append("SendEnv", "LANG LC_*"); err != nil {
		t.Fatalf("Append(SendEnv): %v", err)
	}
	if err := opts.Append("SendEnv", "-LC_ALL"); err != nil {
		t.Fatalf("Append(SendEnv -LC_ALL): %v", err)
	}
	if err := opts.Append("SetEnv", `FOO="bar baz"`); err != nil {
		t.Fatalf("Append(SetEnv): %v", err)
	}
	if err := opts.Set("RemoteCommand", "  NoNe "); err != nil || opts.RemoteCommand() != "none" {
		t.Fatalf("Set(RemoteCommand, NoNe) = (%q, %v)", opts.RemoteCommand(), err)
	}
	if err := opts.Set("RemoteCommand", "tmux attach -t %u"); err != nil {
		t.Fatalf("Set(RemoteCommand): %v", err)
	}
	if err := opts.Set("EscapeChar", "^A"); err != nil {
		t.Fatalf("Set(EscapeChar, ^A): %v", err)
	}
	if !slices.Equal(opts.SendEnvPatterns(), []string{"LANG", "LC_*", "-LC_ALL"}) {
		t.Fatalf("SendEnvPatterns() = %v", opts.SendEnvPatterns())
	}
	if !slices.Equal(opts.SetEnvDirectives(), []string{`FOO="bar baz"`}) {
		t.Fatalf("SetEnvDirectives() = %v", opts.SetEnvDirectives())
	}
	if opts.RemoteCommand() != "tmux attach -t %u" || opts.EscapeChar() != "^A" {
		t.Fatalf("unexpected RemoteCommand/EscapeChar: %q / %q", opts.RemoteCommand(), opts.EscapeChar())
	}
	return opts
}

func assertPhase2OptionSerializationRoundTrip(t *testing.T, opts *Options) {
	t.Helper()
	yamlBytes, err := yaml.Marshal(opts)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	var fromYAML Options
	if err := yaml.Unmarshal(yamlBytes, &fromYAML); err != nil || !fromYAML.Equal(opts) {
		t.Fatalf("YAML round-trip failed: err=%v got=%+v", err, &fromYAML)
	}

	jsonBytes, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var fromJSON Options
	if err := json.Unmarshal(jsonBytes, &fromJSON); err != nil || !fromJSON.Equal(opts) {
		t.Fatalf("JSON round-trip failed: err=%v got=%+v", err, &fromJSON)
	}
}

func assertPhase2SessionOptionsStrippedFromPlan(t *testing.T, opts *Options) {
	t.Helper()
	provider := &mapTestProvider{
		configs: map[string]*ClientConfig{
			"node-a": {
				NodeID:   "node-a",
				Address:  "10.0.0.10",
				Port:     22,
				User:     "ops",
				AuthType: "password",
				Options:  opts,
			},
			"node-b": {
				NodeID:   "node-b",
				Address:  "10.0.0.10",
				Port:     22,
				User:     "ops",
				AuthType: "password",
			},
		},
	}
	planA, err := CapturePlan(t.Context(), provider, "node-a", "test-scope")
	if err != nil {
		t.Fatalf("CapturePlan(node-a): %v", err)
	}
	planB, err := CapturePlan(t.Context(), provider, "node-b", "test-scope")
	if err != nil {
		t.Fatalf("CapturePlan(node-b): %v", err)
	}
	if planA.Hops[0].Options != nil {
		t.Fatalf("expected OptionClassSession options to be stripped from CapturePlan hop, got %+v", planA.Hops[0].Options)
	}
	planB.Hops[0].NodeID = "node-a"
	keyA, err := ConnectionKey(planA)
	if err != nil {
		t.Fatalf("ConnectionKey(planA): %v", err)
	}
	keyB, err := ConnectionKey(planB)
	if err != nil {
		t.Fatalf("ConnectionKey(planB): %v", err)
	}
	if keyA != keyB {
		t.Fatalf("session-class options leaked into ConnectionKey: %s vs %s", keyA, keyB)
	}
}

func TestPhase2_ParseEscapeChar(t *testing.T) {
	cases := []struct {
		spec        string
		wantCh      byte
		wantEnabled bool
		wantErr     bool
	}{
		{spec: "none", wantCh: 0, wantEnabled: false},
		{spec: "NONE", wantCh: 0, wantEnabled: false},
		{spec: " ~ ", wantCh: '~', wantEnabled: true},
		{spec: "#", wantCh: '#', wantEnabled: true},
		{spec: "^A", wantCh: 0x01, wantEnabled: true},
		{spec: "^a", wantCh: 0x01, wantEnabled: true},
		{spec: "^Z", wantCh: 0x1a, wantEnabled: true},
		{spec: "^z", wantCh: 0x1a, wantEnabled: true},
		{spec: "^?", wantCh: 0x7f, wantEnabled: true},
		{spec: "", wantErr: true},
		{spec: "   ", wantErr: true},
		{spec: "~~", wantErr: true},
		{spec: "^@", wantErr: true},
		{spec: "^[", wantErr: true},
		{spec: "\x01", wantErr: true},
		{spec: "abc", wantErr: true},
	}

	for _, tc := range cases {
		ch, enabled, err := ParseEscapeChar(tc.spec)
		if tc.wantErr {
			if !errors.Is(err, ErrSSHOptionsValidation) {
				t.Fatalf("ParseEscapeChar(%q) error = %v, want wrapping ErrSSHOptionsValidation", tc.spec, err)
			}
			continue
		}
		if err != nil || ch != tc.wantCh || enabled != tc.wantEnabled {
			t.Fatalf("ParseEscapeChar(%q) = (0x%02x, %v, %v), want (0x%02x, %v, nil)", tc.spec, ch, enabled, err, tc.wantCh, tc.wantEnabled)
		}
	}
}

func TestPhase2_ExpandRemoteCommand(t *testing.T) {
	env := Environment{
		HomeDir:   `/home/localuser`,
		LocalUser: "localuser",
		LocalHost: "workstation.corp.example",
		LocalUID:  "1001",
	}
	target := TargetContext{
		Host:         "10.20.30.40",
		OriginalHost: "app-prod",
		Port:         2222,
		User:         "deploy",
		JumpHost:     "bastion.corp",
	}
	hash := ComputeConnectionHash(env.LocalHost, target.Host, "2222", target.User, target.JumpHost)

	pattern := `exec /opt/bin//run --win 'C:\Tools\bin' --tilde ~/keep --env $HOME --user %r --host %h --orig %n --port %p --luser %u --uid %i --home %d --lhost %l --short %L --hash %C --pct %%`
	got, err := ExpandRemoteCommand(pattern, env, target)
	if err != nil {
		t.Fatalf("ExpandRemoteCommand failed: %v", err)
	}
	want := fmt.Sprintf(
		`exec /opt/bin//run --win 'C:\Tools\bin' --tilde ~/keep --env $HOME --user deploy --host 10.20.30.40 --orig app-prod --port 2222 --luser localuser --uid 1001 --home /home/localuser --lhost workstation.corp.example --short workstation --hash %s --pct %%`,
		hash,
	)
	if got != want {
		t.Fatalf("ExpandRemoteCommand mismatch:\n got: %s\nwant: %s", got, want)
	}
	if noneOut, err := ExpandRemoteCommand("  NoNe ", env, target); err != nil || noneOut != "none" {
		t.Fatalf("ExpandRemoteCommand(NoNe) = (%q, %v), want (none, nil)", noneOut, err)
	}
	if emptyOut, err := ExpandRemoteCommand("   ", env, target); err != nil || emptyOut != "" {
		t.Fatalf("ExpandRemoteCommand(blank) = (%q, %v), want (\"\", nil)", emptyOut, err)
	}
	for _, bad := range []string{"echo %j", "echo %z", "echo %", "echo \x00"} {
		if _, err := ExpandRemoteCommand(bad, env, target); err == nil {
			t.Fatalf("ExpandRemoteCommand(%q) succeeded, want error", bad)
		}
	}
}

func TestPhase2_ResolveSessionEnv_PrecedenceGlobsDenylistAndBounds(t *testing.T) {
	t.Run("four-tier merge, negative SendEnv, and quoted SetEnv overrides", assertPhase2TierMergeAndQuotes)
	t.Run("hardcoded non-bypassable denylist under SendEnv wildcard", assertPhase2SendEnvDenylist)
	t.Run("variable count, entry size, and identifier validation bounds", assertPhase2SessionEnvBounds)
}

func assertPhase2TierMergeAndQuotes(t *testing.T) {
	tier4 := &Options{}
	_ = tier4.Append("SendEnv", "LC_* LANG")
	_ = tier4.Append("SetEnv", "FOO=tier4 SHARED=from_set_t4")

	tier3 := &Options{}
	_ = tier3.Append("SendEnv", "-LC_ALL")
	_ = tier3.Append("SetEnv", "FOO=tier3")

	tier2 := &Options{}
	_ = tier2.Append("SendEnv", "-LANG")
	_ = tier2.Append("SetEnv", `FOO=tier2 QUOTED="hello world" "FULL_QUOTED=one two"`)

	tier1 := &Options{}
	_ = tier1.Append("SendEnv", "LC_ALL")
	_ = tier1.Append("SetEnv", `FOO=tier1 WIN_PATH="C:\\Tools\\bin" SINGLE='a b c'`)

	merged, err := EffectiveOptions(tier1, tier2, tier3, tier4)
	if err != nil {
		t.Fatalf("EffectiveOptions: %v", err)
	}
	hostEnv := func() []string {
		return []string{
			"LANG=en_US.UTF-8",
			"LC_CTYPE=UTF-8",
			"LC_ALL=C",
			"SHARED=from_host",
			"UNMATCHED=ignored",
		}
	}

	vars, err := ResolveSessionEnv(merged, hostEnv)
	if err != nil {
		t.Fatalf("ResolveSessionEnv: %v", err)
	}
	gotMap := make(map[string]string, len(vars))
	for _, ev := range vars {
		gotMap[ev.Name] = ev.Value
	}
	if _, exists := gotMap["LANG"]; exists {
		t.Fatalf("expected Tier 2 -LANG to suppress LANG, got %v", vars)
	}
	wantPairs := map[string]string{
		"LC_CTYPE":    "UTF-8",
		"LC_ALL":      "C",
		"FOO":         "tier1",
		"SHARED":      "from_set_t4",
		"QUOTED":      "hello world",
		"FULL_QUOTED": "one two",
		"SINGLE":      "a b c",
		"WIN_PATH":    `C:\Tools\bin`,
	}
	for k, wantVal := range wantPairs {
		if gotMap[k] != wantVal {
			t.Fatalf("env[%q] = %q, want %q", k, gotMap[k], wantVal)
		}
	}
}

func assertPhase2SendEnvDenylist(t *testing.T) {
	wildcardOpts := MustOptions(OptionSendEnv, "*")
	deniedEnv := func() []string {
		return []string{
			"XOPS_MASTER_KEY=secret1",
			"xops_token=secret2",
			"SSH_ASKPASS=/tmp/evil",
			"SSH_ASKPASS_REQUIRE=force",
			"SSH_AUTH_SOCK=/tmp/agent.sock",
			"SSH_AGENT_PID=1234",
			"KRB5CCNAME=FILE:/tmp/krb5cc",
			"LD_PRELOAD=/tmp/evil.so",
			"LD_LIBRARY_PATH=/tmp/lib",
			"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
			"AWS_SECRET_ACCESS_KEY=secret3",
			"GITHUB_TOKEN=ghp_secret",
			"SAFE_APP_VAR=allowed_value",
		}
	}
	filtered, err := ResolveSessionEnv(wildcardOpts, deniedEnv)
	if err != nil {
		t.Fatalf("ResolveSessionEnv(SendEnv *): %v", err)
	}
	if len(filtered) != 1 || filtered[0] != (EnvVar{Name: "SAFE_APP_VAR", Value: "allowed_value"}) {
		t.Fatalf("denylist failed under SendEnv *: got %+v", filtered)
	}
}

func assertPhase2SessionEnvBounds(t *testing.T) {
	tooManyOpts := MustOptions(OptionSendEnv, "VAR_*")
	manyEnv := make([]string, 0, MaxSessionEnvVars+1)
	for i := range MaxSessionEnvVars + 1 {
		manyEnv = append(manyEnv, fmt.Sprintf("VAR_%03d=val", i))
	}
	if _, err := ResolveSessionEnv(tooManyOpts, func() []string { return manyEnv }); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("expected >%d env vars to fail with ErrSSHOptionsValidation, got %v", MaxSessionEnvVars, err)
	}

	hugeVal := strings.Repeat("a", MaxSessionEnvEntryBytes)
	hugeOpts := MustOptions(OptionSendEnv, "HUGE_VAR")
	if _, err := ResolveSessionEnv(hugeOpts, func() []string { return []string{"HUGE_VAR=" + hugeVal} }); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("expected >32KiB env entry to fail with ErrSSHOptionsValidation, got %v", err)
	}

	badOpts := &Options{}
	for _, bad := range []string{"1BAD=val", "BAD-NAME=val", "NO_EQUALS", `UNCLOSED="abc`} {
		if err := badOpts.Append("SetEnv", bad); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Fatalf("Append(SetEnv, %q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}
}

type recordedChannelSession struct {
	reqOrder  []string
	envVars   []EnvVar
	subsystem string
	command   string
	gotPTY    bool
}

type phase2ServerConfig struct {
	rejectEnv   bool
	hangEnv     bool
	exitStatus  uint32
	onSubsystem func(name string, ch cryptoSSH.Channel) uint32
	onExec      func(cmd string, ch cryptoSSH.Channel) (handled bool, status uint32)
	resolver    SecretResolver
}

func startPhase2FakeSSHClient(t *testing.T, clientCfg ClientConfig, env Environment, srvCfg phase2ServerConfig) (*Client, func() []recordedChannelSession, *testDebugLogger) {
	t.Helper()
	listener, sshSrvCfg := startKeepAliveTestSSHServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)

	var (
		mu       sync.Mutex
		sessions []recordedChannelSession
		wg       sync.WaitGroup
	)
	recordSession := func(rec recordedChannelSession) {
		mu.Lock()
		sessions = append(sessions, rec)
		mu.Unlock()
	}

	var client *Client
	t.Cleanup(func() {
		cancel()
		if client != nil {
			_ = client.Close()
		}
		_ = listener.Close()
		wg.Wait()
	})

	wg.Go(func() {
		acceptPhase2FakeSSHConns(ctx, listener, sshSrvCfg, srvCfg, &wg, recordSession)
	})

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("net.DialTimeout: %v", err)
	}
	raw, chans, reqs, err := cryptoSSH.NewClientConn(conn, listener.Addr().String(), &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password("test")},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		_ = conn.Close()
		t.Fatalf("NewClientConn: %v", err)
	}
	dbg := &testDebugLogger{}
	if clientCfg.Address == "" {
		clientCfg.Address = "test-host.example"
	}
	client = newClientWithLogger(cryptoSSH.NewClient(raw, chans, reqs), conn, &clientCfg, nil, "", dbg)
	client.resolver = srvCfg.resolver
	client.environment = sanitizeEnvironment(env)
	client.handshakeTimeout = 300 * time.Millisecond

	snapshot := func() []recordedChannelSession {
		mu.Lock()
		defer mu.Unlock()
		return cloneRecordedSessions(sessions)
	}
	return client, snapshot, dbg
}

func cloneRecordedSessions(src []recordedChannelSession) []recordedChannelSession {
	out := make([]recordedChannelSession, len(src))
	for i, s := range src {
		out[i] = recordedChannelSession{
			reqOrder:  slices.Clone(s.reqOrder),
			envVars:   slices.Clone(s.envVars),
			subsystem: s.subsystem,
			command:   s.command,
			gotPTY:    s.gotPTY,
		}
	}
	return out
}

func acceptPhase2FakeSSHConns(
	ctx context.Context,
	listener net.Listener,
	sshSrvCfg *cryptoSSH.ServerConfig,
	srvCfg phase2ServerConfig,
	wg *sync.WaitGroup,
	recordSession func(recordedChannelSession),
) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		wg.Go(func() {
			defer func() { _ = conn.Close() }()
			srvConn, chans, reqs, err := cryptoSSH.NewServerConn(conn, sshSrvCfg)
			if err != nil {
				return
			}
			stop := context.AfterFunc(ctx, func() { _ = srvConn.Close() })
			defer stop()
			defer func() { _ = srvConn.Close() }()
			wg.Go(func() { cryptoSSH.DiscardRequests(reqs) })

			for newCh := range chans {
				if newCh.ChannelType() != "session" {
					_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
					continue
				}
				ch, chReqs, err := newCh.Accept()
				if err != nil {
					continue
				}
				wg.Go(func() {
					servePhase2SessionChannel(ctx, ch, chReqs, srvCfg, recordSession)
				})
			}
		})
	}
}

func servePhase2SessionChannel(
	ctx context.Context,
	ch cryptoSSH.Channel,
	chReqs <-chan *cryptoSSH.Request,
	srvCfg phase2ServerConfig,
	recordSession func(recordedChannelSession),
) {
	defer func() { _ = ch.Close() }()
	var rec recordedChannelSession
	defer func() { recordSession(rec) }()

	for req := range chReqs {
		rec.reqOrder = append(rec.reqOrder, req.Type)
		if done := dispatchPhase2ChannelReq(ctx, ch, req, srvCfg, &rec); done {
			return
		}
	}
}

func dispatchPhase2ChannelReq(
	ctx context.Context,
	ch cryptoSSH.Channel,
	req *cryptoSSH.Request,
	srvCfg phase2ServerConfig,
	rec *recordedChannelSession,
) bool {
	switch req.Type {
	case "env":
		var payload struct{ Name, Value string }
		_ = cryptoSSH.Unmarshal(req.Payload, &payload)
		rec.envVars = append(rec.envVars, EnvVar{Name: payload.Name, Value: payload.Value})
		if srvCfg.hangEnv {
			<-ctx.Done()
			return true
		}
		replyIfWanted(req, !srvCfg.rejectEnv)
		return false
	case "pty-req":
		rec.gotPTY = true
		replyIfWanted(req, true)
		return false
	case "window-change":
		replyIfWanted(req, true)
		return false
	case "exec":
		var payload struct{ Command string }
		_ = cryptoSSH.Unmarshal(req.Payload, &payload)
		rec.command = payload.Command
		replyIfWanted(req, true)
		if srvCfg.onExec != nil {
			if handled, status := srvCfg.onExec(payload.Command, ch); handled {
				sendExitStatus(ch, status)
				return true
			}
		}
		handlePhase2Exec(ch, payload.Command, srvCfg.exitStatus)
		return true
	case "shell":
		replyIfWanted(req, true)
		_, _ = io.WriteString(ch, "shell-ok\n")
		sendExitStatus(ch, srvCfg.exitStatus)
		return true
	case "subsystem":
		var payload struct{ Value string }
		_ = cryptoSSH.Unmarshal(req.Payload, &payload)
		rec.subsystem = payload.Value
		replyIfWanted(req, true)
		status := srvCfg.exitStatus
		if srvCfg.onSubsystem != nil {
			status = srvCfg.onSubsystem(payload.Value, ch)
		}
		sendExitStatus(ch, status)
		return true
	default:
		replyIfWanted(req, false)
		return false
	}
}

func replyIfWanted(req *cryptoSSH.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func sendExitStatus(ch cryptoSSH.Channel, status uint32) {
	_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{status}))
}

func handlePhase2Exec(ch cryptoSSH.Channel, cmd string, defaultStatus uint32) {
	switch {
	case strings.Contains(cmd, "__XOPS_DIALECT_POSIX__"):
		_, _ = io.WriteString(ch, "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n")
		sendExitStatus(ch, 0)
	case strings.Contains(cmd, "__XOPS_INTERP_END__"):
		_, _ = io.WriteString(ch, "__XOPS_INTERP__:bash\n__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n")
		sendExitStatus(ch, 0)
	case strings.Contains(cmd, "id -u"):
		_, _ = io.WriteString(ch, "0\n")
		sendExitStatus(ch, 0)
	default:
		_, _ = io.WriteString(ch, "exec-ok\n")
		sendExitStatus(ch, defaultStatus)
	}
}

func TestPhase2_SessionEnv_TransmissionRejectionAndProbeIsolation(t *testing.T) {
	opts := &Options{}
	_ = opts.Append("SendEnv", "LC_* XOPS_SECRET")
	_ = opts.Append("SetEnv", "APP_MODE=staging")
	env := Environment{
		Environ: func() []string {
			return []string{"LC_CTYPE=en_US.UTF-8", "XOPS_SECRET=never-send"}
		},
	}
	wantEnv := []EnvVar{
		{Name: "LC_CTYPE", Value: "en_US.UTF-8"},
		{Name: "APP_MODE", Value: "staging"},
	}

	t.Run("accepted before exec, pty-req, and subsystem", func(t *testing.T) {
		assertPhase2SessionEnvAcceptedOrder(t, opts, env, wantEnv)
	})
	t.Run("server rejecting env request logs debug and continues", func(t *testing.T) {
		assertPhase2SessionEnvRejectionContinues(t, opts, env)
	})
	t.Run("stalled env request respects bounded handshake timeout", func(t *testing.T) {
		client, _, _ := startPhase2FakeSSHClient(t, ClientConfig{Options: opts}, env, phase2ServerConfig{hangEnv: true})
		client.handshakeTimeout = 50 * time.Millisecond
		if err := client.RunSubsystemWithIO(t.Context(), "sftp", nil, io.Discard, io.Discard, false); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected DeadlineExceeded on stalled env request, got %v", err)
		}
	})
	t.Run("internal dialect and privilege probes never send SendEnv or SetEnv", func(t *testing.T) {
		assertPhase2ProbesOmitSessionEnv(t, opts, env)
	})
}

func assertPhase2SessionEnvAcceptedOrder(t *testing.T, opts *Options, env Environment, wantEnv []EnvVar) {
	client, snapshot, _ := startPhase2FakeSSHClient(t, ClientConfig{Options: opts}, env, phase2ServerConfig{})
	plan, err := PlanCommand("echo hi", CommandOptions{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res := client.ExecuteCommand(t.Context(), plan); res.Err() != nil {
		t.Fatalf("ExecuteCommand failed: %v", res.Err())
	}
	var out bytes.Buffer
	if err := client.RunCommandWithIO(t.Context(), "echo io", false, nil, &out, io.Discard); err != nil {
		t.Fatalf("RunCommandWithIO failed: %v", err)
	}
	if err := client.RunShellWithRemotePTY(t.Context(), nil, &out, io.Discard); err != nil {
		t.Fatalf("RunShellWithRemotePTY failed: %v", err)
	}
	if err := client.RunSubsystemWithIO(t.Context(), "netconf", nil, &out, io.Discard, false); err != nil {
		t.Fatalf("RunSubsystemWithIO failed: %v", err)
	}

	got := snapshot()
	wantOrders := [][]string{
		{"env", "env", "exec"},
		{"env", "env", "exec"},
		{"env", "env", "pty-req", "shell"},
		{"env", "env", "subsystem"},
	}
	if len(got) != len(wantOrders) {
		t.Fatalf("recorded %d sessions, want %d", len(got), len(wantOrders))
	}
	for i, s := range got {
		if !slices.Equal(s.reqOrder, wantOrders[i]) || !slices.Equal(s.envVars, wantEnv) {
			t.Fatalf("session %d = (%v, %+v), want (%v, %+v)", i, s.reqOrder, s.envVars, wantOrders[i], wantEnv)
		}
	}
}

func assertPhase2SessionEnvRejectionContinues(t *testing.T, opts *Options, env Environment) {
	client, snapshot, dbg := startPhase2FakeSSHClient(t, ClientConfig{Options: opts}, env, phase2ServerConfig{rejectEnv: true})
	plan, err := PlanCommand("echo hi", CommandOptions{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res := client.ExecuteCommand(t.Context(), plan); res.Err() != nil {
		t.Fatalf("ExecuteCommand failed when server rejected env: %v", res.Err())
	}
	var out bytes.Buffer
	if err := client.RunSubsystemWithIO(t.Context(), "sftp", nil, &out, io.Discard, false); err != nil {
		t.Fatalf("RunSubsystemWithIO failed when server rejected env: %v", err)
	}
	if len(snapshot()) != 2 {
		t.Fatalf("expected 2 completed sessions, got %d", len(snapshot()))
	}
	if !strings.Contains(strings.Join(dbg.snapshot(), "\n"), "rejected env variable") {
		t.Fatalf("expected debug log on env rejection, got %v", dbg.snapshot())
	}
}

func assertPhase2ProbesOmitSessionEnv(t *testing.T, opts *Options, env Environment) {
	client, snapshot, _ := startPhase2FakeSSHClient(t, ClientConfig{SudoMode: SudoModeAuto, Options: opts}, env, phase2ServerConfig{})
	probeRes, err := client.ProbeExecutionConfig(t.Context())
	if err != nil || probeRes.DetectedDialect != LaunchPOSIX {
		t.Fatalf("ProbeExecutionConfig = (%+v, %v)", probeRes, err)
	}
	if err := client.maybeDetectSudoMode(t.Context()); err != nil {
		t.Fatalf("maybeDetectSudoMode failed: %v", err)
	}
	for i, s := range snapshot() {
		if slices.Contains(s.reqOrder, "env") || len(s.envVars) > 0 {
			t.Fatalf("probe session %d leaked user env vars: order=%v env=%+v", i, s.reqOrder, s.envVars)
		}
	}
}

func TestPhase2_RunSubsystemWithIO_DirectMuxBinaryAndBorrowedStreams(t *testing.T) {
	binaryFrame := []byte("\x00\xffhello\r~.\n~^Z\r\n~#\r\n~?\x00end")
	t.Run("direct client binary transparency, PTY flag, exit propagation, and borrowed stdin", func(t *testing.T) {
		assertPhase2DirectSubsystem(t, binaryFrame)
	})
	t.Run("multiplexed MUX_C_PROXY follower subsystem execution", func(t *testing.T) {
		assertPhase2MuxFollowerSubsystem(t, binaryFrame)
	})
}

func assertPhase2DirectSubsystem(t *testing.T, binaryFrame []byte) {
	client, snapshot, _ := startPhase2FakeSSHClient(t, ClientConfig{
		Options: MustOptions(OptionEscapeChar, "~"),
	}, Environment{}, phase2ServerConfig{
		onSubsystem: func(name string, ch cryptoSSH.Channel) uint32 {
			data, _ := io.ReadAll(ch)
			_, _ = ch.Write(data)
			if name == "fail-42" {
				return 42
			}
			return 0
		},
	})

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = pipeR.Close() }()
	go func() {
		_, _ = pipeW.Write(binaryFrame)
		_ = pipeW.Close()
	}()

	var stdout bytes.Buffer
	if err := client.RunSubsystemWithIO(t.Context(), "netconf", pipeR, &stdout, io.Discard, false); err != nil {
		t.Fatalf("RunSubsystemWithIO(netconf) failed: %v", err)
	}
	if !bytes.Equal(stdout.Bytes(), binaryFrame) {
		t.Fatalf("binary subsystem payload corrupted:\n got: %x\nwant: %x", stdout.Bytes(), binaryFrame)
	}
	if _, statErr := pipeR.Stat(); errors.Is(statErr, os.ErrClosed) {
		t.Fatal("RunSubsystemWithIO closed borrowed *os.File stdin")
	}

	stdout.Reset()
	if err := client.RunSubsystemWithIO(t.Context(), "custom-pty", bytes.NewReader(binaryFrame), &stdout, io.Discard, true); err != nil {
		t.Fatalf("RunSubsystemWithIO(allocatePTY=true) failed: %v", err)
	}
	if !bytes.Equal(stdout.Bytes(), binaryFrame) {
		t.Fatalf("PTY subsystem payload mismatch:\n got: %x\nwant: %x", stdout.Bytes(), binaryFrame)
	}

	err = client.RunSubsystemWithIO(t.Context(), "fail-42", bytes.NewReader([]byte("ping")), io.Discard, io.Discard, false)
	var exitErr *CommandExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode == nil || *exitErr.ExitCode != 42 {
		t.Fatalf("RunSubsystemWithIO exit error = %v, want CommandExitError status 42", err)
	}
	for _, bad := range []string{"", "   ", "bad\x00sub"} {
		if err := client.RunSubsystemWithIO(t.Context(), bad, nil, io.Discard, io.Discard, false); !errors.Is(err, ErrExecutionValidation) {
			t.Fatalf("RunSubsystemWithIO(%q) = %v, want ErrExecutionValidation", bad, err)
		}
	}

	got := snapshot()
	if len(got) != 3 || got[0].gotPTY || got[0].subsystem != "netconf" || !got[1].gotPTY || got[1].subsystem != "custom-pty" {
		t.Fatalf("unexpected server sessions: %+v", got)
	}
}

func assertPhase2MuxFollowerSubsystem(t *testing.T, binaryFrame []byte) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	masterClient, snapshot, _ := startPhase2FakeSSHClient(t, ClientConfig{
		Address: "127.0.0.1",
		Port:    22,
		User:    "test",
	}, Environment{}, phase2ServerConfig{
		onSubsystem: func(_ string, ch cryptoSSH.Channel) uint32 {
			data, _ := io.ReadAll(ch)
			_, _ = ch.Write(data)
			return 0
		},
	})

	sockPath := filepath.Join(shortMuxSocketTempDir(t), "p2-subsys.sock")
	target := TargetContext{Host: "127.0.0.1", Port: 22, User: "test"}
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:     sockPath,
		PersistEnabled:  true,
		PersistDuration: 5 * time.Second,
		SSHClient:       masterClient.SSHClient(),
		Target:          target,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.Serve() }()
	defer func() {
		_ = srv.Shutdown()
		<-srvDone
	}()

	followerOpts := MustOptions(OptionSetEnv, "MUX_SUBSYS_ENV=from_follower")
	follower, err := DialControlProxyClient(ctx, sockPath, target, Environment{}, &ClientConfig{
		Address: "127.0.0.1",
		Port:    22,
		User:    "test",
		Options: followerOpts,
	}, log.NopLogger)
	if err != nil {
		t.Fatalf("DialControlProxyClient: %v", err)
	}
	defer func() { _ = follower.Close() }()

	var stdout bytes.Buffer
	subCtx, subCancel := context.WithTimeout(ctx, 5*time.Second)
	defer subCancel()
	if err := follower.RunSubsystemWithIO(subCtx, "netconf", bytes.NewReader(binaryFrame), &stdout, io.Discard, false); err != nil {
		t.Fatalf("follower.RunSubsystemWithIO(netconf) failed: %v", err)
	}
	if !bytes.Equal(stdout.Bytes(), binaryFrame) {
		t.Fatalf("MUX_C_PROXY subsystem binary frame mismatch:\n got: %x\nwant: %x", stdout.Bytes(), binaryFrame)
	}
	got := snapshot()
	if len(got) != 1 || got[0].subsystem != "netconf" || !slices.Equal(got[0].envVars, []EnvVar{{Name: "MUX_SUBSYS_ENV", Value: "from_follower"}}) {
		t.Fatalf("unexpected MUX_C_PROXY recorded session: %+v", got)
	}
}

func shortMuxSocketTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "xops-p2-")
	if err != nil {
		return t.TempDir()
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestPhase2_EscapeFilterStateMachine(t *testing.T) {
	t.Run("mid-line passthrough, escaped tilde, help, summary, suspend, and disconnect", assertPhase2DefaultTildeEscape)
	t.Run("custom control escape ^A", assertPhase2ControlEscape)
}

func assertPhase2DefaultTildeEscape(t *testing.T) {
	var (
		remoteIn   bytes.Buffer
		localOut   bytes.Buffer
		suspended  int
		disconnect int
	)
	w := newEscapeFilterWriter(&remoteIn, escapeFilterConfig{
		escapeByte:   '~',
		host:         "prod-db.internal",
		localOut:     &localOut,
		onDisconnect: func() { disconnect++ },
		onSuspend:    func() error { suspended++; return nil },
		summaryFn: func() string {
			return "\r\nThe following connections are open:\r\n  #0 client-session (shell)\r\n"
		},
	})

	if _, err := w.Write([]byte("~~.")); err != nil || w.Disconnected() || disconnect != 0 || remoteIn.String() != "~." {
		t.Fatalf("~~. mishandled: err=%v disconnected=%v remoteIn=%q", err, w.Disconnected(), remoteIn.String())
	}

	remoteIn.Reset()
	if _, err := w.Write([]byte("abc~.")); err != nil || w.Disconnected() || remoteIn.String() != "abc~." {
		t.Fatalf("mid-line ~. mishandled: err=%v disconnected=%v remoteIn=%q", err, w.Disconnected(), remoteIn.String())
	}

	remoteIn.Reset()
	if _, err := w.Write([]byte("\n~x\r~\r")); err != nil || remoteIn.String() != "\n~x\r~\r" {
		t.Fatalf("unexpected passthrough: err=%v remoteIn=%q", err, remoteIn.String())
	}

	remoteIn.Reset()
	if _, err := w.Write([]byte{'~', 0x1a, '~', '#', '~', '?'}); err != nil {
		t.Fatal(err)
	}
	if suspended != 1 || remoteIn.Len() != 0 {
		t.Fatalf("control escapes mishandled: suspended=%d remoteIn=%q", suspended, remoteIn.String())
	}
	if !strings.Contains(localOut.String(), "client-session (shell)") || !strings.Contains(localOut.String(), "Supported escape sequences") {
		t.Fatalf("unexpected localOut: %q", localOut.String())
	}

	localOut.Reset()
	if _, err := w.Write([]byte("~.trailing")); err != nil || !w.Disconnected() || disconnect != 1 || remoteIn.Len() != 0 {
		t.Fatalf("disconnect mishandled: err=%v disconnected=%v count=%d remoteIn=%q", err, w.Disconnected(), disconnect, remoteIn.String())
	}
	if !strings.Contains(localOut.String(), "Connection to prod-db.internal closed.") {
		t.Fatalf("missing disconnect message in %q", localOut.String())
	}
}

func assertPhase2ControlEscape(t *testing.T) {
	var remoteIn, localOut bytes.Buffer
	disconnected := false
	w := newEscapeFilterWriter(&remoteIn, escapeFilterConfig{
		escapeByte:   0x01,
		host:         "bastion",
		localOut:     &localOut,
		onDisconnect: func() { disconnected = true },
	})

	_, _ = w.Write([]byte("~.\n"))
	if disconnected || remoteIn.String() != "~.\n" {
		t.Fatalf("expected ~. to pass through under ^A escape, got %q", remoteIn.String())
	}
	_, _ = w.Write([]byte{0x01, '?', 0x01, '.'})
	if !disconnected || !strings.Contains(localOut.String(), "^A.") {
		t.Fatalf("expected ^A? help and ^A. disconnect, localOut=%q", localOut.String())
	}
}

type freezableServerConn struct {
	net.Conn
	frozen    atomic.Bool
	unblock   chan struct{}
	closeOnce sync.Once
}

func (c *freezableServerConn) Write(p []byte) (int, error) {
	if c.frozen.Load() {
		// Drop outbound packets (including server's SSH_MSG_CHANNEL_CLOSE reply) so
		// client channel.Close() stays unacknowledged and exercises c.Interrupt().
		return len(p), nil
	}
	return c.Conn.Write(p)
}

// Close is called concurrently by the kex loop and test cleanup, so closing
// unblock must be serialized; a select/default guard races.
func (c *freezableServerConn) Close() error {
	c.closeOnce.Do(func() { close(c.unblock) })
	return c.Conn.Close()
}

func TestPhase2_RunSubsystemWithIO_StalledRequestCancelJoinsGoroutine(t *testing.T) {
	t.Run("stalled subsystem reply joins via channel close", func(t *testing.T) {
		assertPhase2StalledSubsystemCancel(t, false)
	})
	t.Run("blackholed peer ignoring SSH_MSG_CHANNEL_CLOSE joins via Interrupt fallback", func(t *testing.T) {
		assertPhase2StalledSubsystemCancel(t, true)
	})
}

func assertPhase2StalledSubsystemCancel(t *testing.T, blackholeAfterRequest bool) {
	t.Helper()
	listener, sshSrvCfg := startKeepAliveTestSSHServer(t)
	requestSeen := make(chan struct{})
	serverHandlerExited := make(chan struct{})

	var (
		wg          sync.WaitGroup
		wrappedConn *freezableServerConn
	)
	t.Cleanup(func() {
		_ = listener.Close()
		if wrappedConn != nil {
			_ = wrappedConn.Close()
		}
		wg.Wait()
	})

	wg.Go(func() {
		rawConn, err := listener.Accept()
		if err != nil {
			return
		}
		wrappedConn = &freezableServerConn{Conn: rawConn, unblock: make(chan struct{})}
		defer func() { _ = wrappedConn.Close() }()

		srvConn, chans, reqs, err := cryptoSSH.NewServerConn(wrappedConn, sshSrvCfg)
		if err != nil {
			return
		}
		defer func() { _ = srvConn.Close() }()
		wg.Go(func() { cryptoSSH.DiscardRequests(reqs) })

		for newCh := range chans {
			ch, chReqs, acceptErr := newCh.Accept()
			if acceptErr != nil {
				continue
			}
			wg.Go(func() {
				defer close(serverHandlerExited)
				defer func() { _ = ch.Close() }()
				for req := range chReqs {
					if req.Type == "subsystem" {
						if blackholeAfterRequest {
							wrappedConn.frozen.Store(true)
						}
						close(requestSeen)
						// Intentionally never reply; wait until channel/transport closes chReqs.
					}
				}
			})
		}
	})

	client := dialStalledSubsystemTestClient(t, listener.Addr().String())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.RunSubsystemWithIO(ctx, "stalled-sub", nil, io.Discard, io.Discard, false)
	}()

	select {
	case <-requestSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server to observe subsystem request")
	}

	// If blackholed on server Read, client's channel.Close() stays unacknowledged until Interrupt() closes client socket.
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RunSubsystemWithIO err = %v, want context.Canceled", err)
		}
	case <-time.After(sessionShutdownTimeout + 2*time.Second):
		t.Fatal("RunSubsystemWithIO hung after context cancellation on stalled subsystem request")
	}

	if blackholeAfterRequest && wrappedConn != nil {
		// Unblock server-side Read wrapper once client socket is closed by Interrupt().
		_ = wrappedConn.Close()
	}
	select {
	case <-serverHandlerExited:
	case <-time.After(2 * time.Second):
		t.Fatal("server channel handler did not exit after client cancellation cleanup")
	}
}

func dialStalledSubsystemTestClient(t *testing.T, addr string) *Client {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("net.DialTimeout: %v", err)
	}
	raw, chans, reqs, err := cryptoSSH.NewClientConn(conn, addr, &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password("test")},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		_ = conn.Close()
		t.Fatalf("NewClientConn: %v", err)
	}
	client := newClient(cryptoSSH.NewClient(raw, chans, reqs), conn, &ClientConfig{
		Address: "stalled.example",
	}, nil, "")
	client.handshakeTimeout = 5 * time.Second
	t.Cleanup(func() { _ = client.Close() })
	return client
}

type staticSudoSecretResolver struct {
	password string
}

func (s staticSudoSecretResolver) ResolveSecret(_ context.Context, req SecretRequest) ([]byte, error) {
	if req.Kind == SecretKindSudoPassword {
		return []byte(s.password), nil
	}
	return nil, ErrInteractionRequired
}

func TestPhase2_NonInteractiveClientRunMethods_SendEnvAndProbeIsolation(t *testing.T) {
	opts := MustOptions(
		OptionSendEnv, "APP_* SSH_AUTH_SOCK",
		OptionSetEnv, "APP_SET=override",
	)
	env := Environment{
		Environ: func() []string {
			return []string{
				"APP_ENV=from_host",
				"SSH_AUTH_SOCK=/tmp/agent.sock",
			}
		},
	}
	wantEnv := []EnvVar{
		{Name: "APP_ENV", Value: "from_host"},
		{Name: "APP_SET", Value: "override"},
	}

	t.Run("Run, RunWithoutLogin, RunScript, RunScriptWithExecution, RunStream, and SudoModeAuto probes", func(t *testing.T) {
		assertPhase2NonInteractiveRunAndAutoSudo(t, opts, env, wantEnv)
	})
	t.Run("SudoModeSudoer RunWithSudoExecution and RunScriptWithSudoExecution", func(t *testing.T) {
		assertPhase2NonInteractiveSudoerMethods(t, opts, env, wantEnv)
	})
}

func assertPhase2NonInteractiveRunAndAutoSudo(t *testing.T, opts *Options, env Environment, wantEnv []EnvVar) {
	t.Helper()
	client, snapshot, _ := startPhase2FakeSSHClient(t, ClientConfig{
		Address:  "exec-host.example",
		SudoMode: SudoModeAuto,
		Options:  opts,
	}, env, phase2ServerConfig{
		resolver: staticSudoSecretResolver{password: "sudo-pass"},
		onExec:   handleNonInteractivePhase2Exec,
	})

	ctx := t.Context()
	if _, err := client.Run(ctx, "echo user-run"); err != nil {
		t.Fatalf("Client.Run: %v", err)
	}
	if _, err := client.RunWithoutLogin(ctx, "echo user-nologin"); err != nil {
		t.Fatalf("Client.RunWithoutLogin: %v", err)
	}
	if _, err := client.RunScript(ctx, "echo user-script\n"); err != nil {
		t.Fatalf("Client.RunScript: %v", err)
	}
	if _, err := client.RunScriptWithExecution(ctx, "echo user-exec-script\n", &ExecutionConfig{Interpreter: InterpreterBash}); err != nil {
		t.Fatalf("Client.RunScriptWithExecution: %v", err)
	}
	stream, err := client.RunStream(ctx, "echo user-stream")
	if err != nil {
		t.Fatalf("Client.RunStream: %v", err)
	}
	_, _ = io.ReadAll(stream)
	_ = stream.Close()

	// Triggers dialect/interpreter probes, detectRootOrSudoer ("id -u" -> 1000, "sudo -n true" -> 1),
	// maybeDetectSudoMode ("sudo -S -p '' true" -> 0), then executes user privileged command.
	if _, err := client.RunWithSudo(ctx, "echo user-auto-sudo"); err != nil {
		t.Fatalf("Client.RunWithSudo(auto): %v", err)
	}

	got := snapshot()
	probeCount, userCount := 0, 0
	for _, s := range got {
		if isPhase2InternalProbeCommand(s.command) {
			probeCount++
			if len(s.envVars) != 0 {
				t.Fatalf("internal probe %q leaked envVars: %+v", s.command, s.envVars)
			}
			continue
		}
		userCount++
		assertPhase2SessionEnvBeforeExec(t, s, wantEnv)
	}
	if probeCount < 4 {
		t.Fatalf("expected >=4 internal probe sessions (dialect, interp, id -u, sudo -n, sudo -S), saw %d in %+v", probeCount, got)
	}
	if userCount != 6 {
		t.Fatalf("expected 6 user sessions, saw %d in %+v", userCount, got)
	}
}

func assertPhase2NonInteractiveSudoerMethods(t *testing.T, opts *Options, env Environment, wantEnv []EnvVar) {
	t.Helper()
	client, snapshot, _ := startPhase2FakeSSHClient(t, ClientConfig{
		Address:  "sudoer-host.example",
		SudoMode: SudoModeSudoer,
		Options:  opts,
	}, env, phase2ServerConfig{
		onExec: handleNonInteractivePhase2Exec,
	})

	// Legacy SudoModeSudoer paths (c.runWithSudo(..., true)):
	if _, err := client.RunWithSudo(t.Context(), "echo sudoer-legacy-cmd"); err != nil {
		t.Fatalf("RunWithSudo(sudoer): %v", err)
	}
	if _, err := client.RunScriptWithSudo(t.Context(), "echo sudoer-legacy-script\n"); err != nil {
		t.Fatalf("RunScriptWithSudo(sudoer): %v", err)
	}

	// Configured ExecutionConfig paths (RunWithSudoExecution & RunScriptWithSudoExecution):
	execCfg := &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX}
	if _, err := client.RunWithSudoExecution(t.Context(), "echo sudoer-cmd", execCfg); err != nil {
		t.Fatalf("RunWithSudoExecution: %v", err)
	}
	if _, err := client.RunScriptWithSudoExecution(t.Context(), "echo sudoer-script\n", execCfg); err != nil {
		t.Fatalf("RunScriptWithSudoExecution: %v", err)
	}

	got := snapshot()
	userCount := 0
	for _, s := range got {
		if isPhase2InternalProbeCommand(s.command) {
			if len(s.envVars) != 0 {
				t.Fatalf("internal probe %q leaked envVars: %+v", s.command, s.envVars)
			}
			continue
		}
		userCount++
		assertPhase2SessionEnvBeforeExec(t, s, wantEnv)
	}
	if userCount != 4 {
		t.Fatalf("expected 4 user sudoer sessions, got %d: %+v", userCount, got)
	}
}

func isPhase2InternalProbeCommand(cmd string) bool {
	return strings.Contains(cmd, "__XOPS_DIALECT_POSIX__") ||
		strings.Contains(cmd, "__XOPS_INTERP_END__") ||
		strings.Contains(cmd, "id -u") ||
		strings.Contains(cmd, "sudo -n true") ||
		strings.HasSuffix(cmd, "sudo -S -p '' true")
}

func assertPhase2SessionEnvBeforeExec(t *testing.T, s recordedChannelSession, wantEnv []EnvVar) {
	t.Helper()
	if !slices.Equal(s.envVars, wantEnv) {
		t.Fatalf("session %q envVars = %+v, want %+v", s.command, s.envVars, wantEnv)
	}
	if len(s.reqOrder) < len(wantEnv)+1 {
		t.Fatalf("session %q reqOrder too short: %v", s.command, s.reqOrder)
	}
	for i := range wantEnv {
		if s.reqOrder[i] != "env" {
			t.Fatalf("session %q did not send env before exec/pty-req: %v", s.command, s.reqOrder)
		}
	}
}

func handleNonInteractivePhase2Exec(cmd string, ch cryptoSSH.Channel) (bool, uint32) {
	switch {
	case strings.Contains(cmd, "id -u"):
		_, _ = io.WriteString(ch, "1000\n")
		return true, 0
	case strings.Contains(cmd, "sudo -n true"):
		return true, 1
	case strings.HasSuffix(cmd, "sudo -S -p '' true"):
		_, _ = io.Copy(io.Discard, ch)
		return true, 0
	case strings.Contains(cmd, "[xops-ready-"):
		reader := bufio.NewReader(ch)
		if prompt := protocolToken(cmd, "[xops-password-"); prompt != "" && !strings.Contains(cmd, "sudo -n") {
			_, _ = io.WriteString(ch.Stderr(), prompt)
			_, _ = reader.ReadString('\n')
		}
		if ready := protocolToken(cmd, "[xops-ready-"); ready != "" {
			_, _ = io.WriteString(ch.Stderr(), ready)
			_, _ = reader.ReadString('\n')
		}
		_, _ = io.Copy(io.Discard, reader)
		_, _ = io.WriteString(ch, "sudo-ok\n")
		return true, 0
	default:
		_, _ = io.Copy(io.Discard, ch)
		return false, 0
	}
}
