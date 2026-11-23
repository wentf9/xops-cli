package mcphost

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type w17aMutableGuardrailProvider struct {
	mu  sync.RWMutex
	cfg *config.Configuration
}

func (p *w17aMutableGuardrailProvider) provider() *config.Provider {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return config.NewProviderWithoutOpenSSH(p.cfg)
}

func (p *w17aMutableGuardrailProvider) setGuardrail(g *corepolicy.Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = config.NewProviderWithoutOpenSSH(p.cfg).Snapshot()
	p.cfg.Guardrail = g
}

func (p *w17aMutableGuardrailProvider) Frozen() config.ConfigProvider {
	return p.provider().Frozen()
}
func (p *w17aMutableGuardrailProvider) Resolve(id string) (models.Node, models.Host, models.Identity, error) {
	return p.provider().Resolve(id)
}
func (p *w17aMutableGuardrailProvider) ResolveConnection(id string) (config.ConnectionSnapshot, error) {
	return p.provider().ResolveConnection(id)
}
func (p *w17aMutableGuardrailProvider) GetNode(id string) (models.Node, bool) {
	return p.provider().GetNode(id)
}
func (p *w17aMutableGuardrailProvider) GetHost(id string) (models.Host, bool) {
	return p.provider().GetHost(id)
}
func (p *w17aMutableGuardrailProvider) GetIdentity(id string) (models.Identity, bool) {
	return p.provider().GetIdentity(id)
}
func (p *w17aMutableGuardrailProvider) ListNodes() map[string]models.Node {
	return p.provider().ListNodes()
}
func (p *w17aMutableGuardrailProvider) GetNodesByTag(tag string) map[string]models.Node {
	return p.provider().GetNodesByTag(tag)
}
func (p *w17aMutableGuardrailProvider) ListIdentities() map[string]models.Identity {
	return p.provider().ListIdentities()
}
func (p *w17aMutableGuardrailProvider) Find(input string) string {
	return p.provider().Find(input)
}
func (p *w17aMutableGuardrailProvider) ResolveSelector(input string) (string, error) {
	return p.provider().ResolveSelector(input)
}
func (p *w17aMutableGuardrailProvider) FindAlias(alias string) string {
	return p.provider().FindAlias(alias)
}
func (p *w17aMutableGuardrailProvider) ResolveProxyJumpChain(jumpChain string) (string, error) {
	return p.provider().ResolveProxyJumpChain(jumpChain)
}
func (p *w17aMutableGuardrailProvider) Snapshot() *config.Configuration {
	return p.provider().Snapshot()
}
func (p *w17aMutableGuardrailProvider) GetOpenSSHOptions(alias string) (*ssh.Options, error) {
	return p.provider().GetOpenSSHOptions(alias)
}
func (p *w17aMutableGuardrailProvider) GetOpenSSHControl(alias string) (*ssh.ControlConfig, error) {
	return p.provider().GetOpenSSHControl(alias)
}

type w17aTamperedPermit struct {
	ports.Permit
	tampered ports.OperationSnapshot
}

func (p *w17aTamperedPermit) Snapshot() ports.OperationSnapshot {
	return p.tampered.Clone()
}

func setupW17aDualSSHRepo(t *testing.T, firstExec func(string, cryptoSSH.Channel), secondExec func(string, cryptoSSH.Channel)) (context.Context, *config.Repository, *sshfixture.Server, *sshfixture.Server) {
	t.Helper()
	home := isolateMCPTestEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	first, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: firstExec})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	})
	second, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: secondExec})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Error(err)
		}
	})
	known := knownhosts.Line([]string{knownhosts.Normalize(first.Address)}, first.HostKey) + "\n" +
		knownhosts.Line([]string{knownhosts.Normalize(second.Address)}, second.HostKey) + "\n"
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(known), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := runtimeTestProvider("node").Snapshot()
	cfg.Hosts.Set("host", tunnelSnapshotHost(t, first.Address))
	cfg.Identities.Set("identity", models.Identity{
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
	})
	cfg.Nodes.Set("node", models.Node{
		HostRef:     "host",
		IdentityRef: "identity",
		SudoMode:    models.SudoModeSudo,
	})
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, &tunnelSnapshotStore{cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, repo, first, second
}

func TestP7W17a_AB17M2_BackendUsesAdmittedBindingAndFrozenProvider(t *testing.T) {
	t.Run("tampered_snapshot_rejected_by_binding_validate", testP7W17aAB17M2TamperedSnapshotRejected)
	t.Run("concurrent_repo_password_and_target_edit_after_enter_uses_frozen_snapshot", testP7W17aAB17M2FrozenSnapshotAfterEdit)
	t.Run("http_frozen_mode_preserves_connection_pooling", testP7W17aAB17M2HTTPFrozenPooling)
}

func testP7W17aAB17M2TamperedSnapshotRejected(t *testing.T) {
	ctx, repo, first, second := setupW17aDualSSHRepo(t, nil, nil)
	h := newHost(Config{Provider: repo})
	rawBackend, err := h.dependencies().NewBackend(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rawBackend.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	b := rawBackend.(*backend)

	view, err := h.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.Bind(view, "scope", "terminal", struct{}{})
	if err != nil {
		t.Fatal(err)
	}

	admitTampered := func(phase ports.Phase) ports.Permit {
		p, err := h.Enter(ctx, ports.Admission{OperationID: "tampered-" + string(phase), Phase: phase, Snapshot: view, Binding: binding})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		tampered := view.Clone()
		target := tampered.Targets["node"]
		target.Plan.Hops[0].Address = "192.0.2.99"
		tampered.Targets["node"] = target
		return &w17aTamperedPermit{Permit: p, tampered: tampered}
	}

	if _, err := b.ProbeExecution(ctx, admitTampered(ports.Inspect), "node"); !errors.Is(err, ports.ErrStaleBinding) {
		t.Fatalf("ProbeExecution with tampered snapshot = %v, want ports.ErrStaleBinding", err)
	}
	if _, err := b.Run(ctx, admitTampered(ports.Execute), "node", ports.Command{Text: "echo hi"}); !errors.Is(err, ports.ErrStaleBinding) {
		t.Fatalf("Run with tampered snapshot = %v, want ports.ErrStaleBinding", err)
	}
	if ptySess, err := b.OpenPTY(ctx, admitTampered(ports.Execute), "node"); !errors.Is(err, ports.ErrStaleBinding) {
		if ptySess != nil {
			_ = ptySess.Close()
		}
		t.Fatalf("OpenPTY with tampered snapshot = %v, want ports.ErrStaleBinding", err)
	}
	if first.Authenticated.Load() != 0 || second.Authenticated.Load() != 0 {
		t.Fatalf("tampered permits dialed SSH: first=%d second=%d", first.Authenticated.Load(), second.Authenticated.Load())
	}
}

func w17aProtocolToken(command, prefix string) string {
	at := strings.Index(command, prefix)
	if at >= 0 && strings.HasPrefix(command[at:], prefix+"%s]") {
		nonce := regexp.MustCompile(`[A-Z2-7]{26,}`).FindString(command[at:])
		if nonce != "" {
			return prefix + nonce + "]"
		}
	}
	if at < 0 {
		return ""
	}
	end := strings.Index(command[at:], "]")
	if end < 0 {
		return ""
	}
	return command[at : at+end+1]
}

func w17aFirstExecHandler(t *testing.T, sudoPasswordReceived *atomic.Value) func(string, cryptoSSH.Channel) {
	return func(command string, ch cryptoSSH.Channel) {
		if strings.Contains(command, "__XOPS_") {
			replyLegacyShellProbe(t, ssh.InterpreterZsh, command, ch)
			return
		}
		if promptTok := w17aProtocolToken(command, "[xops-password-"); promptTok != "" {
			readyTok := w17aProtocolToken(command, "[xops-ready-")
			_, _ = io.WriteString(ch.Stderr(), promptTok)
			reader := bufio.NewReader(ch)
			line, _ := reader.ReadString('\n')
			sudoPasswordReceived.Store(strings.TrimSpace(line))
			if readyTok != "" {
				_, _ = io.WriteString(ch.Stderr(), readyTok)
				_, _ = reader.ReadString('\n') // consume ack token
			}
			replyCapturedExecution(t, ch, "sudo-ok-on-first")
			return
		}
		replyCapturedExecution(t, ch, "run-ok-on-first")
	}
}

func assertW17aPTYAdmitted(t *testing.T, ctx context.Context, b *backend, ptyPermit ports.Permit) {
	t.Helper()
	ptySess, err := b.OpenPTY(ctx, ptyPermit, "node")
	if err != nil {
		t.Fatalf("OpenPTY after live repo edit: %v", err)
	}
	if _, err := io.WriteString(ptySess, "echo pty-admitted\nexit\n"); err != nil {
		_ = ptySess.Close()
		t.Fatalf("write PTY: %v", err)
	}
	out, _ := io.ReadAll(io.LimitReader(ptySess, 4096))
	if err := ptySess.Close(); err != nil {
		t.Fatalf("close PTY: %v", err)
	}
	if !strings.Contains(string(out), "pty-admitted") {
		t.Fatalf("PTY output = %q, want pty-admitted", string(out))
	}
}

func testP7W17aAB17M2FrozenSnapshotAfterEdit(t *testing.T) {
	var sudoPasswordReceived atomic.Value
	firstExec := w17aFirstExecHandler(t, &sudoPasswordReceived)
	secondExec := func(_ string, ch cryptoSSH.Channel) {
		replyCapturedExecution(t, ch, "unexpected-second")
	}

	ctx, repo, first, second := setupW17aDualSSHRepo(t, firstExec, secondExec)
	h := newHost(Config{Provider: repo})
	rawBackend, err := h.dependencies().NewBackend(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rawBackend.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	b := rawBackend.(*backend)

	view, err := h.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.Bind(view, "scope", "terminal", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	admit := func(opID string, phase ports.Phase) ports.Permit {
		p, err := h.Enter(ctx, ports.Admission{OperationID: opID, Phase: phase, Snapshot: view, Binding: binding})
		if err != nil {
			t.Fatalf("Enter(%s): %v", opID, err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	inspectPermit := admit("op-probe", ports.Inspect)
	execPermit := admit("op-run", ports.Execute)
	sudoPermit := admit("op-sudo", ports.Execute)
	ptyPermit := admit("op-pty", ports.Execute)

	// Mutate BOTH password and target host in the live repository AFTER Enter.
	ref := repo.View().NodeRefs["node"]
	node, _, identity, err := repo.Resolve("node")
	if err != nil {
		t.Fatal(err)
	}
	identity.Password = "post-edit-unadmitted-password"
	if err := repo.ReplaceNodeAtRefContext(ctx, ref, "node", node, tunnelSnapshotHost(t, second.Address), identity); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext: %v", err)
	}

	probeRes, err := b.ProbeExecution(ctx, inspectPermit, "node")
	if err != nil || probeRes == nil || probeRes.RecommendedInterpreter != ssh.InterpreterZsh {
		t.Fatalf("ProbeExecution after live repo edit = (%+v, %v), want zsh", probeRes, err)
	}
	runRes, err := b.Run(ctx, execPermit, "node", ports.Command{Text: "echo ok", Execution: probeRes.SuggestedConfig.Clone()})
	if err != nil || runRes.Output != "run-ok-on-first" {
		t.Fatalf("Run after live repo edit = (%+v, %v), want run-ok-on-first", runRes, err)
	}
	sudoRes, err := b.Run(ctx, sudoPermit, "node", ports.Command{Text: "id", Sudo: true, Execution: probeRes.SuggestedConfig.Clone()})
	if err != nil || sudoRes.Output != "sudo-ok-on-first" {
		t.Fatalf("Run(sudo) after live repo edit = (%+v, %v), want sudo-ok-on-first", sudoRes, err)
	}
	if gotPwd, _ := sudoPasswordReceived.Load().(string); gotPwd != sshfixture.Password {
		t.Fatalf("sudo received password %q, want admitted %q", gotPwd, sshfixture.Password)
	}
	assertW17aPTYAdmitted(t, ctx, b, ptyPermit)

	if first.Authenticated.Load() < 1 {
		t.Fatalf("expected admitted first server to receive SSH auths, got %d", first.Authenticated.Load())
	}
	if second.Authenticated.Load() != 0 || second.Executed.Load() != 0 {
		t.Fatalf("post-edit second server was contacted: auth=%d exec=%d", second.Authenticated.Load(), second.Executed.Load())
	}
}

func testP7W17aAB17M2HTTPFrozenPooling(t *testing.T) {
	firstExec := func(command string, ch cryptoSSH.Channel) {
		if strings.Contains(command, "__XOPS_") {
			replyLegacyShellProbe(t, ssh.InterpreterZsh, command, ch)
			return
		}
		replyCapturedExecution(t, ch, "pooled-ok")
	}
	ctx, repo, first, _ := setupW17aDualSSHRepo(t, firstExec, nil)
	h := newHost(Config{Provider: repo, HTTP: &mcpruntime.HTTPOptions{}})
	rawBackend, err := h.dependencies().NewBackend(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rawBackend.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	b := rawBackend.(*backend)

	view, err := h.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.Bind(view, "scope", "terminal", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	inspectPermit, err := h.Enter(ctx, ports.Admission{OperationID: "pool-probe", Phase: ports.Inspect, Snapshot: view, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inspectPermit.Close() })
	execPermit, err := h.Enter(ctx, ports.Admission{OperationID: "pool-run", Phase: ports.Execute, Snapshot: view, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = execPermit.Close() })

	probeRes, err := b.ProbeExecution(ctx, inspectPermit, "node")
	if err != nil || probeRes.RecommendedInterpreter != ssh.InterpreterZsh {
		t.Fatalf("HTTP ProbeExecution: %+v %v", probeRes, err)
	}
	runRes, err := b.Run(ctx, execPermit, "node", ports.Command{Text: "echo ok", Execution: probeRes.SuggestedConfig.Clone()})
	if err != nil || runRes.Output != "pooled-ok" {
		t.Fatalf("HTTP Run: %+v %v", runRes, err)
	}
	if first.Authenticated.Load() != 1 {
		t.Fatalf("HTTP frozen mode authenticated %d times, want 1 (connection pooled)", first.Authenticated.Load())
	}
}

func TestP7W17a_AB17L2_StdioDynamicGuardrailPolicySnapshot(t *testing.T) {
	isolateMCPTestEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	baseCfg := runtimeTestProvider("node").Snapshot()
	baseCfg.Guardrail = &corepolicy.Config{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDeny,
	}
	mutable := &w17aMutableGuardrailProvider{cfg: baseCfg}

	// 1. Dynamic stdio host and runtime.
	stdioHost := newHost(Config{Provider: mutable})
	rt, err := newTestRuntime(ctx, Config{Provider: mutable})
	if err != nil {
		t.Fatal(err)
	}
	client := protocolClient(t, rt, "2025-11-25", nil)

	// Initial call succeeds under ApprovalThreshold: "dangerous".
	var listOut mcpruntime.ListNodesOutput
	if _, err := callTool(ctx, client, "nodes", mcpruntime.ListNodesInput{}, &listOut); err != nil {
		t.Fatalf("initial stdio nodes call failed: %v", err)
	}
	if len(listOut.Nodes) != 1 {
		t.Fatalf("initial nodes count = %d, want 1", len(listOut.Nodes))
	}

	// Capture a snapshot & binding BEFORE updating Guardrail policy.
	preView, err := stdioHost.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatal(err)
	}
	preBinding, err := ports.Bind(preView, "scope", "nodes", struct{}{})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Also start an HTTP host before the edit to verify HTTP remains frozen at startup.
	httpHost := newHost(Config{Provider: mutable, HTTP: &mcpruntime.HTTPOptions{}})

	// 3. Dynamically tighten Guardrail policy to ApprovalThreshold: "safe" + BlockedPatterns: ["*"].
	mutable.setGuardrail(&corepolicy.Config{
		ApprovalThreshold: "safe",
		NoElicitFallback:  guardrail.FallbackDeny,
		BlockedPatterns:   []string{"*"},
	})

	// Stdio List & Resolve must reflect the updated Guardrail snapshot dynamically.
	inv, err := stdioHost.List(ctx, ports.NodeQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Policy.ApprovalThreshold != "safe" || len(inv.Policy.BlockedPatterns) != 1 || inv.Policy.BlockedPatterns[0] != "*" {
		t.Fatalf("stdio List policy not updated dynamically: %+v", inv.Policy)
	}
	postView, err := stdioHost.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatal(err)
	}
	if postView.Policy.ApprovalThreshold != "safe" || len(postView.Policy.BlockedPatterns) != 1 {
		t.Fatalf("stdio Resolve policy not updated dynamically: %+v", postView.Policy)
	}

	// Stale binding captured before policy update MUST be rejected by Enter.
	if p, err := stdioHost.Enter(ctx, ports.Admission{OperationID: "stale-policy", Phase: ports.Inspect, Snapshot: preView, Binding: preBinding}); !errors.Is(err, ports.ErrStaleBinding) {
		if p != nil {
			_ = p.Close()
		}
		t.Fatalf("Enter after dynamic policy change = %v, want ports.ErrStaleBinding", err)
	}

	// Running stdio MCP runtime MUST now deny the nodes call under updated BlockedPatterns.
	if _, err := callTool(ctx, client, "nodes", mcpruntime.ListNodesInput{}, &listOut); err == nil {
		t.Fatal("stdio MCP runtime ignored dynamically updated Guardrail policy")
	}

	// HTTP host MUST remain frozen to startup policy ("dangerous", no BlockedPatterns).
	httpInv, err := httpHost.List(ctx, ports.NodeQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if httpInv.Policy.ApprovalThreshold != "dangerous" || len(httpInv.Policy.BlockedPatterns) != 0 {
		t.Fatalf("HTTP host drifted from frozen startup policy: %+v", httpInv.Policy)
	}
}
