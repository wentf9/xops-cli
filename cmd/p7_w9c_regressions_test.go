package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

type w9cCountingCanonicalResolver struct {
	hosts   map[string][]string
	lookups int
}

func (r *w9cCountingCanonicalResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	r.lookups++
	if addrs, ok := r.hosts[host]; ok {
		return addrs, nil
	}
	return nil, errors.New("nxdomain")
}

func (r *w9cCountingCanonicalResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return host + ".", nil
}

func TestP7W9c_FG9M1_CLICanonicalizationPreChecksFailClosed(t *testing.T) {
	t.Run("trace1_saved_web_malformed_proxyjump_fails_closed_without_canonical_hijack", assertFG9M1Trace1MalformedSavedWeb)
	t.Run("trace2_ambiguous_saved_alias_fails_closed_across_ssh_sftp_scp_exec_control", assertFG9M1Trace2AmbiguousWeb)
	t.Run("trace3_inherited_invalid_openssh_hop_fails_closed_without_canonical_hijack", assertFG9M1Trace3InheritedBadHop)
}

func assertFG9M1Trace1MalformedSavedWeb(t *testing.T) {
	const sshCfg = `
Host saved-web.corp.example.com
    HostName 198.51.100.77
    User attacker

Host *
    CanonicalizeHostname always
    CanonicalDomains corp.example.com
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-web", models.Host{Address: "10.96.0.1", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-web", models.Node{
		HostRef:     "h-web",
		IdentityRef: "id-ops",
		ProxyJump:   "bastion,,hop2",
	})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	resolver := &w9cCountingCanonicalResolver{
		hosts: map[string][]string{"saved-web.corp.example.com": {"198.51.100.77"}},
	}
	o := NewSshOptions()
	o.Host = "saved-web"
	o.Target = config.ConnectionTarget{Selector: "saved-web"}
	o.control.CtlCmd = "check"
	o.canonicalResolver = resolver

	if err := o.applyHostnameCanonicalization(t.Context(), prov, resolver); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
		t.Fatalf("applyHostnameCanonicalization(saved-web malformed ProxyJump) err = %v, want ErrSSHOptionsValidation", err)
	}
	if resolver.lookups != 0 || o.canonicalized || o.Target.Selector != "saved-web" {
		t.Fatalf("malformed saved-web hijacked canonicalization: lookups=%d canonicalized=%v selector=%q",
			resolver.lookups, o.canonicalized, o.Target.Selector)
	}

	var stderr bytes.Buffer
	if err := canonicalizeControlOptions(t.Context(), o, prov, &stderr); err == nil {
		t.Fatalf("canonicalizeControlOptions(saved-web) succeeded, want fail-closed error")
	}

	if ok, err := o.probeTargetBackgroundSession(prov, adapter.SessionControlOptions{}, false, false); !errors.Is(err, ssh.ErrSSHOptionsValidation) || ok {
		t.Fatalf("probeTargetBackgroundSession(saved-web) = (%v, %v), want (false, ErrSSHOptionsValidation)", ok, err)
	}
}

func assertFG9M1Trace2AmbiguousWeb(t *testing.T) {
	const sshCfg = `
Host web.corp.example.com
    HostName 198.51.100.88
    User attacker
    SessionType none

Host *
    CanonicalizeHostname always
    CanonicalDomains corp.example.com
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-1", models.Host{Address: "10.96.1.1", Port: 22, Alias: []string{"web"}})
	cfg.Hosts.Set("h-2", models.Host{Address: "10.96.1.2", Port: 22, Alias: []string{"web"}})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("web-1", models.Node{HostRef: "h-1", IdentityRef: "id-ops"})
	cfg.Nodes.Set("web-2", models.Node{HostRef: "h-2", IdentityRef: "id-ops"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	makeResolver := func() *w9cCountingCanonicalResolver {
		return &w9cCountingCanonicalResolver{
			hosts: map[string][]string{"web.corp.example.com": {"198.51.100.88"}},
		}
	}

	var ambigErr *config.AmbiguousNodeError

	// 1. xops ssh web
	rSSH := makeResolver()
	oSSH := NewSshOptions()
	oSSH.Host = "web"
	oSSH.Target = config.ConnectionTarget{Selector: "web"}
	oSSH.canonicalResolver = rSSH
	if err := oSSH.applyHostnameCanonicalization(t.Context(), prov, rSSH); !errors.As(err, &ambigErr) {
		t.Errorf("ssh applyHostnameCanonicalization(web) err = %v, want *config.AmbiguousNodeError", err)
	}
	if rSSH.lookups != 0 || oSSH.canonicalized {
		t.Errorf("ssh attempted canonicalization on ambiguous web (lookups=%d canonicalized=%v)", rSSH.lookups, oSSH.canonicalized)
	}

	// 2. xops sftp web
	rSFTP := makeResolver()
	oSFTP := NewSftpOptions()
	oSFTP.Host = "web"
	oSFTP.Target = config.ConnectionTarget{Selector: "web"}
	oSFTP.canonicalResolver = rSFTP
	if _, err := oSFTP.buildPendingEnsureOptions(t.Context(), prov); !errors.As(err, &ambigErr) {
		t.Errorf("sftp buildPendingEnsureOptions(web) err = %v, want *config.AmbiguousNodeError", err)
	}
	if rSFTP.lookups != 0 || oSFTP.canonicalized {
		t.Errorf("sftp attempted canonicalization on ambiguous web (lookups=%d canonicalized=%v)", rSFTP.lookups, oSFTP.canonicalized)
	}

	// 3. xops scp ./a web:/tmp/a
	rSCP := makeResolver()
	oSCP := NewScpOptions()
	oSCP.Source = "./a"
	oSCP.Dest = "web:/tmp/a"
	oSCP.canonicalResolver = rSCP
	dstPI, err := parsePath(oSCP.Dest)
	if err != nil {
		t.Fatalf("parsePath(web:/tmp/a): %v", err)
	}
	if _, err := oSCP.canonicalizePathInfo(t.Context(), prov, dstPI); !errors.As(err, &ambigErr) {
		t.Errorf("scp canonicalizePathInfo(web) err = %v, want *config.AmbiguousNodeError", err)
	}
	if rSCP.lookups != 0 {
		t.Errorf("scp attempted canonicalization on ambiguous web (lookups=%d)", rSCP.lookups)
	}

	// 4. xops exec --host web id
	rExec := makeResolver()
	oExec := NewExecOptions()
	oExec.Host = "web"
	oExec.Command = "id"
	oExec.canonicalResolver = rExec
	if _, _, _, _, _, err := oExec.resolveExecHostTarget(t.Context(), prov, config.ConnectionTarget{Selector: "web"}); !errors.As(err, &ambigErr) {
		t.Errorf("exec resolveExecHostTarget(web) err = %v, want *config.AmbiguousNodeError", err)
	}
	if rExec.lookups != 0 {
		t.Errorf("exec attempted canonicalization on ambiguous web (lookups=%d)", rExec.lookups)
	}

	// 5. xops ssh -O check web
	rCtl := makeResolver()
	oCtl := NewSshOptions()
	oCtl.Host = "web"
	oCtl.Target = config.ConnectionTarget{Selector: "web"}
	oCtl.control.CtlCmd = "check"
	oCtl.canonicalResolver = rCtl
	var stderr bytes.Buffer
	if err := canonicalizeControlOptions(t.Context(), oCtl, prov, &stderr); err == nil || !strings.Contains(stderr.String(), "ambiguous") {
		t.Errorf("ssh -O check canonicalizeControlOptions(web) = (err=%v, stderr=%q), want ambiguous error", err, stderr.String())
	}
	if rCtl.lookups != 0 || oCtl.canonicalized {
		t.Errorf("ssh -O check attempted canonicalization on ambiguous web (lookups=%d canonicalized=%v)", rCtl.lookups, oCtl.canonicalized)
	}

	// 6. xops ssh -f web
	oBg := NewSshOptions()
	oBg.Host = "web"
	oBg.Target = config.ConnectionTarget{Selector: "web"}
	oBg.BgRun = true
	if ok, err := oBg.probeTargetBackgroundSession(prov, adapter.SessionControlOptions{}, false, false); !errors.As(err, &ambigErr) || ok {
		t.Errorf("probeTargetBackgroundSession(ambiguous web) = (%v, %v), want (false, *config.AmbiguousNodeError)", ok, err)
	}
}

func assertFG9M1Trace3InheritedBadHop(t *testing.T) {
	const sshCfg = `
Host saved-open
    HostName 10.96.2.10
    Port 2222
    User ops

Host saved-open.corp.example.com
    HostName 198.51.100.99
    User attacker

Host *
    CanonicalizeHostname always
    CanonicalDomains corp.example.com
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-open", models.Host{Address: "10.96.2.10", Port: 2222})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@10.96.2.10:2222", models.Node{
		HostRef:     "h-open",
		IdentityRef: "id-ops",
		ProxyJump:   "openssh:bad hop",
	})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	rSSH := &w9cCountingCanonicalResolver{
		hosts: map[string][]string{"saved-open.corp.example.com": {"198.51.100.99"}},
	}
	oSSH := NewSshOptions()
	oSSH.Host = "saved-open"
	oSSH.User = "deploy"
	oSSH.Port = 2222
	oSSH.Target = config.ConnectionTarget{
		Selector: "saved-open",
		User:     "deploy",
		HasUser:  true,
		Port:     2222,
		HasPort:  true,
	}
	oSSH.canonicalResolver = rSSH
	if err := oSSH.applyHostnameCanonicalization(t.Context(), prov, rSSH); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
		t.Fatalf("ssh applyHostnameCanonicalization(deploy@saved-open:2222) err = %v, want ErrSSHOptionsValidation", err)
	}
	if rSSH.lookups != 0 || oSSH.canonicalized {
		t.Fatalf("ssh hijacked deploy@saved-open:2222 (lookups=%d canonicalized=%v)", rSSH.lookups, oSSH.canonicalized)
	}

	rSCP := &w9cCountingCanonicalResolver{
		hosts: map[string][]string{"saved-open.corp.example.com": {"198.51.100.99"}},
	}
	oSCP := NewScpOptions()
	oSCP.Port = 2222
	oSCP.canonicalResolver = rSCP
	if _, err := oSCP.canonicalizePathInfo(t.Context(), prov, PathInfo{
		IsRemote: true,
		User:     "deploy",
		Host:     "saved-open",
		Port:     2222,
		Path:     "/tmp/f",
	}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
		t.Fatalf("scp canonicalizePathInfo(deploy@saved-open:2222) err = %v, want ErrSSHOptionsValidation", err)
	}
	if rSCP.lookups != 0 {
		t.Fatalf("scp hijacked deploy@saved-open:2222 (lookups=%d)", rSCP.lookups)
	}

	rExec := &w9cCountingCanonicalResolver{
		hosts: map[string][]string{"saved-open.corp.example.com": {"198.51.100.99"}},
	}
	oExec := NewExecOptions()
	oExec.canonicalResolver = rExec
	if _, _, _, _, _, err := oExec.resolveExecHostTarget(t.Context(), prov, oSSH.Target); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
		t.Fatalf("exec resolveExecHostTarget(deploy@saved-open:2222) err = %v, want ErrSSHOptionsValidation", err)
	}
	if rExec.lookups != 0 {
		t.Fatalf("exec hijacked deploy@saved-open:2222 (lookups=%d)", rExec.lookups)
	}
}

func TestP7W9c_FG9L1_ScpRejectsLeadingWhitespaceOpenSSHPaths(t *testing.T) {
	t.Parallel()

	badPaths := []string{
		" openssh:web:/tmp/secret",
		"\u00a0openssh:web:/tmp/secret",
		"\topenssh:web:/tmp/secret",
		" OPENSSH:web:/tmp/secret",
		"\nopenssh:web:/tmp/secret",
		"\u2028openssh:web:/tmp/secret",
		"openssh: web:/tmp/secret",
		"openssh:\u00a0web:/tmp/secret",
		"openssh:web :/tmp/secret",
		"openssh:openssh:web:/tmp/secret",
	}
	for _, raw := range badPaths {
		if pi, err := parsePath(raw); err == nil {
			t.Errorf("parsePath(%q) unexpectedly succeeded as %+v, want fail-closed error", raw, pi)
		}
	}

	piClean, err := parsePath("openssh:web:/tmp/secret")
	if err != nil || !piClean.IsRemote || piClean.Host != "openssh:web" || piClean.Path != "/tmp/secret" {
		t.Fatalf("parsePath(openssh:web:/tmp/secret) = (%+v, %v)", piClean, err)
	}
	piTrail, err := parsePath("openssh:web:/tmp/file with space ")
	if err != nil || !piTrail.IsRemote || piTrail.Host != "openssh:web" || piTrail.Path != "/tmp/file with space " {
		t.Fatalf("parsePath(openssh:web:/tmp/file with space ) = (%+v, %v)", piTrail, err)
	}
}

func countProgressBarSpinnerGoroutines() int {
	buf := make([]byte, 256*1024)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), "progressbar/v3.NewOptions64.func")
		}
		buf = make([]byte, len(buf)*2)
	}
}

func TestP7W9c_AB9L3_DirectoryProgressBarStopsSpinnerGoroutineOnFinish(t *testing.T) {
	tmpFile, err := os.Create(filepath.Join(t.TempDir(), "progress.log"))
	if err != nil {
		t.Fatalf("create temp progress sink: %v", err)
	}
	defer func() { _ = tmpFile.Close() }()

	output, err := newSCPDiagnostics(t.Context(), tmpFile, "stderr", false, 0)
	if err != nil {
		t.Fatalf("newSCPDiagnostics: %v", err)
	}

	beforeSpinners := countProgressBarSpinnerGoroutines()
	bar, progress, finish := newTransferProgressBar(-1, "Uploading dir", output, 0)
	if bar.IsFinished() {
		t.Fatal("indeterminate directory bar unexpectedly started finished")
	}

	progress(512)
	progress(1024)
	if bar.IsFinished() {
		t.Fatal("indeterminate directory bar unexpectedly finished after partial progress")
	}

	startDeadline := time.Now().Add(500 * time.Millisecond)
	for countProgressBarSpinnerGoroutines() <= beforeSpinners && time.Now().Before(startDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if active := countProgressBarSpinnerGoroutines(); active <= beforeSpinners {
		t.Fatalf("expected active indeterminate progressbar spinner goroutine (> %d), got %d", beforeSpinners, active)
	}

	if err := finish(); err != nil {
		t.Fatalf("finish() returned error: %v", err)
	}
	if !bar.IsFinished() {
		t.Fatal("expected indeterminate directory bar to be marked finished after finish()")
	}

	stopDeadline := time.Now().Add(time.Second)
	for countProgressBarSpinnerGoroutines() > beforeSpinners && time.Now().Before(stopDeadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if after := countProgressBarSpinnerGoroutines(); after > beforeSpinners {
		t.Fatalf("indeterminate progressbar spinner goroutine leaked after finish(): before=%d after=%d", beforeSpinners, after)
	}

	tmpZero, err := os.Create(filepath.Join(t.TempDir(), "progress-zero.log"))
	if err != nil {
		t.Fatalf("create zero sink: %v", err)
	}
	defer func() { _ = tmpZero.Close() }()
	outZero, err := newSCPDiagnostics(t.Context(), tmpZero, "stderr", false, 0)
	if err != nil {
		t.Fatalf("newSCPDiagnostics(zero): %v", err)
	}
	_, _, finishZero := newTransferProgressBar(0, "Uploading empty", outZero, 0)
	if err := finishZero(); err != nil {
		t.Fatalf("finishZero() returned unexpected error: %v", err)
	}
}
