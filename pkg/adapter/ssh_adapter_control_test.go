package adapter

import (
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func setupTestProvider(
	t *testing.T,
	nodeCtrl *ssh.ControlConfig,
	globalCtrl *ssh.ControlConfig,
	openSSHContent string,
) config.ConfigProvider {
	t.Helper()
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Control:    globalCtrl,
	}

	cfg.Hosts.Set("host1", models.Host{Address: "192.168.1.100", Port: 2222})
	cfg.Identities.Set("id1", models.Identity{User: "alice", AuthType: "auto"})
	cfg.Nodes.Set("testnode", models.Node{
		HostRef:     "host1",
		IdentityRef: "id1",
		Alias:       []string{"node-alias"},
		Control:     nodeCtrl,
	})

	var parser *config.OpenSSHParser
	if openSSHContent != "" {
		p, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHContent))
		if err != nil {
			t.Fatalf("failed to parse openssh config: %v", err)
		}
		parser = p
	}

	return config.NewProviderWithOpenSSHParser(cfg, parser)
}

func TestResolveControl_Tier1OverridesAll(t *testing.T) {
	// T2: Master: auto, Path: ~/.ssh/node.sock, Persist: 5m
	t2 := &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "~/.ssh/node.sock", Persist: "5m"}
	// T3: Master: auto, Path: ~/.ssh/global.sock, Persist: 10m
	t3 := &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "~/.ssh/global.sock", Persist: "10m"}
	// T4: Master: yes
	t4OpenSSH := `
Host testnode
    ControlMaster yes
`
	provider := setupTestProvider(t, t2, t3, t4OpenSSH)
	adp := NewSSHAdapter(provider)

	// T1: Master: yes, Path: /tmp/custom.sock (Persist not set on T1, should retain T2's Persist: 5m)
	var t1 SessionControlOptions
	t1.SetMaster(ssh.ControlMasterYes)
	t1.SetPath("/tmp/custom.sock")

	res, err := adp.ResolveControl("testnode", t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if res.Master != ssh.ControlMasterYes {
		t.Errorf("expected Master=yes, got: %v", res.Master)
	}
	if res.Path != "/tmp/custom.sock" {
		t.Errorf("expected Path=/tmp/custom.sock, got: %v", res.Path)
	}
	if res.Persist != "5m" {
		t.Errorf("expected Persist=5m (retained from Tier 2), got: %v", res.Persist)
	}
}

func TestResolveControl_Tier2OverridesTier3And4(t *testing.T) {
	// T2: Master: ask, Path: ~/.ssh/node.sock (Persist empty)
	t2 := &ssh.ControlConfig{Master: ssh.ControlMasterAsk, Path: "~/.ssh/node.sock"}
	// T3: Master: auto, Path: ~/.ssh/global.sock, Persist: 15m
	t3 := &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "~/.ssh/global.sock", Persist: "15m"}
	// T4: Master: yes
	t4OpenSSH := `
Host testnode
    ControlMaster yes
`
	provider := setupTestProvider(t, t2, t3, t4OpenSSH)
	adp := NewSSHAdapter(provider)

	// T1: empty
	var t1 SessionControlOptions

	res, err := adp.ResolveControl("testnode", t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if res.Master != ssh.ControlMasterAsk {
		t.Errorf("expected Master=ask (from T2), got: %v", res.Master)
	}
	if res.Path != "~/.ssh/node.sock" {
		t.Errorf("expected Path=~/.ssh/node.sock (from T2), got: %v", res.Path)
	}
	if res.Persist != "15m" {
		t.Errorf("expected Persist=15m (fallback to T3), got: %v", res.Persist)
	}
}

func TestResolveControl_Tier3OverridesTier4(t *testing.T) {
	// T2: nil
	// T3: Master: auto, Path: ~/.ssh/global-%r@%h:%p
	t3 := &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "~/.ssh/global-%r@%h:%p"}
	// T4: Master: no, Path: ~/.ssh/ssh-%h.sock
	t4OpenSSH := `
Host testnode
    ControlMaster no
    ControlPath ~/.ssh/ssh-%h.sock
`
	provider := setupTestProvider(t, nil, t3, t4OpenSSH)
	adp := NewSSHAdapter(provider)

	var t1 SessionControlOptions
	res, err := adp.ResolveControl("testnode", t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if res.Master != ssh.ControlMasterAuto {
		t.Errorf("expected Master=auto (from T3), got: %v", res.Master)
	}
	if res.Path != "~/.ssh/global-%r@%h:%p" {
		t.Errorf("expected Path from T3, got: %v", res.Path)
	}
}

func TestResolveControl_Tier4Fallback_NodeMatch(t *testing.T) {
	// T1, T2, T3: nil/empty
	t4OpenSSH := `
Host testnode
    ControlMaster auto
    ControlPath ~/.ssh/mux-%r@%h:%p
    ControlPersist 10m
`
	provider := setupTestProvider(t, nil, nil, t4OpenSSH)
	adp := NewSSHAdapter(provider)

	var t1 SessionControlOptions
	res, err := adp.ResolveControl("testnode", t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if res.Master != ssh.ControlMasterAuto ||
		res.Path != "~/.ssh/mux-%r@%h:%p" ||
		res.Persist != "10m" {
		t.Fatalf("Tier 4 fallback mismatch: %+v", res)
	}
}

func TestResolveControl_Tier4Fallback_Wildcard(t *testing.T) {
	// T1, T2, T3: nil/empty
	t4OpenSSH := `
Host *
    ControlMaster auto
    ControlPath ~/.ssh/mux-%h
`
	provider := setupTestProvider(t, nil, nil, t4OpenSSH)
	adp := NewSSHAdapter(provider)

	var t1 SessionControlOptions
	res, err := adp.ResolveControl("testnode", t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if res.Master != ssh.ControlMasterAuto || res.Path != "~/.ssh/mux-%h" {
		t.Fatalf("wildcard fallback mismatch: %+v", res)
	}
}

func TestResolveControl_FieldByFieldMerging_Orthogonal(t *testing.T) {
	// T3 provides Master: auto
	t3 := &ssh.ControlConfig{Master: ssh.ControlMasterAuto}
	// T2 provides Path: ~/.ssh/node-%h.sock
	t2 := &ssh.ControlConfig{Path: "~/.ssh/node-%h.sock"}
	// T1 provides Persist: 20m
	provider := setupTestProvider(t, t2, t3, "")
	adp := NewSSHAdapter(provider)

	var t1 SessionControlOptions
	t1.SetPersist("20m")

	res, err := adp.ResolveControl("testnode", t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if res.Master != ssh.ControlMasterAuto {
		t.Errorf("expected Master=auto from T3, got: %v", res.Master)
	}
	if res.Path != "~/.ssh/node-%h.sock" {
		t.Errorf("expected Path from T2, got: %v", res.Path)
	}
	if res.Persist != "20m" {
		t.Errorf("expected Persist=20m from T1, got: %v", res.Persist)
	}
}

func assertDisabledControl(t *testing.T, res *ssh.ControlConfig, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}
	if res.Path != "none" {
		t.Errorf("expected Path='none', got: %v", res.Path)
	}
	if res.Master != ssh.ControlMasterNo {
		t.Errorf("expected Master=no when Path=none, got: %v", res.Master)
	}
	if res.Persist != "" {
		t.Errorf("expected Persist='' when Path=none, got: %v", res.Persist)
	}
	if res.IsEnabled() {
		t.Error("expected IsEnabled() == false")
	}
}

func TestResolveControl_DisableSharing_SNone(t *testing.T) {
	// T2 has active multiplexing
	t2 := &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "~/.ssh/sock"}
	provider := setupTestProvider(t, t2, nil, "")
	adp := NewSSHAdapter(provider)

	// T1 specifies Path: "none"
	var t1 SessionControlOptions
	t1.SetPath("none")

	res, err := adp.ResolveControl("testnode", t1)
	assertDisabledControl(t, res, err)
}

func TestResolveControl_DisableSharing_SNone_WithLowerTierPersist(t *testing.T) {
	t.Run("Tier2_Node_Configured_Persist", func(t *testing.T) {
		t2 := &ssh.ControlConfig{
			Master:  ssh.ControlMasterAuto,
			Path:    "~/.ssh/node.sock",
			Persist: "10m",
		}
		provider := setupTestProvider(t, t2, nil, "")
		adp := NewSSHAdapter(provider)

		var t1 SessionControlOptions
		t1.SetPath("none")

		res, err := adp.ResolveControl("testnode", t1)
		assertDisabledControl(t, res, err)
	})

	t.Run("Tier3_Global_Configured_Persist", func(t *testing.T) {
		t3 := &ssh.ControlConfig{
			Master:  ssh.ControlMasterAuto,
			Path:    "~/.ssh/global.sock",
			Persist: "15m",
		}
		provider := setupTestProvider(t, nil, t3, "")
		adp := NewSSHAdapter(provider)

		var t1 SessionControlOptions
		t1.SetPath("none")

		res, err := adp.ResolveControl("testnode", t1)
		assertDisabledControl(t, res, err)
	})

	t.Run("Tier4_OpenSSH_Configured_Persist", func(t *testing.T) {
		openSSH := `
Host testnode
    ControlMaster auto
    ControlPath ~/.ssh/mux-%r@%h:%p
    ControlPersist 10m
`
		provider := setupTestProvider(t, nil, nil, openSSH)
		adp := NewSSHAdapter(provider)

		var t1 SessionControlOptions
		t1.SetPath("none")

		res, err := adp.ResolveControl("testnode", t1)
		assertDisabledControl(t, res, err)
	})

	t.Run("Tier4_OpenSSH_Host_Explicit_PathNone_With_Wildcard_Persist", func(t *testing.T) {
		openSSH := `
Host testnode
    ControlPath none

Host *
    ControlMaster auto
    ControlPath ~/.ssh/mux-%h
    ControlPersist 10m
`
		provider := setupTestProvider(t, nil, nil, openSSH)
		adp := NewSSHAdapter(provider)

		var t1 SessionControlOptions

		res, err := adp.ResolveControl("testnode", t1)
		assertDisabledControl(t, res, err)
	})

	t.Run("Tier2_Node_Explicit_PathNone_With_Tier3_Global_Persist", func(t *testing.T) {
		t2 := &ssh.ControlConfig{Path: "none"}
		t3 := &ssh.ControlConfig{
			Master:  ssh.ControlMasterAuto,
			Path:    "~/.ssh/global.sock",
			Persist: "10m",
		}
		provider := setupTestProvider(t, t2, t3, "")
		adp := NewSSHAdapter(provider)

		var t1 SessionControlOptions

		res, err := adp.ResolveControl("testnode", t1)
		assertDisabledControl(t, res, err)
	})
}

func TestResolveControl_ExplicitMasterNo(t *testing.T) {
	// T3 has active multiplexing
	t3 := &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "~/.ssh/sock"}
	provider := setupTestProvider(t, nil, t3, "")
	adp := NewSSHAdapter(provider)

	// T1 specifies Master: "no"
	var t1 SessionControlOptions
	t1.SetMaster(ssh.ControlMasterNo)

	res, err := adp.ResolveControl("testnode", t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if res.Master != ssh.ControlMasterNo {
		t.Errorf("expected Master=no, got: %v", res.Master)
	}
	if res.Path != "~/.ssh/sock" {
		t.Errorf("expected Path preserved from T3, got: %v", res.Path)
	}
}

func TestResolveControl_Error_MasterWithoutPath(t *testing.T) {
	provider := setupTestProvider(t, nil, nil, "")
	adp := NewSSHAdapter(provider)

	// T1 specifies Master: yes, but no path in any tier
	var t1 SessionControlOptions
	t1.SetMaster(ssh.ControlMasterYes)

	_, err := adp.ResolveControl("testnode", t1)
	if err == nil || !strings.Contains(err.Error(), "ControlPath is required when ControlMaster is yes") {
		t.Fatalf("expected ControlPath is required error, got: %v", err)
	}
}

func TestResolveControl_Error_PersistWithoutPath(t *testing.T) {
	provider := setupTestProvider(t, nil, nil, "")
	adp := NewSSHAdapter(provider)

	// T1 specifies Persist: 10m, but no path in any tier
	var t1 SessionControlOptions
	t1.SetPersist("10m")

	_, err := adp.ResolveControl("testnode", t1)
	if err == nil || !strings.Contains(err.Error(), "ControlPath is required when ControlPersist is configured") {
		t.Fatalf("expected ControlPath is required error, got: %v", err)
	}
}

func TestResolveControl_Error_InvalidMasterMode(t *testing.T) {
	provider := setupTestProvider(t, nil, nil, "")
	adp := NewSSHAdapter(provider)

	opts, err := ParseOptionStrings([]string{"ControlMaster=invalid"})
	if err == nil || !strings.Contains(err.Error(), "unsupported ControlMaster option") {
		t.Fatalf("expected unsupported ControlMaster error, got: %v", err)
	}
	_ = opts

	// Also test direct struct with invalid mode passed to ResolveControl
	invalidMode := ssh.ControlMasterMode("invalid")
	t1 := SessionControlOptions{Master: &invalidMode, Path: new(string)}
	*t1.Path = "/tmp/sock"
	_, err = adp.ResolveControl("testnode", t1)
	if err == nil || !strings.Contains(err.Error(), "unsupported ControlMaster option") {
		t.Fatalf("expected unsupported ControlMaster error, got: %v", err)
	}
}

func TestResolveControl_Error_InvalidPersistDuration(t *testing.T) {
	provider := setupTestProvider(t, nil, nil, "")
	adp := NewSSHAdapter(provider)

	opts, err := ParseOptionStrings([]string{"ControlPersist=badval"})
	if err == nil || !strings.Contains(err.Error(), "invalid ControlPersist") {
		t.Fatalf("expected invalid ControlPersist error, got: %v", err)
	}
	_ = opts

	// Also test direct struct with invalid persist duration passed to ResolveControl
	badPersist := "10xyz"
	t1 := SessionControlOptions{Persist: &badPersist, Path: new(string)}
	*t1.Path = "/tmp/sock"
	_, err = adp.ResolveControl("testnode", t1)
	if err == nil || (!strings.Contains(err.Error(), "bad ControlPersist argument") && !strings.Contains(err.Error(), "invalid")) {
		t.Fatalf("expected invalid persist duration error, got: %v", err)
	}
}

func TestResolveControl_VirtualOpenSSHNode(t *testing.T) {
	openSSHContent := `
Host app1
    HostName 10.0.0.50
    User deploy
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 10m
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(&config.Configuration{}, parser)
	adp := NewSSHAdapter(provider)

	// T1 specifies CLI override for Path
	var t1 SessionControlOptions
	t1.SetPath("/tmp/override.sock")

	res, err := adp.ResolveControl(config.OpenSSHNodePrefix+"app1", t1)
	if err != nil {
		t.Fatalf("ResolveControl failed: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if res.Path != "/tmp/override.sock" {
		t.Errorf("expected overridden Path, got: %v", res.Path)
	}
	if res.Master != ssh.ControlMasterAuto {
		t.Errorf("expected Master=auto from virtual node, got: %v", res.Master)
	}
	if res.Persist != "10m" {
		t.Errorf("expected Persist=10m from virtual node, got: %v", res.Persist)
	}
}

func TestAdapter_GetControlConfig_ControlProviderContract(t *testing.T) {
	var _ ssh.ControlProvider = (*SSHAdapter)(nil)

	t2 := &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "~/.ssh/cm-%h", Persist: "10m"}
	provider := setupTestProvider(t, t2, nil, "")

	var sessionOpts SessionControlOptions
	sessionOpts.SetMaster(ssh.ControlMasterYes)

	adp := NewSSHAdapter(provider, WithSessionControlOverride("testnode", sessionOpts))

	ctrl, err := adp.GetControlConfig("testnode")
	if err != nil {
		t.Fatalf("GetControlConfig failed: %v", err)
	}
	if ctrl == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if ctrl.Master != ssh.ControlMasterYes {
		t.Errorf("expected Master=yes from session override, got: %v", ctrl.Master)
	}
	if ctrl.Path != "~/.ssh/cm-%h" {
		t.Errorf("expected Path preserved from node config, got: %v", ctrl.Path)
	}
	if ctrl.Persist != "10m" {
		t.Errorf("expected Persist preserved from node config, got: %v", ctrl.Persist)
	}
}

func TestAdapter_ExpandControlPath_Helper(t *testing.T) {
	provider := setupTestProvider(t, nil, nil, "")
	adp := NewSSHAdapter(provider)

	raw := "~/.ssh/mux-%r@%h:%p"
	expanded, err := adp.ExpandControlPath("testnode", raw)
	if err != nil {
		t.Fatalf("ExpandControlPath failed: %v", err)
	}

	if !strings.Contains(expanded, "alice@192.168.1.100:2222") {
		t.Fatalf("expected expanded path to contain target info, got: %q", expanded)
	}

	// raw path "none" or empty should be returned as-is
	noneExp, err := adp.ExpandControlPath("testnode", "none")
	if err != nil || noneExp != "none" {
		t.Fatalf("expected none returned as-is, got: %q, %v", noneExp, err)
	}
}

func TestSessionControlOptions_ParseOptionStrings(t *testing.T) {
	options := []string{
		"ControlMaster=auto",
		"ControlPath=~/.ssh/sockets/%r@%h:%p",
		"ControlPersist=15m",
	}

	opts, err := ParseOptionStrings(options)
	if err != nil {
		t.Fatalf("ParseOptionStrings failed: %v", err)
	}

	if opts.Master == nil || *opts.Master != ssh.ControlMasterAuto {
		t.Errorf("expected Master=auto, got: %v", opts.Master)
	}
	if opts.Path == nil || *opts.Path != "~/.ssh/sockets/%r@%h:%p" {
		t.Errorf("expected Path=~/.ssh/sockets/%%r@%%h:%%p, got: %v", opts.Path)
	}
	if opts.Persist == nil || *opts.Persist != "15m" {
		t.Errorf("expected Persist=15m, got: %v", opts.Persist)
	}

	// Invalid format without '='
	_, err = ParseOptionStrings([]string{"ControlMaster"})
	if err == nil || !strings.Contains(err.Error(), "invalid -o option format") {
		t.Fatalf("expected invalid format error, got: %v", err)
	}
}

func TestResolveControl_Tier4_ConcreteHostOverridesWildcard(t *testing.T) {
	// Verifies that a concrete host IP match (Host 192.168.1.100) takes precedence
	// over a generic wildcard fallback (Host *), even though nodeName is "testnode".
	t4OpenSSH := `
Host 192.168.1.100
    ControlMaster yes
    ControlPath ~/.ssh/specific-ip.sock

Host *
    ControlMaster auto
    ControlPath ~/.ssh/fallback-wildcard.sock
`
	provider := setupTestProvider(t, nil, nil, t4OpenSSH)
	adp := NewSSHAdapter(provider)

	var t1 SessionControlOptions
	res, err := adp.ResolveControl("testnode", t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if res.Path != "~/.ssh/specific-ip.sock" {
		t.Errorf("expected Path=~/.ssh/specific-ip.sock (concrete IP match), got: %v", res.Path)
	}
	if res.Master != ssh.ControlMasterYes {
		t.Errorf("expected Master=yes (concrete IP match), got: %v", res.Master)
	}
}

func TestResolveControl_Tier4_ConcreteAliasOverridesWildcard(t *testing.T) {
	// Verifies that a concrete alias match (Host node-alias) takes precedence
	// over a generic wildcard fallback (Host *).
	t4OpenSSH := `
Host node-alias
    ControlMaster ask
    ControlPath ~/.ssh/specific-alias.sock

Host *
    ControlMaster auto
    ControlPath ~/.ssh/fallback-wildcard.sock
`
	provider := setupTestProvider(t, nil, nil, t4OpenSSH)
	adp := NewSSHAdapter(provider)

	var t1 SessionControlOptions
	res, err := adp.ResolveControl("testnode", t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if res.Path != "~/.ssh/specific-alias.sock" {
		t.Errorf("expected Path=~/.ssh/specific-alias.sock (concrete alias match), got: %v", res.Path)
	}
	if res.Master != ssh.ControlMasterAsk {
		t.Errorf("expected Master=ask (concrete alias match), got: %v", res.Master)
	}
}

func TestResolveControl_Tier4_ConcreteNodePrecedenceOverIP(t *testing.T) {
	// Verifies that if both nodeName and Host.Address have concrete definitions,
	// the more specific nodeName definition takes precedence.
	t4OpenSSH := `
Host testnode
    ControlMaster ask
    ControlPath ~/.ssh/specific-node.sock

Host 192.168.1.100
    ControlMaster yes
    ControlPath ~/.ssh/specific-ip.sock

Host *
    ControlMaster auto
    ControlPath ~/.ssh/fallback-wildcard.sock
`
	provider := setupTestProvider(t, nil, nil, t4OpenSSH)
	adp := NewSSHAdapter(provider)

	var t1 SessionControlOptions
	res, err := adp.ResolveControl("testnode", t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}

	if res.Path != "~/.ssh/specific-node.sock" {
		t.Errorf("expected Path=~/.ssh/specific-node.sock (concrete node match), got: %v", res.Path)
	}
	if res.Master != ssh.ControlMasterAsk {
		t.Errorf("expected Master=ask (concrete node match), got: %v", res.Master)
	}
}

// TestResolveControl_VirtualNodeStaysTier4 verifies that ~/.ssh/config values
// imported into an OpenSSH virtual node never outrank the persisted global
// default (Tier 3). The virtual node is a Tier 4 source by definition.
func TestResolveControl_VirtualNodeStaysTier4(t *testing.T) {
	openSSHContent := `
Host app1
    HostName 10.0.0.50
    ControlMaster yes
    ControlPath ~/.ssh/specific.sock
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Control:    &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/global.sock", Persist: "10m"},
	}
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)
	adp := NewSSHAdapter(provider)

	res, err := adp.ResolveControl(config.OpenSSHNodePrefix+"app1", SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveControl failed: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil ControlConfig")
	}
	if res.Path != "/tmp/global.sock" || res.Master != ssh.ControlMasterAuto {
		t.Fatalf("global default must outrank the OpenSSH virtual node, got %+v", res)
	}

	// A session override (Tier 1) still wins over everything.
	var session SessionControlOptions
	session.SetPath("/tmp/session.sock")
	res, err = adp.ResolveControl(config.OpenSSHNodePrefix+"app1", session)
	if err != nil {
		t.Fatalf("ResolveControl with session override failed: %v", err)
	}
	if res.Path != "/tmp/session.sock" {
		t.Fatalf("expected session override to win, got %+v", res)
	}
}

// TestResolveControl_VirtualNodeInheritsMissingMaster verifies that an OpenSSH
// host declaring only ControlPath/ControlPersist inherits the master mode from a
// lower tier instead of forcing "no".
func TestResolveControl_VirtualNodeInheritsMissingMaster(t *testing.T) {
	openSSHContent := `
Host app2
    HostName 10.0.0.60
    ControlPath ~/.ssh/only-path.sock
    ControlPersist 5m
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Control:    &ssh.ControlConfig{Master: ssh.ControlMasterAuto},
	}
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)
	adp := NewSSHAdapter(provider)

	node, _, _, err := provider.Resolve(config.OpenSSHNodePrefix + "app2")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if node.Control == nil || node.Control.Master != "" {
		t.Fatalf("expected an unset ControlMaster for a host that omits it, got %+v", node.Control)
	}

	res, err := adp.ResolveControl(config.OpenSSHNodePrefix+"app2", SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveControl failed: %v", err)
	}
	if res.Master != ssh.ControlMasterAuto {
		t.Fatalf("expected inherited ControlMaster=auto, got %q", res.Master)
	}
	if res.Path != "~/.ssh/only-path.sock" || res.Persist != "5m" {
		t.Fatalf("expected OpenSSH path and persist, got %+v", res)
	}
}

// TestParseOptionStrings_RejectsUnknownKey verifies that a mistyped -o key fails
// loudly. Silently ignoring it would disable the behavior the user asked for.
func TestParseOptionStrings_RejectsUnknownKey(t *testing.T) {
	for _, option := range []string{
		"ControlMaste=yes",
		"EnableMultiplexing=true",
		"Compression=yes",
	} {
		if _, err := ParseOptionStrings([]string{option}); err == nil {
			t.Fatalf("expected %q to be rejected", option)
		} else if !strings.Contains(err.Error(), "unsupported -o option") {
			t.Fatalf("unexpected error for %q: %v", option, err)
		}
	}

	// Supported keys still parse, including the ones applied to the target by the CLI.
	opts, err := ParseOptionStrings([]string{"ControlMaster=auto", "ControlPath=/tmp/x.sock", "Port=2222", "User=deploy", "IdentityFile=~/.ssh/id", "ProxyJump=bastion"})
	if err != nil {
		t.Fatalf("expected supported options to parse: %v", err)
	}
	if opts.Master == nil || *opts.Master != ssh.ControlMasterAuto {
		t.Fatalf("expected ControlMaster=auto, got %v", opts.Master)
	}
}
