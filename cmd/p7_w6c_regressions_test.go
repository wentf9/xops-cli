package cmd

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W6c_DEF6M1_ProxyJumpControlCharsAndWhitespaceFailClosedAcrossCLI(t *testing.T) {
	t.Parallel()

	badJumps := []string{
		"none\n",
		"bastion\n",
		"\n",
		"\t",
		"\r\n",
		"\u0085",
		"\v",
		"\f",
		"\u2028",
		"\u2029",
		"   ",
	}

	t.Run("ToSessionControlOptionsWithJump_rejects_control_and_whitespace", func(t *testing.T) {
		t.Parallel()
		for _, bad := range badJumps {
			f := &SSHControlFlags{}
			if got, err := f.ToSessionControlOptionsWithJump(bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ToSessionControlOptionsWithJump(%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, got, err)
			}
		}
		f := &SSHControlFlags{}
		if got, err := f.ToSessionControlOptionsWithJump(""); err != nil || !got.IsEmpty() {
			t.Fatalf("ToSessionControlOptionsWithJump(\"\") = (%+v, %v), want empty nil error", got, err)
		}
	})

	t.Run("ssh_control_command_with_malformed_dash_J_fails_closed", func(t *testing.T) {
		t.Parallel()
		for _, bad := range append([]string{""}, badJumps...) {
			o := NewSshOptions()
			cmd := newCmdSshWithOptions(o)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			args := []string{"-J", bad, "-S", "/tmp/cm.sock", "-O", "check", "saved-web"}
			if err := cmd.ParseFlags(args); err != nil {
				t.Fatalf("ParseFlags(%q): %v", bad, err)
			}
			err := o.Complete(cmd, cmd.Flags().Args())
			if !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ssh Complete(-J %q -S /tmp/cm.sock -O check saved-web) err = %v, want ErrSSHOptionsValidation", bad, err)
			}
			if code, ok := ExitCodeFromError(err); !ok || code != 255 {
				t.Errorf("ssh Complete(-J %q -O check) exit code = (%d, %v), want (255, true)", bad, code, ok)
			}

			// Direct ExecuteControlCommand without Complete must also reject malformed -J.
			if bad != "" {
				direct := NewSshOptions()
				direct.JumpHost = bad
				direct.control.ControlPath = "/tmp/cm.sock"
				direct.control.CtlCmd = "check"
				direct.control.ctlCmdSet = true
				direct.args = []string{"saved-web"}
				var stderr bytes.Buffer
				execErr := executeControlCommandWithStreams(t.Context(), direct, controlStreams{
					Stdin:  strings.NewReader(""),
					Stdout: io.Discard,
					Stderr: &stderr,
				})
				if execErr == nil {
					t.Errorf("executeControlCommandWithStreams(JumpHost=%q) succeeded, want error", bad)
				}
			}
		}
	})

	t.Run("all_cli_commands_reject_bad_J_and_accept_unset_J", func(t *testing.T) {
		t.Parallel()
		builders := []struct {
			name string
			make func() *cobra.Command
		}{
			{"ssh", NewCmdSsh},
			{"scp", NewCmdScp},
			{"sftp", NewCmdSftp},
			{"exec", NewCmdExec},
		}
		for _, b := range builders {
			// Unset -J must pass "" cleanly.
			unsetCmd := b.make()
			unsetCmd.SetOut(io.Discard)
			unsetCmd.SetErr(io.Discard)
			if err := unsetCmd.ParseFlags(nil); err != nil {
				t.Fatalf("%s ParseFlags(nil): %v", b.name, err)
			}
			optsUnset := NewSshOptions()
			if err := ApplyGeneralOptions(optsUnset, nil, unsetCmd.Flags()); err != nil {
				t.Errorf("%s ApplyGeneralOptions(unset -J) unexpected error: %v", b.name, err)
			}
			if optsUnset.effectiveCLIJumpHost() != "" {
				t.Errorf("%s unset -J effectiveCLIJumpHost() = %q, want empty", b.name, optsUnset.effectiveCLIJumpHost())
			}

			for _, bad := range []string{"", "   ", "\n", "none\n", "bastion\n", "\t", "\r\n", "\u0085"} {
				c := b.make()
				c.SetOut(io.Discard)
				c.SetErr(io.Discard)
				if err := c.ParseFlags([]string{"-J", bad}); err != nil {
					t.Fatalf("%s ParseFlags(-J %q): %v", b.name, bad, err)
				}
				if err := ApplyGeneralOptions(NewSshOptions(), nil, c.Flags()); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
					t.Errorf("%s ApplyGeneralOptions(-J %q) err = %v, want ErrSSHOptionsValidation", b.name, bad, err)
				}
			}
		}
	})
}

func TestP7W6c_DEF6M2_ControlTargetAppliesGeneralOptionsAndMatchesDial(t *testing.T) {
	t.Parallel()

	env := sshenv.Discover()
	globalMux := &ssh.Options{}
	globalMux.SetControlMaster(ssh.ControlMasterAuto)
	globalMux.SetControlPath("/tmp/cm-p7w6c-cmd-%h-%p-%r-%n-%j-%C")

	cases := []struct {
		name     string
		rawOpts  []string
		wantJump string
	}{
		{
			name:     "dash_o_ProxyJump_none",
			rawOpts:  []string{"ProxyJump=none"},
			wantJump: "",
		},
		{
			name:     "dash_o_ProxyJump_edge_jump",
			rawOpts:  []string{"ProxyJump=edge-jump"},
			wantJump: "edge-jump",
		},
		{
			name:     "dash_o_ProxyJump_none_and_ProxyCommand",
			rawOpts:  []string{"ProxyJump=none", "ProxyCommand=nc %h %p"},
			wantJump: "",
		},
		{
			name:     "dash_o_ProxyJump_edge_jump_and_shadowed_ProxyCommand",
			rawOpts:  []string{"ProxyJump=edge-jump", "ProxyCommand=nc %h %p"},
			wantJump: "edge-jump",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			readOnlyProv, repo := buildCmdP3EquivalenceFixtures(t, globalMux)

			// Call controlTarget directly without prior ensureArgsParsed/ApplyGeneralOptions
			// to verify controlTarget invokes ensureGeneralOptionsApplied().
			ctlOpts := NewSshOptions()
			ctlOpts.Host = "web-01"
			ctlOpts.control.Options = append([]string(nil), tc.rawOpts...)

			gotTarget := controlTarget(ctlOpts, readOnlyProv, "web-01")
			if gotTarget.JumpHost != tc.wantJump {
				t.Fatalf("controlTarget(-o %v).JumpHost = %q, want %q", tc.rawOpts, gotTarget.JumpHost, tc.wantJump)
			}
			gotSock, err := controlSocketPath(ctlOpts, readOnlyProv, "web-01")
			if err != nil {
				t.Fatalf("controlSocketPath(-o %v): %v", tc.rawOpts, err)
			}

			// Compare byte-for-byte against dial path.
			dialOpts := NewSshOptions()
			dialOpts.Remember = "never"
			dialOpts.args = []string{"web-01"}
			dialOpts.control.Options = append([]string(nil), tc.rawOpts...)
			if err := dialOpts.ensureArgsParsed(); err != nil {
				t.Fatalf("dialOpts.ensureArgsParsed: %v", err)
			}
			adpOpts, err := dialOpts.buildAdapterOptions("web-01", repo.Snapshot(), repo)
			if err != nil {
				t.Fatalf("buildAdapterOptions: %v", err)
			}
			adp := adapter.NewSSHAdapter(repo, adpOpts...)
			clientCfg, err := adp.GetConfig("web-01")
			if err != nil {
				t.Fatalf("GetConfig(web-01): %v", err)
			}
			dialCtrl, err := adp.GetControlConfig("web-01")
			if err != nil {
				t.Fatalf("GetControlConfig(web-01): %v", err)
			}
			dialTarget := ssh.BuildClientTargetContext("web-01", clientCfg, env, nil)
			dialSock, err := dialCtrl.ResolvePath(env, dialTarget)
			if err != nil {
				t.Fatalf("dialCtrl.ResolvePath: %v", err)
			}

			if gotTarget != dialTarget {
				t.Fatalf("TargetContext mismatch:\n  controlTarget = %+v\n  dial          = %+v", gotTarget, dialTarget)
			}
			if gotTarget.CanonicalTargetIdentity() != dialTarget.CanonicalTargetIdentity() {
				t.Fatalf("CanonicalTargetIdentity mismatch:\n  control = %q\n  dial    = %q",
					gotTarget.CanonicalTargetIdentity(), dialTarget.CanonicalTargetIdentity())
			}
			if gotSock != dialSock {
				t.Fatalf("ControlPath mismatch:\n  control = %q\n  dial    = %q", gotSock, dialSock)
			}
		})
	}
}

func TestP7W6c_DEF6M3_ProxyCommandPathCheckerResolvesTier2SavedAliases(t *testing.T) {
	t.Parallel()

	makeProvider := func(bastionProxyCmd string) config.ConfigProvider {
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Hosts.Set("h-outer", models.Host{Address: "10.0.0.1", Port: 22})
		cfg.Hosts.Set("h-mid", models.Host{Address: "10.0.0.2", Port: 22})
		cfg.Hosts.Set("h-app", models.Host{Address: "10.0.0.3", Port: 22})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})

		var outerOpts *ssh.Options
		if bastionProxyCmd != "" {
			outerOpts = ssh.MustOptions(ssh.OptionProxyCommand, bastionProxyCmd)
		}
		cfg.Nodes.Set("ops@10.0.0.1:22", models.Node{
			HostRef:     "h-outer",
			IdentityRef: "id-ops",
			Alias:       []string{"bastion"},
			SSHOptions:  outerOpts,
		})
		cfg.Nodes.Set("ops@10.0.0.2:22", models.Node{
			HostRef:     "h-mid",
			IdentityRef: "id-ops",
			Alias:       []string{"mid-jump"},
			ProxyJump:   "bastion",
		})
		cfg.Nodes.Set("app", models.Node{
			HostRef:     "h-app",
			IdentityRef: "id-ops",
			ProxyJump:   "bastion",
		})
		cfg.Nodes.Set("app-transitive", models.Node{
			HostRef:     "h-app",
			IdentityRef: "id-ops",
			ProxyJump:   "mid-jump",
		})
		return config.NewProviderWithoutOpenSSH(cfg)
	}

	baseOpts := &SshOptions{}

	// 1. Clean bastion alias: proxyCommandPathChecker resolves "bastion" -> "ops@10.0.0.1:22" and succeeds with false.
	cleanProv := makeProvider("")
	if hasProxy, err := baseOpts.hasActiveProxyCommandInPath(cleanProv, "app", nil); err != nil || hasProxy {
		t.Fatalf("hasActiveProxyCommandInPath(app, clean bastion) = (%v, %v), want (false, nil)", hasProxy, err)
	}
	if hasProxy, err := baseOpts.hasActiveProxyCommandInPath(cleanProv, "app-transitive", nil); err != nil || hasProxy {
		t.Fatalf("hasActiveProxyCommandInPath(app-transitive, clean chain) = (%v, %v), want (false, nil)", hasProxy, err)
	}

	// 2. Bastion with active ProxyCommand: both single-hop and transitive alias paths detect ProxyCommand.
	cmdProv := makeProvider("nc %h %p")
	if hasProxy, err := baseOpts.hasActiveProxyCommandInPath(cmdProv, "app", nil); err != nil || !hasProxy {
		t.Fatalf("hasActiveProxyCommandInPath(app, bastion ProxyCommand) = (%v, %v), want (true, nil)", hasProxy, err)
	}
	if hasProxy, err := baseOpts.hasActiveProxyCommandInPath(cmdProv, "app-transitive", nil); err != nil || !hasProxy {
		t.Fatalf("hasActiveProxyCommandInPath(app-transitive, outer bastion ProxyCommand) = (%v, %v), want (true, nil)", hasProxy, err)
	}
}

func TestP7W6c_DEF6L1_CaseInsensitiveOpenSSHPrefixHandoffAndJumpSuppression(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host bastion
    HostName 10.50.0.1
    User ops
    Port 22
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-saved", models.Host{Address: "10.50.0.9", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-app", models.Node{HostRef: "h-saved", IdentityRef: "id-ops"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	const upperHop = "OPENSSH:alice@bastion:2222"
	const lowerHop = "openssh:alice@bastion:2222"

	// 1. parseJumpHopSpec preserves explicit user@host:port qualifiers for uppercase OPENSSH:.
	user, host, port, hasExplicit := parseJumpHopSpec(upperHop)
	if user != "alice" || host != "bastion" || port != 2222 || !hasExplicit {
		t.Fatalf("parseJumpHopSpec(%q) = (%q, %q, %d, %v), want (alice, bastion, 2222, true)", upperHop, user, host, port, hasExplicit)
	}

	// 2. addPersistentJumpHopKeys + isSuppressedJumpMaster handle mixed-case OPENSSH: symmetrically
	//    while never suppressing an explicit user/port master under a bare alias jump or a different user.
	jumpsFromUpper := make(map[string]bool)
	addPersistentJumpHopKeys(jumpsFromUpper, upperHop, true)
	if !isSuppressedJumpMaster(jumpsFromUpper, lowerHop, "openssh:bastion") {
		t.Fatalf("expected %q to be suppressed when jump hop is %q (jumps=%v)", lowerHop, upperHop, jumpsFromUpper)
	}
	if isSuppressedJumpMaster(jumpsFromUpper, "openssh:bastion", "openssh:bastion") {
		t.Fatalf("explicit jump %q must NOT suppress bare master openssh:bastion (jumps=%v)", upperHop, jumpsFromUpper)
	}
	if isSuppressedJumpMaster(jumpsFromUpper, "OPENSSH:bob@bastion:2222", "openssh:bastion") {
		t.Fatalf("explicit jump %q must NOT suppress distinct user bob@bastion:2222 (jumps=%v)", upperHop, jumpsFromUpper)
	}

	jumpsFromLower := make(map[string]bool)
	addPersistentJumpHopKeys(jumpsFromLower, lowerHop, true)
	if !isSuppressedJumpMaster(jumpsFromLower, upperHop, "openssh:bastion") {
		t.Fatalf("expected %q to be suppressed when jump hop is %q (jumps=%v)", upperHop, lowerHop, jumpsFromLower)
	}

	jumpsBare := make(map[string]bool)
	addPersistentJumpHopKeys(jumpsBare, "openssh:bastion", false)
	if isSuppressedJumpMaster(jumpsBare, upperHop, "openssh:bastion") {
		t.Fatalf("bare jump openssh:bastion must NOT suppress explicit master %q", upperHop)
	}

	// 3. resolveJumpHopConnection resolves uppercase OPENSSH:alice@bastion:2222 to alice@10.50.0.1:2222.
	snap, ok := resolveJumpHopConnection(prov, upperHop, true)
	if !ok || snap.Host.Address != "10.50.0.1" || snap.Host.Port != 2222 || snap.Identity.User != "alice" {
		t.Fatalf("resolveJumpHopConnection(%q) = (%+v, %v), want alice@10.50.0.1:2222", upperHop, snap, ok)
	}

	// 4. normalizeOwnedMasterNodeID, resolveSavedMasterNodeID, and lookupJumpHopMaster treat OPENSSH: case-insensitively.
	if got := normalizeOwnedMasterNodeID(nil, upperHop, nil); got != lowerHop {
		t.Fatalf("normalizeOwnedMasterNodeID(nil, %q) = %q, want %q", upperHop, got, lowerHop)
	}
	if got := resolveSavedMasterNodeID(prov, "OPENSSH:saved-app", "10.50.0.9", "ops", 22); got != "" {
		t.Fatalf("resolveSavedMasterNodeID(OPENSSH:saved-app) = %q, want empty", got)
	}
	if got := resolvePersistentHandoffNodeID(nil, nil, nil, upperHop); got != upperHop {
		t.Fatalf("resolvePersistentHandoffNodeID(%q) = %q, want %q", upperHop, got, upperHop)
	}

	// 5. lookupJumpHopMaster matches an indexed master across mixed-case OPENSSH: prefixes.
	fakeMaster := &ssh.MuxServer{}
	byHost := map[string]*ssh.MuxServer{lowerHop: fakeMaster}
	if gotMaster, _ := lookupJumpHopMaster(nil, byHost, prov, upperHop, true); gotMaster != fakeMaster {
		t.Fatalf("lookupJumpHopMaster(%q) = %v, want indexed master %v", upperHop, gotMaster, fakeMaster)
	}

	// 6. cmd/utils exclude matching handles uppercase OPENSSH: composite IDs consistently.
	excl := map[string]struct{}{lowerHop: {}}
	if !cmdutils.IsTargetExcluded(excl, cmdutils.ExcludeTargetInfo{
		NodeID:     upperHop,
		BaseNodeID: "OPENSSH:bastion",
		User:       "alice",
		Port:       2222,
	}) {
		t.Fatalf("IsTargetExcluded failed to match %q against %q", upperHop, lowerHop)
	}
}

func TestP7W6c_DEF6L1_NoCaseSensitiveOpenSSHPrefixChecksInCmdOrPkg(t *testing.T) {
	t.Parallel()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Dir(filepath.Dir(thisFile))
	allowedFile := filepath.ToSlash(filepath.Join("pkg", "config", "target_ref.go"))

	fset := token.NewFileSet()
	var violations []string

	for _, rootDir := range []string{"cmd", "pkg"} {
		absRoot := filepath.Join(repoRoot, rootDir)
		err := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				return relErr
			}
			relSlash := filepath.ToSlash(rel)
			if relSlash == allowedFile {
				return nil
			}
			fileAST, parseErr := parser.ParseFile(fset, path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			ast.Inspect(fileAST, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall || len(call.Args) < 2 {
					return true
				}
				sel, isSel := call.Fun.(*ast.SelectorExpr)
				if !isSel {
					return true
				}
				switch sel.Sel.Name {
				case "HasPrefix", "TrimPrefix", "CutPrefix":
				default:
					return true
				}
				if exprReferencesOpenSSHPrefix(call.Args[1]) {
					pos := fset.Position(call.Pos())
					violations = append(violations, relSlash+":"+strconv.Itoa(pos.Line)+" calls "+sel.Sel.Name+" with OpenSSH prefix")
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("WalkDir(%s): %v", rootDir, err)
		}
	}

	if len(violations) > 0 {
		t.Fatalf("case-sensitive OpenSSHNodePrefix checks found outside %s:\n%s", allowedFile, strings.Join(violations, "\n"))
	}
}

func exprReferencesOpenSSHPrefix(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "OpenSSHNodePrefix"
	case *ast.SelectorExpr:
		return e.Sel.Name == "OpenSSHNodePrefix"
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return false
		}
		val, err := strconv.Unquote(e.Value)
		return err == nil && strings.EqualFold(val, config.OpenSSHNodePrefix)
	default:
		return false
	}
}
