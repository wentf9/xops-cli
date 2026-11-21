package clicontract

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/ssh"
	"gopkg.in/yaml.v3"
)

// TestP6_SecurityPredicateFailClosedASTGuard AST-verifies critical fail-closed
// security predicates across core/, pkg/, internal/, and cmd/.
func TestP6_SecurityPredicateFailClosedASTGuard(t *testing.T) {
	t.Parallel()
	root := p4RepoRoot(t)

	t.Run("SCP_IsCollectedPathExcludedReturnsBoolAndError", func(t *testing.T) {
		checkSCPIsCollectedPathExcludedSignature(t, root)
	})
	t.Run("MuxDaemon_IsTargetOnlyOptionErrorBranchesFailClosed", func(t *testing.T) {
		checkMuxDaemonTargetOnlyOptionFailClosed(t, root)
	})
	t.Run("ControlConfig_MatchesMasterTargetFailClosedOnEmptyHosts", func(t *testing.T) {
		checkMatchesMasterTargetFailClosed(t, root)
	})
	t.Run("MCPGuardrail_SwitchDecisionHasExplicitFailClosedDefault", func(t *testing.T) {
		checkGuardrailDecisionSwitchDefault(t, root, "WithGuardrail", "core", "mcp", "guardrail", "guardrail.go")
		checkGuardrailDecisionSwitchDefault(t, root, "Authorize", "core", "mcp", "guardrail", "authorization.go")
	})
}

func checkSCPIsCollectedPathExcludedSignature(t *testing.T, root string) {
	t.Helper()
	pf := parseSingleGoFile(t, root, "cmd", "scp.go")
	fn := findFuncDecl(pf.file, "isCollectedPathExcluded")
	if fn == nil {
		t.Fatalf("%s: isCollectedPathExcluded not found", pf.relPath)
	}
	if fn.Type.Results == nil {
		t.Fatalf("%s: isCollectedPathExcluded has no return types, want (bool, error)", pf.relPath)
	}
	var resultTypes []ast.Expr
	for _, field := range fn.Type.Results.List {
		n := len(field.Names)
		if n == 0 {
			n = 1
		}
		for range n {
			resultTypes = append(resultTypes, field.Type)
		}
	}
	if len(resultTypes) != 2 {
		t.Fatalf("%s: isCollectedPathExcluded returns %d values, want 2 (bool, error)", pf.relPath, len(resultTypes))
	}
	if !isIdentName(resultTypes[0], "bool") || !isIdentName(resultTypes[1], "error") {
		t.Fatalf("%s: isCollectedPathExcluded return types = (%T, %T), want (bool, error)", pf.relPath, resultTypes[0], resultTypes[1])
	}
}

func checkMuxDaemonTargetOnlyOptionFailClosed(t *testing.T, root string) {
	t.Helper()
	pf := parseSingleGoFile(t, root, "cmd", "mux_daemon_spec.go")
	fn := findFuncDecl(pf.file, "isTargetOnlyMuxDaemonOption")
	if fn == nil || fn.Body == nil {
		t.Fatalf("%s: isTargetOnlyMuxDaemonOption not found", pf.relPath)
	}
	errBranches := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if exprContainsErrNilComparison(ifStmt.Cond, token.NEQ) {
			errBranches++
			assertBranchReturnsLiteralTrueNamed(t, pf, "isTargetOnlyMuxDaemonOption", ifStmt.Body)
		} else if exprContainsErrNilComparison(ifStmt.Cond, token.EQL) && ifStmt.Else != nil {
			errBranches++
			assertBranchReturnsLiteralTrueNamed(t, pf, "isTargetOnlyMuxDaemonOption", ifStmt.Else)
		}
		return true
	})
	if errBranches == 0 {
		t.Fatalf("%s: expected at least one error branch (err != nil) in isTargetOnlyMuxDaemonOption", pf.relPath)
	}
	if len(fn.Body.List) == 0 || !isLiteralTrueReturnStmt(fn.Body.List[len(fn.Body.List)-1]) {
		t.Errorf("%s: isTargetOnlyMuxDaemonOption fallback return must be literal return true (fail closed)", pf.relPath)
	}
}

func checkMatchesMasterTargetFailClosed(t *testing.T, root string) {
	t.Helper()
	pf := parseSingleGoFile(t, root, "core", "ssh", "control_config.go")
	fn := findFuncDecl(pf.file, "MatchesMasterTarget")
	if fn == nil || fn.Body == nil {
		t.Fatalf("%s: MatchesMasterTarget not found", pf.relPath)
	}
	foundEmptyTHost := false
	foundMissingMHost := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if exprChecksEmptyStringIdent(ifStmt.Cond, "tHost") {
			foundEmptyTHost = true
			assertBranchReturnsLiteralFalse(t, pf, "MatchesMasterTarget(tHost==\"\")", ifStmt.Body)
		}
		if exprChecksEmptyStringIdent(ifStmt.Cond, "mHost") || exprIsNotIdent(ifStmt.Cond, "ok") {
			foundMissingMHost = true
			assertBranchReturnsLiteralFalse(t, pf, "MatchesMasterTarget(missing mHost)", ifStmt.Body)
		}
		return true
	})
	if !foundEmptyTHost {
		t.Errorf("%s: MatchesMasterTarget missing fail-closed guard on empty tHost", pf.relPath)
	}
	if !foundMissingMHost {
		t.Errorf("%s: MatchesMasterTarget missing fail-closed guard on missing mHost / !ok", pf.relPath)
	}

	// Verify parseMasterTargetIdentity rejects empty host fail-closed too.
	parseFn := findFuncDecl(pf.file, "parseMasterTargetIdentity")
	if parseFn == nil || parseFn.Body == nil {
		t.Fatalf("%s: parseMasterTargetIdentity not found", pf.relPath)
	}
	foundEmptyHostReject := false
	ast.Inspect(parseFn.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || !exprChecksEmptyStringIdent(ifStmt.Cond, "host") {
			return true
		}
		foundEmptyHostReject = true
		assertBranchLastReturnResultIsLiteralFalse(t, pf, "parseMasterTargetIdentity(host==\"\")", ifStmt.Body)
		return true
	})
	if !foundEmptyHostReject {
		t.Errorf("%s: parseMasterTargetIdentity missing fail-closed guard on empty host", pf.relPath)
	}

	// Behavioral reinforcement of the AST invariants.
	if (ssh.TargetContext{Host: ""}).MatchesMasterTarget("host=example.com;port=22") {
		t.Fatal("MatchesMasterTarget must return false when tHost is empty and masterIdentity is non-empty")
	}
	if (ssh.TargetContext{Host: "example.com", Port: 22}).MatchesMasterTarget("port=22;user=root") {
		t.Fatal("MatchesMasterTarget must return false when masterIdentity omits host=")
	}
	if (ssh.TargetContext{Host: "example.com", Port: 22}).MatchesMasterTarget("host=;port=22") {
		t.Fatal("MatchesMasterTarget must return false when masterIdentity has empty host=")
	}
}

func checkGuardrailDecisionSwitchDefault(t *testing.T, root, funcName string, relParts ...string) {
	t.Helper()
	pf := parseSingleGoFile(t, root, relParts...)
	fn := findFuncDecl(pf.file, funcName)
	if fn == nil || fn.Body == nil {
		t.Fatalf("%s: %s not found", pf.relPath, funcName)
	}
	decisionSwitches := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || !isIdentName(sw.Tag, "decision") {
			return true
		}
		decisionSwitches++
		var defaultClause *ast.CaseClause
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if ok && cc.List == nil {
				defaultClause = cc
				break
			}
		}
		if defaultClause == nil {
			pos := pf.fset.Position(sw.Pos())
			t.Errorf("%s:%d: switch decision in %s must have an explicit fail-closed default clause", pf.relPath, pos.Line, funcName)
			return true
		}
		if len(defaultClause.Body) == 0 {
			pos := pf.fset.Position(defaultClause.Pos())
			t.Errorf("%s:%d: default clause in %s switch decision must not be empty", pf.relPath, pos.Line, funcName)
			return true
		}
		ast.Inspect(defaultClause, func(cn ast.Node) bool {
			if br, ok := cn.(*ast.BranchStmt); ok && br.Tok == token.FALLTHROUGH {
				pos := pf.fset.Position(br.Pos())
				t.Errorf("%s:%d: default clause in %s switch decision must not fallthrough", pf.relPath, pos.Line, funcName)
			}
			return true
		})
		if _, isRet := defaultClause.Body[len(defaultClause.Body)-1].(*ast.ReturnStmt); !isRet {
			pos := pf.fset.Position(defaultClause.Pos())
			t.Errorf("%s:%d: default clause in %s switch decision must terminate with return (fail closed)", pf.relPath, pos.Line, funcName)
		}
		return true
	})
	if decisionSwitches == 0 {
		t.Fatalf("%s: expected switch decision inside %s, found 0", pf.relPath, funcName)
	}
}

// TestP6_SecurityStructsZeroValueReflectionGuard verifies fail-closed zero-value
// invariants on security-critical structs, enums, YAML policy decoding, and
// AllowList OptionSpec capability metadata.
func TestP6_SecurityStructsZeroValueReflectionGuard(t *testing.T) {
	t.Parallel()

	t.Run("MuxServerOptionsZeroValueEnforcesPeerCheck", checkMuxServerOptionsZeroValue)
	t.Run("GuardrailDecisionZeroValueIsDeny", checkGuardrailDecisionZeroValue)
	t.Run("PolicyConfigYAMLOmittingEnabledDefaultsTrue", checkPolicyConfigYAMLDefaultEnabled)
	t.Run("AllowListSpecsDeclareSupportedAndFailClosedTokens", checkAllowListSpecCapabilities)
}

func checkMuxServerOptionsZeroValue(t *testing.T) {
	var zero ssh.MuxServerOptions
	if ssh.PeerCheckEnforce != 0 {
		t.Fatalf("ssh.PeerCheckEnforce = %d, want 0 (zero-value safe default)", ssh.PeerCheckEnforce)
	}
	if zero.PeerCheck != ssh.PeerCheckEnforce {
		t.Fatalf("zero-value MuxServerOptions.PeerCheck = %v (%d), want PeerCheckEnforce (%d)", zero.PeerCheck, zero.PeerCheck, ssh.PeerCheckEnforce)
	}
	if zero.HasExpectedUID {
		t.Fatal("zero-value MuxServerOptions.HasExpectedUID = true, want false")
	}
	if ssh.PeerCheckDisabledForTesting == 0 {
		t.Fatal("PeerCheckDisabledForTesting must be non-zero")
	}
	rv := reflect.Zero(reflect.TypeFor[ssh.MuxServerOptions]())
	if got := rv.FieldByName("PeerCheck").Uint(); got != uint64(ssh.PeerCheckEnforce) {
		t.Fatalf("reflect.Zero(MuxServerOptions).PeerCheck = %d, want %d", got, ssh.PeerCheckEnforce)
	}
	if rv.FieldByName("HasExpectedUID").Bool() {
		t.Fatal("reflect.Zero(MuxServerOptions).HasExpectedUID = true, want false")
	}
}

func checkGuardrailDecisionZeroValue(t *testing.T) {
	var d guardrail.Decision
	if d != guardrail.Deny {
		t.Fatalf("zero-value guardrail.Decision = %v (%d), want guardrail.Deny (%d)", d, d, guardrail.Deny)
	}
	if d.String() != "deny" {
		t.Fatalf("zero-value guardrail.Decision.String() = %q, want %q", d.String(), "deny")
	}
	rv := reflect.Zero(reflect.TypeFor[guardrail.Decision]())
	if got := rv.Interface().(guardrail.Decision); got != guardrail.Deny {
		t.Fatalf("reflect.Zero(guardrail.Decision) = %v, want guardrail.Deny", got)
	}
}

func checkPolicyConfigYAMLDefaultEnabled(t *testing.T) {
	for _, tc := range []struct {
		name        string
		rawYAML     string
		wantEnabled bool
	}{
		{"omitted_with_other_fields", "approval_threshold: dangerous\nno_elicit_fallback: deny\n", true},
		{"empty_mapping", "{}\n", true},
		{"explicit_false", "enabled: false\n", false},
		{"explicit_true", "enabled: true\n", true},
	} {
		var cfg corepolicy.Config
		if err := yaml.Unmarshal([]byte(tc.rawYAML), &cfg); err != nil {
			t.Fatalf("%s: yaml.Unmarshal failed: %v", tc.name, err)
		}
		if cfg.Enabled != tc.wantEnabled {
			t.Errorf("%s: Enabled = %v, want %v", tc.name, cfg.Enabled, tc.wantEnabled)
		}
	}
}

func checkAllowListSpecCapabilities(t *testing.T) {
	specs := ssh.RegisteredOptionSpecs()
	allowListCount := 0
	sawPreferredAuth := false
	for _, spec := range specs {
		if !spec.AllowList {
			continue
		}
		allowListCount++
		if spec.SupportedTokens == nil {
			t.Errorf("AllowList OptionSpec %q has nil SupportedTokens", spec.CanonicalKey)
			continue
		}
		tokens := spec.SupportedTokens()
		if len(tokens) == 0 {
			t.Errorf("AllowList OptionSpec %q SupportedTokens() returned empty slice", spec.CanonicalKey)
		}
		if spec.CanonicalKey == ssh.OptionPreferredAuthentications {
			sawPreferredAuth = true
			if len(spec.FailClosedTokens) == 0 {
				t.Errorf("OptionSpec %q must declare non-empty FailClosedTokens", spec.CanonicalKey)
			}
			for _, fc := range spec.FailClosedTokens {
				if slices.Contains(tokens, fc) {
					t.Errorf("OptionSpec %q FailClosedToken %q must not overlap SupportedTokens", spec.CanonicalKey, fc)
				}
			}
		}
	}
	if allowListCount < 5 {
		t.Fatalf("expected at least 5 AllowList OptionSpecs, found %d", allowListCount)
	}
	if !sawPreferredAuth {
		t.Fatalf("OptionPreferredAuthentications (%q) not found among AllowList specs", ssh.OptionPreferredAuthentications)
	}
}

// TestP6_SingleAuthorityAndSanitizationGuards enforces Phase 6 single-authority
// and file-read/path-sanitization invariants across core/, pkg/, internal/, and cmd/.
func TestP6_SingleAuthorityAndSanitizationGuards(t *testing.T) {
	t.Parallel()
	root := p4RepoRoot(t)
	files := parseNonTestGoFiles(t, root, "core", "pkg", "internal", "cmd")

	t.Run("NoExtractFailClosedPreferredAuthsInPkgOrCmd", func(t *testing.T) {
		checkNoExtractFailClosedPreferredAuths(t, files)
	})
	t.Run("NoRawToAbsolutePathInInventoryAndFormFiles", func(t *testing.T) {
		checkNoRawToAbsolutePathInInventoryFiles(t, files)
	})
	t.Run("NoProgramDataEnvReadInSSHEnv", func(t *testing.T) {
		checkNoProgramDataEnvInSSHEnv(t, files)
	})
	t.Run("NoBareOSReadFileInCoreSSH", func(t *testing.T) {
		checkNoBareOSReadFileInCoreSSH(t, files)
	})
}

func checkNoExtractFailClosedPreferredAuths(t *testing.T, files []parsedGoFile) {
	t.Helper()
	for _, pf := range files {
		if !strings.HasPrefix(pf.relPath, "pkg/") && !strings.HasPrefix(pf.relPath, "cmd/") {
			continue
		}
		ast.Inspect(pf.file, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && ident.Name == "extractFailClosedPreferredAuths" {
				pos := pf.fset.Position(ident.Pos())
				t.Errorf("%s:%d: forbidden duplicate helper extractFailClosedPreferredAuths in pkg/cmd; use core/ssh.OptionSpec.FailClosedTokens via FilterSupportedListValue", pf.relPath, pos.Line)
			}
			return true
		})
	}
}

func checkNoRawToAbsolutePathInInventoryFiles(t *testing.T, files []parsedGoFile) {
	t.Helper()
	guardedFiles := map[string]bool{
		"cmd/host/add.go":                     false,
		"cmd/host/edit.go":                    false,
		"cmd/host/load.go":                    false,
		"cmd/identity.go":                     false,
		"pkg/tui/form.go":                     false,
		"cmd/utils/inventory_credential.go":   false,
		"cmd/utils/inventory_secret_input.go": false,
	}
	for _, pf := range files {
		if _, guarded := guardedFiles[pf.relPath]; !guarded {
			continue
		}
		guardedFiles[pf.relPath] = true
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				if fun.Name == "ToAbsolutePath" {
					pos := pf.fset.Position(call.Pos())
					t.Errorf("%s:%d: forbidden raw ToAbsolutePath call; use template-aware identity path normalization", pf.relPath, pos.Line)
				}
			case *ast.SelectorExpr:
				if fun.Sel.Name == "ToAbsolutePath" {
					pos := pf.fset.Position(call.Pos())
					t.Errorf("%s:%d: forbidden raw ToAbsolutePath call; use template-aware identity path normalization", pf.relPath, pos.Line)
				}
			}
			return true
		})
	}
	for rel, scanned := range guardedFiles {
		if !scanned {
			t.Errorf("expected guarded file %q to be scanned, but it was not found", rel)
		}
	}
}

func checkNoProgramDataEnvInSSHEnv(t *testing.T, files []parsedGoFile) {
	t.Helper()
	programDataLiterals := map[string]struct{}{"PROGRAMDATA": {}}
	sawKnownFolderCall := false
	scannedCount := 0
	for _, pf := range files {
		if !strings.HasPrefix(pf.relPath, "internal/sshenv/") {
			continue
		}
		scannedCount++
		osPkg := importLocalName(pf.file, "os")
		syscallPkg := importLocalName(pf.file, "syscall")
		winPkg := importLocalName(pf.file, "golang.org/x/sys/windows")
		localIdents := map[string]struct{}{}
		collectMatchingStringIdents(pf.file, programDataLiterals, localIdents)
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if isSelectorCall(call, osPkg, "Getenv") || isSelectorCall(call, osPkg, "LookupEnv") || isSelectorCall(call, syscallPkg, "Getenv") {
				for _, arg := range call.Args {
					if exprMatchesStringSet(arg, programDataLiterals, localIdents) {
						pos := pf.fset.Position(call.Pos())
						t.Errorf("%s:%d: forbidden environment lookup of ProgramData in internal/sshenv; use windows.KnownFolderPath(windows.FOLDERID_ProgramData, ...)", pf.relPath, pos.Line)
					}
				}
			}
			if isSelectorCall(call, winPkg, "KnownFolderPath") && len(call.Args) > 0 {
				if sel, ok := call.Args[0].(*ast.SelectorExpr); ok && isIdentName(sel.X, winPkg) && sel.Sel.Name == "FOLDERID_ProgramData" {
					sawKnownFolderCall = true
				}
			}
			return true
		})
	}
	if scannedCount == 0 {
		t.Fatal("expected non-test files under internal/sshenv/, found 0")
	}
	if !sawKnownFolderCall {
		t.Error("expected internal/sshenv/ to call windows.KnownFolderPath(windows.FOLDERID_ProgramData, ...)")
	}
}

func checkNoBareOSReadFileInCoreSSH(t *testing.T, files []parsedGoFile) {
	t.Helper()
	scannedCount := 0
	for _, pf := range files {
		if !strings.HasPrefix(pf.relPath, "core/ssh/") {
			continue
		}
		scannedCount++
		osPkg := importLocalName(pf.file, "os")
		if osPkg == "" {
			continue
		}
		ast.Inspect(pf.file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && isSelectorCall(call, osPkg, "ReadFile") {
				pos := pf.fset.Position(call.Pos())
				t.Errorf("%s:%d: forbidden bare %s.ReadFile in core/ssh; use bounded file reader", pf.relPath, pos.Line, osPkg)
			}
			return true
		})
	}
	if scannedCount == 0 {
		t.Fatal("expected non-test files under core/ssh/, found 0")
	}
}

type hostsDocOptionRow struct {
	snakeKey     string
	pascalName   string
	valuesColumn string
}

// TestP6_HostsDocOptionTableParity parses the ssh_options Markdown tables in
// docs/guide/hosts.md and docs/en/guide/hosts.md and asserts exact bilingual
// parity, OptionSpec registry alignment, and Normalize validity of discrete tokens.
func TestP6_HostsDocOptionTableParity(t *testing.T) {
	t.Parallel()
	root := p4RepoRoot(t)

	zhRows := parseHostsDocOptionTable(t, filepath.Join(root, "docs", "guide", "hosts.md"))
	enRows := parseHostsDocOptionTable(t, filepath.Join(root, "docs", "en", "guide", "hosts.md"))

	if len(zhRows) < 15 {
		t.Fatalf("docs/guide/hosts.md parsed only %d option rows, expected >= 15", len(zhRows))
	}
	if len(zhRows) != len(enRows) {
		t.Fatalf("hosts.md option table row count mismatch: zh=%d, en=%d", len(zhRows), len(enRows))
	}

	discreteModeOptions := map[string]bool{
		ssh.OptionControlMaster:           true,
		ssh.OptionStrictHostKeyChecking:   true,
		ssh.OptionExitOnForwardFailure:    true,
		ssh.OptionClearAllForwardings:     true,
		ssh.OptionGatewayPorts:            true,
		ssh.OptionStreamLocalBindUnlink:   true,
		ssh.OptionForkAfterAuthentication: true,
		ssh.OptionStdinNull:               true,
		ssh.OptionSessionType:             true,
		ssh.OptionTunnel:                  true,
		ssh.OptionRequestTTY:              true,
	}
	checkedDiscrete := make(map[string]bool, len(discreteModeOptions))

	for i := range zhRows {
		zh := zhRows[i]
		en := enRows[i]
		if zh.snakeKey != en.snakeKey || zh.pascalName != en.pascalName {
			t.Errorf("row %d bilingual mismatch: zh=(%q, %q), en=(%q, %q)", i, zh.snakeKey, zh.pascalName, en.snakeKey, en.pascalName)
			continue
		}
		spec, ok := ssh.LookupOptionSpec(zh.snakeKey)
		if !ok {
			t.Errorf("row %d (%q): not found in ssh.LookupOptionSpec", i, zh.snakeKey)
			continue
		}
		if spec.CanonicalKey != zh.snakeKey || spec.OpenSSHName != zh.pascalName {
			t.Errorf("row %d: doc=(%q, %q) disagrees with OptionSpec=(%q, %q)",
				i, zh.snakeKey, zh.pascalName, spec.CanonicalKey, spec.OpenSSHName)
		}
		if !discreteModeOptions[zh.snakeKey] {
			continue
		}
		checkedDiscrete[zh.snakeKey] = true
		zhTokens := extractDocumentedDiscreteTokens(zh.valuesColumn)
		enTokens := extractDocumentedDiscreteTokens(en.valuesColumn)
		if len(zhTokens) == 0 || !slices.Equal(zhTokens, enTokens) {
			t.Errorf("option %q discrete tokens mismatch: zh=%v, en=%v", zh.snakeKey, zhTokens, enTokens)
			continue
		}
		for _, tok := range zhTokens {
			if _, err := spec.Normalize(tok); err != nil {
				t.Errorf("option %q documented token %q failed spec.Normalize: %v", zh.snakeKey, tok, err)
			}
		}
	}

	for opt := range discreteModeOptions {
		if !checkedDiscrete[opt] {
			t.Errorf("expected discrete-mode option %q to appear in hosts.md option table", opt)
		}
	}
}

func parseHostsDocOptionTable(t *testing.T, docPath string) []hostsDocOptionRow {
	t.Helper()
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}
	lines := strings.Split(string(data), "\n")
	inTable := false
	var rows []hostsDocOptionRow
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if !inTable {
			if strings.HasPrefix(line, "|") && strings.Contains(line, "`snake_case`") && strings.Contains(line, "`PascalCase`") {
				inTable = true
			}
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := splitMarkdownTableRow(line)
		if len(cells) < 3 {
			continue
		}
		if isMarkdownSeparatorRow(cells) {
			continue
		}
		rows = append(rows, hostsDocOptionRow{
			snakeKey:     stripBackticks(cells[0]),
			pascalName:   stripBackticks(cells[1]),
			valuesColumn: strings.TrimSpace(cells[2]),
		})
	}
	return rows
}

func splitMarkdownTableRow(line string) []string {
	trimmed := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(line), "|"), "|")
	parts := strings.Split(trimmed, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func isMarkdownSeparatorRow(cells []string) bool {
	for _, c := range cells {
		cleaned := strings.Trim(c, "-: ")
		if cleaned != "" {
			return false
		}
	}
	return true
}

func stripBackticks(s string) string {
	return strings.Trim(strings.TrimSpace(s), "`")
}

// extractDocumentedDiscreteTokens extracts backtick-quoted slash-separated mode
// tokens from the prefix before any parenthesized note (ASCII '(' or CJK '（').
func extractDocumentedDiscreteTokens(col string) []string {
	prefix := col
	if idx := strings.IndexAny(prefix, "(（"); idx >= 0 {
		prefix = prefix[:idx]
	}
	var tokens []string
	for part := range strings.SplitSeq(prefix, "/") {
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(trimmed, "`") && strings.HasSuffix(trimmed, "`") && len(trimmed) >= 2 {
			tok := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			if tok != "" {
				tokens = append(tokens, tok)
			}
		}
	}
	return tokens
}

func isIdentName(expr ast.Expr, want string) bool {
	ident, ok := unwrapParen(expr).(*ast.Ident)
	return ok && ident.Name == want
}

func isLiteralFalseIdent(expr ast.Expr) bool {
	return isIdentName(expr, "false")
}

func isLiteralFalseReturnStmt(stmt ast.Stmt) bool {
	ret, ok := stmt.(*ast.ReturnStmt)
	return ok && len(ret.Results) == 1 && isLiteralFalseIdent(ret.Results[0])
}

func exprContainsErrNilComparison(expr ast.Expr, op token.Token) bool {
	if isErrNilComparison(expr, op) {
		return true
	}
	bin, ok := unwrapParen(expr).(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if bin.Op == token.LOR || bin.Op == token.LAND {
		return exprContainsErrNilComparison(bin.X, op) || exprContainsErrNilComparison(bin.Y, op)
	}
	return false
}

func exprChecksEmptyStringIdent(expr ast.Expr, identName string) bool {
	bin, ok := unwrapParen(expr).(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if bin.Op == token.EQL {
		return (isIdentName(bin.X, identName) && isEmptyStringLit(bin.Y)) ||
			(isEmptyStringLit(bin.X) && isIdentName(bin.Y, identName))
	}
	if bin.Op == token.LOR || bin.Op == token.LAND {
		return exprChecksEmptyStringIdent(bin.X, identName) || exprChecksEmptyStringIdent(bin.Y, identName)
	}
	return false
}

func isEmptyStringLit(expr ast.Expr) bool {
	lit, ok := unwrapParen(expr).(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	val, err := strconv.Unquote(lit.Value)
	return err == nil && val == ""
}

func exprIsNotIdent(expr ast.Expr, identName string) bool {
	un, ok := unwrapParen(expr).(*ast.UnaryExpr)
	if ok && un.Op == token.NOT && isIdentName(un.X, identName) {
		return true
	}
	bin, ok := unwrapParen(expr).(*ast.BinaryExpr)
	if ok && (bin.Op == token.LOR || bin.Op == token.LAND) {
		return exprIsNotIdent(bin.X, identName) || exprIsNotIdent(bin.Y, identName)
	}
	return false
}

func assertBranchReturnsLiteralTrueNamed(t *testing.T, pf parsedGoFile, fnName string, branch ast.Node) {
	t.Helper()
	returnCount := 0
	ast.Inspect(branch, func(n ast.Node) bool {
		if _, isFuncLit := n.(*ast.FuncLit); isFuncLit {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		returnCount++
		if !isLiteralTrueReturnStmt(ret) {
			pos := pf.fset.Position(ret.Pos())
			t.Errorf("%s:%d: error branch in %s must return literal true (fail closed)", pf.relPath, pos.Line, fnName)
		}
		return true
	})
	block, ok := branch.(*ast.BlockStmt)
	if returnCount == 0 || !ok || len(block.List) == 0 || !isLiteralTrueReturnStmt(block.List[len(block.List)-1]) {
		pos := pf.fset.Position(branch.Pos())
		t.Errorf("%s:%d: error branch in %s must terminate with literal return true", pf.relPath, pos.Line, fnName)
	}
}

func assertBranchReturnsLiteralFalse(t *testing.T, pf parsedGoFile, label string, branch ast.Node) {
	t.Helper()
	returnCount := 0
	ast.Inspect(branch, func(n ast.Node) bool {
		if _, isFuncLit := n.(*ast.FuncLit); isFuncLit {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		returnCount++
		if !isLiteralFalseReturnStmt(ret) {
			pos := pf.fset.Position(ret.Pos())
			t.Errorf("%s:%d: %s must return literal false (fail closed)", pf.relPath, pos.Line, label)
		}
		return true
	})
	block, ok := branch.(*ast.BlockStmt)
	if returnCount == 0 || !ok || len(block.List) == 0 || !isLiteralFalseReturnStmt(block.List[len(block.List)-1]) {
		pos := pf.fset.Position(branch.Pos())
		t.Errorf("%s:%d: %s must terminate with literal return false", pf.relPath, pos.Line, label)
	}
}

func assertBranchLastReturnResultIsLiteralFalse(t *testing.T, pf parsedGoFile, label string, branch ast.Node) {
	t.Helper()
	block, ok := branch.(*ast.BlockStmt)
	if !ok || len(block.List) == 0 {
		pos := pf.fset.Position(branch.Pos())
		t.Errorf("%s:%d: %s must be a non-empty block terminating with false ok result", pf.relPath, pos.Line, label)
		return
	}
	ret, ok := block.List[len(block.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) == 0 || !isLiteralFalseIdent(ret.Results[len(ret.Results)-1]) {
		pos := pf.fset.Position(block.Pos())
		t.Errorf("%s:%d: %s must return literal false as final ok result", pf.relPath, pos.Line, label)
	}
}

func collectMatchingStringIdents(file *ast.File, upperLiterals, out map[string]struct{}) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			for i, val := range node.Values {
				if i < len(node.Names) && exprMatchesStringSet(val, upperLiterals, out) {
					out[node.Names[i].Name] = struct{}{}
				}
			}
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if i >= len(node.Lhs) {
					break
				}
				if ident, ok := node.Lhs[i].(*ast.Ident); ok && ident.Name != "_" && exprMatchesStringSet(rhs, upperLiterals, out) {
					out[ident.Name] = struct{}{}
				}
			}
		}
		return true
	})
}

func exprMatchesStringSet(expr ast.Expr, upperLiterals, idents map[string]struct{}) bool {
	matched := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if matched {
			return false
		}
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				if unquoted, err := strconv.Unquote(node.Value); err == nil {
					if _, hit := upperLiterals[strings.ToUpper(strings.TrimSpace(unquoted))]; hit {
						matched = true
						return false
					}
				}
			}
		case *ast.Ident:
			if _, hit := idents[node.Name]; hit {
				matched = true
				return false
			}
		}
		return true
	})
	return matched
}
