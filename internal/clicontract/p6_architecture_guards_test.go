package clicontract

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

// TestP6_SecurityPredicateFailClosedASTGuard AST-verifies structural fail-closed
// control-flow invariants not enforced by Go types or lint rules.
func TestP6_SecurityPredicateFailClosedASTGuard(t *testing.T) {
	t.Parallel()
	root := p4RepoRoot(t)

	t.Run("MCPGuardrail_SwitchDecisionHasExplicitFailClosedDefault", func(t *testing.T) {
		checkGuardrailDecisionSwitchDefault(t, root, "WithGuardrail", "core", "mcp", "guardrail", "guardrail.go")
		checkGuardrailDecisionSwitchDefault(t, root, "Authorize", "core", "mcp", "guardrail", "authorization.go")
	})
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

// TestP6_SecurityStructsZeroValueReflectionGuard verifies AllowList OptionSpec
// capability metadata (zero-value struct invariants moved to P7 reflection table).
func TestP6_SecurityStructsZeroValueReflectionGuard(t *testing.T) {
	t.Parallel()

	t.Run("AllowListSpecsDeclareSupportedAndFailClosedTokens", checkAllowListSpecCapabilities)
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

// TestP6_SingleAuthorityAndSanitizationGuards enforces Phase 6 sanitization
// invariants not covered by Go types or lint rules.
func TestP6_SingleAuthorityAndSanitizationGuards(t *testing.T) {
	t.Parallel()
	root := p4RepoRoot(t)
	files := parseNonTestGoFiles(t, root, "core", "pkg", "internal", "cmd")

	t.Run("NoRawToAbsolutePathInInventoryAndFormFiles", func(t *testing.T) {
		checkNoRawToAbsolutePathInInventoryFiles(t, files)
	})
	t.Run("NoProgramDataEnvReadInSSHEnv", func(t *testing.T) {
		checkNoProgramDataEnvInSSHEnv(t, files)
	})
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
