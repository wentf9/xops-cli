package clicontract

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const coreSSHImportPath = "github.com/wentf9/xops-cli/core/ssh"

type parsedGoFile struct {
	relPath string
	fset    *token.FileSet
	file    *ast.File
}

func p4RepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test file path via runtime.Caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func parseNonTestGoFiles(t *testing.T, root string, subdirs ...string) []parsedGoFile {
	t.Helper()
	var parsed []parsedGoFile
	for _, subdir := range subdirs {
		baseDir := filepath.Join(root, filepath.FromSlash(subdir))
		count := 0
		err := filepath.WalkDir(baseDir, func(filePath string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, filePath)
			if err != nil {
				return err
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, filePath, nil, 0)
			if err != nil {
				return err
			}
			parsed = append(parsed, parsedGoFile{
				relPath: filepath.ToSlash(rel),
				fset:    fset,
				file:    file,
			})
			count++
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", subdir, err)
		}
		if count == 0 {
			t.Fatalf("expected non-test .go files under %s, found 0", subdir)
		}
	}
	return parsed
}

func parseSingleGoFile(t *testing.T, root string, relParts ...string) parsedGoFile {
	t.Helper()
	fullPath := filepath.Join(append([]string{root}, relParts...)...)
	rel, err := filepath.Rel(root, fullPath)
	if err != nil {
		t.Fatalf("relative path for %s: %v", fullPath, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fullPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", fullPath, err)
	}
	return parsedGoFile{
		relPath: filepath.ToSlash(rel),
		fset:    fset,
		file:    file,
	}
}

func importLocalName(file *ast.File, targetPath string) string {
	for _, imp := range file.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil || importPath != targetPath {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				return ""
			}
			return imp.Name.Name
		}
		return path.Base(importPath)
	}
	return ""
}

func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func declaredTopLevelNames(file *ast.File) []struct {
	name string
	pos  token.Pos
} {
	var out []struct {
		name string
		pos  token.Pos
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			out = append(out, struct {
				name string
				pos  token.Pos
			}{name: d.Name.Name, pos: d.Name.Pos()})
		case *ast.GenDecl:
			if d.Tok != token.VAR && d.Tok != token.CONST {
				continue
			}
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, ident := range vs.Names {
					out = append(out, struct {
						name string
						pos  token.Pos
					}{name: ident.Name, pos: ident.Pos()})
				}
			}
		}
	}
	return out
}

func isSelectorCall(call *ast.CallExpr, pkgName, funcName string) bool {
	if pkgName == "" {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != funcName {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == pkgName
}

func exprContainsSelectorCall(node ast.Node, pkgName, funcName string) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && isSelectorCall(call, pkgName, funcName) {
			found = true
			return false
		}
		return true
	})
	return found
}

// TestP4_NoDuplicateEncodersOrOptionSwitchTables enforces P0-P4 single-authority
// invariants across non-test Go source files in core/, pkg/, internal/, and cmd/.
func TestP4_NoDuplicateEncodersOrOptionSwitchTables(t *testing.T) {
	t.Parallel()

	root := p4RepoRoot(t)
	files := parseNonTestGoFiles(t, root, "core", "pkg", "internal", "cmd")

	t.Run("POSIXShellQuoteSingleAuthority", func(t *testing.T) {
		checkUniquePOSIXShellQuoteEncoder(t, files)
	})
	t.Run("SplitOptionKeyValueSingleAuthority", func(t *testing.T) {
		checkSplitOptionKeyValueAuthority(t, files)
	})
	t.Run("WindowsReservedDeviceNameAndExecSanitizer", func(t *testing.T) {
		checkWindowsReservedDeviceNameAndExecSanitizer(t, files)
	})
	t.Run("NoDeletedParallelSwitchHelpers", func(t *testing.T) {
		checkDeletedParallelSwitchHelpers(t, files)
	})
	t.Run("ControlTargetSingleAuthority", func(t *testing.T) {
		checkControlTargetAuthority(t, files)
	})
}

func checkUniquePOSIXShellQuoteEncoder(t *testing.T, files []parsedGoFile) {
	t.Helper()
	var shellQuoteDecls []string
	var exportedShellQuoteDecls []string
	for _, pf := range files {
		for _, d := range declaredTopLevelNames(pf.file) {
			pos := pf.fset.Position(d.pos)
			switch d.name {
			case "posixSingleQuote":
				t.Errorf("forbidden duplicate POSIX encoder %q declared at %s:%d (use core/ssh.ShellQuote)", d.name, pf.relPath, pos.Line)
			case "shellQuote":
				shellQuoteDecls = append(shellQuoteDecls, pf.relPath)
				// core/ssh/privilege_exchange.go currently hosts the package-private shellQuote
				// wrapped and exported by core/ssh/command_plan.go:ShellQuote.
				if pf.relPath != "core/ssh/command_plan.go" && pf.relPath != "core/ssh/privilege_exchange.go" {
					t.Errorf("duplicate %q declared at %s:%d; only core/ssh may define shellQuote", d.name, pf.relPath, pos.Line)
				}
			case "ShellQuote":
				exportedShellQuoteDecls = append(exportedShellQuoteDecls, pf.relPath)
				if pf.relPath != "core/ssh/command_plan.go" {
					t.Errorf("duplicate %q declared at %s:%d; only core/ssh/command_plan.go may declare ShellQuote", d.name, pf.relPath, pos.Line)
				}
			}
		}
	}
	if len(exportedShellQuoteDecls) != 1 {
		t.Errorf("expected exactly 1 ShellQuote declaration in core/ssh/command_plan.go, found %d (%v)", len(exportedShellQuoteDecls), exportedShellQuoteDecls)
	}
	if len(shellQuoteDecls) > 1 {
		t.Errorf("expected at most 1 shellQuote declaration in core/ssh, found %d (%v)", len(shellQuoteDecls), shellQuoteDecls)
	}
}

func checkSplitOptionKeyValueAuthority(t *testing.T, files []parsedGoFile) {
	t.Helper()
	var coreFound, adapterFound bool
	for _, pf := range files {
		for _, d := range declaredTopLevelNames(pf.file) {
			if d.name != "SplitOptionKeyValue" {
				continue
			}
			pos := pf.fset.Position(d.pos)
			switch pf.relPath {
			case "core/ssh/ssh_options.go":
				coreFound = true
			case "pkg/adapter/ssh_adapter.go":
				adapterFound = true
				assertOneLineSplitOptionDelegate(t, pf)
			default:
				t.Errorf("duplicate SplitOptionKeyValue declared at %s:%d; allowed only in core/ssh/ssh_options.go and 1-line delegate in pkg/adapter/ssh_adapter.go", pf.relPath, pos.Line)
			}
		}
	}
	if !coreFound {
		t.Error("canonical core/ssh/ssh_options.go:SplitOptionKeyValue declaration not found")
	}
	if !adapterFound {
		t.Error("compatibility delegate pkg/adapter/ssh_adapter.go:SplitOptionKeyValue declaration not found")
	}
}

func assertOneLineSplitOptionDelegate(t *testing.T, pf parsedGoFile) {
	t.Helper()
	sshPkg := importLocalName(pf.file, coreSSHImportPath)
	fn := findFuncDecl(pf.file, "SplitOptionKeyValue")
	if fn == nil || fn.Body == nil {
		t.Fatalf("%s: SplitOptionKeyValue function body not found", pf.relPath)
	}
	if len(fn.Body.List) != 1 {
		t.Errorf("%s: SplitOptionKeyValue must remain a 1-line delegate to ssh.SplitOptionKeyValue, got %d statements", pf.relPath, len(fn.Body.List))
		return
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		t.Errorf("%s: SplitOptionKeyValue must return ssh.SplitOptionKeyValue directly", pf.relPath)
		return
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok || !isSelectorCall(call, sshPkg, "SplitOptionKeyValue") {
		t.Errorf("%s: SplitOptionKeyValue must delegate directly to %s.SplitOptionKeyValue", pf.relPath, sshPkg)
	}
}

func checkWindowsReservedDeviceNameAndExecSanitizer(t *testing.T, files []parsedGoFile) {
	t.Helper()
	const coreFSXImportPath = "github.com/wentf9/xops-cli/core/fsx"
	var coreSSHCallsFSX, execCallsSanitizer bool
	for _, pf := range files {
		if pf.relPath == "core/ssh/identity_path.go" {
			fsxPkg := importLocalName(pf.file, coreFSXImportPath)
			coreSSHCallsFSX = exprContainsSelectorCall(pf.file, fsxPkg, "ValidateLocalComponent")
		}
		if pf.relPath == "cmd/exec.go" {
			sshPkg := importLocalName(pf.file, coreSSHImportPath)
			execCallsSanitizer = exprContainsSelectorCall(pf.file, sshPkg, "SanitizeFilenameComponent")
		}
	}
	if !coreSSHCallsFSX {
		t.Error("core/ssh/identity_path.go must call core/fsx.ValidateLocalComponent")
	}
	if !execCallsSanitizer {
		t.Error("cmd/exec.go must call core/ssh.SanitizeFilenameComponent")
	}
}

func checkDeletedParallelSwitchHelpers(t *testing.T, files []parsedGoFile) {
	t.Helper()
	forbidden := map[string]struct{}{
		"isStrictOpenSSHScalarDirective":     {},
		"isOpenSSHMultiTokenListDirective":   {},
		"isOpenSSHRawTokenListDirective":     {},
		"isOpenSSHWholeLineCommandDirective": {},
		"preservesSSHConfigRawValue":         {},
		"isAllowedOpenSSHTrustOption":        {},
		"isMuxDaemonAuthoritativeOption":     {},
		"isMuxDaemonPreservedOption":         {},
		"isSessionOrForwardOption":           {},
	}
	for _, pf := range files {
		if !strings.HasPrefix(pf.relPath, "pkg/") && !strings.HasPrefix(pf.relPath, "cmd/") {
			continue
		}
		for _, d := range declaredTopLevelNames(pf.file) {
			if _, banned := forbidden[d.name]; banned {
				pos := pf.fset.Position(d.pos)
				t.Errorf("deleted parallel switch helper %q reappeared at %s:%d; drive option rules from core/ssh.OptionSpec", d.name, pf.relPath, pos.Line)
			}
		}
	}
}

func checkControlTargetAuthority(t *testing.T, files []parsedGoFile) {
	t.Helper()
	var hasAuthorityTarget, hasAuthoritySocket, hasAuthorityLookup bool
	for _, pf := range files {
		for _, d := range declaredTopLevelNames(pf.file) {
			pos := pf.fset.Position(d.pos)
			if strings.HasPrefix(pf.relPath, "cmd/") {
				if d.name == "resolveSavedControlSessionLookup" ||
					d.name == "targetContextFromResolvedTarget" ||
					d.name == "TargetContextFromResolvedTarget" {
					t.Errorf("duplicate control-plane helper %q declared in cmd at %s:%d; pkg/adapter/control_target.go is the sole authority", d.name, pf.relPath, pos.Line)
				}
			}
			if pf.relPath == "pkg/adapter/control_target.go" {
				switch d.name {
				case "ResolveControlTarget":
					hasAuthorityTarget = true
				case "ResolveControlSocketPath":
					hasAuthoritySocket = true
				case "resolveSavedControlSessionLookup":
					hasAuthorityLookup = true
				}
			}
		}
	}
	if !hasAuthorityTarget || !hasAuthoritySocket || !hasAuthorityLookup {
		t.Errorf("pkg/adapter/control_target.go missing expected control-plane symbols (ResolveControlTarget=%v, ResolveControlSocketPath=%v, resolveSavedControlSessionLookup=%v)",
			hasAuthorityTarget, hasAuthoritySocket, hasAuthorityLookup)
	}
}

// TestP4_TUIRemoteShellCommandEncodingGuard parses pkg/tui/log_stream.go to lock
// in safe ssh.ShellQuote encoding and forbid fmt.Sprintf shell construction.
func TestP4_TUIRemoteShellCommandEncodingGuard(t *testing.T) {
	t.Parallel()

	root := p4RepoRoot(t)
	pf := parseSingleGoFile(t, root, "pkg", "tui", "log_stream.go")
	sshPkg := importLocalName(pf.file, coreSSHImportPath)
	if sshPkg == "" {
		t.Fatalf("%s must import %q", pf.relPath, coreSSHImportPath)
	}
	fmtPkg := importLocalName(pf.file, "fmt")

	fn := findFuncDecl(pf.file, "buildLogStreamCommand")
	if fn == nil || fn.Body == nil {
		t.Fatalf("%s: buildLogStreamCommand not found", pf.relPath)
	}

	shellQuoteCalls := 0
	successReturns := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if isSelectorCall(node, sshPkg, "ShellQuote") {
				shellQuoteCalls++
			}
			if isSelectorCall(node, fmtPkg, "Sprintf") {
				pos := pf.fset.Position(node.Pos())
				t.Errorf("%s:%d: buildLogStreamCommand must not construct shell commands with fmt.Sprintf", pf.relPath, pos.Line)
			}
		case *ast.ReturnStmt:
			if len(node.Results) == 2 && isNilIdent(node.Results[1]) {
				successReturns++
				if !exprContainsSelectorCall(node.Results[0], sshPkg, "ShellQuote") {
					pos := pf.fset.Position(node.Pos())
					t.Errorf("%s:%d: non-error return in buildLogStreamCommand must quote target via %s.ShellQuote", pf.relPath, pos.Line, sshPkg)
				}
			}
		}
		return true
	})

	if shellQuoteCalls == 0 {
		t.Errorf("%s: buildLogStreamCommand must call %s.ShellQuote", pf.relPath, sshPkg)
	}
	if successReturns == 0 {
		t.Errorf("%s: buildLogStreamCommand had 0 success return statements", pf.relPath)
	}
}

func isNilIdent(expr ast.Expr) bool {
	ident, ok := unwrapParen(expr).(*ast.Ident)
	return ok && ident.Name == "nil"
}

func unwrapParen(expr ast.Expr) ast.Expr {
	for {
		p, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = p.X
	}
}

// TestP4_MCPHostUsesConnectPlanExclusively parses non-test internal/mcphost/*.go
// files to ensure zero .Connect( selector calls exist and remote connections use
// .ConnectPlan( on admitted frozen snapshots.
func TestP4_MCPHostUsesConnectPlanExclusively(t *testing.T) {
	t.Parallel()

	root := p4RepoRoot(t)
	files := parseNonTestGoFiles(t, root, "internal/mcphost")

	connectPlanCalls := 0
	capturePlanCalls := 0
	for _, pf := range files {
		sshPkg := importLocalName(pf.file, coreSSHImportPath)
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Connect":
				pos := pf.fset.Position(call.Pos())
				t.Errorf("%s:%d: forbidden .Connect( call in internal/mcphost; all remote connections must use .ConnectPlan( on admitted frozen snapshots", pf.relPath, pos.Line)
			case "ConnectPlan":
				connectPlanCalls++
			case "CapturePlan":
				if isSelectorCall(call, sshPkg, "CapturePlan") {
					capturePlanCalls++
				}
			}
			return true
		})
	}
	if connectPlanCalls == 0 {
		t.Error("expected internal/mcphost to call .ConnectPlan( at least once")
	}
	if capturePlanCalls == 0 {
		t.Error("expected internal/mcphost to call ssh.CapturePlan( at least once")
	}
}

// TestP4_FailClosedSecurityPredicateGuard parses pkg/adapter/ssh_adapter.go
// (isNonInteractiveForNode) to ensure every error branch MUST return literal
// true (not merely forbidding literal false, which can be bypassed by
// fall-through or dead-code boolean expressions).
func TestP4_FailClosedSecurityPredicateGuard(t *testing.T) {
	t.Parallel()

	root := p4RepoRoot(t)
	pf := parseSingleGoFile(t, root, "pkg", "adapter", "ssh_adapter.go")
	fn := findFuncDecl(pf.file, "isNonInteractiveForNode")
	if fn == nil || fn.Body == nil {
		t.Fatalf("%s: isNonInteractiveForNode not found", pf.relPath)
	}

	errBranches := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if isErrNilComparison(ifStmt.Cond, token.NEQ) {
			errBranches++
			assertBranchReturnsLiteralTrue(t, pf, ifStmt.Body)
		} else if isErrNilComparison(ifStmt.Cond, token.EQL) && ifStmt.Else != nil {
			errBranches++
			assertBranchReturnsLiteralTrue(t, pf, ifStmt.Else)
		}
		return true
	})

	if errBranches == 0 {
		t.Fatalf("%s: expected at least one error-handling branch (if err != nil) in isNonInteractiveForNode", pf.relPath)
	}
}

func isErrNilComparison(expr ast.Expr, op token.Token) bool {
	bin, ok := unwrapParen(expr).(*ast.BinaryExpr)
	if !ok || bin.Op != op {
		return false
	}
	return (isErrorIdent(bin.X) && isNilIdent(bin.Y)) || (isNilIdent(bin.X) && isErrorIdent(bin.Y))
}

func isErrorIdent(expr ast.Expr) bool {
	ident, ok := unwrapParen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "err" || strings.HasSuffix(ident.Name, "Err")
}

func isLiteralTrueIdent(expr ast.Expr) bool {
	ident, ok := unwrapParen(expr).(*ast.Ident)
	return ok && ident.Name == "true"
}

func isLiteralTrueReturnStmt(stmt ast.Stmt) bool {
	ret, ok := stmt.(*ast.ReturnStmt)
	return ok && len(ret.Results) == 1 && isLiteralTrueIdent(ret.Results[0])
}

func assertBranchReturnsLiteralTrue(t *testing.T, pf parsedGoFile, branch ast.Node) {
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
			t.Errorf("%s:%d: error branch in isNonInteractiveForNode must return literal true (fail closed), not a non-literal expression or false", pf.relPath, pos.Line)
		}
		return true
	})
	if returnCount == 0 {
		pos := pf.fset.Position(branch.Pos())
		t.Errorf("%s:%d: error branch in isNonInteractiveForNode must unconditionally return literal true", pf.relPath, pos.Line)
		return
	}
	switch b := branch.(type) {
	case *ast.BlockStmt:
		if len(b.List) == 0 || !isLiteralTrueReturnStmt(b.List[len(b.List)-1]) {
			pos := pf.fset.Position(b.Pos())
			t.Errorf("%s:%d: error branch in isNonInteractiveForNode must terminate with literal return true (no fall-through)", pf.relPath, pos.Line)
		}
	default:
		pos := pf.fset.Position(branch.Pos())
		t.Errorf("%s:%d: error branch in isNonInteractiveForNode must be a block terminating with literal return true", pf.relPath, pos.Line)
	}
}

// TestP4_OptionRegistryCrossLayerCompleteness validates core/ssh.RegisteredOptionSpecs()
// using runtime checks and reflection so no OptionSpec can omit policy enums or Normalize.
func TestP4_OptionRegistryCrossLayerCompleteness(t *testing.T) {
	t.Parallel()

	specs := ssh.RegisteredOptionSpecs()
	if len(specs) == 0 {
		t.Fatal("ssh.RegisteredOptionSpecs() returned empty slice")
	}

	validClasses := map[ssh.OptionClass]bool{
		ssh.OptionClassMux:       true,
		ssh.OptionClassTransport: true,
		ssh.OptionClassAuth:      true,
		ssh.OptionClassTrust:     true,
		ssh.OptionClassForward:   true,
		ssh.OptionClassSession:   true,
		ssh.OptionClassLocalExec: true,
	}

	// Discover every uint8-backed enum field on ssh.OptionSpec via reflection so
	// future policy/mode/syntax enum fields cannot silently remain Unset (0).
	specType := reflect.TypeFor[ssh.OptionSpec]()
	var nonZeroEnumFieldIndices []int
	for i := 0; i < specType.NumField(); i++ {
		f := specType.Field(i)
		if f.Type.Kind() == reflect.Uint8 && f.Name != "Scope" {
			nonZeroEnumFieldIndices = append(nonZeroEnumFieldIndices, i)
		}
	}
	if len(nonZeroEnumFieldIndices) < 4 {
		t.Fatalf("expected at least 4 non-zero enum fields on ssh.OptionSpec (MergeMode, ConfigSyntax, Tier4Policy, MuxPolicy), got %d", len(nonZeroEnumFieldIndices))
	}

	seenKeys := make(map[string]struct{}, len(specs))
	seenNames := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		validateRegisteredOptionSpec(t, spec, validClasses, nonZeroEnumFieldIndices, seenKeys, seenNames)
	}
}

func validateRegisteredOptionSpec(
	t *testing.T,
	spec ssh.OptionSpec,
	validClasses map[ssh.OptionClass]bool,
	nonZeroEnumFieldIndices []int,
	seenKeys, seenNames map[string]struct{},
) {
	t.Helper()
	if strings.TrimSpace(spec.CanonicalKey) == "" {
		t.Errorf("option spec %q has empty CanonicalKey", spec.OpenSSHName)
	}
	if strings.TrimSpace(spec.OpenSSHName) == "" {
		t.Errorf("option spec %q has empty OpenSSHName", spec.CanonicalKey)
	}
	lowerKey := strings.ToLower(spec.CanonicalKey)
	if _, dup := seenKeys[lowerKey]; dup {
		t.Errorf("duplicate CanonicalKey %q in RegisteredOptionSpecs", spec.CanonicalKey)
	}
	seenKeys[lowerKey] = struct{}{}

	lowerName := strings.ToLower(spec.OpenSSHName)
	if _, dup := seenNames[lowerName]; dup {
		t.Errorf("duplicate OpenSSHName %q in RegisteredOptionSpecs", spec.OpenSSHName)
	}
	seenNames[lowerName] = struct{}{}

	if spec.Class == "" || !validClasses[spec.Class] {
		t.Errorf("option %q has empty or unknown Class %q", spec.CanonicalKey, spec.Class)
	}
	if spec.Normalize == nil {
		t.Errorf("option %q has nil Normalize function", spec.CanonicalKey)
	}
	if spec.MultiValue != spec.MergeMode.IsMultiValue() {
		t.Errorf("option %q MultiValue=%v disagrees with MergeMode.IsMultiValue()=%v", spec.CanonicalKey, spec.MultiValue, spec.MergeMode.IsMultiValue())
	}
	validateOptionSpecPoliciesAndLookup(t, spec, nonZeroEnumFieldIndices)
}

func validateOptionSpecPoliciesAndLookup(t *testing.T, spec ssh.OptionSpec, nonZeroEnumFieldIndices []int) {
	t.Helper()
	if spec.MergeMode == ssh.OptionMergeUnset {
		t.Errorf("option %q has OptionMergeUnset", spec.CanonicalKey)
	}
	if spec.ConfigSyntax == ssh.OptionSyntaxUnset {
		t.Errorf("option %q has OptionSyntaxUnset", spec.CanonicalKey)
	}
	if spec.Tier4Policy == ssh.OptionTier4Unset {
		t.Errorf("option %q has OptionTier4Unset", spec.CanonicalKey)
	}
	if spec.MuxPolicy == ssh.OptionMuxUnset {
		t.Errorf("option %q has OptionMuxUnset", spec.CanonicalKey)
	}

	rv := reflect.ValueOf(spec)
	rt := rv.Type()
	for _, idx := range nonZeroEnumFieldIndices {
		if rv.Field(idx).Uint() == 0 {
			t.Errorf("option %q has Unset (0) value for enum field %s", spec.CanonicalKey, rt.Field(idx).Name)
		}
	}
	if _, ok := ssh.LookupOptionSpec(spec.CanonicalKey); !ok {
		t.Errorf("LookupOptionSpec(%q) failed", spec.CanonicalKey)
	}
	if _, ok := ssh.LookupOptionSpec(spec.OpenSSHName); !ok {
		t.Errorf("LookupOptionSpec(%q) failed", spec.CanonicalKey)
	}
	for _, alias := range spec.Aliases {
		if _, ok := ssh.LookupOptionSpec(alias); !ok {
			t.Errorf("LookupOptionSpec(alias %q) failed for %q", alias, spec.CanonicalKey)
		}
	}
}

// TestP5_NoEnvVarChildAuthReadsGuard ensures zero non-test os.Getenv / os.LookupEnv
// / syscall.Getenv reads of legacy child markers XOPS_CLI_SSH_MUX_DAEMON or
// XOPS_CLI_SSH_BG_CHILD (or their constant aliases sshMuxDaemonEnv /
// sshBackgroundChildEnv) exist across cmd/, pkg/, internal/, and core/.
func TestP5_NoEnvVarChildAuthReadsGuard(t *testing.T) {
	t.Parallel()

	root := p4RepoRoot(t)
	files := parseNonTestGoFiles(t, root, "core", "pkg", "internal", "cmd")

	forbiddenLiterals := map[string]struct{}{
		"XOPS_CLI_SSH_MUX_DAEMON": {},
		"XOPS_CLI_SSH_BG_CHILD":   {},
	}
	forbiddenIdents := map[string]struct{}{
		"sshMuxDaemonEnv":       {},
		"sshBackgroundChildEnv": {},
	}

	sawCmdFlagFile := false
	for _, pf := range files {
		if pf.relPath == "cmd/ssh_option_flag.go" {
			sawCmdFlagFile = true
		}
		// Discover any const/var identifier initialized to a forbidden env var string.
		ast.Inspect(pf.file, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, val := range vs.Values {
				if i >= len(vs.Names) {
					break
				}
				if exprMatchesForbiddenChildEnv(val, forbiddenLiterals, forbiddenIdents) {
					forbiddenIdents[vs.Names[i].Name] = struct{}{}
				}
			}
			return true
		})
	}
	if !sawCmdFlagFile {
		t.Fatal("expected cmd/ssh_option_flag.go to be scanned")
	}

	for _, pf := range files {
		checkFileForbiddenChildEnvReads(t, pf, forbiddenLiterals, forbiddenIdents)
	}
}

func checkFileForbiddenChildEnvReads(t *testing.T, pf parsedGoFile, forbiddenLiterals, forbiddenIdents map[string]struct{}) {
	t.Helper()
	localForbidden := make(map[string]struct{}, len(forbiddenIdents))
	for k := range forbiddenIdents {
		localForbidden[k] = struct{}{}
	}
	ast.Inspect(pf.file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, rhs := range assign.Rhs {
			if i >= len(assign.Lhs) {
				break
			}
			if ident, ok := assign.Lhs[i].(*ast.Ident); ok && ident.Name != "_" &&
				exprMatchesForbiddenChildEnv(rhs, forbiddenLiterals, localForbidden) {
				localForbidden[ident.Name] = struct{}{}
			}
		}
		return true
	})
	osPkg := importLocalName(pf.file, "os")
	syscallPkg := importLocalName(pf.file, "syscall")
	ast.Inspect(pf.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		isEnvRead := isSelectorCall(call, osPkg, "Getenv") ||
			isSelectorCall(call, osPkg, "LookupEnv") ||
			isSelectorCall(call, syscallPkg, "Getenv")
		if !isEnvRead {
			return true
		}
		for _, arg := range call.Args {
			if exprMatchesForbiddenChildEnv(arg, forbiddenLiterals, localForbidden) {
				pos := pf.fset.Position(call.Pos())
				t.Errorf("%s:%d: forbidden environment read of legacy child marker (XOPS_CLI_SSH_MUX_DAEMON / XOPS_CLI_SSH_BG_CHILD); authenticate child modes via pipe-FD spec flags only", pf.relPath, pos.Line)
			}
		}
		return true
	})
}

func exprMatchesForbiddenChildEnv(expr ast.Expr, literals, idents map[string]struct{}) bool {
	matched := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if matched {
			return false
		}
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				if unquoted, err := strconv.Unquote(node.Value); err == nil {
					if _, bad := literals[strings.ToUpper(strings.TrimSpace(unquoted))]; bad {
						matched = true
						return false
					}
				}
			}
		case *ast.Ident:
			if _, bad := idents[node.Name]; bad {
				matched = true
				return false
			}
		}
		return true
	})
	return matched
}

// TestP5_ZeroValueAndFailClosedSecurityInvariants locks in critical Phase 5
// fail-closed behavioral invariants across guardrail, policy YAML decoding,
// and DNSSEC-authenticated SSHFP evaluation.
func TestP5_ZeroValueAndFailClosedSecurityInvariants(t *testing.T) {
	t.Parallel()

	t.Run("GuardrailDecisionZeroValueIsDeny", func(t *testing.T) {
		var d guardrail.Decision
		if d != guardrail.Deny {
			t.Fatalf("zero-value guardrail.Decision = %v (%d), want guardrail.Deny (%d)", d, d, guardrail.Deny)
		}
		if d.String() != "deny" {
			t.Fatalf("zero-value guardrail.Decision.String() = %q, want %q", d.String(), "deny")
		}
	})

	t.Run("PolicyConfigZeroValueAndYAMLDisabledSemantics", func(t *testing.T) {
		const yamlWithoutDisabled = "approval_threshold: dangerous\nno_elicit_fallback: deny\n"
		var cfg corepolicy.Config
		if err := yaml.Unmarshal([]byte(yamlWithoutDisabled), &cfg); err != nil {
			t.Fatalf("yaml.Unmarshal(policy.Config without disabled): %v", err)
		}
		if cfg.Disabled {
			t.Fatal("YAML policy.Config omitting disabled must default to Disabled == false (guardrail ON)")
		}

		var disabledCfg corepolicy.Config
		if err := yaml.Unmarshal([]byte("disabled: true\n"), &disabledCfg); err != nil {
			t.Fatalf("yaml.Unmarshal(policy.Config disabled:true): %v", err)
		}
		if !disabledCfg.Disabled {
			t.Fatal("YAML policy.Config with explicit disabled:true must decode Disabled == true")
		}
		var legacyCfg corepolicy.Config
		if err := yaml.Unmarshal([]byte("enabled: false\n"), &legacyCfg); err == nil {
			t.Fatal("YAML policy.Config with removed legacy enabled: key must fail")
		}
	})

	t.Run("EvaluateSSHFPAuthenticatedOtherAlgorithmMismatch", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		hostPub, err := cryptoSSH.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("cryptoSSH.NewPublicKey: %v", err)
		}
		otherAlgoDigest := make([]byte, sha256.Size)
		otherAlgoDigest[0] = 0xA5
		result := ssh.SSHFPResult{
			Authenticated: true,
			Records: []ssh.SSHFPRecord{{
				Algorithm:       1, // RSA, while presented host key is Ed25519 (Algorithm 4)
				FingerprintType: 2, // SHA-256
				Fingerprint:     otherAlgoDigest,
			}},
		}
		if got := ssh.EvaluateSSHFP(result, hostPub); got != ssh.SSHFPStatusMismatch {
			t.Fatalf("ssh.EvaluateSSHFP(authenticated other-algorithm SHA-256) = %q, want %q", got, ssh.SSHFPStatusMismatch)
		}
	})
}
