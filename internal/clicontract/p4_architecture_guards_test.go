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

	"github.com/wentf9/xops-cli/core/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
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

// TestP5_ZeroValueAndFailClosedSecurityInvariants locks in behavioral Phase 5
// fail-closed security invariants not covered by P7 zero-value reflection tests.
func TestP5_ZeroValueAndFailClosedSecurityInvariants(t *testing.T) {
	t.Parallel()

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
