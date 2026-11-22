package clicontract

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const clientConfigCoreSSHImportPath = "github.com/wentf9/xops-cli/core/ssh"

type clientConfigViolation struct {
	relPath string
	line    int
	reason  string
}

func (v clientConfigViolation) String() string {
	return fmt.Sprintf("%s:%d: %s; construct core/ssh.ClientConfig via NewClientConfig(...) only",
		v.relPath, v.line, v.reason)
}

type coreSSHScope struct {
	inCoreSSH     bool
	dotImport     bool
	aliases       map[string]bool
	typeAliasExpr map[string]ast.Expr
}

func buildCoreSSHScope(relPath string, file *ast.File) coreSSHScope {
	scope := coreSSHScope{
		inCoreSSH:     filepath.ToSlash(filepath.Dir(relPath)) == "core/ssh" && file.Name != nil && file.Name.Name == "ssh",
		aliases:       make(map[string]bool),
		typeAliasExpr: make(map[string]ast.Expr),
	}
	for _, imp := range file.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil || importPath != clientConfigCoreSSHImportPath {
			continue
		}
		if imp.Name == nil {
			scope.aliases["ssh"] = true
			continue
		}
		switch imp.Name.Name {
		case ".":
			scope.dotImport = true
		case "_":
			// Side-effect-only import does not bind an identifier.
		default:
			scope.aliases[imp.Name.Name] = true
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || !ts.Assign.IsValid() || ts.Name == nil || ts.Type == nil {
			return true
		}
		if ts.Name.Name != "_" {
			scope.typeAliasExpr[ts.Name.Name] = ts.Type
		}
		return true
	})
	return scope
}

func (s coreSSHScope) resolveTypeAlias(expr ast.Expr) ast.Expr {
	cur := unwrapParen(expr)
	for range 16 {
		ident, ok := cur.(*ast.Ident)
		if !ok {
			return cur
		}
		next, exists := s.typeAliasExpr[ident.Name]
		if !exists || next == nil {
			return cur
		}
		cur = unwrapParen(next)
	}
	return cur
}

func (s coreSSHScope) isClientConfigType(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	switch t := s.resolveTypeAlias(expr).(type) {
	case *ast.Ident:
		return (s.inCoreSSH || s.dotImport) && t.Name == "ClientConfig"
	case *ast.SelectorExpr:
		if t.Sel.Name != "ClientConfig" {
			return false
		}
		xIdent, ok := unwrapParen(t.X).(*ast.Ident)
		return ok && s.aliases[xIdent.Name]
	default:
		return false
	}
}

func (s coreSSHScope) isClientConfigElemType(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	resolved := s.resolveTypeAlias(expr)
	if star, ok := resolved.(*ast.StarExpr); ok {
		return s.isClientConfigType(star.X)
	}
	return s.isClientConfigType(resolved)
}

func (s coreSSHScope) isNewClientConfigCall(call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	switch fn := unwrapParen(call.Fun).(type) {
	case *ast.Ident:
		return (s.inCoreSSH || s.dotImport) && fn.Name == "NewClientConfig"
	case *ast.SelectorExpr:
		if fn.Sel.Name != "NewClientConfig" {
			return false
		}
		xIdent, ok := unwrapParen(fn.X).(*ast.Ident)
		return ok && s.aliases[xIdent.Name]
	default:
		return false
	}
}

func (s coreSSHScope) isNewBuiltinClientConfigCall(call *ast.CallExpr) bool {
	if call == nil || len(call.Args) != 1 {
		return false
	}
	ident, ok := unwrapParen(call.Fun).(*ast.Ident)
	if !ok || ident.Name != "new" {
		return false
	}
	return s.isClientConfigType(call.Args[0])
}

func (s coreSSHScope) isMakeSliceOfClientConfigCall(call *ast.CallExpr) bool {
	if call == nil || len(call.Args) < 2 || len(call.Args) > 3 {
		return false
	}
	ident, ok := unwrapParen(call.Fun).(*ast.Ident)
	if !ok || ident.Name != "make" {
		return false
	}
	arr, ok := s.resolveTypeAlias(call.Args[0]).(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	return s.isClientConfigType(arr.Elt)
}

func (s coreSSHScope) resolveCompositeLitType(lit *ast.CompositeLit, stack []ast.Node) ast.Expr {
	if lit == nil {
		return nil
	}
	if lit.Type != nil {
		return s.resolveTypeAlias(lit.Type)
	}
	parent := enclosingNonParen(stack)
	if parent == nil {
		return nil
	}
	if kv, ok := parent.(*ast.KeyValueExpr); ok {
		isVal := unwrapParen(kv.Value) == lit
		isKey := unwrapParen(kv.Key) == lit
		if !isVal && !isKey {
			return nil
		}
		grandparent := enclosingNodeBefore(stack, kv)
		container, ok := grandparent.(*ast.CompositeLit)
		if !ok {
			return nil
		}
		containerType := s.resolveCompositeLitType(container, stackBefore(stack, container))
		return s.resolveKeyValueElemType(containerType, kv, isKey, isVal)
	}
	container, ok := parent.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	containerType := s.resolveCompositeLitType(container, stackBefore(stack, container))
	if arr, ok := s.resolveTypeAlias(containerType).(*ast.ArrayType); ok {
		return s.resolveTypeAlias(arr.Elt)
	}
	return nil
}

func (s coreSSHScope) resolveKeyValueElemType(containerType ast.Expr, kv *ast.KeyValueExpr, isKey, isVal bool) ast.Expr {
	switch ct := s.resolveTypeAlias(containerType).(type) {
	case *ast.MapType:
		if isVal {
			return s.resolveTypeAlias(ct.Value)
		}
		if isKey {
			return s.resolveTypeAlias(ct.Key)
		}
	case *ast.ArrayType:
		if isVal {
			return s.resolveTypeAlias(ct.Elt)
		}
	case *ast.StructType:
		if !isVal || ct.Fields == nil {
			return nil
		}
		keyIdent, ok := unwrapParen(kv.Key).(*ast.Ident)
		if !ok {
			return nil
		}
		for _, field := range ct.Fields.List {
			for _, name := range field.Names {
				if name.Name == keyIdent.Name {
					return s.resolveTypeAlias(field.Type)
				}
			}
		}
	}
	return nil
}

func (s coreSSHScope) isElidedClientConfigLit(lit *ast.CompositeLit, stack []ast.Node) bool {
	if lit.Type != nil {
		return false
	}
	return s.isClientConfigElemType(s.resolveCompositeLitType(lit, stack))
}

func enclosingNonParen(stack []ast.Node) ast.Node {
	for i := len(stack) - 1; i >= 0; i-- {
		if _, isParen := stack[i].(*ast.ParenExpr); !isParen {
			return stack[i]
		}
	}
	return nil
}

func enclosingNodeBefore(stack []ast.Node, target ast.Node) ast.Node {
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i] == target {
			return enclosingNonParen(stack[:i])
		}
	}
	return nil
}

func stackBefore(stack []ast.Node, target ast.Node) []ast.Node {
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i] == target {
			return stack[:i]
		}
	}
	return nil
}

func isDirectArgToNewClientConfig(scope coreSSHScope, lit *ast.CompositeLit, stack []ast.Node) bool {
	if lit.Type == nil {
		return false
	}
	call, ok := enclosingNonParen(stack).(*ast.CallExpr)
	if !ok || !scope.isNewClientConfigCall(call) || len(call.Args) != 1 {
		return false
	}
	return unwrapParen(call.Args[0]) == lit
}

func isZeroFailureReturn(lit *ast.CompositeLit, stack []ast.Node) bool {
	if lit.Type == nil || len(lit.Elts) != 0 {
		return false
	}
	ret, ok := enclosingNonParen(stack).(*ast.ReturnStmt)
	if !ok || len(ret.Results) < 2 {
		return false
	}
	// Verify lit is a direct return result (not &ClientConfig{} and not the last
	// error/ok slot itself).
	last := unwrapParen(ret.Results[len(ret.Results)-1])
	foundInNonLast := false
	for _, res := range ret.Results[:len(ret.Results)-1] {
		if unwrapParen(res) == lit {
			foundInNonLast = true
			break
		}
	}
	if !foundInNonLast {
		return false
	}
	if ident, ok := last.(*ast.Ident); ok {
		switch ident.Name {
		case "false":
			return true
		case "nil", "true":
			return false
		}
	}
	return true
}

func analyzeClientConfigLiteralsInFile(relPath string, fset *token.FileSet, file *ast.File) []clientConfigViolation {
	scope := buildCoreSSHScope(relPath, file)
	if !scope.inCoreSSH && !scope.dotImport && len(scope.aliases) == 0 {
		return nil
	}

	var violations []clientConfigViolation
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		violations = append(violations, inspectClientConfigNode(relPath, fset, scope, n, stack)...)
		stack = append(stack, n)
		return true
	})
	return violations
}

func inspectClientConfigNode(
	relPath string,
	fset *token.FileSet,
	scope coreSSHScope,
	n ast.Node,
	stack []ast.Node,
) []clientConfigViolation {
	switch node := n.(type) {
	case *ast.CompositeLit:
		return inspectClientConfigCompositeLit(relPath, fset, scope, node, stack)
	case *ast.CallExpr:
		if scope.isNewBuiltinClientConfigCall(node) {
			return []clientConfigViolation{{
				relPath: relPath,
				line:    fset.Position(node.Pos()).Line,
				reason:  "new(core/ssh.ClientConfig) allocation outside NewClientConfig(...)",
			}}
		}
		if scope.isMakeSliceOfClientConfigCall(node) {
			return []clientConfigViolation{{
				relPath: relPath,
				line:    fset.Position(node.Pos()).Line,
				reason:  "make([]core/ssh.ClientConfig, ...) allocation outside NewClientConfig(...)",
			}}
		}
	case *ast.ValueSpec:
		if len(node.Values) == 0 && node.Type != nil && scope.isClientConfigType(node.Type) {
			return []clientConfigViolation{{
				relPath: relPath,
				line:    fset.Position(node.Pos()).Line,
				reason:  "zero-value var core/ssh.ClientConfig declaration outside NewClientConfig(...)",
			}}
		}
	case *ast.FuncType:
		return inspectClientConfigNamedReturns(relPath, fset, scope, node)
	case *ast.TypeSpec:
		if node.Assign.IsValid() && scope.isClientConfigType(node.Type) {
			return []clientConfigViolation{{
				relPath: relPath,
				line:    fset.Position(node.Pos()).Line,
				reason:  fmt.Sprintf("type alias %q to core/ssh.ClientConfig bypasses constructor guard", node.Name.Name),
			}}
		}
	}
	return nil
}

func inspectClientConfigCompositeLit(
	relPath string,
	fset *token.FileSet,
	scope coreSSHScope,
	node *ast.CompositeLit,
	stack []ast.Node,
) []clientConfigViolation {
	matched := scope.isClientConfigType(node.Type) || scope.isElidedClientConfigLit(node, stack)
	if !matched || isDirectArgToNewClientConfig(scope, node, stack) || isZeroFailureReturn(node, stack) {
		return nil
	}
	reason := "direct core/ssh.ClientConfig composite literal outside NewClientConfig(...)"
	if node.Type == nil {
		reason = "elided core/ssh.ClientConfig composite literal outside NewClientConfig(...)"
	}
	return []clientConfigViolation{{
		relPath: relPath,
		line:    fset.Position(node.Pos()).Line,
		reason:  reason,
	}}
}

func inspectClientConfigNamedReturns(
	relPath string,
	fset *token.FileSet,
	scope coreSSHScope,
	node *ast.FuncType,
) []clientConfigViolation {
	if node.Results == nil {
		return nil
	}
	var out []clientConfigViolation
	for _, field := range node.Results.List {
		if len(field.Names) > 0 && scope.isClientConfigType(field.Type) {
			out = append(out, clientConfigViolation{
				relPath: relPath,
				line:    fset.Position(field.Pos()).Line,
				reason:  "named core/ssh.ClientConfig return value outside NewClientConfig(...)",
			})
		}
	}
	return out
}

func scanRepoForRawClientConfigLiterals(t *testing.T, repoRoot string) []clientConfigViolation {
	t.Helper()
	var out []clientConfigViolation
	err := filepath.WalkDir(repoRoot, func(filePath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if filePath != repoRoot && (strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" || name == "docs" || name == "dist" || name == "build") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(repoRoot, filePath)
		if relErr != nil {
			return relErr
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, filePath, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		out = append(out, analyzeClientConfigLiteralsInFile(filepath.ToSlash(rel), fset, file)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository %s: %v", repoRoot, err)
	}
	slices.SortFunc(out, func(a, b clientConfigViolation) int {
		if a.relPath != b.relPath {
			return strings.Compare(a.relPath, b.relPath)
		}
		return a.line - b.line
	})
	return out
}

// TestP7_ClientConfigGuard_SelfTest verifies that the AST structural guard
// flags bare, aliased, dot-imported, in-package, address-of, elided,
// nested-container, new(...), zero-value var, named-return, type-alias, and
// non-failure-return core/ssh.ClientConfig constructions while permitting
// NewClientConfig(...), pointer declarations, zero failure returns, and
// x/crypto/ssh.ClientConfig.
func TestP7_ClientConfigGuard_SelfTest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		relPath        string
		src            string
		wantViolations int
	}{
		{
			name:    "bare_addr_of_clientconfig_flagged",
			relPath: "pkg/example/bad.go",
			src: `package example
import "github.com/wentf9/xops-cli/core/ssh"
func bad() *ssh.ClientConfig {
	return &ssh.ClientConfig{Address: "x"}
}`,
			wantViolations: 1,
		},
		{
			name:    "aliased_dot_elided_and_bad_zero_returns_flagged",
			relPath: "pkg/example/bad_forms.go",
			src: `package example
import (
	coressh "github.com/wentf9/xops-cli/core/ssh"
)
func f1() coressh.ClientConfig { return coressh.ClientConfig{Address: "x"} }
func f2() *coressh.ClientConfig { return &coressh.ClientConfig{} }
func f3() (coressh.ClientConfig, error) { return coressh.ClientConfig{}, nil }
func f4() (coressh.ClientConfig, bool) { return coressh.ClientConfig{}, true }
func f5() (coressh.ClientConfig, bool) { return coressh.ClientConfig{Address: "x"}, false }
func f6() []coressh.ClientConfig { return []coressh.ClientConfig{{Address: "x"}} }
func f7() map[string]*coressh.ClientConfig { return map[string]*coressh.ClientConfig{"a": {Address: "x"}} }
func f8() { _ = wrap(coressh.ClientConfig{Address: "x"}) }
func wrap(coressh.ClientConfig) int { return 0 }`,
			wantViolations: 8,
		},
		{
			name:    "new_var_named_return_type_alias_and_deep_nested_literals_flagged",
			relPath: "pkg/example/bad_bypass.go",
			src: `package example
import "github.com/wentf9/xops-cli/core/ssh"

func badNew() *ssh.ClientConfig {
	return new(ssh.ClientConfig)
}

func badVar() ssh.ClientConfig {
	var cfg ssh.ClientConfig
	return cfg
}

func badNamedReturn() (cfg ssh.ClientConfig) {
	return
}

func badLocalAlias() *ssh.ClientConfig {
	type T = ssh.ClientConfig
	return &T{Address: "x"}
}

func badChainedAliasNewAndVar() {
	type A = ssh.ClientConfig
	type B = A
	_ = new(B)
	var x B
	_ = x
}

func badDeepNestedContainers() {
	_ = [][]ssh.ClientConfig{{{Address: "a"}}}
	_ = map[string][]*ssh.ClientConfig{"k": {{Address: "b"}}}
	_ = [1]map[string][1]ssh.ClientConfig{{"k": {{Address: "c"}}}}
	_ = []ssh.ClientConfig{0: {Address: "d"}}
}

func badMakeSliceAllocations(n int) {
	_ = make([]ssh.ClientConfig, 1)
	_ = make([]ssh.ClientConfig, n)
	_ = make([]ssh.ClientConfig, 0, 2)
	type S = []ssh.ClientConfig
	_ = make(S, 1)
}
`,
			// 1 (badNew) + 1 (badVar) + 1 (badNamedReturn)
			// + 2 (badLocalAlias: type T + &T{})
			// + 4 (badChainedAliasNewAndVar: type A + type B + new(B) + var x B)
			// + 4 (badDeepNestedContainers: 4 elided literals)
			// + 4 (badMakeSliceAllocations: 4 make([]ClientConfig, ...) calls)
			wantViolations: 17,
		},
		{
			name:    "dot_import_flagged_and_allowed",
			relPath: "pkg/example/dot.go",
			src: `package example
import . "github.com/wentf9/xops-cli/core/ssh"
func ok() *ClientConfig { return NewClientConfig(ClientConfig{Address: "x"}) }
func bad() *ClientConfig { return &ClientConfig{Address: "x"} }`,
			wantViolations: 1,
		},
		{
			name:    "in_core_ssh_bare_flagged_but_crypto_ssh_and_constructor_allowed",
			relPath: "core/ssh/sample.go",
			src: `package ssh
import (
	"errors"
	"golang.org/x/crypto/ssh"
)
func ok1() *ClientConfig { return NewClientConfig(ClientConfig{Address: "x"}) }
func ok2() (ClientConfig, bool) { return ClientConfig{}, false }
func ok3() (ClientConfig, error) { return ClientConfig{}, errors.New("boom") }
func ok4() *ssh.ClientConfig { return &ssh.ClientConfig{User: "u"} }
func ok5() *ssh.ClientConfig { return new(ssh.ClientConfig) }
func ok6() (cfg *ClientConfig, err error) { return nil, nil }
func ok7() { var p *ClientConfig; _ = p }
func bad1() *ClientConfig { return &ClientConfig{Address: "x"} }
func bad2() ClientConfig { return ClientConfig{Address: "y"} }
func bad3() *ClientConfig { return new(ClientConfig) }`,
			wantViolations: 3,
		},
		{
			name:    "external_valid_constructor_and_error_returns_and_crypto_ssh_allowed",
			relPath: "pkg/example/good.go",
			src: `package example
import (
	"errors"
	coressh "github.com/wentf9/xops-cli/core/ssh"
	"golang.org/x/crypto/ssh"
)
func ok1() *coressh.ClientConfig { return coressh.NewClientConfig(coressh.ClientConfig{Address: "x"}) }
func ok2(err error) (coressh.ClientConfig, error) { return coressh.ClientConfig{}, err }
func ok3() (coressh.ClientConfig, error) { return coressh.ClientConfig{}, errors.New("nope") }
func ok4() (coressh.ClientConfig, bool) { return coressh.ClientConfig{}, false }
func ok5() *ssh.ClientConfig { return &ssh.ClientConfig{User: "ops"} }
func ok6() (cfg *coressh.ClientConfig, err error) { return nil, nil }
func ok7() { var p *coressh.ClientConfig; _ = p }
func ok8() { var x ssh.ClientConfig; _ = x }
func ok9() {
	_ = make([]*coressh.ClientConfig, 2)
	_ = make(map[string]coressh.ClientConfig)
	_ = make([]ssh.ClientConfig, 1)
}`,
			wantViolations: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, filepath.Base(tc.relPath), tc.src, 0)
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			got := analyzeClientConfigLiteralsInFile(tc.relPath, fset, file)
			if len(got) != tc.wantViolations {
				t.Fatalf("got %d violations %v, want %d", len(got), got, tc.wantViolations)
			}
		})
	}
}

// TestP7_ClientConfigConstructedViaNewClientConfigOnly enforces that every
// non-test Go file in the repository constructs core/ssh.ClientConfig solely
// through NewClientConfig(...) (with empty zero-literal ClientConfig{} allowed
// only on failure returns such as `return ClientConfig{}, false` / error).
func TestP7_ClientConfigConstructedViaNewClientConfigOnly(t *testing.T) {
	t.Parallel()

	root := p4RepoRoot(t)
	violations := scanRepoForRawClientConfigLiterals(t, root)
	for _, v := range violations {
		t.Error(v.String())
	}
}
