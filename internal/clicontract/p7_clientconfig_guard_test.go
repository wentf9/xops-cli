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
	inCoreSSH bool
	dotImport bool
	aliases   map[string]bool
}

func buildCoreSSHScope(relPath string, file *ast.File) coreSSHScope {
	scope := coreSSHScope{
		inCoreSSH: filepath.ToSlash(filepath.Dir(relPath)) == "core/ssh" && file.Name != nil && file.Name.Name == "ssh",
		aliases:   make(map[string]bool),
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
	return scope
}

func (s coreSSHScope) isClientConfigType(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	switch t := unwrapParen(expr).(type) {
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
	if star, ok := unwrapParen(expr).(*ast.StarExpr); ok {
		return s.isClientConfigType(star.X)
	}
	return s.isClientConfigType(expr)
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

func (s coreSSHScope) isElidedClientConfigLit(lit *ast.CompositeLit, stack []ast.Node) bool {
	if lit.Type != nil {
		return false
	}
	parent := enclosingNonParen(stack)
	if kv, ok := parent.(*ast.KeyValueExpr); ok && unwrapParen(kv.Value) == lit {
		parent = enclosingNodeBefore(stack, kv)
	}
	container, ok := parent.(*ast.CompositeLit)
	if !ok || container.Type == nil {
		return false
	}
	switch ct := unwrapParen(container.Type).(type) {
	case *ast.ArrayType:
		return s.isClientConfigElemType(ct.Elt)
	case *ast.MapType:
		return s.isClientConfigElemType(ct.Value)
	default:
		return false
	}
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
		if lit, ok := n.(*ast.CompositeLit); ok {
			matched := scope.isClientConfigType(lit.Type) || scope.isElidedClientConfigLit(lit, stack)
			if matched && !isDirectArgToNewClientConfig(scope, lit, stack) && !isZeroFailureReturn(lit, stack) {
				reason := "direct core/ssh.ClientConfig composite literal outside NewClientConfig(...)"
				if lit.Type == nil {
					reason = "elided core/ssh.ClientConfig composite literal outside NewClientConfig(...)"
				}
				violations = append(violations, clientConfigViolation{
					relPath: relPath,
					line:    fset.Position(lit.Pos()).Line,
					reason:  reason,
				})
			}
		}
		stack = append(stack, n)
		return true
	})
	return violations
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
// flags bare, aliased, dot-imported, in-package, address-of, elided, and
// non-failure-return core/ssh.ClientConfig composite literals while permitting
// NewClientConfig(...), zero failure returns, and x/crypto/ssh.ClientConfig.
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
func bad1() *ClientConfig { return &ClientConfig{Address: "x"} }
func bad2() ClientConfig { return ClientConfig{Address: "y"} }`,
			wantViolations: 2,
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
func ok5() *ssh.ClientConfig { return &ssh.ClientConfig{User: "ops"} }`,
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
