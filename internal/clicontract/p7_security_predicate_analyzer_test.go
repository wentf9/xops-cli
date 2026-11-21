package clicontract

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	// securityPredicatePackages enumerates the security-sensitive packages where
	// bare-bool error-swallowing predicates are forbidden (Pillar E / Pillar G).
	securityPredicatePackages = []string{
		"core/ssh",
		"core/sftp",
		"core/fsx",
		"core/winsec",
		"core/mcp/guardrail",
		"core/mcp/policy",
		"internal/sshenv",
		"internal/mcphost",
		"pkg/adapter",
		"pkg/config",
	}

	// securityPredicateNameRe matches exported and unexported predicate names
	// starting with is/allow/can/should/check/verify/match followed by an
	// uppercase letter.
	securityPredicateNameRe = regexp.MustCompile(`^([Ii]s|[Aa]llow|[Cc]an|[Ss]hould|[Cc]heck|[Vv]erify|[Mm]atch)[A-Z]`)

	// secpredNolintRe matches explicit "//nolint:secpred // <reason>" (or
	// comma-separated linter lists containing secpred) requiring a non-empty
	// justification after the second "//".
	secpredNolintRe = regexp.MustCompile(`^//\s*nolint:([a-z0-9_,-]+)\s+//\s*(\S.*)$`)
)

func hasJustifiedSecpredNolint(fset *token.FileSet, file *ast.File, fn *ast.FuncDecl) bool {
	fnLine := fset.Position(fn.Pos()).Line
	checkComment := func(text string) bool {
		m := secpredNolintRe.FindStringSubmatch(strings.TrimSpace(text))
		if len(m) != 3 {
			return false
		}
		for part := range strings.SplitSeq(m[1], ",") {
			if strings.TrimSpace(part) == "secpred" {
				return strings.TrimSpace(m[2]) != ""
			}
		}
		return false
	}
	if fn.Doc != nil {
		for _, c := range fn.Doc.List {
			if checkComment(c.Text) {
				return true
			}
		}
	}
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			if fset.Position(c.Pos()).Line == fnLine && checkComment(c.Text) {
				return true
			}
		}
	}
	return false
}

type securityPredicateViolation struct {
	relPath  string
	line     int
	funcName string
	branchAt int
	retKind  string
}

func (v securityPredicateViolation) key() string {
	return v.relPath + ":" + v.funcName
}

func (v securityPredicateViolation) String() string {
	return fmt.Sprintf("%s:%d: %s returns bare bool while swallowing err!=nil at line %d (returns %s); return (verdict.Verdict, error) instead",
		v.relPath, v.line, v.funcName, v.branchAt, v.retKind)
}

// analyzeSecurityPredicatesInFile scans a single parsed Go file for exported or
// unexported functions/methods matching securityPredicateNameRe that return a
// bare bool and contain an err != nil branch (or else of err == nil) returning
// a bool without propagating the error.
func analyzeSecurityPredicatesInFile(relPath string, fset *token.FileSet, file *ast.File) []securityPredicateViolation {
	var violations []securityPredicateViolation
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if !securityPredicateNameRe.MatchString(fn.Name.Name) || !returnsBareBool(fn) {
			continue
		}
		if hasJustifiedSecpredNolint(fset, file, fn) {
			continue
		}
		if branchLine, retKind, hit := findErrSwallowBoolReturn(fset, fn.Body); hit {
			violations = append(violations, securityPredicateViolation{
				relPath:  relPath,
				line:     fset.Position(fn.Pos()).Line,
				funcName: fn.Name.Name,
				branchAt: branchLine,
				retKind:  retKind,
			})
		}
	}
	return violations
}

func analyzeSecurityPredicatePackages(t *testing.T, repoRoot string, pkgDirs []string) []securityPredicateViolation {
	t.Helper()
	var out []securityPredicateViolation
	for _, relPkg := range pkgDirs {
		absPkg := filepath.Join(repoRoot, filepath.FromSlash(relPkg))
		err := filepath.WalkDir(absPkg, func(filePath string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if filePath != absPkg {
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
			file, parseErr := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
			if parseErr != nil {
				return parseErr
			}
			out = append(out, analyzeSecurityPredicatesInFile(filepath.ToSlash(rel), fset, file)...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk security package %s: %v", relPkg, err)
		}
	}
	slices.SortFunc(out, func(a, b securityPredicateViolation) int {
		if a.relPath != b.relPath {
			return strings.Compare(a.relPath, b.relPath)
		}
		return a.line - b.line
	})
	return out
}

func returnsBareBool(fn *ast.FuncDecl) bool {
	if fn.Type == nil || fn.Type.Results == nil {
		return false
	}
	var types []ast.Expr
	for _, field := range fn.Type.Results.List {
		n := len(field.Names)
		if n == 0 {
			n = 1
		}
		for range n {
			types = append(types, field.Type)
		}
	}
	if len(types) != 1 {
		return false
	}
	ident, ok := unwrapParen(types[0]).(*ast.Ident)
	return ok && ident.Name == "bool"
}

func findErrSwallowBoolReturn(fset *token.FileSet, body *ast.BlockStmt) (int, string, bool) {
	var hitLine int
	var hitRet string
	ast.Inspect(body, func(n ast.Node) bool {
		if hitLine != 0 {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if exprContainsErrNilCheck(ifStmt.Cond, token.NEQ) {
			if kind, ok := branchReturnsBoolValue(ifStmt.Body); ok {
				hitLine = fset.Position(ifStmt.Pos()).Line
				hitRet = kind
				return false
			}
		}
		if exprContainsErrNilCheck(ifStmt.Cond, token.EQL) && ifStmt.Else != nil {
			if kind, ok := branchReturnsBoolValue(ifStmt.Else); ok {
				hitLine = fset.Position(ifStmt.Else.Pos()).Line
				hitRet = kind
				return false
			}
		}
		return true
	})
	return hitLine, hitRet, hitLine != 0
}

func exprContainsErrNilCheck(expr ast.Expr, op token.Token) bool {
	bin, ok := unwrapParen(expr).(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if bin.Op == op {
		return (isErrLikeIdent(bin.X) && isNilIdent(bin.Y)) || (isNilIdent(bin.X) && isErrLikeIdent(bin.Y))
	}
	if bin.Op == token.LAND || bin.Op == token.LOR {
		return exprContainsErrNilCheck(bin.X, op) || exprContainsErrNilCheck(bin.Y, op)
	}
	return false
}

func isErrLikeIdent(expr ast.Expr) bool {
	ident, ok := unwrapParen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "err" || strings.HasSuffix(ident.Name, "Err") || strings.HasPrefix(ident.Name, "err")
}

func branchReturnsBoolValue(branch ast.Node) (string, bool) {
	var retKind string
	ast.Inspect(branch, func(n ast.Node) bool {
		if retKind != "" {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		if len(ret.Results) == 1 {
			if ident, ok := unwrapParen(ret.Results[0]).(*ast.Ident); ok && (ident.Name == "true" || ident.Name == "false") {
				retKind = ident.Name
				return false
			}
			retKind = "bool-expr"
			return false
		}
		return true
	})
	return retKind, retKind != ""
}

// TestP7_SecurityPredicateAnalyzer_SelfTest verifies that the custom analyzer
// flags exported/unexported bare-bool predicates swallowing err != nil while
// permitting (verdict.Verdict, error), (bool, error), pure predicates, and
// error classifiers.
func TestP7_SecurityPredicateAnalyzer_SelfTest(t *testing.T) {
	t.Parallel()

	const syntheticSrc = `package sample

import "errors"

type S struct{}

func isAllowedTarget(x string) bool {
	if _, err := parse(x); err != nil {
		return false
	}
	return true
}

func AllowRemotePeer(x string) bool {
	if err := check(x); err != nil {
		return true
	}
	return false
}

func (s *S) canUseSocket(x string) bool {
	if _, statErr := parse(x); statErr == nil {
		return true
	} else {
		return false
	}
}

func ShouldRetryHandshake(x string) bool {
	if _, err := parse(x); err != nil || x == "" {
		return false
	}
	return true
}

func checkHostRule(x string) bool {
	err := check(x)
	if err != nil {
		return false
	}
	return true
}

func VerifyPeerCert(x string) bool {
	if err := check(x); err != nil {
		return false
	}
	return true
}

func matchPolicyHost(x string) bool {
	if _, err := parse(x); err != nil {
		return false
	}
	return true
}

//nolint:secpred
func isMissingReasonNolint(x string) bool {
	if err := check(x); err != nil {
		return false
	}
	return true
}

// Allowed forms:

//nolint:secpred // external library callback requires func(string) bool
func isExemptedCallback(x string) bool {
	if err := check(x); err != nil {
		return false
	}
	return true
}

func isExemptedInline(x string) bool { //nolint:secpred // external interface constraint
	if err := check(x); err != nil {
		return false
	}
	return true
}

func isErrorTimeout(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, errors.New("timeout"))
}

func checkWithError(x string) (bool, error) {
	if err := check(x); err != nil {
		return false, err
	}
	return true, nil
}

func allowWithVerdict(x string) (uint8, error) {
	if err := check(x); err != nil {
		return 0, err
	}
	return 1, nil
}

func isPurePrefix(x string) bool {
	return x == "ok"
}

func helperNotPredicate(x string) bool {
	if err := check(x); err != nil {
		return false
	}
	return true
}

func parse(string) (string, error) { return "", nil }
func check(string) error           { return nil }
`

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample.go", syntheticSrc, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	got := analyzeSecurityPredicatesInFile("sample/sample.go", fset, file)
	var gotNames []string
	for _, v := range got {
		gotNames = append(gotNames, v.funcName)
	}
	wantNames := []string{
		"isAllowedTarget",
		"AllowRemotePeer",
		"canUseSocket",
		"ShouldRetryHandshake",
		"checkHostRule",
		"VerifyPeerCert",
		"matchPolicyHost",
		"isMissingReasonNolint",
	}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("analyzer flagged %v, want %v", gotNames, wantNames)
	}
}

// TestP7_SecurityPredicateAnalyzer_NoNewBareBoolErrSwallow runs the analyzer
// across all 10 security packages (every OS build tag). Pre-existing violations
// tracked during W2/W3 transition are explicitly listed below and will be
// burned down to zero (or explicitly justified) in W3 finalization.
func TestP7_SecurityPredicateAnalyzer_NoNewBareBoolErrSwallow(t *testing.T) {
	t.Parallel()

	// Temporary W2/W3 transition baseline (pending coordinator disposition &
	// W2b/W2c/W2d/W2e migrations). Any NEW violation fails immediately.
	transitionBaseline := map[string]string{
		"core/fsx/fsx_unix.go:isUnixDevNullStat":                          "devnull stat device comparison inside fsx",
		"core/ssh/agent_forward.go:shouldRequestMuxProxyAgentForward":     "pending W3 verdict migration",
		"core/ssh/auth.go:isUnencryptedPrivateKeyFile":                    "pending W3 verdict/err review",
		"core/ssh/connector_knownhosts.go:isReadableRegularFile":          "pending W2e fsx migration",
		"core/ssh/host_algorithms.go:isHostAuthority":                     "x/crypto/ssh.CertChecker.IsHostAuthority requires func(PublicKey,string) bool",
		"core/winsec/handle_windows.go:IsSecureSystemSSHObjectByHandle":   "pending W2e/W3 verdict migration",
		"core/winsec/handle_windows.go:IsSecureSystemAncestorDirByHandle": "pending W2e/W3 verdict migration",
		"core/winsec/windows.go:IsSecureSecurityDescriptor":               "pending W2e/W3 verdict migration",
		"core/winsec/windows.go:IsSecureSystemSSHObject":                  "pending W2e deletion/migration",
		"core/winsec/windows.go:IsSecureSystemAncestorDirDescriptor":      "pending W2e/W3 verdict migration",
		"core/winsec/windows.go:IsSecureSystemAncestorDir":                "pending W2e deletion/migration",
		"pkg/adapter/ssh_adapter.go:isNonInteractiveForNode":              "pending W2b/W3 verdict migration",
		"pkg/config/openssh.go:isOpenSSHDevNullFileInfo":                  "pending W2e fsx.AllowDevNull migration",
		"pkg/config/target.go:IsPersistableIdentityPath":                  "pending W3 verdict/review",
		"pkg/config/target.go:isDirectJumpTarget":                         "pending W2d TargetRef migration",
	}

	root := p4RepoRoot(t)
	violations := analyzeSecurityPredicatePackages(t, root, securityPredicatePackages)
	for _, v := range violations {
		if _, known := transitionBaseline[v.key()]; !known {
			t.Error(v.String())
		}
	}
}
