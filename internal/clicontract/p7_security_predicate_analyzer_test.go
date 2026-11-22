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
	"strconv"
	"strings"
	"testing"
)

var (
	// securityPredicateRootDirs enumerates all production source roots walked
	// recursively repo-wide so bare-bool error-swallowing predicates cannot hide
	// in any package (Pillar E / Pillar G).
	securityPredicateRootDirs = []string{
		"core",
		"pkg",
		"internal",
		"cmd",
	}

	// securityPredicateNameRe matches exported and unexported predicate names
	// starting with is/has/allow/can/should/check/verify/match followed by an
	// uppercase letter.
	securityPredicateNameRe = regexp.MustCompile(`^([Ii]s|[Hh]as|[Aa]llow|[Cc]an|[Ss]hould|[Cc]heck|[Vv]erify|[Mm]atch)[A-Z]`)

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

func (v securityPredicateViolation) String() string {
	return fmt.Sprintf("%s:%d: %s omits error return while swallowing err at line %d (%s); return (verdict.Verdict, error) or (..., error) instead",
		v.relPath, v.line, v.funcName, v.branchAt, v.retKind)
}

// analyzeSecurityPredicatesInFile scans a single parsed Go file for exported or
// unexported functions/methods matching securityPredicateNameRe that return a
// bool without an error return and swallow a local error via any of:
//  1. if ... err != nil { return <bool> }
//  2. if ... err == nil { ... } else { return <bool> }
//  3. if ..., err := ...; err == nil { ... return ... } with fallback return
//  4. return ... err == nil ... / return ... err != nil ...
func analyzeSecurityPredicatesInFile(relPath string, fset *token.FileSet, file *ast.File) []securityPredicateViolation {
	var violations []securityPredicateViolation
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if !securityPredicateNameRe.MatchString(fn.Name.Name) || !returnsBoolWithoutError(fn) {
			continue
		}
		if hasJustifiedSecpredNolint(fset, file, fn) {
			continue
		}
		ignoredErrs := errorOnlyParamNames(fn)
		for name := range stdlibPureSyntaxErrNames(file, fn) {
			ignoredErrs[name] = true
		}
		if branchLine, retKind, hit := findErrSwallowBoolReturn(fset, fn.Body, ignoredErrs); hit {
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

func analyzeSecurityPredicatePackages(t *testing.T, repoRoot string, rootDirs []string) []securityPredicateViolation {
	t.Helper()
	var out []securityPredicateViolation
	scannedFiles := 0
	for _, relRoot := range rootDirs {
		absRoot := filepath.Join(repoRoot, filepath.FromSlash(relRoot))
		err := filepath.WalkDir(absRoot, func(filePath string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				name := d.Name()
				if filePath != absRoot && (strings.HasPrefix(name, ".") || name == "vendor" || name == "scripts" || name == "testdata") {
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
			scannedFiles++
			out = append(out, analyzeSecurityPredicatesInFile(filepath.ToSlash(rel), fset, file)...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk security root %s: %v", relRoot, err)
		}
	}
	if scannedFiles == 0 {
		t.Fatalf("expected to scan non-test production Go files under %v, found 0", rootDirs)
	}
	slices.SortFunc(out, func(a, b securityPredicateViolation) int {
		if a.relPath != b.relPath {
			return strings.Compare(a.relPath, b.relPath)
		}
		return a.line - b.line
	})
	return out
}

func returnsBoolWithoutError(fn *ast.FuncDecl) bool {
	if fn.Type == nil || fn.Type.Results == nil {
		return false
	}
	hasBool := false
	for _, field := range fn.Type.Results.List {
		ident, ok := unwrapParen(field.Type).(*ast.Ident)
		if !ok {
			continue
		}
		if ident.Name == "error" {
			return false
		}
		if ident.Name == "bool" {
			hasBool = true
		}
	}
	return hasBool
}

// errorOnlyParamNames returns parameter names of type error that are never
// reassigned or re-bound in fn.Body, distinguishing pure error classifiers
// such as `func isErrorTimeout(err error) bool` from functions swallowing a
// newly produced local error.
func errorOnlyParamNames(fn *ast.FuncDecl) map[string]bool {
	params := make(map[string]bool)
	if fn.Type == nil || fn.Type.Params == nil {
		return params
	}
	for _, field := range fn.Type.Params.List {
		ident, ok := unwrapParen(field.Type).(*ast.Ident)
		if !ok || ident.Name != "error" {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				params[name.Name] = true
			}
		}
	}
	if len(params) == 0 || fn.Body == nil {
		return params
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range stmt.Lhs {
				if id, ok := unwrapParen(lhs).(*ast.Ident); ok {
					delete(params, id.Name)
				}
			}
		case *ast.ValueSpec:
			for _, name := range stmt.Names {
				delete(params, name.Name)
			}
		}
		return true
	})
	return params
}

// stdlibPureSyntaxErrNames returns local error variable names whose ONLY
// assignment in fn.Body comes from a side-effect-free Go standard-library
// IP/CIDR syntax parser (netip.ParseAddr, netip.ParsePrefix, net.ParseCIDR).
// Those parsers return error solely to report syntax non-match rather than an
// I/O, policy, or resolution failure. If the same variable is assigned by any
// other expression anywhere in fn.Body, it is excluded and flagged normally.
func stdlibPureSyntaxErrNames(file *ast.File, fn *ast.FuncDecl) map[string]bool {
	if file == nil || fn == nil || fn.Body == nil {
		return nil
	}
	netipNames, netNames := collectStdlibIPParserImports(file)
	if len(netipNames) == 0 && len(netNames) == 0 {
		return nil
	}

	candidates := make(map[string]bool)
	tainted := make(map[string]bool)
	taint := func(name string) {
		if name == "" || name == "_" {
			return
		}
		tainted[name] = true
		delete(candidates, name)
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			recordAssignPureSyntaxErrs(stmt, netipNames, netNames, candidates, tainted, taint)
		case *ast.ValueSpec:
			for _, name := range stmt.Names {
				taint(name.Name)
			}
		}
		return true
	})
	return candidates
}

func collectStdlibIPParserImports(file *ast.File) (netipNames, netNames map[string]bool) {
	netipNames = make(map[string]bool)
	netNames = make(map[string]bool)
	for _, imp := range file.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		localName := ""
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				continue
			}
			localName = imp.Name.Name
		}
		switch importPath {
		case "net/netip":
			if localName == "" {
				localName = "netip"
			}
			netipNames[localName] = true
		case "net":
			if localName == "" {
				localName = "net"
			}
			netNames[localName] = true
		}
	}
	return netipNames, netNames
}

func isPureStdlibIPOrCIDRCall(expr ast.Expr, netipNames, netNames map[string]bool) bool {
	call, ok := unwrapParen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := unwrapParen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgIdent, ok := unwrapParen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	if netipNames[pkgIdent.Name] && (sel.Sel.Name == "ParseAddr" || sel.Sel.Name == "ParsePrefix") {
		return true
	}
	return netNames[pkgIdent.Name] && sel.Sel.Name == "ParseCIDR"
}

func recordAssignPureSyntaxErrs(
	stmt *ast.AssignStmt,
	netipNames, netNames map[string]bool,
	candidates, tainted map[string]bool,
	taint func(string),
) {
	pureLastErr := false
	if len(stmt.Rhs) == 1 && len(stmt.Lhs) >= 2 && isPureStdlibIPOrCIDRCall(stmt.Rhs[0], netipNames, netNames) {
		if id, ok := unwrapParen(stmt.Lhs[len(stmt.Lhs)-1]).(*ast.Ident); ok && isErrLikeName(id.Name) {
			pureLastErr = true
			if !tainted[id.Name] {
				candidates[id.Name] = true
			}
		}
	}
	for i, lhs := range stmt.Lhs {
		if pureLastErr && i == len(stmt.Lhs)-1 {
			continue
		}
		if id, ok := unwrapParen(lhs).(*ast.Ident); ok {
			taint(id.Name)
		}
	}
}

func isErrLikeName(name string) bool {
	return name == "err" || strings.HasSuffix(name, "Err") || strings.HasPrefix(name, "err")
}

func findErrSwallowBoolReturn(fset *token.FileSet, body *ast.BlockStmt, errOnlyParams map[string]bool) (int, string, bool) {
	var hitLine int
	var hitRet string
	ast.Inspect(body, func(n ast.Node) bool {
		if hitLine != 0 {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		switch node := n.(type) {
		case *ast.IfStmt:
			if exprContainsLocalErrNilCheck(node.Cond, token.NEQ, errOnlyParams) {
				if kind, ok := branchReturnsValue(node.Body); ok {
					hitLine = fset.Position(node.Pos()).Line
					hitRet = "if err!=nil return " + kind
					return false
				}
			}
			if exprContainsLocalErrNilCheck(node.Cond, token.EQL, errOnlyParams) {
				if node.Else != nil {
					if kind, ok := branchReturnsValue(node.Else); ok {
						hitLine = fset.Position(node.Else.Pos()).Line
						hitRet = "else of err==nil return " + kind
						return false
					}
				}
				if kind, ok := branchReturnsValue(node.Body); ok && hasReturnOutside(body, node) {
					hitLine = fset.Position(node.Pos()).Line
					hitRet = "if err==nil early return " + kind + " with fallback"
					return false
				}
			}
		case *ast.ReturnStmt:
			for _, res := range node.Results {
				if exprContainsLocalErrNilCheck(res, token.EQL, errOnlyParams) || exprContainsLocalErrNilCheck(res, token.NEQ, errOnlyParams) {
					hitLine = fset.Position(node.Pos()).Line
					hitRet = "return err nil-comparison expr"
					return false
				}
			}
		}
		return true
	})
	return hitLine, hitRet, hitLine != 0
}

func exprContainsLocalErrNilCheck(expr ast.Expr, op token.Token, errOnlyParams map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != op {
			return true
		}
		if isLocalErrLikeIdent(bin.X, errOnlyParams) && isNilIdent(bin.Y) {
			found = true
			return false
		}
		if isNilIdent(bin.X) && isLocalErrLikeIdent(bin.Y, errOnlyParams) {
			found = true
			return false
		}
		return true
	})
	return found
}

func isLocalErrLikeIdent(expr ast.Expr, errOnlyParams map[string]bool) bool {
	ident, ok := unwrapParen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	if errOnlyParams[ident.Name] {
		return false
	}
	return isErrLikeName(ident.Name)
}

func branchReturnsValue(branch ast.Node) (string, bool) {
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
		if len(ret.Results) == 0 {
			retKind = "named-return"
			return false
		}
		for _, res := range ret.Results {
			if ident, ok := unwrapParen(res).(*ast.Ident); ok && (ident.Name == "true" || ident.Name == "false") {
				retKind = ident.Name
				return false
			}
		}
		retKind = "bool-expr"
		return false
	})
	return retKind, retKind != ""
}

func hasReturnOutside(body *ast.BlockStmt, exclude ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found || n == exclude {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		if _, ok := n.(*ast.ReturnStmt); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

// TestP7_SecurityPredicateAnalyzer_SelfTest verifies that the custom analyzer
// flags exported/unexported predicates omitting an error return across all four
// error-swallowing shapes (if err!=nil, if err==nil else, if err==nil early
// return with fallback, and return err==nil/err!=nil boolean expressions) while
// permitting (verdict.Verdict, error), (bool, error), pure predicates, and
// error classifiers.
func TestP7_SecurityPredicateAnalyzer_SelfTest(t *testing.T) {
	t.Parallel()

	const syntheticSrc = `package sample

import (
	"errors"
	"net"
	"net/netip"
)

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

func hasActiveProxy(x string) bool {
	if v, err := parse(x); err == nil {
		if v != "" {
			return true
		}
	}
	return false
}

func HasValidCertExpr(x string) bool {
	v, err := parse(x)
	return err == nil && v != ""
}

func isUnreachableExpr(x string) bool {
	err := check(x)
	return err != nil
}

func checkTupleWithoutError(x string) (string, bool) {
	v, err := parse(x)
	if err != nil {
		return "", false
	}
	return v, true
}

func isNamedBoolReturn(x string) (ok bool) {
	if err := check(x); err != nil {
		return
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

func isMixedNetipAndCheck(x string) bool {
	if _, err := netip.ParseAddr(x); err == nil {
		return true
	}
	if err := check(x); err != nil {
		return false
	}
	return true
}

// Allowed forms:

func isPureNetipSyntax(x string) bool {
	_, err := netip.ParseAddr(x)
	return err == nil
}

func isPureCIDRSyntax(x string) bool {
	_, _, err := net.ParseCIDR(x)
	return err == nil
}

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

func isErrorPresent(err error) bool {
	return err != nil
}

func isMutatingWithoutReturning(x string) bool {
	if v, err := parse(x); err == nil && v != "" {
		x = v
	}
	return x == "ok"
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
		"hasActiveProxy",
		"HasValidCertExpr",
		"isUnreachableExpr",
		"checkTupleWithoutError",
		"isNamedBoolReturn",
		"isMissingReasonNolint",
		"isMixedNetipAndCheck",
	}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("analyzer flagged %v, want %v", gotNames, wantNames)
	}

	const shadowedNetipSrc = `package shadowed

import netip "example.com/custom/netip"

func isShadowedParseAddr(x string) bool {
	_, err := netip.ParseAddr(x)
	return err == nil
}
`
	shadowFset := token.NewFileSet()
	shadowFile, err := parser.ParseFile(shadowFset, "shadowed.go", shadowedNetipSrc, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse shadowed source: %v", err)
	}
	shadowGot := analyzeSecurityPredicatesInFile("shadowed/shadowed.go", shadowFset, shadowFile)
	if len(shadowGot) != 1 || shadowGot[0].funcName != "isShadowedParseAddr" {
		t.Fatalf("shadowed netip import flagged %+v, want [isShadowedParseAddr]", shadowGot)
	}
}

// TestP7_SecurityPredicateAnalyzer_ZeroBareBoolErrSwallow runs the analyzer
// repo-wide across all production packages under core/, pkg/, internal/, and
// cmd/ (every OS build tag) with zero baseline: every bare-bool predicate
// swallowing a local error must be migrated to (verdict.Verdict, error) /
// (..., error), or carry an explicit justified "//nolint:secpred // <reason>".
func TestP7_SecurityPredicateAnalyzer_ZeroBareBoolErrSwallow(t *testing.T) {
	t.Parallel()

	root := p4RepoRoot(t)
	violations := analyzeSecurityPredicatePackages(t, root, securityPredicateRootDirs)
	for _, v := range violations {
		t.Error(v.String())
	}
}
