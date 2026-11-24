package failclosed

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
	"unicode"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

type constDef struct {
	obj    *types.Const
	pos    token.Pos
	inTest bool
}

func checkFailClosedTypes(pass *analysis.Pass) {
	constsByType := collectLocalConsts(pass)
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			checkFailClosedDecl(pass, gen, constsByType)
		}
	}
}

func collectLocalConsts(pass *analysis.Pass) map[types.Object][]constDef {
	out := make(map[types.Object][]constDef)
	for id, obj := range pass.TypesInfo.Defs {
		c, ok := obj.(*types.Const)
		if !ok || c == nil || c.Name() == "_" {
			continue
		}
		named, ok := types.Unalias(c.Type()).(*types.Named)
		if !ok || named.Origin() == nil || named.Origin().Obj() == nil {
			continue
		}
		key := named.Origin().Obj()
		out[key] = append(out[key], constDef{
			obj:    c,
			pos:    id.Pos(),
			inTest: vetutil.IsPosInTestFile(pass, id.Pos()),
		})
	}
	return out
}

func checkFailClosedDecl(pass *analysis.Pass, gen *ast.GenDecl, constsByType map[types.Object][]constDef) {
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok || ts.Assign.IsValid() {
			continue
		}
		if !vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveFailClosed) {
			continue
		}
		tn, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName)
		if !ok || tn == nil {
			continue
		}
		checkSingleFailClosedType(pass, ts, tn, constsByType[tn])
	}
}

func checkSingleFailClosedType(pass *analysis.Pass, ts *ast.TypeSpec, tn *types.TypeName, consts []constDef) {
	switch u := tn.Type().Underlying().(type) {
	case *types.Basic:
		checkFailClosedScalar(pass, ts, tn.Name(), u, consts)
	case *types.Struct:
		checkFailClosedStruct(pass, ts, tn.Name(), u)
	case *types.Interface:
		if !hasSealedMethod(u) {
			pass.ReportRangef(ts.Name, "failclosed: //xops:failclosed 不支持非封闭接口类型 %s", tn.Name())
		}
	default:
		pass.ReportRangef(ts.Name, "failclosed: //xops:failclosed 仅支持基础标量枚举、结构体及封闭和类型接口，不支持 %s", tn.Name())
	}
}

func hasSealedMethod(iface *types.Interface) bool {
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if !m.Exported() && strings.HasPrefix(m.Name(), "sealed") {
			return true
		}
	}
	return false
}

func checkFailClosedScalar(pass *analysis.Pass, ts *ast.TypeSpec, typeName string, basic *types.Basic, consts []constDef) {
	if !isSupportedFailClosedBasic(basic) {
		pass.ReportRangef(ts.Name, "failclosed: //xops:failclosed 不支持标量类型 %s", typeName)
		return
	}
	tsInTest := vetutil.IsPosInTestFile(pass, ts.Pos())
	var zeroConsts []constDef
	for _, cd := range consts {
		if !tsInTest && cd.inTest {
			continue
		}
		if isZeroConstVal(cd.obj.Val(), basic) {
			zeroConsts = append(zeroConsts, cd)
		}
	}
	if len(zeroConsts) == 0 {
		pass.ReportRangef(ts.Name, "failclosed: 标记 //xops:failclosed 的枚举类型 %s 必须定义代表最严/拒绝/无效语义的零值常量", typeName)
		return
	}
	for _, zc := range zeroConsts {
		validateZeroConstName(pass, zc)
	}
}

func isSupportedFailClosedBasic(basic *types.Basic) bool {
	if basic.Info()&types.IsInteger != 0 {
		return true
	}
	return basic.Kind() == types.String || basic.Kind() == types.Bool
}

func isZeroConstVal(val constant.Value, basic *types.Basic) bool {
	if val == nil {
		return false
	}
	switch {
	case basic.Info()&types.IsInteger != 0:
		return val.Kind() == constant.Int && constant.Sign(val) == 0
	case basic.Kind() == types.String:
		return val.Kind() == constant.String && constant.StringVal(val) == ""
	case basic.Kind() == types.Bool:
		return val.Kind() == constant.Bool && !constant.BoolVal(val)
	default:
		return false
	}
}

func validateZeroConstName(pass *analysis.Pass, zc constDef) {
	tokens := splitIdentTokens(zc.obj.Name())
	for _, tok := range tokens {
		if isForbiddenZeroToken(tok) {
			pass.ReportRangef(posOrZeroRange(zc.pos), "failclosed: //xops:failclosed 零值常量 %s 命名不得包含放行/有效语义词", zc.obj.Name())
			return
		}
	}
	for _, tok := range tokens {
		if isRequiredZeroToken(tok) {
			return
		}
	}
	pass.ReportRangef(posOrZeroRange(zc.pos), "failclosed: //xops:failclosed 零值常量 %s 命名必须显式体现拒绝/无效/未设置语义", zc.obj.Name())
}

type posRange token.Pos

func (p posRange) Pos() token.Pos { return token.Pos(p) }
func (p posRange) End() token.Pos { return token.Pos(p) }

func posOrZeroRange(pos token.Pos) analysis.Range {
	return posRange(pos)
}

func checkFailClosedStruct(pass *analysis.Pass, ts *ast.TypeSpec, typeName string, st *types.Struct) {
	var negField *types.Var
	hasPositiveGate := false
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Exported() {
			pass.ReportRangef(fieldReportRange(ts, f), "failclosed: //xops:failclosed 结构体 %s 禁止导出字段 %s", typeName, f.Name())
		}
		if !isBoolFieldType(f.Type()) {
			continue
		}
		tokens := splitIdentTokens(f.Name())
		if negField == nil && anyTokenMatches(tokens, isNegativeBoolToken) {
			negField = f
		}
		if anyTokenMatches(tokens, isPositiveGateBoolToken) {
			hasPositiveGate = true
		}
	}
	if negField != nil && !hasPositiveGate {
		pass.ReportRangef(
			fieldReportRange(ts, negField),
			"failclosed: //xops:failclosed 结构体 %s 含否定语义 bool 字段 %s（零值 false 存在 fail-open 风险），请改用正向门控字段（如 valid/sealed/initialized）或 //xops:failclosed 枚举",
			typeName,
			negField.Name(),
		)
	}
}

func fieldReportRange(ts *ast.TypeSpec, f *types.Var) analysis.Range {
	if f.Pos().IsValid() {
		return posRange(f.Pos())
	}
	return ts.Name
}

func isBoolFieldType(t types.Type) bool {
	basic, ok := types.Unalias(t).(*types.Basic)
	return ok && basic.Kind() == types.Bool
}

func anyTokenMatches(tokens []string, pred func(string) bool) bool {
	for _, tok := range tokens {
		if pred(tok) {
			return true
		}
	}
	return false
}

func isForbiddenZeroToken(tok string) bool {
	switch tok {
	case "allow", "allowed", "permit", "permitted", "valid", "enable", "enabled",
		"ok", "pass", "passed", "accept", "accepted", "grant", "granted",
		"open", "active", "success", "true", "approve", "approved", "default":
		return true
	default:
		return false
	}
}

func isRequiredZeroToken(tok string) bool {
	switch tok {
	case "deny", "denied", "invalid", "unset", "disabled", "disable", "unknown",
		"none", "reject", "rejected", "forbid", "forbidden", "block", "blocked",
		"closed", "halted", "fail", "failed", "uninitialized", "unspecified",
		"disallow", "disallowed":
		return true
	default:
		return false
	}
}

func isNegativeBoolToken(tok string) bool {
	switch tok {
	case "disabled", "disable", "denied", "deny", "revoked", "revoke",
		"blocked", "block", "halted", "halt", "closed", "close",
		"wiped", "wipe", "invalid", "rejected", "reject", "forbidden", "forbid",
		"bypass", "bypassed", "insecure", "unverified":
		return true
	default:
		return false
	}
}

func isPositiveGateBoolToken(tok string) bool {
	switch tok {
	case "valid", "initialized", "init", "active", "enabled", "ready",
		"ok", "sealed", "usable", "authenticated", "authorized":
		return true
	default:
		return false
	}
}

func splitIdentTokens(name string) []string {
	var tokens []string
	for _, part := range strings.Split(name, "_") {
		if part == "" {
			continue
		}
		tokens = append(tokens, splitCamelWord(part)...)
	}
	return tokens
}

func splitCamelWord(word string) []string {
	runes := []rune(word)
	var out []string
	start := 0
	for i := 1; i < len(runes); i++ {
		if isWordBoundary(runes, i) {
			out = append(out, strings.ToLower(string(runes[start:i])))
			start = i
		}
	}
	if start < len(runes) {
		out = append(out, strings.ToLower(string(runes[start:])))
	}
	return out
}

func isWordBoundary(runes []rune, i int) bool {
	prev, cur := runes[i-1], runes[i]
	if unicode.IsLower(prev) && unicode.IsUpper(cur) {
		return true
	}
	return i+1 < len(runes) && unicode.IsUpper(prev) && unicode.IsUpper(cur) && unicode.IsLower(runes[i+1])
}
