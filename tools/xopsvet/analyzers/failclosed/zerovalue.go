package failclosed

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strings"

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
	vetutil.ForEachTypeSpec(pass, func(_ *ast.File, gen *ast.GenDecl, ts *ast.TypeSpec) {
		if ts.Assign.IsValid() || !vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveFailClosed) {
			return
		}
		if tn, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName); ok && tn != nil {
			checkSingleFailClosedType(pass, ts, tn, constsByType[tn])
		}
	})
}

func collectLocalConsts(pass *analysis.Pass) map[types.Object][]constDef {
	out := make(map[types.Object][]constDef)
	for id, obj := range pass.TypesInfo.Defs {
		c, ok := obj.(*types.Const)
		if !ok || c == nil || c.Name() == "_" {
			continue
		}
		if named, ok := types.Unalias(c.Type()).(*types.Named); ok && named.Origin() != nil && named.Origin().Obj() != nil {
			key := named.Origin().Obj()
			out[key] = append(out[key], constDef{obj: c, pos: id.Pos(), inTest: vetutil.IsPosInTestFile(pass, id.Pos())})
		}
	}
	return out
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
	for i := range iface.NumMethods() {
		if m := iface.Method(i); !m.Exported() && strings.HasPrefix(m.Name(), "sealed") {
			return true
		}
	}
	return false
}

func checkFailClosedScalar(pass *analysis.Pass, ts *ast.TypeSpec, typeName string, basic *types.Basic, consts []constDef) {
	if basic.Info()&types.IsInteger == 0 && basic.Kind() != types.String && basic.Kind() != types.Bool {
		pass.ReportRangef(ts.Name, "failclosed: //xops:failclosed 不支持标量类型 %s", typeName)
		return
	}
	tsInTest, foundZero := vetutil.IsPosInTestFile(pass, ts.Pos()), false
	for _, cd := range consts {
		if (tsInTest || !cd.inTest) && isZeroConstVal(cd.obj.Val(), basic) {
			foundZero = true
			validateZeroConstName(pass, cd)
		}
	}
	if !foundZero {
		pass.ReportRangef(ts.Name, "failclosed: 标记 //xops:failclosed 的枚举类型 %s 必须定义代表最严/拒绝/无效语义的零值常量", typeName)
	}
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
	tokens := vetutil.SplitIdentTokens(zc.obj.Name())
	forbidden := []string{"allow", "allowed", "permit", "permitted", "valid", "enable", "enabled", "ok", "pass", "passed", "accept", "accepted", "grant", "granted", "open", "active", "success", "true", "approve", "approved", "default"}
	if slices.ContainsFunc(tokens, func(t string) bool { return slices.Contains(forbidden, t) }) {
		pass.Report(analysis.Diagnostic{Pos: zc.pos, End: zc.pos, Message: "failclosed: //xops:failclosed 零值常量 " + zc.obj.Name() + " 命名不得包含放行/有效语义词"})
		return
	}
	required := []string{"deny", "denied", "invalid", "unset", "disabled", "disable", "unknown", "none", "reject", "rejected", "forbid", "forbidden", "block", "blocked", "closed", "halted", "fail", "failed", "uninitialized", "unspecified", "disallow", "disallowed"}
	if !slices.ContainsFunc(tokens, func(t string) bool { return slices.Contains(required, t) }) {
		pass.Report(analysis.Diagnostic{Pos: zc.pos, End: zc.pos, Message: "failclosed: //xops:failclosed 零值常量 " + zc.obj.Name() + " 命名必须显式体现拒绝/无效/未设置语义"})
	}
}

func checkFailClosedStruct(pass *analysis.Pass, ts *ast.TypeSpec, typeName string, st *types.Struct) {
	var negField *types.Var
	hasPositiveGate := false
	for i := range st.NumFields() {
		f := st.Field(i)
		if f.Exported() {
			reportAtField(pass, ts, f, "failclosed: //xops:failclosed 结构体 "+typeName+" 禁止导出字段 "+f.Name())
		}
		isBoolLike, isPtr := classifyBoolGateField(f.Type())
		if !isBoolLike {
			continue
		}
		tokens := vetutil.SplitIdentTokens(f.Name())
		if negField == nil && hasNegativeBoolField(tokens) {
			negField = f
		}
		// 指针字段零值为 nil 存在 panic 风险，严禁充当安全正向门控；否定前缀同样禁作正向门控（MED-3）。
		if !isPtr && hasPositiveGateField(tokens) {
			hasPositiveGate = true
		}
	}
	if negField != nil && !hasPositiveGate {
		reportAtField(pass, ts, negField, "failclosed: //xops:failclosed 结构体 "+typeName+" 含否定语义 bool 字段 "+negField.Name()+"（零值存在 fail-open 风险），请改用非指针正向门控字段（如 valid/sealed/initialized）或 //xops:failclosed 枚举")
	}
}

func reportAtField(pass *analysis.Pass, ts *ast.TypeSpec, f *types.Var, msg string) {
	if f.Pos().IsValid() {
		pass.Report(analysis.Diagnostic{Pos: f.Pos(), End: f.Pos(), Message: msg})
		return
	}
	pass.ReportRangef(ts.Name, "%s", msg)
}

// classifyBoolGateField 识别裸 bool、sync/atomic.Bool 及其单层指针类型，返回 isPtr 阻断指针充当正向门控。
func classifyBoolGateField(t types.Type) (isBoolLike, isPtr bool) {
	if t == nil {
		return false, false
	}
	u := types.Unalias(t)
	if ptr, ok := u.(*types.Pointer); ok {
		u, isPtr = types.Unalias(ptr.Elem()), true
	}
	if named, ok := u.(*types.Named); ok && vetutil.IsPkgSymbol(named.Obj(), "sync/atomic", "Bool") {
		return true, isPtr
	}
	basic, ok := u.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.Bool, isPtr
}

func hasNegativeBoolField(tokens []string) bool {
	neg := []string{"disabled", "disable", "denied", "deny", "revoked", "revoke", "blocked", "block", "halted", "halt", "closed", "close", "wiped", "wipe", "invalid", "rejected", "reject", "forbidden", "forbid", "bypass", "bypassed", "insecure", "unverified"}
	for i, tok := range tokens {
		if slices.Contains(neg, tok) || (isPositiveGateBoolToken(tok) && vetutil.HasPrecedingNegation(tokens, i)) {
			return true
		}
	}
	return false
}

func hasPositiveGateField(tokens []string) bool {
	for i, tok := range tokens {
		if isPositiveGateBoolToken(tok) && !vetutil.HasPrecedingNegation(tokens, i) {
			return true
		}
	}
	return false
}

func isPositiveGateBoolToken(tok string) bool {
	return slices.Contains([]string{"valid", "initialized", "init", "active", "enabled", "ready", "ok", "sealed", "usable", "authenticated", "authorized"}, tok)
}
