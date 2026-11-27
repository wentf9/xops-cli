package i18nguard

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// checkConstParamProse 执行规则 5：拦截全仓生产包对 {core/domain/i18n, internal/i18n}.{Str, BoundStr}
// 传入编译期散文常量：
//   - 规则 5A：key ∈ {"reason", "detail", "op"} 时禁止任何非空编译期字符串常量；
//   - 规则 5B：key ∈ {"field", "kind", "component", "feature", "expected", "action"} 时禁止含 ASCII 空白字符（空格/制表/换行）。
func checkConstParamProse(pass *analysis.Pass) {
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok || vetutil.IsPosInTestFile(pass, call.Pos()) {
			return
		}
		callee := vetutil.ResolveCalledObject(pass.TypesInfo, call)
		if callee == nil || !isStringParamConstructor(callee) || len(call.Args) < 2 {
			return
		}
		checkConstParamProseArgs(pass, callee.Name(), call.Args[0], call.Args[1])
	})
}

func isStringParamConstructor(obj types.Object) bool {
	return vetutil.IsPkgSymbol(obj, coreDomainI18nPkgPath, "Str", "BoundStr") ||
		vetutil.IsPkgSymbol(obj, internalI18nPkgPath, "Str", "BoundStr")
}

func checkConstParamProseArgs(pass *analysis.Pass, fnName string, keyArg, valArg ast.Expr) {
	key, okKey := evalConstString(pass.TypesInfo, keyArg)
	val, okVal := evalConstString(pass.TypesInfo, valArg)
	if !okKey || !okVal {
		return
	}
	if isForbiddenConstValueSlot(key) && val != "" {
		pass.ReportRangef(valArg, "i18nguard: 禁止向 %s(%q, ...) 传入非空编译期字符串常量 %q，请改用 Msg(%q, NewMessage(...)) 或专用 MessageID", fnName, key, val, key)
		return
	}
	if isSingleIdentParamSlot(key) && strings.ContainsAny(val, " \t\r\n") {
		pass.ReportRangef(valArg, "i18nguard: 禁止向 %s(%q, ...) 传入含空白字符的散文常量 %q，请改用单标识符、Msg(...) 或专用 MessageID", fnName, key, val)
	}
}

// isForbiddenConstValueSlot 返回禁止传入非空编译期字符串常量的高语义参数槽位集合（规则 5A）。
func isForbiddenConstValueSlot(key string) bool {
	switch key {
	case "reason", "detail", "op":
		return true
	default:
		return false
	}
}

// isSingleIdentParamSlot 返回仅允许单标识符、禁止含 ASCII 空白字符散文的参数槽位集合（规则 5B）。
func isSingleIdentParamSlot(key string) bool {
	switch key {
	case "field", "kind", "component", "feature", "expected", "action":
		return true
	default:
		return false
	}
}
