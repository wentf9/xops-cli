package i18nguard

import (
	"go/ast"
	"go/constant"
	"go/types"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// checkSentinelAndDetailGuards 执行规则 4：
//   - 规则 4A：拦截对 WrapSentinelDetail（arg2）与 DynamicDetailError（arg0）传入非空编译期字符串常量；
//   - 规则 4B：拦截对 {core/domain/i18n, internal/i18n}.{EF, WrapS} 传入 common.detail、对安全/不可逆
//     红线哨兵使用 "common.*" 弱模板，以及对非通用输入/格式具名包级哨兵使用泛化空壳骨架键。
func checkSentinelAndDetailGuards(pass *analysis.Pass) {
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok || vetutil.IsPosInTestFile(pass, call.Pos()) {
			return
		}
		callee := vetutil.ResolveCalledObject(pass.TypesInfo, call)
		if callee == nil {
			return
		}
		checkDynamicDetailCall(pass, call, callee)
		checkSentinelWrapCall(pass, call, callee)
	})
}

func checkDynamicDetailCall(pass *analysis.Pass, call *ast.CallExpr, callee types.Object) {
	var detailArg ast.Expr
	switch {
	case vetutil.IsPkgSymbol(callee, coreDomainI18nPkgPath, "WrapSentinelDetail"):
		if len(call.Args) < 3 {
			return
		}
		detailArg = call.Args[2]
	case vetutil.IsPkgSymbol(callee, coreDomainI18nPkgPath, "DynamicDetailError"):
		if len(call.Args) < 1 {
			return
		}
		detailArg = call.Args[0]
	default:
		return
	}
	if val, ok := evalConstString(pass.TypesInfo, detailArg); ok && val != "" {
		pass.ReportRangef(detailArg, "i18nguard: 禁止向 %s 传入非空编译期字符串常量 %q，请改用结构化 MessageID 或运行期动态明细", callee.Name(), val)
	}
}

func checkSentinelWrapCall(pass *analysis.Pass, call *ast.CallExpr, callee types.Object) {
	sentinelArg, idArg, ok := extractSentinelWrapArgs(call, callee)
	if !ok {
		return
	}
	idVal, ok := evalConstString(pass.TypesInfo, idArg)
	if !ok {
		return
	}
	if idVal == "common.detail" {
		pass.ReportRangef(idArg, "i18nguard: 禁止向 %s 传入 common.detail（会吞噬哨兵语义），请改用 WrapSentinelDetail 或专用自包含 MessageID", callee.Name())
		return
	}
	sentinelVar := resolvePkgLevelVar(pass.TypesInfo, sentinelArg)
	if sentinelVar == nil {
		return
	}
	if isSafetyRedlineSentinel(sentinelVar.Name()) && strings.HasPrefix(idVal, "common.") {
		pass.ReportRangef(idArg, "i18nguard: 禁止对安全红线哨兵 %s 在 %s 中使用泛化弱模板 %q，请改用 WrapSentinel 或自包含专用 MessageID", sentinelVar.Name(), callee.Name(), idVal)
		return
	}
	if !isGenericInputSentinel(sentinelVar.Name()) && isGenericSkeletonKey(idVal) {
		pass.ReportRangef(idArg, "i18nguard: 禁止对具名业务哨兵 %s 在 %s 中使用泛化骨架键 %q（会吞噬哨兵语义），请改用 WrapSentinel 或自包含专用 MessageID", sentinelVar.Name(), callee.Name(), idVal)
	}
}

func extractSentinelWrapArgs(call *ast.CallExpr, callee types.Object) (ast.Expr, ast.Expr, bool) {
	pkg := vetutil.ObjectPkgPath(callee)
	if pkg != coreDomainI18nPkgPath && pkg != internalI18nPkgPath {
		return nil, nil, false
	}
	switch callee.Name() {
	case "EF":
		if len(call.Args) >= 2 {
			return call.Args[0], call.Args[1], true
		}
	case "WrapS":
		if len(call.Args) >= 3 {
			return call.Args[0], call.Args[2], true
		}
	}
	return nil, nil, false
}

// evalConstString 解析编译期字符串常量表达式（兼容具名 string 类型如 MessageID 与括号包裹）。
func evalConstString(info *types.Info, expr ast.Expr) (string, bool) {
	if info == nil || expr == nil {
		return "", false
	}
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}

// resolvePkgLevelVar 解析指向包级变量声明的标识符或限定选择器（排除局部变量、形参与结构体字段）。
func resolvePkgLevelVar(info *types.Info, expr ast.Expr) *types.Var {
	if info == nil || expr == nil {
		return nil
	}
	var obj types.Object
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		obj = info.Uses[e]
	case *ast.SelectorExpr:
		if info.Selections[e] != nil {
			return nil
		}
		obj = info.Uses[e.Sel]
	default:
		return nil
	}
	v, ok := obj.(*types.Var)
	if !ok || v == nil || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
		return nil
	}
	return v
}

// isSafetyRedlineSentinel 判断包级哨兵名是否属于安全或不可逆终态红线哨兵（禁止搭配任何 "common.*" 弱模板）。
func isSafetyRedlineSentinel(name string) bool {
	switch name {
	case "ErrOutcomeUnknown",
		"ErrAuditHalted",
		"ErrGateHalted",
		"ErrUncertainDurability",
		"ErrUncertainCommit",
		"ErrUncertainOutcome",
		"ErrSagaUncertain",
		"ErrEnrollmentUncertain",
		"ErrCommitOutcomeUnknown",
		"ErrNonLoopbackAddress",
		"ErrOrphanedProcessGroup",
		"ErrIncludeDepthExceeded",
		"ErrIncludeCycle":
		return true
	default:
		return false
	}
}

// isGenericInputSentinel 判断包级哨兵名是否属于通用输入/格式/损坏哨兵，允许搭配泛化字段校验骨架键。
func isGenericInputSentinel(name string) bool {
	return strings.HasPrefix(name, "ErrInvalid") ||
		name == "ErrUsage" ||
		strings.HasPrefix(name, "ErrCorrupt") ||
		name == "ErrCatalogCorrupt"
}

// isGenericSkeletonKey 判断 MessageID 是否为不含独立业务语义的泛化空壳骨架键。
func isGenericSkeletonKey(id string) bool {
	switch id {
	case "common.field_invalid",
		"common.field_value_invalid",
		"common.value_invalid",
		"common.op_failed",
		"common.op_target_failed",
		"host.sys.syscall_failed":
		return true
	default:
		return false
	}
}
