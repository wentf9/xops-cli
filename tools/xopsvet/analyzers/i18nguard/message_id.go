package i18nguard

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

const (
	msgIDValueErr      = "i18nguard: i18n.MessageID 必须源自 core/domain/i18n 或 internal/i18n 声明的常量，禁止使用字面量、非常量转换或拼接值"
	msgIDConvErr       = "i18nguard: 禁止在属主包外通过类型转换构造 i18n.MessageID，请直接使用 core/domain/i18n 或 internal/i18n 导出的 MessageID 常量"
	msgIDConcat        = "i18nguard: 禁止通过拼接构造或修改 i18n.MessageID，请直接使用导出的 MessageID 常量"
	msgIDGenericErr    = "i18nguard: 禁止在属主包外将 i18n.MessageID 实例化至含 string 底层约束的非标准库泛型声明"
	msgIDInvalidArgErr = "i18nguard: 禁止向 i18n 构造或渲染函数传入无效标识 MessageIDInvalid"
	msgIDCrossDomain   = "i18nguard: 禁止将 internal/i18n 声明的 MessageID 常量传入 core/domain/i18n 构造器，请改用 internal/i18n 对应构造器"
)

// checkMessageIDIntegrity 执行规则 1：保护 core/domain/i18n.MessageID 强类型完整性、
// 封锁包外 *WithFallback 桥接符号与 ~string 泛型伪造，并拦截 MessageIDInvalid 实参与跨域键错配。
func checkMessageIDIntegrity(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	isOwner := !pkgInfo.IsExternalTest && isMessageIDOwnerPkg(pkgInfo.BasePath)
	constSpecs, constAddExprs := inspectConstAndTypeDecls(pass, isOwner)
	if !isOwner {
		checkForbiddenWithFallbackUses(pass)
		checkMessageIDGenericInstances(pass)
	}
	reported := make(map[token.Pos]bool)
	vetutil.InspectorOf(pass).Preorder([]ast.Node{
		(*ast.CallExpr)(nil),
		(*ast.ValueSpec)(nil),
		(*ast.AssignStmt)(nil),
		(*ast.CompositeLit)(nil),
		(*ast.ReturnStmt)(nil),
		(*ast.IndexExpr)(nil),
		(*ast.SendStmt)(nil),
		(*ast.CaseClause)(nil),
		(*ast.BinaryExpr)(nil),
	}, func(n ast.Node) {
		if !vetutil.IsPosInTestFile(pass, n.Pos()) {
			checkMessageIDNode(pass, n, isOwner, constSpecs, constAddExprs, reported)
		}
	})
}

// inspectConstAndTypeDecls 扫描全部 const 与 type 声明：包外禁止声明 MessageID 常量或类型别名，
// 同时记录所有 const ValueSpec 及其内部常量拼接表达式，避免包内合法 const 声明误报或包外重复报错。
func inspectConstAndTypeDecls(pass *analysis.Pass, isOwner bool) (map[*ast.ValueSpec]bool, map[*ast.BinaryExpr]bool) {
	constSpecs := make(map[*ast.ValueSpec]bool)
	constAddExprs := make(map[*ast.BinaryExpr]bool)
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.GenDecl)(nil)}, func(n ast.Node) {
		gen, ok := n.(*ast.GenDecl)
		if !ok || vetutil.IsPosInTestFile(pass, gen.Pos()) {
			return
		}
		switch gen.Tok {
		case token.TYPE:
			if !isOwner {
				checkForbiddenMessageIDAliases(pass, gen)
			}
		case token.CONST:
			collectConstSpecs(pass, gen, isOwner, constSpecs, constAddExprs)
		}
	})
	return constSpecs, constAddExprs
}

func checkForbiddenMessageIDAliases(pass *analysis.Pass, gen *ast.GenDecl) {
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok || !ts.Assign.IsValid() {
			continue
		}
		if obj := pass.TypesInfo.Defs[ts.Name]; obj != nil && isMessageIDType(obj.Type()) {
			pass.ReportRangef(ts.Name, "i18nguard: 禁止在 core/domain/i18n 与 internal/i18n 之外声明 i18n.MessageID 类型别名")
		}
	}
}

func collectConstSpecs(pass *analysis.Pass, gen *ast.GenDecl, isOwner bool, constSpecs map[*ast.ValueSpec]bool, constAddExprs map[*ast.BinaryExpr]bool) {
	for _, spec := range gen.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		constSpecs[vs] = true
		if isOwner {
			markConstBinaryExprs(vs.Values, constAddExprs)
			continue
		}
		for _, name := range vs.Names {
			if c, ok := pass.TypesInfo.Defs[name].(*types.Const); ok && c != nil && isMessageIDType(c.Type()) {
				pass.ReportRangef(name, "i18nguard: 禁止在 core/domain/i18n 与 internal/i18n 之外声明 i18n.MessageID 常量")
			}
		}
	}
}

func markConstBinaryExprs(exprs []ast.Expr, dst map[*ast.BinaryExpr]bool) {
	for _, expr := range exprs {
		ast.Inspect(expr, func(n ast.Node) bool {
			if bin, ok := n.(*ast.BinaryExpr); ok {
				dst[bin] = true
			}
			return true
		})
	}
}

func checkMessageIDNode(
	pass *analysis.Pass,
	n ast.Node,
	isOwner bool,
	constSpecs map[*ast.ValueSpec]bool,
	constAddExprs map[*ast.BinaryExpr]bool,
	reported map[token.Pos]bool,
) {
	switch node := n.(type) {
	case *ast.CallExpr:
		checkMessageIDCall(pass, node, isOwner, reported)
	case *ast.ValueSpec:
		if !constSpecs[node] {
			checkMessageIDExprs(pass, node.Values, isOwner, reported)
		}
	case *ast.AssignStmt:
		checkMessageIDAssign(pass, node, isOwner, reported)
	case *ast.CompositeLit:
		checkMessageIDCompositeLit(pass, node, isOwner, reported)
	case *ast.ReturnStmt:
		checkMessageIDExprs(pass, node.Results, isOwner, reported)
	case *ast.IndexExpr:
		checkMessageIDValueExpr(pass, node.Index, isOwner, reported)
	case *ast.SendStmt:
		checkMessageIDValueExpr(pass, node.Value, isOwner, reported)
	case *ast.CaseClause:
		checkMessageIDExprs(pass, node.List, isOwner, reported)
	case *ast.BinaryExpr:
		checkMessageIDBinary(pass, node, isOwner, constAddExprs, reported)
	}
}

func checkMessageIDCall(pass *analysis.Pass, call *ast.CallExpr, isOwner bool, reported map[token.Pos]bool) {
	if tv, ok := pass.TypesInfo.Types[call.Fun]; ok && tv.IsType() {
		checkMessageIDTypeConversion(pass, call, tv.Type, isOwner, reported)
		return
	}
	checkMessageIDExprs(pass, call.Args, isOwner, reported)
	checkI18nConstructorCall(pass, call, reported)
}

func checkMessageIDAssign(pass *analysis.Pass, stmt *ast.AssignStmt, isOwner bool, reported map[token.Pos]bool) {
	if stmt.Tok == token.ADD_ASSIGN && len(stmt.Lhs) == 1 && isMessageIDType(pass.TypesInfo.TypeOf(stmt.Lhs[0])) {
		reportOnce(pass, stmt, reported, msgIDConcat)
		return
	}
	checkMessageIDExprs(pass, stmt.Rhs, isOwner, reported)
}

func checkMessageIDCompositeLit(pass *analysis.Pass, lit *ast.CompositeLit, isOwner bool, reported map[token.Pos]bool) {
	isStruct := isStructCompositeLit(pass.TypesInfo, lit)
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if !isStruct {
				checkMessageIDValueExpr(pass, kv.Key, isOwner, reported)
			}
			checkMessageIDValueExpr(pass, kv.Value, isOwner, reported)
			continue
		}
		checkMessageIDValueExpr(pass, elt, isOwner, reported)
	}
}

func checkMessageIDBinary(pass *analysis.Pass, bin *ast.BinaryExpr, isOwner bool, constAddExprs map[*ast.BinaryExpr]bool, reported map[token.Pos]bool) {
	if bin.Op == token.ADD && !constAddExprs[bin] && isMessageIDType(pass.TypesInfo.TypeOf(bin)) {
		reportOnce(pass, bin, reported, msgIDConcat)
		return
	}
	if isComparisonOp(bin.Op) {
		checkMessageIDValueExpr(pass, bin.X, isOwner, reported)
		checkMessageIDValueExpr(pass, bin.Y, isOwner, reported)
	}
}

func checkMessageIDExprs(pass *analysis.Pass, exprs []ast.Expr, isOwner bool, reported map[token.Pos]bool) {
	for _, expr := range exprs {
		checkMessageIDValueExpr(pass, expr, isOwner, reported)
	}
}

func checkMessageIDValueExpr(pass *analysis.Pass, expr ast.Expr, isOwner bool, reported map[token.Pos]bool) {
	if expr == nil {
		return
	}
	tv, ok := pass.TypesInfo.Types[expr]
	if !ok || !tv.IsValue() || !isMessageIDType(tv.Type) {
		return
	}
	if !isAllowedMessageIDExpr(pass.TypesInfo, expr, isOwner) {
		reportOnce(pass, expr, reported, msgIDValueErr)
	}
}

func isAllowedMessageIDExpr(info *types.Info, expr ast.Expr, isOwner bool) bool {
	e := ast.Unparen(expr)
	switch node := e.(type) {
	case *ast.BasicLit:
		// 仅属主包内允许零值空串 ""（等价于 MessageIDInvalid）；包外一律禁止任何字面量。
		return isOwner && node.Kind == token.STRING && isEmptyStringLit(node.Value)
	case *ast.BinaryExpr:
		return false
	case *ast.Ident:
		return isAllowedMessageIDObj(info.Uses[node])
	case *ast.SelectorExpr:
		if sel := info.Selections[node]; sel != nil {
			return isMessageIDType(sel.Type())
		}
		return isAllowedMessageIDObj(info.Uses[node.Sel])
	case *ast.CallExpr:
		// 仅放行目标类型为 MessageID 的显式类型转换（由 checkMessageIDCall 独立检查，避免同行重复报错）；
		// 严格拦截 string(...) / []byte(...) / localStr(...) 等非 MessageID 转换包装绕过。
		if tv, ok := info.Types[node.Fun]; ok && tv.IsType() {
			return isMessageIDType(tv.Type)
		}
		tv, ok := info.Types[node]
		return ok && tv.Value == nil && isMessageIDType(tv.Type)
	default:
		tv, ok := info.Types[node]
		return ok && tv.Value == nil && isMessageIDType(tv.Type)
	}
}

func isAllowedMessageIDObj(obj types.Object) bool {
	if obj == nil {
		return false
	}
	if c, ok := obj.(*types.Const); ok {
		return isMessageIDType(c.Type()) && isMessageIDOwnerPkg(vetutil.ObjectPkgPath(c))
	}
	if v, ok := obj.(*types.Var); ok {
		return isMessageIDType(v.Type())
	}
	return false
}

func isMessageIDType(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named != nil && vetutil.IsPkgSymbol(named.Obj(), coreDomainI18nPkgPath, "MessageID")
}

func isStructCompositeLit(info *types.Info, lit *ast.CompositeLit) bool {
	t := info.TypeOf(lit)
	if t == nil {
		return false
	}
	_, isStruct := types.Unalias(t).Underlying().(*types.Struct)
	return isStruct
}

func isComparisonOp(op token.Token) bool {
	return op == token.EQL || op == token.NEQ || op == token.LSS || op == token.LEQ || op == token.GTR || op == token.GEQ
}

func isEmptyStringLit(raw string) bool {
	return raw == `""` || raw == "``"
}

func reportOnce(pass *analysis.Pass, node ast.Node, reported map[token.Pos]bool, msg string) {
	if pos := node.Pos(); pos.IsValid() && !reported[pos] {
		reported[pos] = true
		pass.ReportRangef(node, "%s", msg)
	}
}
