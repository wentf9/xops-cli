package noimplicit

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

const cmdXopsPkgPath = vetutil.ModulePrefix + "/cmd/xops"

// collectSentinelVars 预收集本包中所有具备哨兵错误签名（Err*/err* 且类型为内置 error）的包级变量，
// 供后续判断 fmt.Errorf("%w", ...) 包装合法性与运行期不可变性检查。
func collectSentinelVars(pass *analysis.Pass) map[*types.Var]bool {
	sentinels := make(map[*types.Var]bool)
	if pass.TypesInfo == nil {
		return sentinels
	}
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			collectDeclSentinels(pass.TypesInfo, gen, sentinels)
		}
	}
	return sentinels
}

func collectDeclSentinels(info *types.Info, gen *ast.GenDecl, sentinels map[*types.Var]bool) {
	for _, spec := range gen.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
			continue
		}
		id := vs.Names[0]
		if !isSentinelName(id.Name) {
			continue
		}
		if vs.Type != nil && !vetutil.IsErrorInterfaceType(info.TypeOf(vs.Type)) {
			continue
		}
		if v, ok := info.Defs[id].(*types.Var); ok && v != nil && vetutil.IsErrorInterfaceType(v.Type()) {
			sentinels[v] = true
		}
	}
}

// collectBuildVars 独立收集 cmd/xops package main 非测试文件中满足 6 重硬约束的 //xops:buildvar 变量。
// 该集合与 sentinels 严格隔离（绝不混入 isPureErrorfCall），但在运行期不可变性检查中与 sentinels 取并集，
// 覆盖同包生产代码与 cmd/xops/*_test.go 全包禁止赋值、range 覆盖与取地址。
func collectBuildVars(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) map[*types.Var]bool {
	buildVars := make(map[*types.Var]bool)
	if !isBuildVarEligiblePkg(pass, pkgInfo) {
		return buildVars
	}
	for _, file := range pass.Files {
		if vetutil.IsTestFile(pass, file) {
			continue
		}
		collectFileBuildVars(pass.TypesInfo, file, buildVars)
	}
	return buildVars
}

func isBuildVarEligiblePkg(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) bool {
	return pass != nil &&
		pass.TypesInfo != nil &&
		pass.Pkg != nil &&
		!pkgInfo.IsExternalTest &&
		pkgInfo.BasePath == cmdXopsPkgPath &&
		pass.Pkg.Name() == "main"
}

func collectFileBuildVars(info *types.Info, file *ast.File, buildVars map[*types.Var]bool) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if v := validBuildVar(info, gen, vs); v != nil {
				buildVars[v] = true
			}
		}
	}
}

// validBuildVar 强制校验 //xops:buildvar 的声明级约束：
// 单 spec 才继承 gen.Doc（防 var (...) 块注释串扰）、未导出单变量、精确内置 string 类型、
// 无初值或编译期字符串常量初值。
func validBuildVar(info *types.Info, gen *ast.GenDecl, vs *ast.ValueSpec) *types.Var {
	if !valueSpecHasDirective(gen, vs, vetutil.DirectiveBuildVar) || len(vs.Names) != 1 {
		return nil
	}
	id := vs.Names[0]
	if id.Name == "_" || id.IsExported() {
		return nil
	}
	v, ok := info.Defs[id].(*types.Var)
	if !ok || v == nil || !isBuiltinStringType(v.Type()) {
		return nil
	}
	if !isValidBuildVarInit(info, vs.Values) {
		return nil
	}
	return v
}

func valueSpecHasDirective(gen *ast.GenDecl, vs *ast.ValueSpec, kind vetutil.DirectiveKind) bool {
	if vs == nil {
		return false
	}
	if vetutil.HasDirective(vs.Doc, kind) || vetutil.HasDirective(vs.Comment, kind) {
		return true
	}
	return gen != nil && len(gen.Specs) == 1 && vetutil.HasDirective(gen.Doc, kind)
}

func isBuiltinStringType(t types.Type) bool {
	basic, ok := t.(*types.Basic)
	return ok && basic.Kind() == types.String
}

func isValidBuildVarInit(info *types.Info, values []ast.Expr) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	tv, ok := info.Types[values[0]]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.String
}

func checkPkgVarDecl(pass *analysis.Pass, gen *ast.GenDecl, sentinels, buildVars map[*types.Var]bool) {
	for _, spec := range gen.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		if isInterfaceAssertionSpec(pass.TypesInfo, vs) ||
			isImmutableSentinelSpec(pass.TypesInfo, vs, sentinels) ||
			isRecordedBuildVarSpec(pass.TypesInfo, vs, buildVars) {
			continue
		}
		pass.ReportRangef(vs, "noimplicit: 禁止声明可变包级 var（仅允许编译期接口断言 var _ I = (*T)(nil)、不可变哨兵错误及 cmd/xops 只读 //xops:buildvar）")
	}
}

func isRecordedBuildVarSpec(info *types.Info, vs *ast.ValueSpec, buildVars map[*types.Var]bool) bool {
	if info == nil || len(vs.Names) != 1 {
		return false
	}
	v, ok := info.Defs[vs.Names[0]].(*types.Var)
	return ok && buildVars[v]
}

// isInterfaceAssertionSpec 仅豁免形如 `var _ I = (*T)(nil)` 的编译期零副作用接口断言，
// 右值必须为纯常量、字面量零值或无副作用类型转换/new(T)。
func isInterfaceAssertionSpec(info *types.Info, vs *ast.ValueSpec) bool {
	if info == nil || vs.Type == nil || len(vs.Names) == 0 || len(vs.Names) != len(vs.Values) {
		return false
	}
	for _, name := range vs.Names {
		if name.Name != "_" {
			return false
		}
	}
	for _, val := range vs.Values {
		if !isPureZeroOrTypeConvExpr(info, val) {
			return false
		}
	}
	return true
}

func isPureZeroOrTypeConvExpr(info *types.Info, expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return isConstOrNilIdent(info, e)
	case *ast.CompositeLit:
		return isPureCompositeLit(info, e)
	case *ast.UnaryExpr:
		return isPureUnaryExpr(info, e)
	case *ast.CallExpr:
		return isPureTypeConvOrNew(info, e)
	default:
		return false
	}
}

func isConstOrNilIdent(info *types.Info, id *ast.Ident) bool {
	if id.Name == "nil" {
		return true
	}
	if tv, ok := info.Types[id]; ok && tv.Value != nil {
		return true
	}
	obj := info.Uses[id]
	_, isConst := obj.(*types.Const)
	_, isNil := obj.(*types.Nil)
	return isConst || isNil
}

func isPureCompositeLit(info *types.Info, lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if !isPureZeroOrTypeConvExpr(info, kv.Value) {
				return false
			}
			continue
		}
		if !isPureZeroOrTypeConvExpr(info, elt) {
			return false
		}
	}
	return true
}

func isPureUnaryExpr(info *types.Info, un *ast.UnaryExpr) bool {
	if un.Op == token.AND {
		lit, ok := ast.Unparen(un.X).(*ast.CompositeLit)
		return ok && isPureCompositeLit(info, lit)
	}
	if un.Op == token.ADD || un.Op == token.SUB || un.Op == token.NOT || un.Op == token.XOR {
		return isPureZeroOrTypeConvExpr(info, un.X)
	}
	return false
}

func isPureTypeConvOrNew(info *types.Info, call *ast.CallExpr) bool {
	if len(call.Args) != 1 {
		return false
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok && id.Name == "new" {
		if b, isBuiltin := info.Uses[id].(*types.Builtin); isBuiltin && b.Name() == "new" {
			return true
		}
	}
	if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
		return isPureZeroOrTypeConvExpr(info, call.Args[0])
	}
	return false
}

// isImmutableSentinelSpec 仅豁免单变量不可变哨兵错误声明，
// 要求右值为常量参数 errors.New(...) 或仅引用常量与已知哨兵的 fmt.Errorf(...)。
func isImmutableSentinelSpec(info *types.Info, vs *ast.ValueSpec, sentinels map[*types.Var]bool) bool {
	if info == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
		return false
	}
	id := vs.Names[0]
	if !isSentinelName(id.Name) {
		return false
	}
	if vs.Type != nil && !vetutil.IsErrorInterfaceType(info.TypeOf(vs.Type)) {
		return false
	}
	call, ok := ast.Unparen(vs.Values[0]).(*ast.CallExpr)
	if !ok {
		return false
	}
	callee := vetutil.ResolveCalledObject(info, call)
	if vetutil.IsPkgSymbol(callee, "errors", "New") {
		return len(call.Args) == 1 && isConstExpr(info, call.Args[0])
	}
	if vetutil.IsPkgSymbol(callee, "fmt", "Errorf") {
		return isPureErrorfCall(info, call, sentinels)
	}
	return false
}

func isPureErrorfCall(info *types.Info, call *ast.CallExpr, sentinels map[*types.Var]bool) bool {
	if len(call.Args) == 0 || !isConstExpr(info, call.Args[0]) {
		return false
	}
	for _, arg := range call.Args[1:] {
		if !isPureErrorArg(info, arg, sentinels) {
			return false
		}
	}
	return true
}

func isPureErrorArg(info *types.Info, expr ast.Expr, sentinels map[*types.Var]bool) bool {
	if isConstExpr(info, expr) {
		return true
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return isAllowedSentinelObj(info.Uses[e], sentinels)
	case *ast.SelectorExpr:
		return isAllowedSentinelObj(info.Uses[e.Sel], sentinels)
	default:
		return false
	}
}

func isAllowedSentinelObj(obj types.Object, sentinels map[*types.Var]bool) bool {
	v, ok := obj.(*types.Var)
	if !ok || v == nil {
		return false
	}
	if sentinels[v] {
		return true
	}
	// 允许包装外部包的导出哨兵错误（如 io.EOF、os.ErrNotExist）。
	if v.Pkg() == nil || !vetutil.IsErrorInterfaceType(v.Type()) {
		return false
	}
	return strings.HasPrefix(v.Name(), "Err") || (v.Pkg().Path() == "io" && v.Name() == "EOF")
}

func isConstExpr(info *types.Info, expr ast.Expr) bool {
	tv, ok := info.Types[expr]
	return ok && tv.Value != nil
}

func isSentinelName(name string) bool {
	return name != "_" && (strings.HasPrefix(name, "Err") || strings.HasPrefix(name, "err"))
}

// checkImmutableVarMutations 扫描全包（含同包 *_test.go）所有赋值、for-range 赋值、自增减与取地址表达式，
// 防止在运行期篡改包级哨兵错误或 cmd/xops 只读 //xops:buildvar 构建变量。
func checkImmutableVarMutations(pass *analysis.Pass, sentinels, buildVars map[*types.Var]bool) {
	if pass.TypesInfo == nil {
		return
	}
	ins := vetutil.InspectorOf(pass)
	nodeFilter := []ast.Node{
		(*ast.AssignStmt)(nil),
		(*ast.RangeStmt)(nil),
		(*ast.IncDecStmt)(nil),
		(*ast.UnaryExpr)(nil),
	}
	ins.Preorder(nodeFilter, func(n ast.Node) {
		checkImmutableVarMutationNode(pass, n, sentinels, buildVars)
	})
}

func checkImmutableVarMutationNode(pass *analysis.Pass, n ast.Node, sentinels, buildVars map[*types.Var]bool) {
	switch node := n.(type) {
	case *ast.AssignStmt:
		for _, lhs := range node.Lhs {
			reportIfImmutableVarExpr(pass, lhs, sentinels, buildVars, false)
		}
	case *ast.RangeStmt:
		// 仅拦截使用 "=" 覆盖已有只读变量的 range 赋值；":=" 为循环块内新局部变量遮蔽。
		if node.Tok == token.ASSIGN {
			reportIfImmutableVarExpr(pass, node.Key, sentinels, buildVars, false)
			reportIfImmutableVarExpr(pass, node.Value, sentinels, buildVars, false)
		}
	case *ast.IncDecStmt:
		reportIfImmutableVarExpr(pass, node.X, sentinels, buildVars, false)
	case *ast.UnaryExpr:
		if node.Op == token.AND {
			reportIfImmutableVarExpr(pass, node.X, sentinels, buildVars, true)
		}
	}
}

// reportIfImmutableVarExpr 同时识别同包标识符（ErrFoo/buildVersion）与跨包选择器（otherpkg.ErrShared），
// 并排除结构体字段选择器（Selection != nil），确保不误报 obj.ErrField 赋值。
func reportIfImmutableVarExpr(
	pass *analysis.Pass,
	expr ast.Expr,
	sentinels, buildVars map[*types.Var]bool,
	isAddr bool,
) {
	target, v, name := resolvePkgVarExpr(pass.TypesInfo, expr)
	if v == nil {
		return
	}
	if buildVars[v] {
		if isAddr {
			pass.ReportRangef(target, "noimplicit: 禁止对只读构建变量 %s 取地址", name)
			return
		}
		pass.ReportRangef(target, "noimplicit: 禁止在运行期修改只读构建变量 %s", name)
		return
	}
	if isTrackedSentinelVar(v, sentinels) {
		if isAddr {
			pass.ReportRangef(target, "noimplicit: 禁止对哨兵错误 %s 取地址", name)
			return
		}
		pass.ReportRangef(target, "noimplicit: 禁止在运行期修改哨兵错误 %s", name)
	}
}

func resolvePkgVarExpr(info *types.Info, expr ast.Expr) (ast.Expr, *types.Var, string) {
	if expr == nil {
		return nil, nil, ""
	}
	switch target := ast.Unparen(expr).(type) {
	case *ast.Ident:
		v, _ := info.Uses[target].(*types.Var)
		return target, v, target.Name
	case *ast.SelectorExpr:
		if info.Selections[target] != nil {
			return nil, nil, ""
		}
		v, _ := info.Uses[target.Sel].(*types.Var)
		return target, v, target.Sel.Name
	default:
		return nil, nil, ""
	}
}

func isTrackedSentinelVar(v *types.Var, sentinels map[*types.Var]bool) bool {
	if v == nil {
		return false
	}
	if sentinels[v] {
		return true
	}
	// 跨包（或点导入）的包级 error 哨兵变量同样受不可变约束保护。
	return v.Pkg() != nil &&
		!v.IsField() &&
		v.Parent() == v.Pkg().Scope() &&
		isSentinelName(v.Name()) &&
		vetutil.IsErrorInterfaceType(v.Type())
}
