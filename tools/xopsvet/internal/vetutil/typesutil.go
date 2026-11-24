package vetutil

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// InspectorOf 优先复用 passes/inspect 的缓存 AST 索引器，避免每包重复建树。
func InspectorOf(pass *analysis.Pass) *inspector.Inspector {
	if pass == nil {
		return nil
	}
	if ins, ok := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector); ok && ins != nil {
		return ins
	}
	return inspector.New(pass.Files)
}

// IsTestFile 判断 AST 文件是否为 *_test.go（优先使用 token.File.Name()，防止 //line 干扰）。
func IsTestFile(pass *analysis.Pass, f *ast.File) bool {
	return f != nil && IsPosInTestFile(pass, f.Package)
}

// IsPosInTestFile 判断给定源码位置 pos 是否位于 *_test.go 测试文件中。
func IsPosInTestFile(pass *analysis.Pass, pos token.Pos) bool {
	if pass == nil || pass.Fset == nil || !pos.IsValid() {
		return false
	}
	tf := pass.Fset.File(pos)
	return tf != nil && strings.HasSuffix(tf.Name(), "_test.go")
}

// AllowNolintInFile 按单个源码文件判定是否允许 //nolint：仅限 8 个特权包的生产源码文件（白盒/外置测试 0 例外）。
func AllowNolintInFile(pass *analysis.Pass, file *ast.File, info PkgInfo) bool {
	return AllowNolint(info) && !IsTestFile(pass, file)
}

// IsErrorInterfaceType 判断类型 t（解别名后）是否为 Go 内置 error 接口类型。
func IsErrorInterfaceType(t types.Type) bool {
	errObj := types.Universe.Lookup("error")
	return t != nil && errObj != nil && types.Identical(types.Unalias(t), errObj.Type())
}

// ImplementsError 判断类型 t 或其指针 *t 是否实现内置 error 接口。
func ImplementsError(t types.Type) bool {
	errObj := types.Universe.Lookup("error")
	if t == nil || errObj == nil {
		return false
	}
	errIface, ok := errObj.Type().Underlying().(*types.Interface)
	if !ok {
		return false
	}
	u := types.Unalias(t)
	if types.Implements(u, errIface) {
		return true
	}
	_, isPtr := u.(*types.Pointer)
	_, isIface := u.(*types.Interface)
	return !isPtr && !isIface && types.Implements(types.NewPointer(u), errIface)
}

// UnwrapNamedType 解引用类型别名及单层指针，提取命名类型 *types.Named。
func UnwrapNamedType(t types.Type) (*types.Named, bool) {
	if t == nil {
		return nil, false
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	named, ok := t.(*types.Named)
	return named, ok && named != nil
}

// isNilObject 安全识别 nil 及携带 nil 具体指针的 typed-nil types.Object 接口值。
func isNilObject(obj types.Object) bool {
	if obj == nil {
		return true
	}
	rv := reflect.ValueOf(obj)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

// ObjectPkgPath 返回 types.Object 所属包的规范路径（已剥离 _test 后缀；内置/nil 返回空串）。
func ObjectPkgPath(obj types.Object) string {
	if isNilObject(obj) || obj.Pkg() == nil {
		return ""
	}
	base, _ := NormalizePkgPath(obj.Pkg().Path())
	return base
}

// IsPkgSymbol 判断 types.Object 是否为指定规范包路径下的目标符号之一。
func IsPkgSymbol(obj types.Object, pkgPath string, names ...string) bool {
	return !isNilObject(obj) && ObjectPkgPath(obj) == pkgPath && slices.Contains(names, obj.Name())
}

// ResolveCalledObject 解析调用表达式指向的被调 types.Object（自动剥离括号与泛型实参索引）。
func ResolveCalledObject(info *types.Info, call *ast.CallExpr) types.Object {
	if info == nil || call == nil {
		return nil
	}
	switch e := unwrapCallFun(call.Fun).(type) {
	case *ast.Ident:
		return info.Uses[e]
	case *ast.SelectorExpr:
		if sel := info.Selections[e]; sel != nil {
			return sel.Obj()
		}
		return info.Uses[e.Sel]
	default:
		return nil
	}
}

func unwrapCallFun(expr ast.Expr) ast.Expr {
	for {
		switch e := expr.(type) {
		case *ast.ParenExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.IndexListExpr:
			expr = e.X
		default:
			return expr
		}
	}
}

// IsFreshLocalSliceAlloc 判断 AST 调用表达式是否必为全新分配的局部切片。
func IsFreshLocalSliceAlloc(info *types.Info, call *ast.CallExpr) bool {
	if info == nil || call == nil {
		return false
	}
	fun := ast.Unparen(call.Fun)
	if id, ok := fun.(*ast.Ident); ok {
		if b, isB := info.Uses[id].(*types.Builtin); isB && b.Name() == "make" {
			return isSliceUnderlying(info.TypeOf(call))
		}
	}
	tv, ok := info.Types[fun]
	return ok && tv.IsType() && len(call.Args) == 1 && !call.Ellipsis.IsValid() &&
		isSliceUnderlying(tv.Type) && isFreshSliceConvArg(info, call.Args[0])
}

func isSliceUnderlying(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := types.Unalias(t).Underlying().(*types.Slice)
	return ok
}

func isFreshSliceConvArg(info *types.Info, arg ast.Expr) bool {
	if id, ok := ast.Unparen(arg).(*ast.Ident); ok {
		if _, isNil := info.Uses[id].(*types.Nil); isNil {
			return true
		}
	}
	if argType := info.TypeOf(arg); argType != nil {
		b, ok := types.Unalias(argType).Underlying().(*types.Basic)
		return ok && (b.Kind() == types.UntypedNil || b.Info()&types.IsString != 0)
	}
	return false
}

type elemType interface{ Elem() types.Type }

type typeWalkOpt struct {
	localPkg        *types.Package
	localOnly       bool
	valueLayoutOnly bool // true 时绝不进入 Interface.Methods 与 Signature（CRIT-3）
}

// ContainsValueType 递归检查类型 t 的「值持有布局」中是否包含满足 pred 的命名类型，
// 绝不穿透 *types.Interface.Methods 与 *types.Signature（避免误杀 ports.SecretVault 等接口）。
func ContainsValueType(t types.Type, pred func(*types.Named) bool) bool {
	return t != nil && pred != nil && walkType(t, typeWalkOpt{valueLayoutOnly: true}, pred, make(map[types.Type]bool))
}

// ContainsValueNamed 判断类型 t 的值持有布局中是否包含指定包路径与名称的命名类型。
func ContainsValueNamed(t types.Type, pkgPath, typeName string) bool {
	return ContainsValueType(t, func(n *types.Named) bool { return IsPkgSymbol(n.Obj(), pkgPath, typeName) })
}

// TypeContains 递归检查类型 t 的全部引用类型树（含签名、接口方法、泛型实参与 *types.Union）。
func TypeContains(t types.Type, pred func(*types.Named) bool) bool {
	return t != nil && pred != nil && walkType(t, typeWalkOpt{}, pred, make(map[types.Type]bool))
}

// TypeContainsNamed 判断类型 t 是否直接或间接引用指定包路径与名称的命名类型。
func TypeContainsNamed(t types.Type, pkgPath, typeName string) bool {
	return TypeContains(t, func(n *types.Named) bool { return IsPkgSymbol(n.Obj(), pkgPath, typeName) })
}

// TypeContainsLocalNamed 仅展开当前包 pkg 内定义的命名类型底层结构，不穿透外部包结构体字段。
func TypeContainsLocalNamed(t types.Type, pkg *types.Package, pkgPath, typeName string) bool {
	return TypeContainsLocalPred(t, pkg, func(n *types.Named) bool { return IsPkgSymbol(n.Obj(), pkgPath, typeName) })
}

// TypeContainsLocalPred 对本地定义类型展开执行谓词检查，覆盖全引用类型树含 Union。
func TypeContainsLocalPred(t types.Type, pkg *types.Package, pred func(*types.Named) bool) bool {
	return t != nil && pred != nil && walkType(t, typeWalkOpt{localPkg: pkg, localOnly: true}, pred, make(map[types.Type]bool))
}

func walkType(t types.Type, opt typeWalkOpt, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok {
		return walkNamedType(named, opt, pred, seen)
	}
	return walkCompositeType(t, opt, pred, seen)
}

func walkNamedType(named *types.Named, opt typeWalkOpt, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	if pred(named) {
		return true
	}
	if seen[named] {
		return false
	}
	seen[named] = true
	if ta := named.TypeArgs(); ta != nil && walkIndexedTypes(ta.Len(), ta.At, opt, pred, seen) {
		return true
	}
	if opt.localOnly && named.Obj() != nil && named.Obj().Pkg() != opt.localPkg {
		return false
	}
	u := types.Unalias(named.Underlying())
	_, isI := u.(*types.Interface)
	_, isS := u.(*types.Signature)
	return (!opt.valueLayoutOnly || (!isI && !isS)) && walkType(u, opt, pred, seen)
}

func walkIndexedTypes(n int, at func(int) types.Type, opt typeWalkOpt, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	for i := range n {
		if walkType(at(i), opt, pred, seen) {
			return true
		}
	}
	return false
}

func walkCompositeType(t types.Type, opt typeWalkOpt, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	switch v := t.(type) {
	case *types.Map:
		return walkType(v.Key(), opt, pred, seen) || walkType(v.Elem(), opt, pred, seen)
	case elemType:
		return walkType(v.Elem(), opt, pred, seen)
	case *types.Struct:
		return markFirstSeen(seen, v) && walkIndexedTypes(v.NumFields(), func(i int) types.Type { return v.Field(i).Type() }, opt, pred, seen)
	case *types.Tuple:
		return v != nil && walkIndexedTypes(v.Len(), func(i int) types.Type { return v.At(i).Type() }, opt, pred, seen)
	case *types.Union:
		return markFirstSeen(seen, v) && walkIndexedTypes(v.Len(), func(i int) types.Type { return v.Term(i).Type() }, opt, pred, seen)
	case *types.TypeParam:
		return walkTypeParam(v, opt, pred, seen)
	case *types.Signature:
		return !opt.valueLayoutOnly && (walkCompositeType(v.Params(), opt, pred, seen) || walkCompositeType(v.Results(), opt, pred, seen))
	case *types.Interface:
		return !opt.valueLayoutOnly && markFirstSeen(seen, v) &&
			(walkIndexedTypes(v.NumEmbeddeds(), v.EmbeddedType, opt, pred, seen) ||
				walkIndexedTypes(v.NumMethods(), func(i int) types.Type { return v.Method(i).Type() }, opt, pred, seen))
	default:
		return false
	}
}

func markFirstSeen(seen map[types.Type]bool, t types.Type) bool {
	if seen[t] {
		return false
	}
	seen[t] = true
	return true
}

func walkTypeParam(tp *types.TypeParam, opt typeWalkOpt, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	if !markFirstSeen(seen, tp) {
		return false
	}
	if !opt.valueLayoutOnly {
		return walkType(tp.Constraint(), opt, pred, seen)
	}
	iface, ok := types.Unalias(tp.Constraint()).Underlying().(*types.Interface)
	return ok && walkValueIfaceTerms(iface, opt, pred, seen)
}

func walkValueIfaceTerms(iface *types.Interface, opt typeWalkOpt, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	if !markFirstSeen(seen, iface) {
		return false
	}
	for i := range iface.NumEmbeddeds() {
		emb := types.Unalias(iface.EmbeddedType(i))
		if sub, ok := emb.Underlying().(*types.Interface); ok {
			if walkValueIfaceTerms(sub, opt, pred, seen) {
				return true
			}
		} else if walkType(emb, opt, pred, seen) {
			return true
		}
	}
	return false
}
