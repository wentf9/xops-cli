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

// AllowNolintInFile 按单个源码文件判定是否允许 //nolint：仅限 8 个特权包的生产源码文件（白盒/外置测试与非法参数均 fail-closed）。
func AllowNolintInFile(pass *analysis.Pass, file *ast.File, info PkgInfo) bool {
	if pass == nil || pass.Fset == nil || file == nil || !file.Package.IsValid() {
		return false
	}
	return AllowNolint(info) && !IsTestFile(pass, file)
}

// IsPlainSecretParamType 判断参数类型底层是否为明文机密常见载体（[]byte / []uint8 / string），
// 供 secretfact、vetssa、secrettaint 与 linearlease 共享单一事实源。
func IsPlainSecretParamType(t types.Type) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t).Underlying()
	if sl, ok := u.(*types.Slice); ok {
		b, ok := types.Unalias(sl.Elem()).Underlying().(*types.Basic)
		return ok && (b.Kind() == types.Byte || b.Kind() == types.Uint8)
	}
	b, ok := u.(*types.Basic)
	return ok && b.Info()&types.IsString != 0
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

// UnwrapStructType 解引用别名与任意层指针，提取底层 *types.Struct（供 failclosed/digestcover/archbound 共享）。
func UnwrapStructType(t types.Type) *types.Struct {
	if t == nil {
		return nil
	}
	u := types.Unalias(t)
	for ptr, ok := u.(*types.Pointer); ok; ptr, ok = u.(*types.Pointer) {
		u = types.Unalias(ptr.Elem())
	}
	st, _ := u.Underlying().(*types.Struct)
	return st
}

// ParamTypeAt 返回参数列表第 i 个形参的类型（自动解包可变参末位的切片元素类型）。
func ParamTypeAt(params *types.Tuple, variadic bool, i int) types.Type {
	if params == nil || i < 0 {
		return nil
	}
	n := params.Len()
	if n == 0 || (!variadic && i >= n) {
		return nil
	}
	if i < n-1 || !variadic {
		return params.At(i).Type()
	}
	if sl, ok := types.Unalias(params.At(n - 1).Type()).(*types.Slice); ok {
		return sl.Elem()
	}
	return nil
}

func isNilObject(obj types.Object) bool {
	if obj == nil {
		return true
	}
	rv := reflect.ValueOf(obj)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

// ObjectPkgPath 返回 types.Object 所属包的真实路径（仅剥离驱动 " [...]" 后缀，不剥离 _test 以防外置测试包伪造符号）。
func ObjectPkgPath(obj types.Object) string {
	if isNilObject(obj) || obj.Pkg() == nil {
		return ""
	}
	p, _, _ := strings.Cut(obj.Pkg().Path(), " [")
	return p
}

// IsPkgSymbol 判断 types.Object 是否为指定规范包路径下的目标符号之一。
func IsPkgSymbol(obj types.Object, pkgPath string, names ...string) bool {
	return !isNilObject(obj) && ObjectPkgPath(obj) == pkgPath && slices.Contains(names, obj.Name())
}

// ResolveCalledObject 解析调用表达式指向的被调 types.Object（自动剥离括号与泛型实参索引，不误剥普通切片/Map 索引）。
func ResolveCalledObject(info *types.Info, call *ast.CallExpr) types.Object {
	if info == nil || call == nil {
		return nil
	}
	switch e := unwrapCallFun(info, call.Fun).(type) {
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

func unwrapCallFun(info *types.Info, expr ast.Expr) ast.Expr {
	for {
		switch e := expr.(type) {
		case *ast.ParenExpr:
			expr = e.X
		case *ast.IndexExpr:
			if !isGenericIndexTarget(info, e.X) {
				return expr
			}
			expr = e.X
		case *ast.IndexListExpr:
			if !isGenericIndexTarget(info, e.X) {
				return expr
			}
			expr = e.X
		default:
			return expr
		}
	}
}

func isGenericIndexTarget(info *types.Info, x ast.Expr) bool {
	if info == nil || x == nil {
		return false
	}
	var id *ast.Ident
	switch e := ast.Unparen(x).(type) {
	case *ast.Ident:
		id = e
	case *ast.SelectorExpr:
		id = e.Sel
	}
	if id != nil {
		if _, ok := info.Instances[id]; ok {
			return true
		}
	}
	tv, ok := info.Types[x]
	return ok && tv.IsType()
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
