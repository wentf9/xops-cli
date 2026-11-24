package vetutil

import (
	"go/ast"
	"go/types"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ast/inspector"
)

// InspectorOf 获取或按需构造当前分析 Pass 的 AST 索引器。
func InspectorOf(pass *analysis.Pass) *inspector.Inspector {
	if pass == nil {
		return nil
	}
	return inspector.New(pass.Files)
}

// IsTestFile 判断 AST 文件是否为 *_test.go 测试源码文件。
// 优先使用 token.File.Name()，避免 //line 指令干扰真实文件名判定。
func IsTestFile(pass *analysis.Pass, f *ast.File) bool {
	if pass == nil || pass.Fset == nil || f == nil {
		return false
	}
	tokFile := pass.Fset.File(f.Package)
	if tokFile == nil {
		return false
	}
	return strings.HasSuffix(tokFile.Name(), "_test.go")
}

// ObjectPkgPath 返回 types.Object 所属包的规范路径（已剥离 _test 后缀）。
// 对内置符号或 nil 对象返回空字符串。
func ObjectPkgPath(obj types.Object) string {
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	base, _ := NormalizePkgPath(obj.Pkg().Path())
	return base
}

// IsPkgSymbol 判断 types.Object 是否为指定规范包路径下的目标符号之一。
func IsPkgSymbol(obj types.Object, pkgPath string, names ...string) bool {
	if obj == nil {
		return false
	}
	if ObjectPkgPath(obj) != pkgPath {
		return false
	}
	return slices.Contains(names, obj.Name())
}

// ResolveCalledObject 解析函数调用表达式指向的被调 types.Object。
// 自动剥离括号与泛型实参索引表达式，同时覆盖直接函数调用与选择器方法调用。
func ResolveCalledObject(info *types.Info, call *ast.CallExpr) types.Object {
	if info == nil || call == nil {
		return nil
	}
	fun := unwrapCallFun(call.Fun)
	switch e := fun.(type) {
	case *ast.Ident:
		return info.Uses[e]
	case *ast.SelectorExpr:
		if sel, ok := info.Selections[e]; ok && sel != nil {
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

// TypeContains 递归检查类型 t（含指针、切片、数组、Map、Chan、结构体字段、
// 签名、泛型实参及接口嵌入）中是否包含满足谓词 pred 的命名类型。
// 内置环路检测集合 seen，可安全处理自引用结构体或递归接口。
func TypeContains(t types.Type, pred func(*types.Named) bool) bool {
	if t == nil || pred == nil {
		return false
	}
	return typeContains(t, nil, false, pred, make(map[types.Type]bool))
}

// TypeContainsNamed 判断类型 t 是否直接或间接包含指定包路径与名称的命名类型。
func TypeContainsNamed(t types.Type, pkgPath, typeName string) bool {
	return TypeContains(t, func(n *types.Named) bool {
		return IsPkgSymbol(n.Obj(), pkgPath, typeName)
	})
}

// TypeContainsLocalNamed 与 TypeContainsNamed 类似，但仅展开当前包 pkg 内定义的
// 命名类型底层结构，不穿透展开外部包结构体（如 usecase.Service）的内部字段。
func TypeContainsLocalNamed(t types.Type, pkg *types.Package, pkgPath, typeName string) bool {
	if t == nil {
		return false
	}
	pred := func(n *types.Named) bool {
		return IsPkgSymbol(n.Obj(), pkgPath, typeName)
	}
	return typeContains(t, pkg, true, pred, make(map[types.Type]bool))
}

func typeContains(t types.Type, localPkg *types.Package, localOnly bool, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok {
		return typeContainsNamed(named, localPkg, localOnly, pred, seen)
	}
	return typeContainsComposite(t, localPkg, localOnly, pred, seen)
}

func typeContainsNamed(named *types.Named, localPkg *types.Package, localOnly bool, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	if pred(named) {
		return true
	}
	if seen[named] {
		return false
	}
	seen[named] = true
	if typeArgs := named.TypeArgs(); typeArgs != nil {
		for i := 0; i < typeArgs.Len(); i++ {
			if typeContains(typeArgs.At(i), localPkg, localOnly, pred, seen) {
				return true
			}
		}
	}
	if localOnly && named.Obj() != nil && named.Obj().Pkg() != localPkg {
		return false
	}
	return typeContains(named.Underlying(), localPkg, localOnly, pred, seen)
}

func typeContainsComposite(t types.Type, localPkg *types.Package, localOnly bool, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	switch v := t.(type) {
	case *types.Pointer:
		return typeContains(v.Elem(), localPkg, localOnly, pred, seen)
	case *types.Slice:
		return typeContains(v.Elem(), localPkg, localOnly, pred, seen)
	case *types.Array:
		return typeContains(v.Elem(), localPkg, localOnly, pred, seen)
	case *types.Chan:
		return typeContains(v.Elem(), localPkg, localOnly, pred, seen)
	case *types.Map:
		return typeContains(v.Key(), localPkg, localOnly, pred, seen) || typeContains(v.Elem(), localPkg, localOnly, pred, seen)
	case *types.Struct:
		return typeContainsStruct(v, localPkg, localOnly, pred, seen)
	case *types.Signature:
		return typeContainsTuple(v.Params(), localPkg, localOnly, pred, seen) || typeContainsTuple(v.Results(), localPkg, localOnly, pred, seen)
	case *types.Tuple:
		return typeContainsTuple(v, localPkg, localOnly, pred, seen)
	case *types.Interface:
		return typeContainsInterface(v, localPkg, localOnly, pred, seen)
	case *types.TypeParam:
		return typeContainsTypeParam(v, localPkg, localOnly, pred, seen)
	default:
		return false
	}
}

func typeContainsStruct(st *types.Struct, localPkg *types.Package, localOnly bool, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	if seen[st] {
		return false
	}
	seen[st] = true
	for i := 0; i < st.NumFields(); i++ {
		if typeContains(st.Field(i).Type(), localPkg, localOnly, pred, seen) {
			return true
		}
	}
	return false
}

func typeContainsTuple(tup *types.Tuple, localPkg *types.Package, localOnly bool, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	if tup == nil {
		return false
	}
	for i := 0; i < tup.Len(); i++ {
		if typeContains(tup.At(i).Type(), localPkg, localOnly, pred, seen) {
			return true
		}
	}
	return false
}

func typeContainsInterface(iface *types.Interface, localPkg *types.Package, localOnly bool, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	if seen[iface] {
		return false
	}
	seen[iface] = true
	for i := 0; i < iface.NumEmbeddeds(); i++ {
		if typeContains(iface.EmbeddedType(i), localPkg, localOnly, pred, seen) {
			return true
		}
	}
	for i := 0; i < iface.NumMethods(); i++ {
		if typeContains(iface.Method(i).Type(), localPkg, localOnly, pred, seen) {
			return true
		}
	}
	return false
}

func typeContainsTypeParam(tp *types.TypeParam, localPkg *types.Package, localOnly bool, pred func(*types.Named) bool, seen map[types.Type]bool) bool {
	if seen[tp] {
		return false
	}
	seen[tp] = true
	return typeContains(tp.Constraint(), localPkg, localOnly, pred, seen)
}
