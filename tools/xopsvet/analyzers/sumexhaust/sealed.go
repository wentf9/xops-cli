package sumexhaust

import (
	"go/types"
	"slices"
	"strings"
)

// sealedInfo 保存待检查封闭接口的元数据及其所有必需具体变体。
type sealedInfo struct {
	named         *types.Named
	iface         *types.Interface
	sealedMethods []*types.Func
	variants      []types.Type
}

// extractSealedInterface 从 type switch 表达式中提取封闭接口及必需变体集合；非封闭接口返回 nil。
func extractSealedInterface(passPkg *types.Package, switchedType types.Type) *sealedInfo {
	if switchedType == nil {
		return nil
	}
	var named *types.Named
	var iface *types.Interface
	switch t := types.Unalias(switchedType).(type) {
	case *types.Named:
		named = t
		iface, _ = t.Underlying().(*types.Interface)
	case *types.Interface:
		iface = t
	}
	if iface == nil {
		return nil
	}
	sealedMethods := findSealedMethods(iface)
	if len(sealedMethods) == 0 {
		return nil
	}
	return &sealedInfo{named: named, iface: iface, sealedMethods: sealedMethods, variants: collectConcreteVariants(passPkg, named, iface, sealedMethods)}
}

func findSealedMethods(iface *types.Interface) []*types.Func {
	var out []*types.Func
	for i := range iface.NumMethods() {
		if m := iface.Method(i); !m.Exported() && strings.HasPrefix(m.Name(), "sealed") {
			out = append(out, m)
		}
	}
	return out
}

func collectConcreteVariants(passPkg *types.Package, named *types.Named, iface *types.Interface, sealedMethods []*types.Func) []types.Type {
	seen := make(map[*types.Package]bool)
	var pkgs []*types.Package
	addPkg := func(pkg *types.Package) {
		if pkg != nil && !seen[pkg] {
			seen[pkg] = true
			pkgs = append(pkgs, pkg)
		}
	}
	if named != nil && named.Obj() != nil {
		addPkg(named.Obj().Pkg())
	}
	for _, m := range sealedMethods {
		addPkg(m.Pkg())
	}
	var variants []types.Type
	for _, pkg := range pkgs {
		variants = append(variants, scanPackageVariants(passPkg, pkg, named, iface)...)
	}
	return variants
}

func scanPackageVariants(passPkg, defPkg *types.Package, ifaceNamed *types.Named, iface *types.Interface) []types.Type {
	scope := defPkg.Scope()
	names := scope.Names()
	slices.Sort(names)
	var candidates, variants []types.Type
	for _, name := range names {
		if cand := resolveCandidateType(passPkg, defPkg, scope.Lookup(name), ifaceNamed); cand != nil {
			candidates = append(candidates, cand)
		}
	}
	for _, cand := range candidates {
		if !isSealMixin(defPkg, passPkg, cand, candidates, iface) {
			variants = append(variants, requiredVariantForms(cand, iface)...)
		}
	}
	return variants
}

func resolveCandidateType(passPkg, defPkg *types.Package, obj types.Object, ifaceNamed *types.Named) types.Type {
	tn, ok := obj.(*types.TypeName)
	if !ok || tn.IsAlias() || (defPkg != passPkg && !tn.Exported()) {
		return nil
	}
	candNamed, ok := tn.Type().(*types.Named)
	if !ok {
		return nil
	}
	switch candNamed.Underlying().(type) {
	case *types.Interface, *types.TypeParam:
		return nil
	}
	return instantiateVariant(candNamed, ifaceNamed)
}

// isSealMixin 识别用于组合嵌入的未导出 sealed* 标记结构体（如 type sealedCapability struct{}），防止误判为业务变体。
func isSealMixin(defPkg, passPkg *types.Package, cand types.Type, allCandidates []types.Type, iface *types.Interface) bool {
	named, ok := cand.(*types.Named)
	if defPkg != passPkg || !ok || named.Obj() == nil || named.Obj().Exported() {
		return false
	}
	if strings.HasPrefix(named.Obj().Name(), "sealed") {
		return true
	}
	st, ok := named.Underlying().(*types.Struct)
	return ok && st.NumFields() == 0 && slices.ContainsFunc(allCandidates, func(other types.Type) bool {
		return !types.Identical(other, cand) && len(requiredVariantForms(other, iface)) > 0 && structEmbedsType(other, cand)
	})
}

func structEmbedsType(container, target types.Type) bool {
	st, ok := container.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := range st.NumFields() {
		if f := st.Field(i); f.Embedded() {
			ft, _ := unwrapPointerElem(f.Type())
			if types.Identical(ft, target) {
				return true
			}
		}
	}
	return false
}

func requiredVariantForms(cand types.Type, iface *types.Interface) []types.Type {
	valImpl, ptrImpl := checkVariantImplements(cand, iface)
	if valImpl && ptrImpl {
		// 值接收者同时满足 T 与 *T 两种动态类型，type switch 须同时覆盖两者以免漏判指针实例。
		return []types.Type{cand, types.NewPointer(cand)}
	}
	if ptrImpl {
		return []types.Type{types.NewPointer(cand)}
	}
	return nil
}
