package sumexhaust

import (
	"go/types"
	"sort"
	"strings"
)

// sealedInfo 保存待检查封闭接口的元数据及其所有必需具体变体。
type sealedInfo struct {
	named         *types.Named
	iface         *types.Interface
	sealedMethods []*types.Func
	variants      []types.Type
}

// extractSealedInterface 从 type switch 表达式中提取封闭接口及必需变体集合。
// 若目标类型并非含未导出 sealed*() 方法的接口，则返回 nil。
func extractSealedInterface(passPkg *types.Package, switchedType types.Type) *sealedInfo {
	if switchedType == nil {
		return nil
	}
	u := types.Unalias(switchedType)
	var named *types.Named
	var iface *types.Interface
	switch t := u.(type) {
	case *types.Named:
		named = t
		iface, _ = t.Underlying().(*types.Interface)
	case *types.Interface:
		iface = t
	default:
		return nil
	}
	if iface == nil {
		return nil
	}
	sealedMethods := findSealedMethods(iface)
	if len(sealedMethods) == 0 {
		return nil
	}
	variants := collectConcreteVariants(passPkg, named, iface, sealedMethods)
	return &sealedInfo{
		named:         named,
		iface:         iface,
		sealedMethods: sealedMethods,
		variants:      variants,
	}
}

func findSealedMethods(iface *types.Interface) []*types.Func {
	var out []*types.Func
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if !m.Exported() && strings.HasPrefix(m.Name(), "sealed") {
			out = append(out, m)
		}
	}
	return out
}

func collectConcreteVariants(
	passPkg *types.Package,
	named *types.Named,
	iface *types.Interface,
	sealedMethods []*types.Func,
) []types.Type {
	pkgs := collectDefiningPackages(named, sealedMethods)
	var variants []types.Type
	for _, pkg := range pkgs {
		variants = append(variants, scanPackageVariants(passPkg, pkg, named, iface)...)
	}
	return variants
}

func collectDefiningPackages(named *types.Named, sealedMethods []*types.Func) []*types.Package {
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
	return pkgs
}

func scanPackageVariants(
	passPkg *types.Package,
	defPkg *types.Package,
	ifaceNamed *types.Named,
	iface *types.Interface,
) []types.Type {
	scope := defPkg.Scope()
	names := scope.Names()
	sort.Strings(names)

	var candidates []types.Type
	for _, name := range names {
		cand := resolveCandidateType(passPkg, defPkg, scope.Lookup(name), ifaceNamed)
		if cand == nil {
			continue
		}
		candidates = append(candidates, cand)
	}

	var variants []types.Type
	for _, cand := range candidates {
		if isSealMixin(defPkg, passPkg, cand, candidates, iface) {
			continue
		}
		variants = append(variants, requiredVariantForms(cand, iface)...)
	}
	return variants
}

func resolveCandidateType(
	passPkg *types.Package,
	defPkg *types.Package,
	obj types.Object,
	ifaceNamed *types.Named,
) types.Type {
	tn, ok := obj.(*types.TypeName)
	if !ok || tn.IsAlias() {
		return nil
	}
	if defPkg != passPkg && !tn.Exported() {
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

func instantiateVariant(candNamed, ifaceNamed *types.Named) types.Type {
	tp := candNamed.TypeParams()
	if tp == nil || tp.Len() == 0 {
		return candNamed
	}
	if ifaceNamed != nil && ifaceNamed.TypeArgs() != nil && ifaceNamed.TypeArgs().Len() == tp.Len() {
		args := make([]types.Type, ifaceNamed.TypeArgs().Len())
		for i := 0; i < len(args); i++ {
			args[i] = ifaceNamed.TypeArgs().At(i)
		}
		if inst, err := types.Instantiate(nil, candNamed, args, true); err == nil {
			return inst
		}
	}
	// 当泛型参数目与接口类型实参不一致或存在未命名接口包装时，保留未实例化原型以供方法集兼容判定。
	return candNamed
}

// isSealMixin 识别用于组合嵌入的未导出 sealed* 标记结构体（如 type sealedCapability struct{}），
// 防止将其误判为必须出现在 type switch 中的业务变体。
func isSealMixin(
	defPkg *types.Package,
	passPkg *types.Package,
	cand types.Type,
	allCandidates []types.Type,
	iface *types.Interface,
) bool {
	if defPkg != passPkg {
		return false
	}
	named, ok := cand.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Exported() {
		return false
	}
	if strings.HasPrefix(named.Obj().Name(), "sealed") {
		return true
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || st.NumFields() != 0 {
		return false
	}
	return isEmbeddedByImplementer(cand, allCandidates, iface)
}

func isEmbeddedByImplementer(cand types.Type, allCandidates []types.Type, iface *types.Interface) bool {
	for _, other := range allCandidates {
		if types.Identical(other, cand) {
			continue
		}
		if len(requiredVariantForms(other, iface)) == 0 {
			continue
		}
		if structEmbedsType(other, cand) {
			return true
		}
	}
	return false
}

func structEmbedsType(container, target types.Type) bool {
	st, ok := container.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if !f.Embedded() {
			continue
		}
		ft := types.Unalias(f.Type())
		if ptr, ok := ft.(*types.Pointer); ok {
			ft = types.Unalias(ptr.Elem())
		}
		if types.Identical(ft, target) {
			return true
		}
	}
	return false
}

func requiredVariantForms(cand types.Type, iface *types.Interface) []types.Type {
	valImpl, ptrImpl := checkVariantImplements(cand, iface)
	switch {
	case valImpl && ptrImpl:
		// 值接收者同时满足 T 与 *T 两种动态类型，type switch 须同时覆盖两者以免漏判指针实例。
		return []types.Type{cand, types.NewPointer(cand)}
	case ptrImpl:
		return []types.Type{types.NewPointer(cand)}
	default:
		return nil
	}
}

func checkVariantImplements(cand types.Type, iface *types.Interface) (bool, bool) {
	if candNamed, isUninst := isUninstantiatedGenericNamed(cand); isUninst {
		return uninstantiatedMethodMatch(candNamed, iface)
	}
	valImpl := types.Implements(cand, iface)
	ptrImpl := types.Implements(types.NewPointer(cand), iface)
	return valImpl, ptrImpl
}

func isUninstantiatedGenericNamed(t types.Type) (*types.Named, bool) {
	named, ok := t.(*types.Named)
	if !ok || named == nil {
		return nil, false
	}
	tp := named.TypeParams()
	ta := named.TypeArgs()
	return named, tp != nil && tp.Len() > 0 && (ta == nil || ta.Len() == 0)
}

func uninstantiatedMethodMatch(candNamed *types.Named, iface *types.Interface) (bool, bool) {
	if methodSetImplementsGeneric(types.NewMethodSet(candNamed), iface) {
		return true, true
	}
	if methodSetImplementsGeneric(types.NewMethodSet(types.NewPointer(candNamed)), iface) {
		return false, true
	}
	return false, false
}

func methodSetImplementsGeneric(ms *types.MethodSet, iface *types.Interface) bool {
	if ms == nil || iface == nil {
		return false
	}
	for i := 0; i < iface.NumMethods(); i++ {
		im := iface.Method(i)
		sel := ms.Lookup(im.Pkg(), im.Name())
		if sel == nil {
			return false
		}
		fn, ok := sel.Obj().(*types.Func)
		if !ok || !compatibleUninstantiatedMethodSig(fn.Signature(), im.Signature()) {
			return false
		}
	}
	return true
}

func compatibleUninstantiatedMethodSig(fnSig, imSig *types.Signature) bool {
	if fnSig == nil || imSig == nil || fnSig.Variadic() != imSig.Variadic() {
		return false
	}
	return compatibleTupleTypes(fnSig.Params(), imSig.Params()) &&
		compatibleTupleTypes(fnSig.Results(), imSig.Results())
}

func compatibleTupleTypes(fnTup, imTup *types.Tuple) bool {
	if fnTup.Len() != imTup.Len() {
		return false
	}
	for i := 0; i < fnTup.Len(); i++ {
		if !compatibleSingleType(fnTup.At(i).Type(), imTup.At(i).Type()) {
			return false
		}
	}
	return true
}

func compatibleSingleType(fnType, imType types.Type) bool {
	fnHasTP := hasTypeParam(fnType)
	imHasTP := hasTypeParam(imType)
	if !fnHasTP && !imHasTP {
		return types.Identical(fnType, imType)
	}
	if tp, ok := types.Unalias(fnType).(*types.TypeParam); ok && !imHasTP && imType != types.Typ[types.Invalid] {
		if constraint, ok := tp.Constraint().Underlying().(*types.Interface); ok {
			return types.Satisfies(imType, constraint)
		}
	}
	return true
}

func hasTypeParam(t types.Type) bool {
	return hasTypeParamSeen(t, make(map[types.Type]bool))
}

func hasTypeParamSeen(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t)
	if seen[u] {
		return false
	}
	seen[u] = true
	switch v := u.(type) {
	case *types.TypeParam:
		return true
	case *types.Pointer:
		return hasTypeParamSeen(v.Elem(), seen)
	case *types.Slice:
		return hasTypeParamSeen(v.Elem(), seen)
	case *types.Array:
		return hasTypeParamSeen(v.Elem(), seen)
	case *types.Chan:
		return hasTypeParamSeen(v.Elem(), seen)
	case *types.Map:
		return hasTypeParamSeen(v.Key(), seen) || hasTypeParamSeen(v.Elem(), seen)
	case *types.Named:
		return typeArgsHaveParam(v.TypeArgs(), seen)
	default:
		return false
	}
}

func typeArgsHaveParam(ta *types.TypeList, seen map[types.Type]bool) bool {
	if ta == nil {
		return false
	}
	for i := 0; i < ta.Len(); i++ {
		if hasTypeParamSeen(ta.At(i), seen) {
			return true
		}
	}
	return false
}
