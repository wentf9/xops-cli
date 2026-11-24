package sumexhaust

import "go/types"

// instantiateVariant 尝试按封闭接口的类型实参实例化候选泛型变体；
// 当泛型参数目不一致或处于未命名接口包装上下文时，保留未实例化原型以供后续结构化兼容匹配。
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

// checkVariantImplements 检查候选具体类型的值接收者与指针接收者是否实现目标封闭接口。
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

type typePair struct {
	a types.Type
	b types.Type
}

func compatibleUninstantiatedMethodSig(fnSig, imSig *types.Signature) bool {
	return compatibleSignatureTypes(fnSig, imSig, make(map[typePair]bool))
}

func compatibleSignatureTypes(fnSig, imSig *types.Signature, seen map[typePair]bool) bool {
	if fnSig == nil || imSig == nil || fnSig.Variadic() != imSig.Variadic() {
		return false
	}
	return compatibleTupleTypesSeen(fnSig.Params(), imSig.Params(), seen) &&
		compatibleTupleTypesSeen(fnSig.Results(), imSig.Results(), seen)
}

func compatibleTupleTypesSeen(fnTup, imTup *types.Tuple, seen map[typePair]bool) bool {
	if fnTup.Len() != imTup.Len() {
		return false
	}
	for i := 0; i < fnTup.Len(); i++ {
		if !compatibleSingleTypeSeen(fnTup.At(i).Type(), imTup.At(i).Type(), seen) {
			return false
		}
	}
	return true
}

func compatibleSingleTypeSeen(fnType, imType types.Type, seen map[typePair]bool) bool {
	fnU := types.Unalias(fnType)
	imU := types.Unalias(imType)
	pair := typePair{a: fnU, b: imU}
	if seen[pair] {
		return true
	}
	seen[pair] = true

	if !hasTypeParam(fnU) && !hasTypeParam(imU) {
		return types.Identical(fnU, imU)
	}
	if tp, ok := fnU.(*types.TypeParam); ok {
		return compatibleTypeParamWithType(tp, imU)
	}
	// 接口侧本身仍为未实例化类型参数时（例如泛型函数内部对 Gen[T] 做 type switch），复合类型参数具备潜在匹配可能。
	if _, ok := imU.(*types.TypeParam); ok {
		return true
	}
	return compatibleCompoundType(fnU, imU, seen)
}

func compatibleTypeParamWithType(tp *types.TypeParam, imU types.Type) bool {
	if hasTypeParam(imU) || imU == types.Typ[types.Invalid] {
		return true
	}
	if constraint, ok := tp.Constraint().Underlying().(*types.Interface); ok {
		return types.Satisfies(imU, constraint)
	}
	return true
}

// compatibleCompoundType 在含类型参数的复合类型（含函数签名、结构体、匿名接口与具名泛型）间执行结构化兼容校验。
func compatibleCompoundType(fnU, imU types.Type, seen map[typePair]bool) bool {
	switch fv := fnU.(type) {
	case *types.Slice:
		iv, ok := imU.(*types.Slice)
		return ok && compatibleSingleTypeSeen(fv.Elem(), iv.Elem(), seen)
	case *types.Pointer:
		iv, ok := imU.(*types.Pointer)
		return ok && compatibleSingleTypeSeen(fv.Elem(), iv.Elem(), seen)
	case *types.Array:
		iv, ok := imU.(*types.Array)
		return ok && fv.Len() == iv.Len() && compatibleSingleTypeSeen(fv.Elem(), iv.Elem(), seen)
	case *types.Chan:
		iv, ok := imU.(*types.Chan)
		return ok && fv.Dir() == iv.Dir() && compatibleSingleTypeSeen(fv.Elem(), iv.Elem(), seen)
	case *types.Map:
		iv, ok := imU.(*types.Map)
		return ok && compatibleSingleTypeSeen(fv.Key(), iv.Key(), seen) && compatibleSingleTypeSeen(fv.Elem(), iv.Elem(), seen)
	case *types.Named:
		iv, ok := imU.(*types.Named)
		return ok && compatibleNamedTypeArgs(fv, iv, seen)
	case *types.Signature:
		iv, ok := imU.(*types.Signature)
		return ok && compatibleSignatureTypes(fv, iv, seen)
	case *types.Struct:
		iv, ok := imU.(*types.Struct)
		return ok && compatibleStructTypes(fv, iv, seen)
	case *types.Interface:
		iv, ok := imU.(*types.Interface)
		return ok && compatibleInterfaceTypes(fv, iv, seen)
	default:
		return false
	}
}

func compatibleStructTypes(fnSt, imSt *types.Struct, seen map[typePair]bool) bool {
	if fnSt == nil || imSt == nil || fnSt.NumFields() != imSt.NumFields() {
		return false
	}
	for i := 0; i < fnSt.NumFields(); i++ {
		ff, imf := fnSt.Field(i), imSt.Field(i)
		if ff.Name() != imf.Name() || ff.Embedded() != imf.Embedded() || fnSt.Tag(i) != imSt.Tag(i) {
			return false
		}
		if !compatibleSingleTypeSeen(ff.Type(), imf.Type(), seen) {
			return false
		}
	}
	return true
}

// compatibleInterfaceTypes 按接口完整方法集（含显式与嵌入方法）逐一核验名称标识与签名兼容性。
func compatibleInterfaceTypes(fnIface, imIface *types.Interface, seen map[typePair]bool) bool {
	if fnIface == nil || imIface == nil || fnIface.IsComparable() != imIface.IsComparable() {
		return false
	}
	if fnIface.NumMethods() != imIface.NumMethods() {
		return false
	}
	for i := 0; i < fnIface.NumMethods(); i++ {
		fm, imm := fnIface.Method(i), imIface.Method(i)
		if fm == nil || imm == nil || fm.Id() != imm.Id() {
			return false
		}
		if !compatibleSignatureTypes(fm.Signature(), imm.Signature(), seen) {
			return false
		}
	}
	return true
}

func compatibleNamedTypeArgs(fnNamed, imNamed *types.Named, seen map[typePair]bool) bool {
	if fnNamed.Origin() == nil || fnNamed.Origin() != imNamed.Origin() {
		return false
	}
	fnArgs := fnNamed.TypeArgs()
	imArgs := imNamed.TypeArgs()
	if fnArgs == nil && imArgs == nil {
		return true
	}
	if fnArgs == nil || imArgs == nil || fnArgs.Len() != imArgs.Len() {
		return false
	}
	for i := 0; i < fnArgs.Len(); i++ {
		if !compatibleSingleTypeSeen(fnArgs.At(i), imArgs.At(i), seen) {
			return false
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
	case *types.Signature:
		// 函数类型参数或返回值若包含类型参数，须进入结构化签名兼容比对而非直接 Identical 判定。
		return v != nil && (tupleHasTypeParamSeen(v.Params(), seen) || tupleHasTypeParamSeen(v.Results(), seen))
	case *types.Tuple:
		return tupleHasTypeParamSeen(v, seen)
	case *types.Struct:
		return structHasTypeParamSeen(v, seen)
	case *types.Interface:
		// 匿名接口方法签名若携带类型参数，须进入方法集结构化比对而非直接 Identical 判定。
		return interfaceHasTypeParamSeen(v, seen)
	default:
		return false
	}
}

func tupleHasTypeParamSeen(tup *types.Tuple, seen map[types.Type]bool) bool {
	if tup == nil {
		return false
	}
	for i := 0; i < tup.Len(); i++ {
		if hasTypeParamSeen(tup.At(i).Type(), seen) {
			return true
		}
	}
	return false
}

func structHasTypeParamSeen(st *types.Struct, seen map[types.Type]bool) bool {
	if st == nil {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		if hasTypeParamSeen(st.Field(i).Type(), seen) {
			return true
		}
	}
	return false
}

func interfaceHasTypeParamSeen(iface *types.Interface, seen map[types.Type]bool) bool {
	if iface == nil {
		return false
	}
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if m != nil && m.Signature() != nil && hasTypeParamSeen(m.Signature(), seen) {
			return true
		}
	}
	return false
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
