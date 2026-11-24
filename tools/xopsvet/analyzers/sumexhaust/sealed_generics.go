package sumexhaust

import "go/types"

// instantiateVariant 尝试按封闭接口的类型实参实例化候选泛型变体；参数不匹配时保留未实例化原型以供兼容匹配。
func instantiateVariant(candNamed, ifaceNamed *types.Named) types.Type {
	tp := candNamed.TypeParams()
	if tp == nil || tp.Len() == 0 || ifaceNamed == nil || ifaceNamed.TypeArgs() == nil || ifaceNamed.TypeArgs().Len() != tp.Len() {
		return candNamed
	}
	args := make([]types.Type, tp.Len())
	for i := range args {
		args[i] = ifaceNamed.TypeArgs().At(i)
	}
	if inst, err := types.Instantiate(nil, candNamed, args, true); err == nil {
		return inst
	}
	return candNamed
}

// checkVariantImplements 检查候选具体类型的值接收者与指针接收者是否实现目标封闭接口。
func checkVariantImplements(cand types.Type, iface *types.Interface) (bool, bool) {
	if candNamed, isUninst := isUninstantiatedGenericNamed(cand); isUninst {
		if methodSetImplementsGeneric(types.NewMethodSet(candNamed), iface) {
			return true, true
		}
		return false, methodSetImplementsGeneric(types.NewMethodSet(types.NewPointer(candNamed)), iface)
	}
	return types.Implements(cand, iface), types.Implements(types.NewPointer(cand), iface)
}

func isUninstantiatedGenericNamed(t types.Type) (*types.Named, bool) {
	named, ok := t.(*types.Named)
	if !ok || named == nil {
		return nil, false
	}
	tp, ta := named.TypeParams(), named.TypeArgs()
	return named, tp != nil && tp.Len() > 0 && (ta == nil || ta.Len() == 0)
}

func methodSetImplementsGeneric(ms *types.MethodSet, iface *types.Interface) bool {
	if ms == nil || iface == nil {
		return false
	}
	for i := range iface.NumMethods() {
		im := iface.Method(i)
		sel := ms.Lookup(im.Pkg(), im.Name())
		if sel == nil {
			return false
		}
		if fn, ok := sel.Obj().(*types.Func); !ok || !compatibleSignatureTypes(fn.Signature(), im.Signature(), make(map[typePair]bool)) {
			return false
		}
	}
	return true
}

type typePair struct{ a, b types.Type }

func compatibleSignatureTypes(fnSig, imSig *types.Signature, seen map[typePair]bool) bool {
	return fnSig != nil && imSig != nil && fnSig.Variadic() == imSig.Variadic() &&
		compatibleTupleTypesSeen(fnSig.Params(), imSig.Params(), seen) &&
		compatibleTupleTypesSeen(fnSig.Results(), imSig.Results(), seen)
}

func compatibleTupleTypesSeen(fnTup, imTup *types.Tuple, seen map[typePair]bool) bool {
	if fnTup.Len() != imTup.Len() {
		return false
	}
	for i := range fnTup.Len() {
		if !compatibleSingleTypeSeen(fnTup.At(i).Type(), imTup.At(i).Type(), seen) {
			return false
		}
	}
	return true
}

func compatibleSingleTypeSeen(fnType, imType types.Type, seen map[typePair]bool) bool {
	fnU, imU := types.Unalias(fnType), types.Unalias(imType)
	if pair := (typePair{fnU, imU}); seen[pair] {
		return true
	} else {
		seen[pair] = true
	}
	if !hasTypeParam(fnU) && !hasTypeParam(imU) {
		return types.Identical(fnU, imU)
	}
	if tp, ok := fnU.(*types.TypeParam); ok {
		if hasTypeParam(imU) || imU == types.Typ[types.Invalid] {
			return true
		}
		constraint, isIface := tp.Constraint().Underlying().(*types.Interface)
		return !isIface || types.Satisfies(imU, constraint)
	}
	if _, ok := imU.(*types.TypeParam); ok {
		return true
	}
	return compatibleCompoundType(fnU, imU, seen)
}

// compatibleCompoundType 在含类型参数的复合类型间执行结构化兼容校验。
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
	for i := range fnSt.NumFields() {
		ff, imf := fnSt.Field(i), imSt.Field(i)
		if ff.Name() != imf.Name() || ff.Embedded() != imf.Embedded() || fnSt.Tag(i) != imSt.Tag(i) ||
			!compatibleSingleTypeSeen(ff.Type(), imf.Type(), seen) {
			return false
		}
	}
	return true
}

func compatibleInterfaceTypes(fnIface, imIface *types.Interface, seen map[typePair]bool) bool {
	if fnIface == nil || imIface == nil || fnIface.IsComparable() != imIface.IsComparable() || fnIface.NumMethods() != imIface.NumMethods() {
		return false
	}
	for i := range fnIface.NumMethods() {
		fm, imm := fnIface.Method(i), imIface.Method(i)
		if fm == nil || imm == nil || fm.Id() != imm.Id() || !compatibleSignatureTypes(fm.Signature(), imm.Signature(), seen) {
			return false
		}
	}
	return true
}

func compatibleNamedTypeArgs(fnNamed, imNamed *types.Named, seen map[typePair]bool) bool {
	if fnNamed.Origin() == nil || fnNamed.Origin() != imNamed.Origin() {
		return false
	}
	fnArgs, imArgs := fnNamed.TypeArgs(), imNamed.TypeArgs()
	if fnArgs == nil && imArgs == nil {
		return true
	}
	if fnArgs == nil || imArgs == nil || fnArgs.Len() != imArgs.Len() {
		return false
	}
	for i := range fnArgs.Len() {
		if !compatibleSingleTypeSeen(fnArgs.At(i), imArgs.At(i), seen) {
			return false
		}
	}
	return true
}

type elemCarrier interface{ Elem() types.Type }

func hasTypeParam(t types.Type) bool { return hasTypeParamSeen(t, make(map[types.Type]bool)) }

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
	case *types.Map:
		return hasTypeParamSeen(v.Key(), seen) || hasTypeParamSeen(v.Elem(), seen)
	case elemCarrier:
		return hasTypeParamSeen(v.Elem(), seen)
	case *types.Named:
		return v.TypeArgs() != nil && anyTypeIndex(v.TypeArgs().Len(), v.TypeArgs().At, seen)
	case *types.Signature:
		return v != nil && (tupleHasParam(v.Params(), seen) || tupleHasParam(v.Results(), seen))
	case *types.Tuple:
		return tupleHasParam(v, seen)
	case *types.Struct:
		return v != nil && anyTypeIndex(v.NumFields(), func(i int) types.Type { return v.Field(i).Type() }, seen)
	case *types.Interface:
		return v != nil && anyTypeIndex(v.NumMethods(), func(i int) types.Type { return v.Method(i).Type() }, seen)
	default:
		return false
	}
}

func tupleHasParam(tup *types.Tuple, seen map[types.Type]bool) bool {
	return tup != nil && anyTypeIndex(tup.Len(), func(i int) types.Type { return tup.At(i).Type() }, seen)
}

func anyTypeIndex(n int, at func(int) types.Type, seen map[types.Type]bool) bool {
	for i := range n {
		if hasTypeParamSeen(at(i), seen) {
			return true
		}
	}
	return false
}
