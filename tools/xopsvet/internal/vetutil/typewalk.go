package vetutil

import "go/types"

type elemType interface{ Elem() types.Type }

type typeWalkOpt struct {
	localPkg        *types.Package
	localOnly       bool
	valueLayoutOnly bool // true 时绝不进入 Interface.Methods 与 Signature（CRIT-3）
	skipUnexported  bool // true 时具名结构体跳过未导出非嵌入字段（供 osfs_net B-2）
	skipStructs     bool // true 时不展开结构体字段（供 osboundary RemotePath）
	matchTypeParam  bool // true 时命中 *types.TypeParam 即返回 true（供 HasTypeParam）
}

type typeWalker struct {
	opt            typeWalkOpt
	pred           func(*types.Named) bool
	seen           map[types.Type]bool
	expandedOrigin map[*types.Named]bool
}

func runTypeWalk(t types.Type, opt typeWalkOpt, pred func(*types.Named) bool) bool {
	if t == nil || (!opt.matchTypeParam && pred == nil) {
		return false
	}
	w := &typeWalker{opt: opt, pred: pred, seen: map[types.Type]bool{}, expandedOrigin: map[*types.Named]bool{}}
	return w.walk(t)
}

// ContainsValueType 递归检查类型 t 的「值持有布局」中是否包含满足 pred 的命名类型，
// 绝不穿透 *types.Interface（含泛型接口实参）与 *types.Signature（含泛型函数实参）。
func ContainsValueType(t types.Type, pred func(*types.Named) bool) bool {
	return runTypeWalk(t, typeWalkOpt{valueLayoutOnly: true}, pred)
}

// ContainsValueNamed 判断类型 t 的值持有布局中是否包含指定包路径与名称的命名类型。
func ContainsValueNamed(t types.Type, pkgPath, typeName string) bool {
	return ContainsValueType(t, func(n *types.Named) bool { return IsPkgSymbol(n.Obj(), pkgPath, typeName) })
}

// ContainsExportedValueType 检查值布局中是否通过直接/容器/匿名结构体或具名结构体的导出/嵌入字段持有目标类型（B-2）。
func ContainsExportedValueType(t types.Type, pred func(*types.Named) bool) bool {
	return runTypeWalk(t, typeWalkOpt{valueLayoutOnly: true, skipUnexported: true}, pred)
}

// ContainsNonStructValue 检查类型自身/容器/泛型实参是否命中 pred，绝不展开普通结构体字段（B-6）。
func ContainsNonStructValue(t types.Type, pred func(*types.Named) bool) bool {
	return runTypeWalk(t, typeWalkOpt{valueLayoutOnly: true, skipStructs: true}, pred)
}

// TypeContains 递归检查类型 t 的全部引用类型树（含签名接收者/类型形参、接口方法、泛型实参与 *types.Union）。
func TypeContains(t types.Type, pred func(*types.Named) bool) bool {
	return runTypeWalk(t, typeWalkOpt{}, pred)
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
	return runTypeWalk(t, typeWalkOpt{localPkg: pkg, localOnly: true}, pred)
}

// HasTypeParam 递归判断类型 t 内部是否包含未实例化 *types.TypeParam（复用统一 typeWalker）。
func HasTypeParam(t types.Type) bool {
	return runTypeWalk(t, typeWalkOpt{matchTypeParam: true}, nil)
}

func (w *typeWalker) walk(t types.Type) bool {
	if t == nil {
		return false
	}
	if !w.opt.valueLayoutOnly && !w.opt.matchTypeParam {
		if al, ok := t.(*types.Alias); ok {
			if ta := al.TypeArgs(); ta != nil && w.walkIndexed(ta.Len(), ta.At) {
				return true
			}
		}
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok {
		return w.walkNamed(named)
	}
	return w.walkComposite(t)
}

func (w *typeWalker) walkNamed(named *types.Named) bool {
	if w.pred != nil && w.pred(named) {
		return true
	}
	u := types.Unalias(named.Underlying())
	if w.opt.valueLayoutOnly && isIfaceOrSig(u) {
		return false
	}
	if !markFirstSeen(w.seen, named) {
		return false
	}
	if ta := named.TypeArgs(); ta != nil && w.walkIndexed(ta.Len(), ta.At) {
		return true
	}
	if w.stopExpandingNamed(named) {
		return false
	}
	if !w.opt.valueLayoutOnly && w.walkTypeParams(named.TypeParams()) {
		return true
	}
	// 按 Origin() 去重底层结构展开，杜绝 Poly[T] -> *Poly[[]T] 多态递归栈溢出（B-1）。
	orig := named.Origin()
	if w.expandedOrigin[orig] {
		return false
	}
	w.expandedOrigin[orig] = true
	if st, isSt := u.(*types.Struct); isSt {
		return !w.opt.skipStructs && w.walkStruct(st, true)
	}
	return w.walk(u)
}

func isIfaceOrSig(t types.Type) bool {
	_, isI := t.(*types.Interface)
	_, isS := t.(*types.Signature)
	return isI || isS
}

func (w *typeWalker) stopExpandingNamed(named *types.Named) bool {
	return w.opt.matchTypeParam || (w.opt.localOnly && named.Obj() != nil && named.Obj().Pkg() != w.opt.localPkg)
}

func (w *typeWalker) walkStruct(st *types.Struct, inNamed bool) bool {
	if !markFirstSeen(w.seen, st) {
		return false
	}
	for i := range st.NumFields() {
		f := st.Field(i)
		if w.opt.skipUnexported && inNamed && !f.Exported() && !f.Embedded() {
			continue
		}
		if w.walk(f.Type()) {
			return true
		}
	}
	return false
}

func (w *typeWalker) walkIndexed(n int, at func(int) types.Type) bool {
	for i := range n {
		if w.walk(at(i)) {
			return true
		}
	}
	return false
}

func (w *typeWalker) walkTypeParams(tps *types.TypeParamList) bool {
	return tps != nil && w.walkIndexed(tps.Len(), func(i int) types.Type { return tps.At(i).Constraint() })
}

func (w *typeWalker) walkComposite(t types.Type) bool {
	switch v := t.(type) {
	case *types.TypeParam:
		return w.opt.matchTypeParam || w.walkTypeParam(v)
	case *types.Map:
		return w.walk(v.Key()) || w.walk(v.Elem())
	case elemType:
		return w.walk(v.Elem())
	case *types.Struct:
		return !w.opt.skipStructs && w.walkStruct(v, false)
	case *types.Tuple:
		return v != nil && w.walkIndexed(v.Len(), func(i int) types.Type { return v.At(i).Type() })
	case *types.Union:
		return markFirstSeen(w.seen, v) && w.walkIndexed(v.Len(), func(i int) types.Type { return v.Term(i).Type() })
	case *types.Signature:
		return !w.opt.valueLayoutOnly && w.walkSignature(v)
	case *types.Interface:
		return !w.opt.valueLayoutOnly && markFirstSeen(w.seen, v) &&
			(w.walkIndexed(v.NumEmbeddeds(), v.EmbeddedType) ||
				w.walkIndexed(v.NumMethods(), func(i int) types.Type { return v.Method(i).Type() }))
	default:
		return false
	}
}

func (w *typeWalker) walkSignature(sig *types.Signature) bool {
	if w.opt.matchTypeParam {
		return w.walkComposite(sig.Params()) || w.walkComposite(sig.Results())
	}
	return (sig.Recv() != nil && w.walk(sig.Recv().Type())) ||
		w.walkTypeParams(sig.TypeParams()) || w.walkTypeParams(sig.RecvTypeParams()) ||
		w.walkComposite(sig.Params()) || w.walkComposite(sig.Results())
}

func markFirstSeen(seen map[types.Type]bool, t types.Type) bool {
	if seen[t] {
		return false
	}
	seen[t] = true
	return true
}

func (w *typeWalker) walkTypeParam(tp *types.TypeParam) bool {
	if !markFirstSeen(w.seen, tp) {
		return false
	}
	c := types.Unalias(tp.Constraint())
	if !w.opt.valueLayoutOnly {
		return w.walk(c)
	}
	if named, ok := c.(*types.Named); ok && w.pred != nil && w.pred(named) {
		return true
	}
	iface, ok := c.Underlying().(*types.Interface)
	return ok && w.walkValueIfaceTerms(iface)
}

func (w *typeWalker) walkValueIfaceTerms(iface *types.Interface) bool {
	if !markFirstSeen(w.seen, iface) {
		return false
	}
	for i := range iface.NumEmbeddeds() {
		emb := types.Unalias(iface.EmbeddedType(i))
		if named, ok := emb.(*types.Named); ok && w.pred != nil && w.pred(named) {
			return true
		}
		if sub, ok := emb.Underlying().(*types.Interface); ok {
			if w.walkValueIfaceTerms(sub) {
				return true
			}
		} else if w.walk(emb) {
			return true
		}
	}
	return false
}
