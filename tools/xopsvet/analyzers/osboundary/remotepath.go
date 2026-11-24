package osboundary

import (
	"go/token"
	"go/types"
	"slices"
	"strconv"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

type fieldKey struct {
	base ssa.Value
	path string
}

type remoteTaintState struct {
	ssaInfo *buildssa.SSA
	tainted map[ssa.Value]bool
	fields  map[fieldKey]bool
}

// checkRemotePathFilepath 基于 vetssa 在全包 SSA 函数上执行字段敏感（含嵌套字段路径与闭包双向投影）
// 的不动点传播，拦截对 RemotePath 及其派生值调用 path/filepath.*，并保证非远端字段与值构造器零误报（B-6 / H4）。
func checkRemotePathFilepath(pass *analysis.Pass, s *buildssa.SSA) {
	if s == nil {
		return
	}
	funcs := vetssa.AllFuncs(s)
	st := &remoteTaintState{ssaInfo: s, tainted: make(map[ssa.Value]bool), fields: make(map[fieldKey]bool)}
	vetssa.SeedTypedValues(funcs, isRemotePathType, st.mark)
	st.propagateFixpoint(funcs)
	var diags []vetutil.Diag
	vetssa.ForEachFuncInst(funcs, func(fn *ssa.Function, inst ssa.Instruction) {
		if callInst, ok := inst.(ssa.CallInstruction); ok {
			rc := vetssa.ResolveCall(s, callInst)
			if vetutil.ObjectPkgPath(rc.FuncObj) == "path/filepath" && slices.ContainsFunc(rc.UserArgs, st.isTainted) {
				vetssa.AppendDiag(pass, &diags, fn, callInst, "osboundary: 禁止对 RemotePath 调用 path/filepath.*，远端 POSIX 路径请使用 path.* 或 RemotePath 方法")
			}
		}
	})
	vetutil.ReportSortedDedup(pass, diags, true)
}

func (st *remoteTaintState) isTainted(v ssa.Value) bool {
	return v != nil && (st.tainted[v] || isRemotePathType(v.Type()))
}

func (st *remoteTaintState) mark(v ssa.Value) bool {
	if v == nil || st.tainted[v] {
		return false
	}
	st.tainted[v] = true
	return true
}

func (st *remoteTaintState) markFieldPath(base ssa.Value, path string) bool {
	changed := false
	for _, root := range vetssa.RootStorageValues(base, false) {
		changed = st.addFieldKey(root, path) || changed
		if fv, ok := root.(*ssa.FreeVar); ok {
			for _, orig := range vetssa.TraceFreeVarOrigins(fv) {
				changed = st.addFieldKey(orig, path) || changed
			}
		}
	}
	return changed
}

func (st *remoteTaintState) addFieldKey(root ssa.Value, path string) bool {
	k := fieldKey{base: root, path: path}
	if st.fields[k] {
		return false
	}
	st.fields[k] = true
	return true
}

func (st *remoteTaintState) isFieldPathTainted(base ssa.Value, path string) bool {
	return slices.ContainsFunc(vetssa.RootStorageValues(base, false), func(root ssa.Value) bool {
		return st.fields[fieldKey{base: root, path: path}]
	})
}

// extractFieldPath 递归提取嵌套结构体字段访问路径（如 a.Inner.Remote -> base=a, path="0.1"），
// 同时穿透针对 FieldAddr 的指针解引用，支持 s.M["k"]=rp / copy(s.Buf, rp) / append(s.S, rp)（H4）。
func extractFieldPath(v ssa.Value) (ssa.Value, string, bool) {
	if u, ok := v.(*ssa.UnOp); ok && u.Op == token.MUL {
		v = u.X
	}
	var base ssa.Value
	var seg string
	switch node := v.(type) {
	case *ssa.FieldAddr:
		base, seg = node.X, strconv.Itoa(node.Field)
	case *ssa.Field:
		base, seg = node.X, strconv.Itoa(node.Field)
	default:
		return nil, "", false
	}
	if pBase, pPath, ok := extractFieldPath(base); ok {
		return pBase, pPath + "." + seg, true
	}
	return base, seg, true
}

func (st *remoteTaintState) propagateFixpoint(funcs []*ssa.Function) {
	for {
		changed := false
		for _, fn := range funcs {
			changed = st.propagateYieldParams(fn) || changed
			vetssa.ForEachInst(fn, func(inst ssa.Instruction) { changed = st.propagateInst(inst) || changed })
		}
		if !changed {
			return
		}
	}
}

func (st *remoteTaintState) propagateYieldParams(fn *ssa.Function) bool {
	if !vetssa.IsYieldFunc(fn) {
		return false
	}
	_, _, rc := vetssa.FindYieldCall(st.ssaInfo, fn.Parent(), fn)
	if rc.Common == nil || !st.isTainted(rc.Common.Value) {
		return false
	}
	changed := false
	for _, p := range fn.Params {
		changed = st.mark(p) || changed
	}
	return changed
}

func (st *remoteTaintState) propagateInst(inst ssa.Instruction) bool {
	if ext, isExt := inst.(*ssa.Extract); isExt {
		return st.isTainted(ext.Tuple) && canCarryRemotePathValue(ext.Type()) && st.mark(ext)
	}
	if op, ok := vetssa.UnaryFlowOperand(inst, false); ok && !isFieldInst(inst) {
		val, isVal := inst.(ssa.Value)
		return isVal && st.isTainted(op) && st.mark(val)
	}
	switch ins := inst.(type) {
	case *ssa.Store:
		return st.propagateStore(ins)
	case *ssa.MapUpdate:
		return (st.isTainted(ins.Key) || st.isTainted(ins.Value)) && st.markTarget(ins.Map)
	case *ssa.MakeClosure:
		return st.propagateClosure(ins)
	case *ssa.FieldAddr:
		base, path, ok := extractFieldPath(ins)
		return ok && st.isFieldPathTainted(base, path) && st.mark(ins)
	case *ssa.Field:
		base, path, ok := extractFieldPath(ins)
		return (isRemotePathType(ins.Type()) || (ok && st.isFieldPathTainted(base, path))) && st.mark(ins)
	case *ssa.Call:
		return st.propagateCall(ins)
	case *ssa.BinOp:
		return ins.Op == token.ADD && (st.isTainted(ins.X) || st.isTainted(ins.Y)) && st.mark(ins)
	case *ssa.Phi:
		return slices.ContainsFunc(ins.Edges, st.isTainted) && st.mark(ins)
	default:
		return false
	}
}

func isFieldInst(inst ssa.Instruction) bool {
	_, isF := inst.(*ssa.Field)
	_, isFA := inst.(*ssa.FieldAddr)
	return isF || isFA
}

// propagateClosure 既向闭包 FreeVar 传播整体污点，也将被捕获结构体的字段级污点投影至 FreeVar（H4）。
func (st *remoteTaintState) propagateClosure(mc *ssa.MakeClosure) bool {
	changed := vetssa.PropagateClosureFreeVars(mc, st.tainted)
	fn, ok := mc.Fn.(*ssa.Function)
	if !ok || fn == nil || len(st.fields) == 0 {
		return changed
	}
	for i, b := range mc.Bindings {
		if i < len(fn.FreeVars) {
			changed = st.copyStructFieldTaints(b, fn.FreeVars[i]) || changed
		}
	}
	return changed
}

func (st *remoteTaintState) propagateStore(ins *ssa.Store) bool {
	if base, path, ok := extractFieldPath(ins.Addr); ok {
		changed := st.copyStructFieldTaintsWithPrefix(ins.Val, base, path)
		if st.isTainted(ins.Val) {
			changed = st.markFieldPath(base, path) || changed
		}
		return changed
	}
	changed := st.copyStructFieldTaintsWithPrefix(ins.Val, ins.Addr, "")
	if !st.isTainted(ins.Val) {
		return changed
	}
	return st.markTarget(ins.Addr) || changed
}

// copyStructFieldTaints 在整结构体值拷贝或闭包捕获时按字段路径精确复制污点，绝不污染非远端字段。
func (st *remoteTaintState) copyStructFieldTaints(src, dst ssa.Value) bool {
	return st.copyStructFieldTaintsWithPrefix(src, dst, "")
}

// copyStructFieldTaintsWithPrefix 支持向嵌套结构体字段（如 o.In = inner{Raw: rp}）投影全部子字段路径污点（H4）。
func (st *remoteTaintState) copyStructFieldTaintsWithPrefix(src, dst ssa.Value, prefix string) bool {
	if len(st.fields) == 0 {
		return false
	}
	srcRoots := vetssa.RootStorageValues(src, false)
	var dstRoots []ssa.Value
	changed := false
	for fk := range st.fields {
		if !slices.Contains(srcRoots, fk.base) {
			continue
		}
		if dstRoots == nil {
			dstRoots = vetssa.RootStorageValues(dst, false)
		}
		dstPath := fk.path
		if prefix != "" {
			dstPath = prefix + "." + fk.path
		}
		for _, dr := range dstRoots {
			changed = st.addFieldKey(dr, dstPath) || changed
		}
	}
	return changed
}

func (st *remoteTaintState) propagateCall(call *ssa.Call) bool {
	rc := vetssa.ResolveCall(st.ssaInfo, call)
	if rc.Kind == vetssa.CallBuiltin && rc.Builtin != nil {
		switch rc.Builtin.Name() {
		case "copy":
			return len(rc.UserArgs) >= 2 && st.isTainted(rc.UserArgs[1]) && st.markTarget(rc.UserArgs[0])
		case "append":
			if slices.ContainsFunc(rc.UserArgs, st.isTainted) {
				c1 := st.mark(call)
				c2 := len(rc.UserArgs) > 0 && st.markTarget(rc.UserArgs[0])
				return c1 || c2
			}
		}
		return false
	}
	hasInput := (rc.Recv != nil && st.isTainted(rc.Recv)) || slices.ContainsFunc(rc.UserArgs, st.isTainted)
	// B-6: 仅当返回类型本身可承载路径值（非普通结构体）时标污，避免 NewCopyTask(remote, local) 误染 LocalDir。
	return hasInput && canCarryRemotePathValue(call.Type()) && st.mark(call)
}

func (st *remoteTaintState) markTarget(v ssa.Value) bool {
	if base, path, ok := extractFieldPath(v); ok {
		return st.markFieldPath(base, path)
	}
	changed := false
	for _, root := range vetssa.RootStorageValues(v, false) {
		if base, path, ok := extractFieldPath(root); ok {
			changed = st.markFieldPath(base, path) || changed
			continue
		}
		changed = st.mark(root) || changed
		if fv, ok := root.(*ssa.FreeVar); ok {
			for _, orig := range vetssa.TraceFreeVarOrigins(fv) {
				changed = st.mark(orig) || changed
			}
		}
	}
	return changed
}

// isRemotePathType 判断类型 t 本身或其容器元素/泛型实参是否为 RemotePath，绝不展开普通结构体字段。
func isRemotePathType(t types.Type) bool {
	return vetutil.ContainsNonStructValue(t, isNamedRemotePath)
}

func isNamedRemotePath(n *types.Named) bool { return n.Obj() != nil && n.Obj().Name() == "RemotePath" }

// canCarryRemotePathValue 判断函数返回类型是否可直接携带路径值（排除非 RemotePath 的普通结构体）。
func canCarryRemotePathValue(t types.Type) bool {
	if t == nil {
		return false
	}
	type remoteElemCarrier interface{ Elem() types.Type }

	switch v := types.Unalias(t).(type) {
	case *types.Tuple:
		for i := range v.Len() {
			if canCarryRemotePathValue(v.At(i).Type()) {
				return true
			}
		}
		return false
	case *types.Named:
		return isNamedRemotePath(v) || canCarryRemotePathValue(v.Underlying())
	case *types.Basic:
		return v.Info()&types.IsString != 0 || v.Kind() == types.Byte || v.Kind() == types.Uint8 || v.Kind() == types.Rune
	case *types.Interface, *types.Signature:
		return true
	case *types.Map:
		return canCarryRemotePathValue(v.Key()) || canCarryRemotePathValue(v.Elem())
	case remoteElemCarrier:
		return canCarryRemotePathValue(v.Elem())
	default:
		return false
	}
}
