package osboundary

import (
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

type fieldKey struct {
	base  ssa.Value
	field int
}

type remoteTaintState struct {
	ssaInfo *buildssa.SSA
	tainted map[ssa.Value]bool
	fields  map[fieldKey]bool
}

// checkRemotePathFilepath 基于 vetssa 在全包 SSA 函数上执行字段敏感（field-sensitive）的不动点传播，
// 拦截对 RemotePath 及其派生值调用 path/filepath.*，同时保证含 RemotePath 字段的结构体其非远端字段零误报（B6c + M2）。
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

func (st *remoteTaintState) markField(base ssa.Value, field int) bool {
	changed := false
	for _, root := range vetssa.RootStorageValues(base, false) {
		if k := (fieldKey{base: root, field: field}); !st.fields[k] {
			st.fields[k], changed = true, true
		}
	}
	return changed
}

func (st *remoteTaintState) isFieldTainted(base ssa.Value, field int) bool {
	return slices.ContainsFunc(vetssa.RootStorageValues(base, false), func(root ssa.Value) bool {
		return st.fields[fieldKey{base: root, field: field}]
	})
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
	if op, ok := vetssa.UnaryFlowOperand(inst, false); ok && !isFieldInst(inst) {
		val, isVal := inst.(ssa.Value)
		return isVal && st.isTainted(op) && st.mark(val)
	}
	switch ins := inst.(type) {
	case *ssa.Store:
		return st.propagateStore(ins)
	case *ssa.MapUpdate:
		return (st.isTainted(ins.Key) || st.isTainted(ins.Value)) && st.markRootsNonField(ins.Map)
	case *ssa.MakeClosure:
		return vetssa.PropagateClosureFreeVars(ins, st.tainted)
	case *ssa.FieldAddr:
		return st.isFieldTainted(ins.X, ins.Field) && st.mark(ins)
	case *ssa.Field:
		return (st.isTainted(ins.X) || st.isFieldTainted(ins.X, ins.Field)) && st.mark(ins)
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

func (st *remoteTaintState) propagateStore(ins *ssa.Store) bool {
	if fa, ok := ins.Addr.(*ssa.FieldAddr); ok {
		return st.isTainted(ins.Val) && st.markField(fa.X, fa.Field)
	}
	changed := st.copyStructFieldTaints(ins.Val, ins.Addr)
	if !st.isTainted(ins.Val) {
		return changed
	}
	for _, root := range vetssa.RootStorageValues(ins.Addr, false) {
		if fa, ok := root.(*ssa.FieldAddr); ok {
			changed = st.markField(fa.X, fa.Field) || changed
		} else {
			changed = st.mark(root) || changed
		}
	}
	return changed
}

// copyStructFieldTaints 在整结构体值拷贝时按字段索引精确复制单字段污点，不污染非远端字段。
func (st *remoteTaintState) copyStructFieldTaints(src, dst ssa.Value) bool {
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
		for _, dr := range dstRoots {
			if k := (fieldKey{base: dr, field: fk.field}); !st.fields[k] {
				st.fields[k], changed = true, true
			}
		}
	}
	return changed
}

func (st *remoteTaintState) propagateCall(call *ssa.Call) bool {
	rc := vetssa.ResolveCall(st.ssaInfo, call)
	if rc.Kind == vetssa.CallBuiltin && rc.Builtin != nil {
		switch rc.Builtin.Name() {
		case "copy":
			return len(rc.UserArgs) >= 2 && st.isTainted(rc.UserArgs[1]) && st.markRootsNonField(rc.UserArgs[0])
		case "append":
			if slices.ContainsFunc(rc.UserArgs, st.isTainted) {
				c1 := st.mark(call)
				c2 := len(rc.UserArgs) > 0 && st.markRootsNonField(rc.UserArgs[0])
				return c1 || c2
			}
		}
		return false
	}
	return ((rc.Recv != nil && st.isTainted(rc.Recv)) || slices.ContainsFunc(rc.UserArgs, st.isTainted)) && st.mark(call)
}

func (st *remoteTaintState) markRootsNonField(v ssa.Value) bool {
	changed := false
	for _, root := range vetssa.RootStorageValues(v, false) {
		if _, isField := root.(*ssa.FieldAddr); !isField && st.mark(root) {
			changed = true
		}
	}
	return changed
}

// isRemotePathType 判断类型 t 本身或其容器元素/泛型实参是否为 RemotePath，绝不展开普通结构体字段（B6c）。
func isRemotePathType(t types.Type) bool { return hasRemotePathType(t, make(map[types.Type]bool)) }

type elemCarrier interface{ Elem() types.Type }

func hasRemotePathType(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok {
		return namedIsRemotePath(named, seen)
	}
	switch v := t.(type) {
	case *types.Map:
		return hasRemotePathType(v.Key(), seen) || hasRemotePathType(v.Elem(), seen)
	case elemCarrier:
		return hasRemotePathType(v.Elem(), seen)
	default:
		return false
	}
}

func namedIsRemotePath(named *types.Named, seen map[types.Type]bool) bool {
	if named.Obj() != nil && named.Obj().Name() == "RemotePath" {
		return true
	}
	if seen[named] {
		return false
	}
	seen[named] = true
	if typeArgs := named.TypeArgs(); typeArgs != nil {
		for i := range typeArgs.Len() {
			if hasRemotePathType(typeArgs.At(i), seen) {
				return true
			}
		}
	}
	_, isStruct := named.Underlying().(*types.Struct)
	return !isStruct && hasRemotePathType(named.Underlying(), seen)
}
