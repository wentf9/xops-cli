package vetssa

import (
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// IsFreshLocalSlice 判断 SSA 值是否必为当前函数体内全新分配的局部切片（防菱形 DAG 误杀，L4）。
func IsFreshLocalSlice(v ssa.Value) bool { return isFreshLocalSlice(v, make(map[ssa.Value]bool)) }

func isFreshLocalSlice(v ssa.Value, visiting map[ssa.Value]bool) bool {
	if v == nil || visiting[v] {
		return false
	}
	visiting[v] = true
	defer delete(visiting, v)
	switch val := v.(type) {
	case *ssa.MakeSlice:
		return true
	case *ssa.Const:
		return val.IsNil()
	case *ssa.Slice:
		if alloc, ok := val.X.(*ssa.Alloc); ok {
			return isLocalArrayAlloc(alloc)
		}
		return isFreshLocalSlice(val.X, visiting)
	case *ssa.Convert:
		if _, ok := types.Unalias(val.Type()).Underlying().(*types.Slice); !ok {
			return false
		}
		b, ok := types.Unalias(val.X.Type()).Underlying().(*types.Basic)
		return ok && (b.Kind() == types.UntypedNil || b.Info()&types.IsString != 0)
	case *ssa.ChangeType:
		return isFreshLocalSlice(val.X, visiting)
	case *ssa.Phi:
		return len(val.Edges) > 0 && !slices.ContainsFunc(val.Edges, func(e ssa.Value) bool { return !isFreshLocalSlice(e, visiting) })
	default:
		return false
	}
}

func isLocalArrayAlloc(alloc *ssa.Alloc) bool {
	if alloc == nil {
		return false
	}
	if alloc.Comment == "makeslice" {
		return true
	}
	ptr, ok := types.Unalias(alloc.Type()).(*types.Pointer)
	if !ok {
		return false
	}
	_, isArr := types.Unalias(ptr.Elem()).Underlying().(*types.Array)
	return isArr
}

func rootStorageStep(v ssa.Value, traverseFields bool) (ssa.Value, bool) {
	switch val := v.(type) {
	case *ssa.Slice:
		return val.X, true
	case *ssa.SliceToArrayPointer:
		return val.X, true
	case *ssa.IndexAddr:
		return val.X, true
	case *ssa.FieldAddr:
		return val.X, traverseFields
	case *ssa.ChangeType:
		return val.X, true
	case *ssa.Convert:
		return val.X, true
	case *ssa.MultiConvert:
		return val.X, true
	case *ssa.MakeInterface:
		return val.X, true
	case *ssa.ChangeInterface:
		return val.X, true
	}
	return nil, false
}

// TraceFreeVarOrigins 将 *ssa.FreeVar 沿外层 MakeClosure.Bindings 递归回溯至根对象（含常量容量 Slice/FieldAddr，B-5）。
func TraceFreeVarOrigins(fv *ssa.FreeVar) []ssa.Value {
	var origins []ssa.Value
	traceFreeVar(fv, make(map[ssa.Value]bool), &origins)
	return origins
}

func traceFreeVar(v ssa.Value, seen map[ssa.Value]bool, origins *[]ssa.Value) {
	if v == nil || seen[v] {
		return
	}
	seen[v] = true
	if next, ok := rootStorageStep(v, true); ok {
		traceFreeVar(next, seen, origins)
		return
	}
	switch val := v.(type) {
	case *ssa.FreeVar:
		traceFreeVarFromParent(val, seen, origins)
	case *ssa.Phi:
		for _, e := range val.Edges {
			traceFreeVar(e, seen, origins)
		}
	default:
		*origins = append(*origins, val)
	}
}

func traceFreeVarFromParent(fv *ssa.FreeVar, seen map[ssa.Value]bool, origins *[]ssa.Value) {
	fn, fvIdx := fv.Parent(), -1
	if fn != nil && fn.Parent() != nil {
		fvIdx = slices.Index(fn.FreeVars, fv)
	}
	if fvIdx < 0 {
		*origins = append(*origins, fv)
		return
	}
	found := false
	ForEachInst(fn.Parent(), func(inst ssa.Instruction) {
		if mc, ok := inst.(*ssa.MakeClosure); ok && mc.Fn == fn && fvIdx < len(mc.Bindings) {
			found = true
			traceFreeVar(mc.Bindings[fvIdx], seen, origins)
		}
	})
	if !found {
		*origins = append(*origins, fv)
	}
}

// IsValueOwnedInScope 判断根存储对象是否声明在指定源码区间 [scopeStart, scopeEnd] 内的新建局部存储。
func IsValueOwnedInScope(root ssa.Value, scopeStart, scopeEnd token.Pos) bool {
	if root == nil || !scopeStart.IsValid() || !scopeEnd.IsValid() {
		return false
	}
	switch r := root.(type) {
	case *ssa.Alloc, *ssa.MakeSlice, *ssa.MakeMap:
		return r.Pos().IsValid() && r.Pos() >= scopeStart && r.Pos() <= scopeEnd
	default:
		return false
	}
}

// IsStdlibSyncIter 判断函数是否为 Go 标准库纯数据同步 range-over-func 迭代器构造器（剔除带用户回调的 FieldsFuncSeq）。
func IsStdlibSyncIter(obj *types.Func) bool {
	if obj == nil {
		return false
	}
	switch vetutil.ObjectPkgPath(obj) {
	case "slices":
		return slices.Contains([]string{"All", "Values", "Backward", "Chunk"}, obj.Name())
	case "maps":
		return slices.Contains([]string{"All", "Keys", "Values"}, obj.Name())
	case "bytes", "strings":
		return slices.Contains([]string{"Lines", "SplitSeq", "SplitAfterSeq", "FieldsSeq"}, obj.Name())
	default:
		return false
	}
}

// FindYieldCall 在父函数 parentFn 中定位消费 range-over-func yield 闭包的调用指令及 MakeClosure。
func FindYieldCall(s *buildssa.SSA, parentFn, yieldFn *ssa.Function) (ssa.CallInstruction, *ssa.MakeClosure, ResolvedCall) {
	if parentFn == nil || !IsYieldFunc(yieldFn) {
		return nil, nil, ResolvedCall{}
	}
	var foundCall ssa.CallInstruction
	var foundMC *ssa.MakeClosure
	ForEachInst(parentFn, func(inst ssa.Instruction) {
		if foundCall == nil {
			if mc, ok := inst.(*ssa.MakeClosure); ok && mc.Fn == yieldFn {
				if callInst := firstCallReferrer(mc); callInst != nil {
					foundCall, foundMC = callInst, mc
				}
			}
		}
	})
	if foundCall == nil {
		return nil, nil, ResolvedCall{}
	}
	return foundCall, foundMC, ResolveCall(s, foundCall)
}

func firstCallReferrer(v ssa.Value) ssa.CallInstruction {
	if v == nil || v.Referrers() == nil {
		return nil
	}
	for _, ref := range *v.Referrers() {
		if callInst, ok := ref.(ssa.CallInstruction); ok {
			return callInst
		}
	}
	return nil
}

// IsRuntimeSecretDo 判断调用目标是否为 Go 1.27 标准库 runtime/secret.Do（唯一标准库同步闭包白名单）。
func IsRuntimeSecretDo(obj *types.Func) bool { return vetutil.IsPkgSymbol(obj, "runtime/secret", "Do") }
