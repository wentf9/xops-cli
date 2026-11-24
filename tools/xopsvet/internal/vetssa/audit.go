package vetssa

import (
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
)

// AuditKey 为递归函数审计提供确定性防环与去重键（按目标函数 + 种子形参掩码 + 捕获 FreeVar 掩码）。
type AuditKey struct {
	Fn        *ssa.Function
	ParamMask uint64
	FreeMask  uint64
}

// MakeAuditKey 构造给定函数与种子集合的唯一 AuditKey。
func MakeAuditKey(fn *ssa.Function, seedParams map[int]bool, captured map[ssa.Value]ScopeRange) AuditKey {
	var pm, fm uint64
	for idx := range seedParams {
		if idx >= 0 && idx < 64 {
			pm |= 1 << uint(idx)
		}
	}
	for i, fv := range fn.FreeVars {
		if _, ok := captured[fv]; i < 64 && ok {
			fm |= 1 << uint(i)
		}
	}
	return AuditKey{Fn: fn, ParamMask: pm, FreeMask: fm}
}

// AuditTracker 统一管理跨函数递归审计的深度上限、环路防护与无捕获去重（供 secrettaint/linearlease 共享）。
type AuditTracker struct {
	audited, inProgress map[AuditKey]bool
}

// NewAuditTracker 构造递归函数审计跟踪器。
func NewAuditTracker() *AuditTracker {
	return &AuditTracker{audited: make(map[AuditKey]bool), inProgress: make(map[AuditKey]bool)}
}

// Enter 尝试进入目标函数审计；若已超出深度、处于环路或已审计过则返回 (nil, false)。
func (t *AuditTracker) Enter(fn *ssa.Function, seedParams map[int]bool, captured map[ssa.Value]ScopeRange, depth, maxDepth int) (func(), bool) {
	if fn == nil || len(fn.Blocks) == 0 || depth > maxDepth {
		return nil, false
	}
	key := MakeAuditKey(fn, seedParams, captured)
	if t.inProgress[key] || (len(captured) == 0 && t.audited[key]) {
		return nil, false
	}
	t.inProgress[key] = true
	if len(captured) == 0 {
		t.audited[key] = true
	}
	return func() { delete(t.inProgress, key) }, true
}

// SeedScopeParams 初始化函数体的受控值集合与不可写调用方形参集合（C4 CallerParam 隔离）。
func SeedScopeParams(fn *ssa.Function, seedParams map[int]bool, captured map[ssa.Value]ScopeRange, ownScope ScopeRange) (map[ssa.Value]ScopeRange, map[ssa.Value]bool) {
	scoped := make(map[ssa.Value]ScopeRange, len(seedParams)+len(captured))
	callerParams := make(map[ssa.Value]bool, len(fn.Params))
	for i, p := range fn.Params {
		if seedParams[i] {
			scoped[p] = ownScope
		} else {
			callerParams[p] = true
		}
	}
	for v, sc := range captured {
		scoped[v] = sc
	}
	return scoped, callerParams
}

// ForEachInst 顺序遍历单个 SSA 函数全部基本块的指令。
func ForEachInst(fn *ssa.Function, visit func(ssa.Instruction)) {
	for _, block := range fn.Blocks {
		for _, inst := range block.Instrs {
			visit(inst)
		}
	}
}

// ForEachFuncInst 顺序遍历一组 SSA 函数全部基本块的指令。
func ForEachFuncInst(funcs []*ssa.Function, visit func(*ssa.Function, ssa.Instruction)) {
	for _, fn := range funcs {
		ForEachInst(fn, func(inst ssa.Instruction) { visit(fn, inst) })
	}
}

// RunFixpoint 在单个 SSA 函数上迭代执行单指令传播函数直至不动点收敛。
func RunFixpoint(fn *ssa.Function, step func(ssa.Instruction) bool) {
	for {
		changed := false
		ForEachInst(fn, func(inst ssa.Instruction) { changed = step(inst) || changed })
		if !changed {
			return
		}
	}
}

// AppendDiag 使用确定性 ResolvePos 向诊断切片追加一条 SSA 位置诊断。
func AppendDiag(pass *analysis.Pass, diags *[]vetutil.Diag, fn *ssa.Function, inst ssa.Instruction, msg string) {
	if pos := ResolvePos(pass, fn, inst); pos.IsValid() {
		*diags = append(*diags, vetutil.Diag{Pos: pos, End: pos, Msg: msg})
	}
}

// HasRecvParam 若 SSA 函数具备方法接收者形参则返回偏移 1，否则返回 0。
func HasRecvParam(fn *ssa.Function) int {
	if fn != nil && fn.Signature != nil && fn.Signature.Recv() != nil {
		return 1
	}
	return 0
}

// CollectCallSeeds 收集调用点中命中的受控接收者与实参对应的被调形参索引（maxParams<=0 表示不设上界）。
func CollectCallSeeds(rc ResolvedCall, scoped map[ssa.Value]ScopeRange, maxParams int, allow func(ssa.Value) bool) map[int]bool {
	seeds, offset := make(map[int]bool), 0
	if rc.Recv != nil {
		if _, ok := scoped[rc.Recv]; ok && (allow == nil || allow(rc.Recv)) {
			seeds[0] = true
		}
		offset = 1
	}
	for i, arg := range rc.UserArgs {
		if idx := offset + i; maxParams > 0 && idx >= maxParams {
			break
		} else if _, ok := scoped[arg]; ok && (allow == nil || allow(arg)) {
			seeds[idx] = true
		}
	}
	return seeds
}

// SeedTypedValues 在一组 SSA 函数中为所有满足 match(t) 的形参与指令值注入初始污点。
func SeedTypedValues(funcs []*ssa.Function, match func(types.Type) bool, mark func(ssa.Value) bool) {
	for _, fn := range funcs {
		for _, p := range fn.Params {
			if match(p.Type()) {
				mark(p)
			}
		}
		ForEachInst(fn, func(inst ssa.Instruction) {
			if val, ok := inst.(ssa.Value); ok && match(val.Type()) {
				mark(val)
			}
		})
	}
}

// PropagateClosureFreeVars 将布尔污点表沿 MakeClosure.Bindings 传播至目标闭包 FreeVars。
func PropagateClosureFreeVars(mc *ssa.MakeClosure, tainted map[ssa.Value]bool) bool {
	target, ok := mc.Fn.(*ssa.Function)
	if !ok {
		return false
	}
	changed := false
	for i, b := range mc.Bindings {
		if i < len(target.FreeVars) && tainted[b] && !tainted[target.FreeVars[i]] {
			tainted[target.FreeVars[i]], changed = true, true
		}
	}
	return changed
}
