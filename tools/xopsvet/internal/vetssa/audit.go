package vetssa

import (
	"go/types"
	"slices"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
)

// EnterStatus 表示进入递归函数审计的状态（正常进入、已缓存/环路跳过、超深 Fail-Closed）。
type EnterStatus uint8

const (
	EnterOK EnterStatus = iota
	EnterSkip
	EnterDepthExceeded
)

// AuditKey 为递归函数审计提供确定性防环与去重键（区分 depth==0 与 depth>0，兼容超 64 参数，C6/M8）。
type AuditKey struct {
	Fn        *ssa.Function
	ParamMask uint64
	FreeMask  uint64
	TopLevel  bool
	ExtraSig  string
}

// MakeAuditKey 构造给定函数与种子集合的唯一 AuditKey。
func MakeAuditKey(fn *ssa.Function, seedParams map[int]bool, captured map[ssa.Value]ScopeRange, topLevel bool) AuditKey {
	if fn == nil {
		return AuditKey{}
	}
	var pm, fm uint64
	var extra []string
	for idx := range seedParams {
		if idx >= 0 && idx < 64 {
			pm |= 1 << uint(idx)
		} else if idx >= 64 {
			extra = append(extra, "p"+strconv.Itoa(idx))
		}
	}
	for i, fv := range fn.FreeVars {
		if _, ok := captured[fv]; ok {
			if i < 64 {
				fm |= 1 << uint(i)
			} else {
				extra = append(extra, "f"+strconv.Itoa(i))
			}
		}
	}
	slices.Sort(extra)
	return AuditKey{Fn: fn, ParamMask: pm, FreeMask: fm, TopLevel: topLevel, ExtraSig: strings.Join(extra, ",")}
}

// AuditTracker 统一管理跨函数递归审计的深度上限、环路防护、最小深度去重与返回值污点掩码缓存。
type AuditTracker struct {
	minDepth   map[AuditKey]int
	inProgress map[AuditKey]bool
	returnMask map[AuditKey]uint64
}

// NewAuditTracker 构造递归函数审计跟踪器。
func NewAuditTracker() *AuditTracker {
	return &AuditTracker{minDepth: map[AuditKey]int{}, inProgress: map[AuditKey]bool{}, returnMask: map[AuditKey]uint64{}}
}

// Enter 尝试进入目标函数审计；返回键、退出回调与三态结果。
func (t *AuditTracker) Enter(fn *ssa.Function, seedParams map[int]bool, captured map[ssa.Value]ScopeRange, depth, maxDepth int) (AuditKey, func(), EnterStatus) {
	if fn == nil || len(fn.Blocks) == 0 {
		return AuditKey{}, nil, EnterSkip
	}
	if depth > maxDepth {
		return AuditKey{}, nil, EnterDepthExceeded
	}
	key := MakeAuditKey(fn, seedParams, captured, depth == 0)
	if t.inProgress[key] {
		return key, nil, EnterSkip
	}
	if prevDepth, ok := t.minDepth[key]; len(captured) == 0 && ok && depth >= prevDepth {
		return key, nil, EnterSkip
	}
	t.inProgress[key] = true
	if len(captured) == 0 {
		t.minDepth[key] = depth
	}
	return key, func() { delete(t.inProgress, key) }, EnterOK
}

// RecordReturnMask 记录审计函数的返回值污点槽位掩码；ReturnMask 查询缓存值。
func (t *AuditTracker) RecordReturnMask(key AuditKey, mask uint64) {
	if t != nil && mask != 0 {
		t.returnMask[key] |= mask
	}
}
func (t *AuditTracker) ReturnMask(key AuditKey) uint64 {
	if t == nil {
		return 0
	}
	return t.returnMask[key]
}

// RunScopedFixpoint 迭代执行单函数内传播与嵌套审计直至受控值集合收敛，并回冲 FreeVar 至外层（LL-1/C5）。
func RunScopedFixpoint(fn *ssa.Function, scoped, outerShared map[ssa.Value]ScopeRange, prop func(ssa.Instruction) bool, nested func(ssa.Instruction)) {
	for {
		RunFixpoint(fn, prop)
		before := len(scoped)
		ForEachInst(fn, nested)
		if len(scoped) == before {
			break
		}
	}
	FlushFreeVarsToOuter(fn, scoped, outerShared)
}

// ReportDepthExceeded 在超深审计触发 Fail-Closed 时向调用点位置追加诊断。
func ReportDepthExceeded(pass *analysis.Pass, diags *[]vetutil.Diag, fn *ssa.Function, siteInst ssa.Instruction, msg string) {
	reportFn := fn
	if siteInst != nil && siteInst.Parent() != nil {
		reportFn = siteInst.Parent()
	}
	AppendDiag(pass, diags, reportFn, siteInst, msg)
}

// SeedScopeParams 初始化函数体的受控值集合与不可写调用方形参集合（CallerParam 隔离）。
func SeedScopeParams(fn *ssa.Function, seedParams map[int]bool, captured map[ssa.Value]ScopeRange, ownScope ScopeRange) (map[ssa.Value]ScopeRange, map[ssa.Value]bool) {
	scoped, callerParams := make(map[ssa.Value]ScopeRange, len(seedParams)+len(captured)), make(map[ssa.Value]bool)
	if fn == nil {
		return scoped, callerParams
	}
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

// ForEachInst / ForEachFuncInst / RunFixpoint 提供统一 SSA 指令遍历与不动点引擎。
func ForEachInst(fn *ssa.Function, visit func(ssa.Instruction)) {
	if fn == nil || visit == nil {
		return
	}
	for _, block := range fn.Blocks {
		for _, inst := range block.Instrs {
			visit(inst)
		}
	}
}
func ForEachFuncInst(funcs []*ssa.Function, visit func(*ssa.Function, ssa.Instruction)) {
	for _, fn := range funcs {
		ForEachInst(fn, func(inst ssa.Instruction) { visit(fn, inst) })
	}
}
func RunFixpoint(fn *ssa.Function, step func(ssa.Instruction) bool) {
	if fn == nil || step == nil {
		return
	}
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
	pos := ResolvePos(pass, fn, inst)
	if !pos.IsValid() && IsPkgInitFunc(fn) && pass != nil {
		pos = firstProdFilePos(pass)
	}
	if pos.IsValid() {
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
	if match == nil || mark == nil {
		return
	}
	for _, fn := range funcs {
		if fn == nil {
			continue
		}
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
	if mc == nil || tainted == nil {
		return false
	}
	target, ok := mc.Fn.(*ssa.Function)
	if !ok || target == nil {
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
