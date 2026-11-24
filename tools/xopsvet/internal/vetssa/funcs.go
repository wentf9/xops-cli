package vetssa

import (
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// PackageSSA 从 pass.ResultOf 提取 passes/buildssa 为当前包单次构建的 SSA 结果。
func PackageSSA(pass *analysis.Pass) *buildssa.SSA {
	if pass == nil || pass.ResultOf == nil {
		return nil
	}
	s, _ := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	return s
}

// AllFuncs 返回当前包全部需要分析的 SSA 函数（含 pkg.init、SrcFuncs 及递归 AnonFuncs）。
func AllFuncs(s *buildssa.SSA) []*ssa.Function {
	if s == nil {
		return nil
	}
	seen := make(map[*ssa.Function]bool)
	var out []*ssa.Function
	var visit func(*ssa.Function)
	visit = func(fn *ssa.Function) {
		if fn == nil || seen[fn] {
			return
		}
		seen[fn] = true
		out = append(out, fn)
		for _, anon := range fn.AnonFuncs {
			visit(anon)
		}
	}
	if s.Pkg != nil {
		visit(s.Pkg.Func("init"))
	}
	for _, fn := range s.SrcFuncs {
		visit(fn)
	}
	return out
}

// IsYieldFunc 判断 fn 是否为 Go 1.23+/1.27 range-over-func 合成的 yield 闭包。
func IsYieldFunc(fn *ssa.Function) bool { return fn != nil && fn.Synthetic == "range-over-func yield" }

// IsPkgInitFunc 判断 fn 是否为包级合成 init 函数（合并生产与白盒测试 var 初始化器）。
func IsPkgInitFunc(fn *ssa.Function) bool {
	return fn != nil && fn.Name() == "init" && fn.Synthetic == "package initializer"
}

// UnwrapOriginFunc 将泛型实例化包装器解包回源泛型 *ssa.Function（修复 Pkg == nil 问题）。
func UnwrapOriginFunc(fn *ssa.Function) *ssa.Function {
	for fn != nil && fn.Origin() != nil {
		fn = fn.Origin()
	}
	return fn
}

// OriginFuncObj 提取 SSA 函数对应的原始声明 *types.Func（自动取 Origin() 命中跨包 Fact）。
func OriginFuncObj(fn *ssa.Function) *types.Func {
	for _, cur := range []*ssa.Function{fn, UnwrapOriginFunc(fn)} {
		if cur != nil {
			if obj, ok := cur.Object().(*types.Func); ok && obj != nil {
				return obj.Origin()
			}
		}
	}
	return nil
}

// IsSamePackageFunc 判断 SSA 函数（兼容泛型包装器 Pkg == nil）是否属于当前分析包。
func IsSamePackageFunc(s *buildssa.SSA, fn *ssa.Function) bool {
	if s == nil || s.Pkg == nil || fn == nil {
		return false
	}
	orig := UnwrapOriginFunc(fn)
	if orig.Pkg == s.Pkg {
		return true
	}
	obj := OriginFuncObj(orig)
	return obj != nil && obj.Pkg() == s.Pkg.Pkg
}

// LookupPackageFunc 在当前包的 SSA 符号表中查找给定 *types.Func 对应的源 *ssa.Function。
func LookupPackageFunc(s *buildssa.SSA, fnObj *types.Func) *ssa.Function {
	if s == nil || s.Pkg == nil || s.Pkg.Prog == nil || fnObj == nil || fnObj.Origin().Pkg() != s.Pkg.Pkg {
		return nil
	}
	return UnwrapOriginFunc(s.Pkg.Prog.FuncValue(fnObj.Origin()))
}

// ResolvePos 为可能缺失源码位置（Pos() == token.NoPos）的 SSA 指令确定性解析有效源码位置（修复 C8）。
// 仅当接口包装操作数是单引用局部加载/字面量分配时优先取其位置，否则优先采用直接 Referrers 位置
// （防多次 MakeInterface 挤占声明行）；pkg.init 严禁跨文件借位。
func ResolvePos(pass *analysis.Pass, fn *ssa.Function, inst ssa.Instruction) token.Pos {
	if pos := resolveInstOwnPos(inst); pos.IsValid() {
		return pos
	}
	if pos := resolveExclusiveOperandPos(inst); pos.IsValid() {
		return pos
	}
	if pos := resolveInstReferrerPos(inst); pos.IsValid() {
		return pos
	}
	if pos := resolveInstOperandPos(inst); pos.IsValid() {
		return pos
	}
	if IsPkgInitFunc(fn) {
		return token.NoPos
	}
	if inst != nil && inst.Block() != nil {
		if pos := resolveBlockNearbyPos(inst.Block().Instrs, inst); pos.IsValid() {
			return pos
		}
	}
	if fn != nil && fn.Pos().IsValid() {
		return fn.Pos()
	}
	return firstProdFilePos(pass)
}

func firstProdFilePos(pass *analysis.Pass) token.Pos {
	if pass == nil || len(pass.Files) == 0 {
		return token.NoPos
	}
	for _, f := range pass.Files {
		if !vetutil.IsTestFile(pass, f) {
			return f.Package
		}
	}
	return pass.Files[0].Package
}

func resolveInstOwnPos(inst ssa.Instruction) token.Pos {
	if inst == nil {
		return token.NoPos
	}
	if inst.Pos().IsValid() {
		return inst.Pos()
	}
	if mc, ok := inst.(*ssa.MakeClosure); ok && mc.Fn != nil && mc.Fn.Pos().IsValid() {
		return mc.Fn.Pos()
	}
	return token.NoPos
}

func resolveInstReferrerPos(inst ssa.Instruction) token.Pos {
	if val, ok := inst.(ssa.Value); ok && val.Referrers() != nil {
		for _, ref := range *val.Referrers() {
			if ref != nil && ref.Pos().IsValid() {
				return ref.Pos()
			}
		}
	}
	return token.NoPos
}

func resolveExclusiveOperandPos(inst ssa.Instruction) token.Pos {
	val, ok := inst.(ssa.Value)
	if !ok {
		return token.NoPos
	}
	unwrapped := UnwrapInterface(val)
	if unwrapped == val || unwrapped.Referrers() == nil || len(*unwrapped.Referrers()) != 1 {
		return token.NoPos
	}
	switch op := unwrapped.(type) {
	case *ssa.Alloc, *ssa.UnOp:
		if opInst, isInst := op.(ssa.Instruction); isInst && opInst.Block() == inst.Block() && opInst.Pos().IsValid() {
			return opInst.Pos()
		}
	}
	return token.NoPos
}

func resolveInstOperandPos(inst ssa.Instruction) token.Pos {
	if val, ok := inst.(ssa.Value); ok {
		if unwrapped := UnwrapInterface(val); unwrapped != val {
			if opInst, isInst := unwrapped.(ssa.Instruction); isInst && opInst.Block() == inst.Block() && opInst.Pos().IsValid() {
				return opInst.Pos()
			}
		}
	}
	return token.NoPos
}

func resolveBlockNearbyPos(instrs []ssa.Instruction, target ssa.Instruction) token.Pos {
	idx := slices.Index(instrs, target)
	if idx < 0 {
		for _, ins := range instrs {
			if ins.Pos().IsValid() {
				return ins.Pos()
			}
		}
		return token.NoPos
	}
	for d := 1; idx-d >= 0 || idx+d < len(instrs); d++ {
		if idx+d < len(instrs) && instrs[idx+d].Pos().IsValid() {
			return instrs[idx+d].Pos()
		}
		if idx-d >= 0 && instrs[idx-d].Pos().IsValid() {
			return instrs[idx-d].Pos()
		}
	}
	return token.NoPos
}

// IsInstInTestFile 基于解析后的指令位置判定指令是否位于 *_test.go（绝不依赖混合生产/测试的 fn.Pos()）。
func IsInstInTestFile(pass *analysis.Pass, fn *ssa.Function, inst ssa.Instruction) bool {
	return vetutil.IsPosInTestFile(pass, ResolvePos(pass, fn, inst))
}

// FuncSyntaxRange 安全提取 SSA 函数对应的语法起止位置（兼容 FuncDecl / FuncLit / RangeStmt）。
func FuncSyntaxRange(fn *ssa.Function) (token.Pos, token.Pos, bool) {
	if fn != nil && fn.Syntax() != nil {
		syn := fn.Syntax()
		return syn.Pos(), syn.End(), syn.Pos().IsValid() && syn.End().IsValid()
	}
	return token.NoPos, token.NoPos, false
}

// IsBoundWrapper 判断 fn 是否为 go/ssa 为方法值（recv.M）合成的 $bound 闭包包装器。
func IsBoundWrapper(fn *ssa.Function) bool {
	return fn != nil && (strings.HasSuffix(fn.Name(), "$bound") || strings.HasPrefix(fn.Synthetic, "bound method wrapper"))
}

// IsThunkWrapper 判断 fn 是否为 go/ssa 为方法表达式（(*T).M）合成的 $thunk 包装器。
func IsThunkWrapper(fn *ssa.Function) bool {
	return fn != nil && (strings.HasSuffix(fn.Name(), "$thunk") || strings.HasPrefix(fn.Synthetic, "thunk for "))
}
