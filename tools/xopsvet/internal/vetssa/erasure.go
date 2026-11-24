package vetssa

import (
	"go/ast"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// ErasureConfig 配置统一防擦除守卫 CheckNoErasure 的匹配规则（MatchType 应使用 vetutil.ContainsValueType）。
type ErasureConfig struct {
	MatchType          func(types.Type) bool
	MatchTargetIface   func(*types.Interface) bool
	CheckInstances     bool
	MatchInstance      func(arg types.Type) bool
	AllowMakeInterface func(fn *ssa.Function, mi *ssa.MakeInterface) bool
	SkipInst           func(fn *ssa.Function, inst ssa.Instruction) bool
	SkipInstance       func(ident *ast.Ident) bool
	Message            string
}

// CheckNoErasure 扫描全包 SSA 函数及泛型实例化表，拦截 MakeInterface/ChangeInterface/ChangeType/TypeAssert 与泛型擦除。
func CheckNoErasure(pass *analysis.Pass, s *buildssa.SSA, cfg ErasureConfig) []vetutil.Diag {
	if pass == nil || cfg.MatchType == nil {
		return nil
	}
	var diags []vetutil.Diag
	if s != nil {
		ForEachFuncInst(AllFuncs(s), func(fn *ssa.Function, inst ssa.Instruction) {
			if (cfg.SkipInst == nil || !cfg.SkipInst(fn, inst)) && matchesErasureInst(fn, inst, cfg) {
				AppendDiag(pass, &diags, fn, inst, cfg.Message)
			}
		})
	}
	if cfg.CheckInstances && pass.TypesInfo != nil {
		appendInstanceErasures(pass, cfg, &diags)
	}
	return diags
}

func appendInstanceErasures(pass *analysis.Pass, cfg ErasureConfig, diags *[]vetutil.Diag) {
	for ident, inst := range pass.TypesInfo.Instances {
		if ident != nil && ident.Pos().IsValid() && inst.TypeArgs != nil &&
			(cfg.SkipInstance == nil || !cfg.SkipInstance(ident)) && instanceHasBlockedArg(inst.TypeArgs, cfg) {
			*diags = append(*diags, vetutil.Diag{Pos: ident.Pos(), End: ident.End(), Msg: cfg.Message})
		}
	}
}

func matchesErasureInst(fn *ssa.Function, inst ssa.Instruction, cfg ErasureConfig) bool {
	switch ins := inst.(type) {
	case *ssa.MakeInterface:
		return cfg.MatchType(ins.X.Type()) && matchesTargetIface(ins.Type(), cfg.MatchTargetIface) &&
			(cfg.AllowMakeInterface == nil || !cfg.AllowMakeInterface(fn, ins))
	case *ssa.ChangeInterface:
		return cfg.MatchType(ins.X.Type()) && matchesTargetIface(ins.Type(), cfg.MatchTargetIface)
	case *ssa.ChangeType:
		return matchesIfaceCast(ins.X.Type(), ins.Type(), cfg)
	case *ssa.TypeAssert:
		return matchesIfaceCast(ins.X.Type(), ins.AssertedType, cfg)
	default:
		return false
	}
}

func matchesIfaceCast(src, dst types.Type, cfg ErasureConfig) bool {
	iface, ok := underlyingInterface(dst)
	return ok && cfg.MatchType(src) && (cfg.MatchTargetIface == nil || cfg.MatchTargetIface(iface))
}

func matchesTargetIface(t types.Type, pred func(*types.Interface) bool) bool {
	if pred == nil {
		return true
	}
	iface, ok := underlyingInterface(t)
	return ok && pred(iface)
}

func underlyingInterface(t types.Type) (*types.Interface, bool) {
	if t == nil {
		return nil, false
	}
	iface, ok := types.Unalias(t).Underlying().(*types.Interface)
	return iface, ok && iface != nil
}

func instanceHasBlockedArg(typeArgs *types.TypeList, cfg ErasureConfig) bool {
	for i := range typeArgs.Len() {
		if arg := typeArgs.At(i); cfg.MatchType(arg) && (cfg.MatchInstance == nil || cfg.MatchInstance(arg)) {
			return true
		}
	}
	return false
}
