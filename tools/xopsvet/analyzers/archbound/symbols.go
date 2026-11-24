package archbound

import (
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

const portsPkgPath = vetutil.ModulePrefix + "/core/ports"

type symDiag struct {
	pos token.Pos
	end token.Pos
	msg string
}

type lineKey struct {
	file string
	line int
}

func checkSymbolBoundaries(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	if pass.TypesInfo == nil {
		return
	}
	switch pkgInfo.Layer {
	case vetutil.LayerCoreDomain:
		checkDomainTimeSymbols(pass)
	case vetutil.LayerCoreOSFS:
		checkOSFSNetSymbols(pass)
	case vetutil.LayerCoreMCPRuntime:
		checkMCPOperatorReadFS(pass)
	}
}

func checkDomainTimeSymbols(pass *analysis.Pass) {
	var diags []symDiag
	for ident, obj := range pass.TypesInfo.Uses {
		if ident == nil || !ident.Pos().IsValid() {
			continue
		}
		if isBannedDomainTimeSymbol(obj) {
			diags = append(diags, symDiag{
				pos: ident.Pos(),
				end: ident.End(),
				msg: "archbound: core/domain/** 禁止使用非确定性时钟或定时符号 time." + obj.Name(),
			})
		}
	}
	reportSortedDiags(pass, diags)
}

func isBannedDomainTimeSymbol(obj types.Object) bool {
	return vetutil.IsPkgSymbol(
		obj,
		"time",
		"Now",
		"Since",
		"Until",
		"NewTimer",
		"NewTicker",
		"After",
		"Sleep",
		"AfterFunc",
		"Tick",
	)
}

// checkMCPOperatorReadFS 物理封禁 core/internal/mcpruntime 对 ports.OperatorReadFS 的一切直接与间接使用：
// 覆盖 Uses（显式引用/类型别名）、Defs（局部变量/字段/参数类型）、Selections（方法/字段选择）及
// TypesInfo.Types（匿名表达式返回值直传/返回，如 consumeAny(session.LeakOpFS())）；
// 后三者均采用 vetutil.TypeContainsLocalNamed，确保合法持有 *session.Service（内部字段含 OperatorReadFS）零误报。
// 所有命中项先按 (Pos, End) 确定性排序再按源码行去重输出，消除 Go map 随机遍历导致的诊断抖动。
func checkMCPOperatorReadFS(pass *analysis.Pass) {
	var diags []symDiag
	addDiag := func(pos, end token.Pos) {
		if !pos.IsValid() {
			return
		}
		diags = append(diags, symDiag{
			pos: pos,
			end: end,
			msg: "archbound: core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS",
		})
	}

	collectMCPUses(pass.TypesInfo, addDiag)
	collectMCPDefs(pass.Pkg, pass.TypesInfo, addDiag)
	collectMCPSelections(pass.Pkg, pass.TypesInfo, addDiag)
	collectMCPExprTypes(pass.Pkg, pass.TypesInfo, addDiag)
	reportDedupedLineDiags(pass, diags)
}

func collectMCPUses(info *types.Info, addDiag func(pos, end token.Pos)) {
	for ident, obj := range info.Uses {
		if ident == nil || obj == nil {
			continue
		}
		if vetutil.IsPkgSymbol(obj, portsPkgPath, "OperatorReadFS") {
			addDiag(ident.Pos(), ident.End())
		}
	}
}

func collectMCPDefs(pkg *types.Package, info *types.Info, addDiag func(pos, end token.Pos)) {
	for ident, obj := range info.Defs {
		if ident == nil || obj == nil || obj.Type() == nil {
			continue
		}
		if _, isVar := obj.(*types.Var); !isVar {
			continue
		}
		if vetutil.TypeContainsLocalNamed(obj.Type(), pkg, portsPkgPath, "OperatorReadFS") {
			addDiag(ident.Pos(), ident.End())
		}
	}
}

func collectMCPSelections(pkg *types.Package, info *types.Info, addDiag func(pos, end token.Pos)) {
	for selExpr, sel := range info.Selections {
		if selExpr == nil || sel == nil {
			continue
		}
		if isOperatorReadFSSelection(pkg, sel) {
			addDiag(selExpr.Sel.Pos(), selExpr.Sel.End())
		}
	}
}

func collectMCPExprTypes(pkg *types.Package, info *types.Info, addDiag func(pos, end token.Pos)) {
	var hits []symDiag
	for expr, tv := range info.Types {
		if expr == nil || !expr.Pos().IsValid() || tv.Type == nil || tv.IsType() {
			continue
		}
		if vetutil.TypeContainsLocalNamed(tv.Type, pkg, portsPkgPath, "OperatorReadFS") {
			hits = append(hits, symDiag{pos: expr.Pos(), end: expr.End()})
		}
	}
	// 对 Types map 收集结果先做位置排序，再交给上层统一行去重，保证报告位置完全确定。
	slices.SortFunc(hits, compareSymDiag)
	for _, h := range hits {
		addDiag(h.pos, h.end)
	}
}

func isOperatorReadFSSelection(pkg *types.Package, sel *types.Selection) bool {
	if vetutil.TypeContainsLocalNamed(sel.Recv(), pkg, portsPkgPath, "OperatorReadFS") {
		return true
	}
	obj := sel.Obj()
	if obj == nil {
		return false
	}
	return vetutil.TypeContainsLocalNamed(obj.Type(), pkg, portsPkgPath, "OperatorReadFS")
}

func reportDedupedLineDiags(pass *analysis.Pass, diags []symDiag) {
	slices.SortFunc(diags, compareSymDiag)
	seenLines := make(map[lineKey]bool)
	for _, d := range diags {
		p := pass.Fset.Position(d.pos)
		lk := lineKey{file: p.Filename, line: p.Line}
		if seenLines[lk] {
			continue
		}
		seenLines[lk] = true
		pass.Report(analysis.Diagnostic{
			Pos:     d.pos,
			End:     d.end,
			Message: d.msg,
		})
	}
}

func compareSymDiag(a, b symDiag) int {
	if a.pos != b.pos {
		if a.pos < b.pos {
			return -1
		}
		return 1
	}
	if a.end < b.end {
		return -1
	}
	if a.end > b.end {
		return 1
	}
	return 0
}

func reportSortedDiags(pass *analysis.Pass, diags []symDiag) {
	slices.SortFunc(diags, compareSymDiag)
	for _, d := range diags {
		pass.Report(analysis.Diagnostic{
			Pos:     d.pos,
			End:     d.end,
			Message: d.msg,
		})
	}
}
