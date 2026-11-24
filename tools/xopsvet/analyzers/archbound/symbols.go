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

func checkMCPOperatorReadFS(pass *analysis.Pass) {
	seenLines := make(map[lineKey]bool)
	var diags []symDiag
	addDiag := func(pos, end token.Pos) {
		if !pos.IsValid() {
			return
		}
		p := pass.Fset.Position(pos)
		lk := lineKey{file: p.Filename, line: p.Line}
		if seenLines[lk] {
			return
		}
		seenLines[lk] = true
		diags = append(diags, symDiag{
			pos: pos,
			end: end,
			msg: "archbound: core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS",
		})
	}

	collectMCPUses(pass.TypesInfo, addDiag)
	collectMCPDefs(pass.Pkg, pass.TypesInfo, addDiag)
	collectMCPSelections(pass.Pkg, pass.TypesInfo, addDiag)
	reportSortedDiags(pass, diags)
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

func reportSortedDiags(pass *analysis.Pass, diags []symDiag) {
	slices.SortFunc(diags, func(a, b symDiag) int {
		if a.pos < b.pos {
			return -1
		}
		if a.pos > b.pos {
			return 1
		}
		return 0
	})
	for _, d := range diags {
		pass.Report(analysis.Diagnostic{
			Pos:     d.pos,
			End:     d.end,
			Message: d.msg,
		})
	}
}
