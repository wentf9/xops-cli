package archbound

import (
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

const portsPkgPath = vetutil.ModulePrefix + "/core/ports"

func checkSymbolBoundaries(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	if pass.TypesInfo == nil {
		return
	}
	switch pkgInfo.Layer {
	case vetutil.LayerCoreDomain:
		checkDomainTimeSymbols(pass, "core/domain/**")
	case vetutil.LayerInternalI18n:
		checkDomainTimeSymbols(pass, "internal/i18n")
	case vetutil.LayerCoreOSFS:
		checkOSFSNetSymbols(pass)
	case vetutil.LayerCoreMCPRuntime:
		checkMCPOperatorReadFS(pass)
	}
}

func checkDomainTimeSymbols(pass *analysis.Pass, layerLabel string) {
	var diags []vetutil.Diag
	for ident, obj := range pass.TypesInfo.Uses {
		if fn, isFn := obj.(*types.Func); isFn {
			if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
				continue
			}
		}
		if ident != nil && ident.Pos().IsValid() &&
			vetutil.IsPkgSymbol(obj, "time", "Now", "Since", "Until", "NewTimer", "NewTicker", "After", "Sleep", "AfterFunc", "Tick", "LoadLocation", "Local") {
			diags = append(diags, vetutil.Diag{Pos: ident.Pos(), End: ident.End(), Msg: "archbound: " + layerLabel + " 禁止使用非确定性时钟或定时符号 time." + obj.Name()})
		}
	}
	for selExpr, sel := range pass.TypesInfo.Selections {
		if selExpr != nil && sel != nil && sel.Obj() != nil && sel.Obj().Name() == "Local" &&
			vetutil.ContainsValueNamed(sel.Recv(), "time", "Time") {
			diags = append(diags, vetutil.Diag{Pos: selExpr.Sel.Pos(), End: selExpr.Sel.End(), Msg: "archbound: " + layerLabel + " 禁止使用非确定性本地时区方法 (time.Time).Local"})
		}
	}
	vetutil.ReportSortedDedup(pass, diags, false)
}

// checkMCPOperatorReadFS 物理封禁 core/internal/mcpruntime 对 ports.OperatorReadFS 的一切直接与间接使用，
// 对 Defs/Selections/Types 采用 TypeContainsLocalNamed 以保证合法持有外部服务结构体零误报。
func checkMCPOperatorReadFS(pass *analysis.Pass) {
	var diags []vetutil.Diag
	addDiag := func(pos, end token.Pos) {
		if pos.IsValid() {
			diags = append(diags, vetutil.Diag{Pos: pos, End: end, Msg: "archbound: core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS"})
		}
	}
	hasOpFS := func(t types.Type) bool {
		return vetutil.TypeContainsLocalNamed(t, pass.Pkg, portsPkgPath, "OperatorReadFS")
	}
	collectMCPOpFSUsesDefs(pass.TypesInfo, hasOpFS, addDiag)
	collectMCPOpFSSelectionsTypes(pass.TypesInfo, hasOpFS, addDiag)
	vetutil.ReportSortedDedup(pass, diags, true)
}

func collectMCPOpFSUsesDefs(info *types.Info, hasOpFS func(types.Type) bool, addDiag func(token.Pos, token.Pos)) {
	for ident, obj := range info.Uses {
		if ident != nil && vetutil.IsPkgSymbol(obj, portsPkgPath, "OperatorReadFS") {
			addDiag(ident.Pos(), ident.End())
		}
	}
	for ident, obj := range info.Defs {
		if _, isVar := obj.(*types.Var); ident != nil && isVar && hasOpFS(obj.Type()) {
			addDiag(ident.Pos(), ident.End())
		}
	}
}

func collectMCPOpFSSelectionsTypes(info *types.Info, hasOpFS func(types.Type) bool, addDiag func(token.Pos, token.Pos)) {
	for selExpr, sel := range info.Selections {
		if selExpr == nil || sel == nil {
			continue
		}
		if hasOpFS(sel.Recv()) || (sel.Obj() != nil && (hasOpFS(sel.Obj().Type()) || funcRecvHasOpFS(sel.Obj(), hasOpFS))) {
			addDiag(selExpr.Sel.Pos(), selExpr.Sel.End())
		}
	}
	for expr, tv := range info.Types {
		if expr != nil && expr.Pos().IsValid() && !tv.IsType() && hasOpFS(tv.Type) {
			addDiag(expr.Pos(), expr.End())
		}
	}
}

func funcRecvHasOpFS(obj types.Object, hasOpFS func(types.Type) bool) bool {
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	return ok && sig.Recv() != nil && hasOpFS(sig.Recv().Type())
}
