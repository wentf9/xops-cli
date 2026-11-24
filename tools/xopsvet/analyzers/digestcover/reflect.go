package digestcover

import (
	"go/ast"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// checkNoReflectReachable 从 WriteCanonical 出发沿同包可解析调用图遍历全部可达函数与方法，
// 禁止在 WriteCanonical 及其任意同包辅助调用（含非接收者值传递辅助函数）中使用 reflect。
func checkNoReflectReachable(
	pass *analysis.Pass,
	writeFn *ast.FuncDecl,
	funcDecls map[*types.Func]*ast.FuncDecl,
) {
	visited := make(map[*types.Func]bool)
	if fnObj, ok := pass.TypesInfo.Defs[writeFn.Name].(*types.Func); ok && fnObj != nil {
		visited[fnObj.Origin()] = true
	}
	walkReflectInBody(pass, writeFn.Body, funcDecls, visited)
}

func walkReflectInBody(
	pass *analysis.Pass,
	body *ast.BlockStmt,
	funcDecls map[*types.Func]*ast.FuncDecl,
	visited map[*types.Func]bool,
) {
	if body == nil {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			if vetutil.ObjectPkgPath(pass.TypesInfo.Uses[node]) == "reflect" {
				pass.ReportRangef(node, "digestcover: WriteCanonical 禁止使用 reflect")
			}
		case *ast.CallExpr:
			visitReflectCallee(pass, node, funcDecls, visited)
		}
		return true
	})
}

func visitReflectCallee(
	pass *analysis.Pass,
	call *ast.CallExpr,
	funcDecls map[*types.Func]*ast.FuncDecl,
	visited map[*types.Func]bool,
) {
	callee, ok := vetutil.ResolveCalledObject(pass.TypesInfo, call).(*types.Func)
	if !ok || callee == nil {
		return
	}
	orig := callee.Origin()
	if orig == nil || orig.Pkg() != pass.Pkg || visited[orig] {
		return
	}
	decl := funcDecls[orig]
	if decl == nil || decl.Body == nil {
		return
	}
	visited[orig] = true
	walkReflectInBody(pass, decl.Body, funcDecls, visited)
}
