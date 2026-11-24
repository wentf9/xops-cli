package digestcover

import (
	"go/ast"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// checkNoReflectReachable 从 WriteCanonical 出发沿同包全部直接/间接函数与方法引用遍历，禁止使用 reflect（M8）。
func checkNoReflectReachable(pass *analysis.Pass, writeFn *ast.FuncDecl, funcDecls map[*types.Func]*ast.FuncDecl) {
	visited := make(map[*types.Func]bool)
	if fnObj, ok := pass.TypesInfo.Defs[writeFn.Name].(*types.Func); ok && fnObj != nil {
		visited[fnObj.Origin()] = true
	}
	walkReflectInBody(pass, writeFn.Body, funcDecls, visited)
}

func walkReflectInBody(pass *analysis.Pass, body *ast.BlockStmt, funcDecls map[*types.Func]*ast.FuncDecl, visited map[*types.Func]bool) {
	if body == nil {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		checkReflectNode(pass, n, funcDecls, visited)
		return true
	})
}

func checkReflectNode(pass *analysis.Pass, n ast.Node, funcDecls map[*types.Func]*ast.FuncDecl, visited map[*types.Func]bool) {
	var fn *types.Func
	switch node := n.(type) {
	case *ast.Ident:
		obj := pass.TypesInfo.Uses[node]
		if vetutil.ObjectPkgPath(obj) == "reflect" {
			pass.ReportRangef(node, "digestcover: WriteCanonical 禁止使用 reflect")
			return
		}
		fn, _ = obj.(*types.Func)
	case *ast.SelectorExpr:
		if sel := pass.TypesInfo.Selections[node]; sel != nil {
			fn, _ = sel.Obj().(*types.Func)
		}
	case *ast.CallExpr:
		fn, _ = vetutil.ResolveCalledObject(pass.TypesInfo, node).(*types.Func)
	}
	visitReflectFunc(pass, fn, funcDecls, visited)
}

func visitReflectFunc(pass *analysis.Pass, fn *types.Func, funcDecls map[*types.Func]*ast.FuncDecl, visited map[*types.Func]bool) {
	if fn == nil {
		return
	}
	orig := fn.Origin()
	if orig == nil || orig.Pkg() != pass.Pkg || visited[orig] {
		return
	}
	if decl := funcDecls[orig]; decl != nil && decl.Body != nil {
		visited[orig] = true
		walkReflectInBody(pass, decl.Body, funcDecls, visited)
	}
}
