package secrettaint

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

type secretFactIndex struct {
	funcFacts     map[*types.Func]bool
	typeFacts     map[*types.TypeName]bool
	commentsByPos map[*token.File][]*ast.CommentGroup
}

func collectAndExportSecretFacts(pass *analysis.Pass) *secretFactIndex {
	idx := &secretFactIndex{
		funcFacts:     make(map[*types.Func]bool),
		typeFacts:     make(map[*types.TypeName]bool),
		commentsByPos: make(map[*token.File][]*ast.CommentGroup),
	}
	for _, file := range pass.Files {
		if tokFile := pass.Fset.File(file.Package); tokFile != nil {
			idx.commentsByPos[tokFile] = file.Comments
		}
		collectFileSecretFacts(pass, file, idx)
	}
	return idx
}

func collectFileSecretFacts(pass *analysis.Pass, file *ast.File, idx *secretFactIndex) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			collectFuncDeclSecretFact(pass, file.Comments, d, idx)
		case *ast.GenDecl:
			if d.Tok == token.TYPE {
				collectTypeDeclSecretFacts(pass, file.Comments, d, idx)
			}
		}
	}
}

func collectFuncDeclSecretFact(pass *analysis.Pass, comments []*ast.CommentGroup, fn *ast.FuncDecl, idx *secretFactIndex) {
	if fn.Name == nil || fn.Type == nil {
		return
	}
	fnObj, ok := pass.TypesInfo.Defs[fn.Name].(*types.Func)
	if !ok || fnObj == nil {
		return
	}
	hasDir := vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveSecretUse) ||
		hasAnyParamDirective(pass.Fset, comments, fn.Type.Params, vetutil.DirectiveSecretUse)
	if !hasDir {
		return
	}
	idx.funcFacts[fnObj] = true
	pass.ExportObjectFact(fnObj, &secretUseFact{})
}

func collectTypeDeclSecretFacts(pass *analysis.Pass, comments []*ast.CommentGroup, gen *ast.GenDecl, idx *secretFactIndex) {
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		switch t := ts.Type.(type) {
		case *ast.InterfaceType:
			collectInterfaceSecretFacts(pass, comments, t, idx)
		case *ast.FuncType:
			if vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveSecretUse) {
				if tn, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName); ok && tn != nil {
					idx.typeFacts[tn] = true
					pass.ExportObjectFact(tn, &secretUseFact{})
				}
			}
		}
	}
}

func collectInterfaceSecretFacts(pass *analysis.Pass, comments []*ast.CommentGroup, iface *ast.InterfaceType, idx *secretFactIndex) {
	if iface.Methods == nil {
		return
	}
	for _, m := range iface.Methods.List {
		if len(m.Names) == 0 {
			continue
		}
		hasDir := vetutil.FieldHasDirective(m, vetutil.DirectiveSecretUse)
		if ft, ok := ast.Unparen(m.Type).(*ast.FuncType); ok {
			hasDir = hasDir || hasAnyParamDirective(pass.Fset, comments, ft.Params, vetutil.DirectiveSecretUse)
		}
		if !hasDir {
			continue
		}
		if fnObj, ok := pass.TypesInfo.Defs[m.Names[0]].(*types.Func); ok && fnObj != nil {
			idx.funcFacts[fnObj] = true
			pass.ExportObjectFact(fnObj, &secretUseFact{})
		}
	}
}

func hasAnyParamDirective(
	fset *token.FileSet,
	comments []*ast.CommentGroup,
	fl *ast.FieldList,
	kind vetutil.DirectiveKind,
) bool {
	if fl == nil {
		return false
	}
	for i := range fl.List {
		if vetutil.ParamFieldHasDirective(fset, comments, fl, i, kind) {
			return true
		}
	}
	return false
}

func (idx *secretFactIndex) commentsFor(fset *token.FileSet, pos token.Pos) []*ast.CommentGroup {
	if fset == nil || !pos.IsValid() {
		return nil
	}
	tokFile := fset.File(pos)
	if tokFile == nil {
		return nil
	}
	return idx.commentsByPos[tokFile]
}

func (idx *secretFactIndex) hasFuncSecretUseFact(pass *analysis.Pass, fn *types.Func) bool {
	if fn == nil {
		return false
	}
	orig := fn.Origin()
	if idx.funcFacts[orig] {
		return true
	}
	var f secretUseFact
	return pass.ImportObjectFact(orig, &f)
}

func (idx *secretFactIndex) hasTypeSecretUseFact(pass *analysis.Pass, tn *types.TypeName) bool {
	if tn == nil {
		return false
	}
	if idx.typeFacts[tn] {
		return true
	}
	var f secretUseFact
	return pass.ImportObjectFact(tn, &f)
}

func isSecretBoxUseMethod(obj types.Object) bool {
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil || fn.Name() != "Use" {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	named, ok := vetutil.UnwrapNamedType(sig.Recv().Type())
	return ok && vetutil.IsPkgSymbol(named.Obj(), secretPkgPath, secretBoxName)
}

func (idx *secretFactIndex) isSecretUseObject(pass *analysis.Pass, obj types.Object) bool {
	if isSecretBoxUseMethod(obj) {
		return true
	}
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil {
		return false
	}
	return idx.hasFuncSecretUseFact(pass, fn)
}

func (idx *secretFactIndex) isSecretUseCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	obj := vetutil.ResolveCalledObject(pass.TypesInfo, call)
	if idx.isSecretUseObject(pass, obj) {
		return true
	}
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil {
		return false
	}
	sig, ok := fn.Type().Underlying().(*types.Signature)
	if !ok || sig.Params() == nil {
		return false
	}
	for i := range sig.Params().Len() {
		named, ok := types.Unalias(sig.Params().At(i).Type()).(*types.Named)
		if ok && named != nil && idx.hasTypeSecretUseFact(pass, named.Origin().Obj()) {
			return true
		}
	}
	return false
}

func checkSecretUseWhitelist(pass *analysis.Pass, pkgInfo vetutil.PkgInfo, idx *secretFactIndex) {
	if vetutil.AllowSecretPlaintext(pkgInfo) {
		return
	}
	reported := make(map[token.Pos]bool)
	selIdents := make(map[*ast.Ident]bool)
	ins := vetutil.InspectorOf(pass)
	ins.Preorder([]ast.Node{(*ast.CallExpr)(nil), (*ast.SelectorExpr)(nil), (*ast.Ident)(nil)}, func(n ast.Node) {
		checkWhitelistNode(pass, idx, n, selIdents, reported)
	})
}

func checkWhitelistNode(
	pass *analysis.Pass,
	idx *secretFactIndex,
	n ast.Node,
	selIdents map[*ast.Ident]bool,
	reported map[token.Pos]bool,
) {
	switch node := n.(type) {
	case *ast.CallExpr:
		if idx.isSecretUseCall(pass, node) {
			reportWhitelistViolation(pass, reported, node.Fun)
		}
	case *ast.SelectorExpr:
		selIdents[node.Sel] = true
		obj := resolveSelectorObj(pass.TypesInfo, node)
		if idx.isSecretUseObject(pass, obj) {
			reportWhitelistViolation(pass, reported, node)
		}
	case *ast.Ident:
		if !selIdents[node] && idx.isSecretUseObject(pass, pass.TypesInfo.Uses[node]) {
			reportWhitelistViolation(pass, reported, node)
		}
	}
}

func resolveSelectorObj(info *types.Info, selExpr *ast.SelectorExpr) types.Object {
	if sel := info.Selections[selExpr]; sel != nil {
		return sel.Obj()
	}
	return info.Uses[selExpr.Sel]
}

func reportWhitelistViolation(pass *analysis.Pass, reported map[token.Pos]bool, rng ast.Node) {
	if rng == nil || reported[rng.Pos()] {
		return
	}
	reported[rng.Pos()] = true
	pass.ReportRangef(
		rng,
		"secrettaint: 禁止在白名单（core/domain/secret、internal/host/vault、core/internal/sshnet/dial、core/internal/sshnet/priv、core/internal/sim）外调用或引用 SecretBox.Use / //xops:secretuse",
	)
}
