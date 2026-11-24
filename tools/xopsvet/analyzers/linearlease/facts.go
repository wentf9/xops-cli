package linearlease

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// factIndex 索引本包内收集的函数/类型借用契约，以及每个文件的注释列表以便参数级指令检索。
type factIndex struct {
	funcFacts     map[*types.Func]*borrowedFuncFact
	typeFacts     map[*types.TypeName]*borrowedFuncFact
	directParams  map[*types.Func][]int
	commentsByPos map[*token.File][]*ast.CommentGroup
}

type callLeaseSpec struct {
	syncClosure      bool
	callbackBorrowed map[int][]int
}

func collectAndExportFacts(pass *analysis.Pass) *factIndex {
	idx := &factIndex{
		funcFacts:     make(map[*types.Func]*borrowedFuncFact),
		typeFacts:     make(map[*types.TypeName]*borrowedFuncFact),
		directParams:  make(map[*types.Func][]int),
		commentsByPos: make(map[*token.File][]*ast.CommentGroup),
	}
	for _, file := range pass.Files {
		if tokFile := pass.Fset.File(file.Package); tokFile != nil {
			idx.commentsByPos[tokFile] = file.Comments
		}
		collectFileDeclFacts(pass, file, idx)
	}
	return idx
}

func collectFileDeclFacts(pass *analysis.Pass, file *ast.File, idx *factIndex) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name != nil && d.Type != nil {
				hasB := vetutil.FuncDeclHasDirective(d, vetutil.DirectiveBorrowed)
				hasS := vetutil.FuncDeclHasDirective(d, vetutil.DirectiveSyncClosure) || vetutil.FuncDeclHasDirective(d, vetutil.DirectiveSecretUse)
				recordFuncFact(pass, file.Comments, d.Name, d.Type.Params, hasB, hasS, true, idx)
			}
		case *ast.GenDecl:
			if d.Tok == token.TYPE {
				collectGenDeclTypeFacts(pass, file.Comments, d, idx)
			}
		}
	}
}

func (idx *factIndex) commentsFor(fset *token.FileSet, pos token.Pos) []*ast.CommentGroup {
	if fset == nil || !pos.IsValid() {
		return nil
	}
	if tokFile := fset.File(pos); tokFile != nil {
		return idx.commentsByPos[tokFile]
	}
	return nil
}

func collectGenDeclTypeFacts(pass *analysis.Pass, comments []*ast.CommentGroup, gen *ast.GenDecl, idx *factIndex) {
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		switch t := ts.Type.(type) {
		case *ast.InterfaceType:
			collectInterfaceFacts(pass, comments, t, idx)
		case *ast.FuncType:
			collectNamedFuncTypeFact(pass, comments, gen, ts, t, idx)
		}
	}
}

func collectInterfaceFacts(pass *analysis.Pass, comments []*ast.CommentGroup, iface *ast.InterfaceType, idx *factIndex) {
	if iface.Methods == nil {
		return
	}
	for _, m := range iface.Methods.List {
		if ft, ok := m.Type.(*ast.FuncType); ok && len(m.Names) > 0 {
			hasB := vetutil.FieldHasDirective(m, vetutil.DirectiveBorrowed)
			hasS := vetutil.FieldHasDirective(m, vetutil.DirectiveSyncClosure) || vetutil.FieldHasDirective(m, vetutil.DirectiveSecretUse)
			recordFuncFact(pass, comments, m.Names[0], ft.Params, hasB, hasS, false, idx)
		}
	}
}

func recordFuncFact(pass *analysis.Pass, comments []*ast.CommentGroup, ident *ast.Ident, params *ast.FieldList, hasB, hasS, saveDirect bool, idx *factIndex) {
	fnObj, ok := pass.TypesInfo.Defs[ident].(*types.Func)
	if !ok || fnObj == nil {
		return
	}
	cbBorrowed, direct := analyzeFuncParams(pass, comments, params, hasB)
	orig := fnObj.Origin()
	if saveDirect && len(direct) > 0 {
		idx.directParams[orig] = direct
	}
	if hasB || hasS || len(cbBorrowed) > 0 {
		fact := &borrowedFuncFact{SyncClosure: true, CallbackBorrowed: cbBorrowed}
		idx.funcFacts[orig] = fact
		pass.ExportObjectFact(orig, fact)
	}
}

func collectNamedFuncTypeFact(pass *analysis.Pass, comments []*ast.CommentGroup, gen *ast.GenDecl, ts *ast.TypeSpec, ft *ast.FuncType, idx *factIndex) {
	tn, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName)
	if !ok || tn == nil {
		return
	}
	hasB := vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveBorrowed)
	hasS := vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveSyncClosure) || vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveSecretUse)
	direct := collectInnerBorrowedIndices(pass.Fset, pass.TypesInfo, comments, ft.Params, hasB)
	if hasB || hasS || len(direct) > 0 {
		fact := &borrowedFuncFact{SyncClosure: true, DirectBorrowed: direct}
		idx.typeFacts[tn] = fact
		pass.ExportObjectFact(tn, fact)
	}
}

func analyzeFuncParams(pass *analysis.Pass, comments []*ast.CommentGroup, fl *ast.FieldList, outerBorrowed bool) (map[int][]int, []int) {
	if fl == nil {
		return nil, nil
	}
	cbBorrowed := make(map[int][]int)
	var directBorrowed []int
	paramIdx := 0
	for fieldIdx, f := range fl.List {
		count := max(len(f.Names), 1)
		fieldHasB := vetutil.ParamFieldHasDirective(pass.Fset, comments, fl, fieldIdx, vetutil.DirectiveBorrowed)
		if ft, isFunc := unwrapParamFuncType(f.Type); isFunc {
			recordCallbackBorrowed(cbBorrowed, paramIdx, count, collectInnerBorrowedIndices(pass.Fset, pass.TypesInfo, comments, ft.Params, outerBorrowed || fieldHasB))
		} else if fieldHasB {
			directBorrowed = appendParamRange(directBorrowed, paramIdx, count)
		}
		paramIdx += count
	}
	if len(cbBorrowed) == 0 {
		return nil, directBorrowed
	}
	return cbBorrowed, directBorrowed
}

func recordCallbackBorrowed(cbBorrowed map[int][]int, start, count int, inner []int) {
	if len(inner) == 0 {
		return
	}
	for k := range count {
		cbBorrowed[start+k] = inner
	}
}

func appendParamRange(dst []int, start, count int) []int {
	for k := range count {
		dst = append(dst, start+k)
	}
	return dst
}

func unwrapParamFuncType(expr ast.Expr) (*ast.FuncType, bool) {
	e := ast.Unparen(expr)
	if ell, ok := e.(*ast.Ellipsis); ok {
		e = ast.Unparen(ell.Elt)
	}
	ft, ok := e.(*ast.FuncType)
	return ft, ok && ft != nil
}

func collectInnerBorrowedIndices(fset *token.FileSet, info *types.Info, comments []*ast.CommentGroup, fl *ast.FieldList, outerBorrowed bool) []int {
	if fl == nil {
		return nil
	}
	if explicit := collectExplicitParamIndices(fset, comments, fl, vetutil.DirectiveBorrowed); len(explicit) > 0 || !outerBorrowed {
		return explicit
	}
	var allNonCtx, resourceLike []int
	paramIdx := 0
	for _, f := range fl.List {
		count, t := max(len(f.Names), 1), info.TypeOf(f.Type)
		if named, ok := vetutil.UnwrapNamedType(t); !ok || !vetutil.IsPkgSymbol(named.Obj(), "context", "Context") {
			allNonCtx = appendParamRange(allNonCtx, paramIdx, count)
			var b *types.Basic
			if t != nil {
				b, _ = types.Unalias(t).Underlying().(*types.Basic)
			}
			if b == nil || b.Kind() == types.UnsafePointer {
				resourceLike = appendParamRange(resourceLike, paramIdx, count)
			}
		}
		paramIdx += count
	}
	if len(resourceLike) > 0 {
		return resourceLike
	}
	return allNonCtx
}

func collectExplicitParamIndices(fset *token.FileSet, comments []*ast.CommentGroup, fl *ast.FieldList, kind vetutil.DirectiveKind) []int {
	if fl == nil {
		return nil
	}
	var indices []int
	paramIdx := 0
	for fieldIdx, f := range fl.List {
		count := max(len(f.Names), 1)
		if vetutil.ParamFieldHasDirective(fset, comments, fl, fieldIdx, kind) {
			indices = appendParamRange(indices, paramIdx, count)
		}
		paramIdx += count
	}
	return indices
}

type factObjKey interface {
	comparable
	types.Object
}

func lookupBorrowedFact[K factObjKey](pass *analysis.Pass, local map[K]*borrowedFuncFact, obj K) (borrowedFuncFact, bool) {
	var zero K
	if obj == zero {
		return borrowedFuncFact{}, false
	}
	if f, ok := local[obj]; ok {
		return *f, true
	}
	var imported borrowedFuncFact
	return imported, pass.ImportObjectFact(obj, &imported)
}

// resolveSSACallLeaseSpec 100% 基于显式 Fact 与精确标准/核心白名单推导调用的同步与借用契约（废除 L2a 名称启发）。
func resolveSSACallLeaseSpec(pass *analysis.Pass, idx *factIndex, secretFacts *secretfact.Result, rc vetssa.ResolvedCall) callLeaseSpec {
	spec := callLeaseSpec{callbackBorrowed: make(map[int][]int)}
	if rc.Closure != nil && rc.Common != nil && rc.Common.Value == rc.Closure && !vetssa.IsBoundWrapper(rc.TargetFn) {
		spec.syncClosure = true
		return spec
	}
	fn := rc.FuncObj
	if fn == nil {
		return spec
	}
	if f, found := lookupBorrowedFact(pass, idx.funcFacts, fn.Origin()); found {
		applyFuncFactToSpec(fn, f, len(rc.UserArgs), &spec)
	}
	if vetssa.IsRuntimeSecretDo(fn) || vetssa.IsStdlibSyncIter(fn) || secretfact.IsSecretBoxUseMethod(fn) ||
		(secretFacts != nil && (secretFacts.IsSyncClosureObject(fn) || secretFacts.HasSecretUseCallbackParam(fn))) {
		spec.syncClosure = true
	}
	mergeParamTypeFacts(pass, idx, fn, len(rc.UserArgs), &spec)
	return spec
}

func applyFuncFactToSpec(fn *types.Func, f borrowedFuncFact, argCount int, spec *callLeaseSpec) {
	spec.syncClosure = spec.syncClosure || f.SyncClosure
	for k, v := range f.CallbackBorrowed {
		spec.callbackBorrowed[k] = slices.Clone(v)
	}
	sig, ok := fn.Type().Underlying().(*types.Signature)
	if !ok || !sig.Variadic() || sig.Params() == nil || sig.Params().Len() == 0 {
		return
	}
	varIdx := sig.Params().Len() - 1
	if varBorrowed := f.CallbackBorrowed[varIdx]; len(varBorrowed) > 0 {
		for i := varIdx; i < argCount; i++ {
			spec.callbackBorrowed[i] = mergeIntSlices(spec.callbackBorrowed[i], varBorrowed)
		}
	}
}

func mergeParamTypeFacts(pass *analysis.Pass, idx *factIndex, fn *types.Func, argCount int, spec *callLeaseSpec) {
	sig, ok := fn.Type().Underlying().(*types.Signature)
	if !ok || sig.Params() == nil {
		return
	}
	for i := range argCount {
		mergeSingleParamTypeFact(pass, idx, vetutil.ParamTypeAt(sig.Params(), sig.Variadic(), i), i, spec)
	}
}

func mergeSingleParamTypeFact(pass *analysis.Pass, idx *factIndex, pt types.Type, argIdx int, spec *callLeaseSpec) {
	if pt == nil {
		return
	}
	named, ok := types.Unalias(pt).(*types.Named)
	if !ok || named == nil || named.Origin().Obj() == nil {
		return
	}
	if tf, found := lookupBorrowedFact(pass, idx.typeFacts, named.Origin().Obj()); found {
		spec.syncClosure = spec.syncClosure || tf.SyncClosure
		if len(tf.DirectBorrowed) > 0 {
			spec.callbackBorrowed[argIdx] = mergeIntSlices(spec.callbackBorrowed[argIdx], tf.DirectBorrowed)
		}
	}
}

func mergeIntSlices(a, b []int) []int {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
