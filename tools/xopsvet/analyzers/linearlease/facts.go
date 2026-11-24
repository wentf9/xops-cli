package linearlease

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

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
		collectFileFacts(pass, file, idx)
	}
	return idx
}

func (idx *factIndex) commentsFor(fset *token.FileSet, pos token.Pos) []*ast.CommentGroup {
	if fset == nil || !pos.IsValid() {
		return nil
	}
	tokFile := fset.File(pos)
	if tokFile == nil {
		return nil
	}
	return idx.commentsByPos[tokFile]
}

func collectFileFacts(pass *analysis.Pass, file *ast.File, idx *factIndex) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			collectFuncDeclFact(pass, file.Comments, d, idx)
		case *ast.GenDecl:
			if d.Tok == token.TYPE {
				collectGenDeclTypeFacts(pass, file.Comments, d, idx)
			}
		}
	}
}

func collectFuncDeclFact(pass *analysis.Pass, comments []*ast.CommentGroup, fn *ast.FuncDecl, idx *factIndex) {
	if fn.Name == nil || fn.Type == nil {
		return
	}
	fnObj, ok := pass.TypesInfo.Defs[fn.Name].(*types.Func)
	if !ok || fnObj == nil {
		return
	}
	hasDeclBorrowed := vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveBorrowed)
	hasDeclSync := vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveSyncClosure) ||
		vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveSecretUse)

	cbBorrowed, direct := analyzeFuncParams(pass, comments, fn.Type.Params, hasDeclBorrowed)
	if len(direct) > 0 {
		idx.directParams[fnObj] = direct
	}
	if !hasDeclBorrowed && !hasDeclSync && len(cbBorrowed) == 0 {
		return
	}
	fact := &borrowedFuncFact{
		SyncClosure:      hasDeclSync || hasDeclBorrowed || len(cbBorrowed) > 0,
		CallbackBorrowed: cbBorrowed,
	}
	idx.funcFacts[fnObj] = fact
	pass.ExportObjectFact(fnObj, fact)
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
		ft, ok := m.Type.(*ast.FuncType)
		if !ok || len(m.Names) == 0 {
			continue
		}
		fnObj, ok := pass.TypesInfo.Defs[m.Names[0]].(*types.Func)
		if !ok || fnObj == nil {
			continue
		}
		hasBorrowed := vetutil.FieldHasDirective(m, vetutil.DirectiveBorrowed)
		hasSync := vetutil.FieldHasDirective(m, vetutil.DirectiveSyncClosure) ||
			vetutil.FieldHasDirective(m, vetutil.DirectiveSecretUse)
		cbBorrowed, _ := analyzeFuncParams(pass, comments, ft.Params, hasBorrowed)
		if !hasBorrowed && !hasSync && len(cbBorrowed) == 0 {
			continue
		}
		fact := &borrowedFuncFact{
			SyncClosure:      hasSync || hasBorrowed || len(cbBorrowed) > 0,
			CallbackBorrowed: cbBorrowed,
		}
		idx.funcFacts[fnObj] = fact
		pass.ExportObjectFact(fnObj, fact)
	}
}

func collectNamedFuncTypeFact(
	pass *analysis.Pass,
	comments []*ast.CommentGroup,
	gen *ast.GenDecl,
	ts *ast.TypeSpec,
	ft *ast.FuncType,
	idx *factIndex,
) {
	tn, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName)
	if !ok || tn == nil {
		return
	}
	hasBorrowed := vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveBorrowed)
	hasSync := vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveSyncClosure) ||
		vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveSecretUse)
	direct := collectInnerBorrowedIndices(pass.Fset, pass.TypesInfo, comments, ft.Params, hasBorrowed)
	if !hasBorrowed && !hasSync && len(direct) == 0 {
		return
	}
	fact := &borrowedFuncFact{
		SyncClosure:    hasSync || hasBorrowed || len(direct) > 0,
		DirectBorrowed: direct,
	}
	idx.typeFacts[tn] = fact
	pass.ExportObjectFact(tn, fact)
}

// analyzeFuncParams 展开函数形参表：对函数类型形参推导回调内部借用参数索引，
// 对非函数类型形参仅在显式标注 //xops:borrowed 时记入 directBorrowed。
func analyzeFuncParams(
	pass *analysis.Pass,
	comments []*ast.CommentGroup,
	fl *ast.FieldList,
	outerBorrowed bool,
) (map[int][]int, []int) {
	if fl == nil {
		return nil, nil
	}
	cbBorrowed := make(map[int][]int)
	var directBorrowed []int
	paramIdx := 0
	for fieldIdx, f := range fl.List {
		count := max(len(f.Names), 1)
		fieldHasBorrowed := vetutil.ParamFieldHasDirective(pass.Fset, comments, fl, fieldIdx, vetutil.DirectiveBorrowed)
		if ft, isFunc := unwrapParamFuncType(f.Type); isFunc {
			inner := collectInnerBorrowedIndices(pass.Fset, pass.TypesInfo, comments, ft.Params, outerBorrowed || fieldHasBorrowed)
			recordCallbackBorrowed(cbBorrowed, paramIdx, count, inner)
		} else if fieldHasBorrowed {
			directBorrowed = appendParamRange(directBorrowed, paramIdx, count)
		}
		paramIdx += count
	}
	if len(cbBorrowed) == 0 {
		return nil, directBorrowed
	}
	return cbBorrowed, directBorrowed
}

// unwrapParamFuncType 解引用形参类型外层的括号与可变参数省略号（...func(...)），
// 返回底层的函数签名 AST 节点。
func unwrapParamFuncType(expr ast.Expr) (*ast.FuncType, bool) {
	e := ast.Unparen(expr)
	if ell, ok := e.(*ast.Ellipsis); ok {
		e = ast.Unparen(ell.Elt)
	}
	ft, ok := e.(*ast.FuncType)
	return ft, ok && ft != nil
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

// collectInnerBorrowedIndices 解析回调签名中的借用参数索引。
// 若内层参数显式标注了 //xops:borrowed，精确采用显式索引；否则在 outerBorrowed 成立时推断资源参数。
func collectInnerBorrowedIndices(
	fset *token.FileSet,
	info *types.Info,
	comments []*ast.CommentGroup,
	fl *ast.FieldList,
	outerBorrowed bool,
) []int {
	if fl == nil {
		return nil
	}
	explicit := collectExplicitParamIndices(fset, comments, fl, vetutil.DirectiveBorrowed)
	if len(explicit) > 0 || !outerBorrowed {
		return explicit
	}
	return inferBorrowedInnerIndices(info, fl)
}

func collectExplicitParamIndices(
	fset *token.FileSet,
	comments []*ast.CommentGroup,
	fl *ast.FieldList,
	kind vetutil.DirectiveKind,
) []int {
	if fl == nil {
		return nil
	}
	var indices []int
	paramIdx := 0
	for fieldIdx, f := range fl.List {
		count := max(len(f.Names), 1)
		if vetutil.ParamFieldHasDirective(fset, comments, fl, fieldIdx, kind) {
			for k := range count {
				indices = append(indices, paramIdx+k)
			}
		}
		paramIdx += count
	}
	return indices
}

func inferBorrowedInnerIndices(info *types.Info, fl *ast.FieldList) []int {
	if fl == nil {
		return nil
	}
	var allNonCtx []int
	var resourceLike []int
	paramIdx := 0
	for _, f := range fl.List {
		count := max(len(f.Names), 1)
		t := info.TypeOf(f.Type)
		isCtx := isContextType(t)
		isScalar := isBasicScalarType(t)
		for k := range count {
			idx := paramIdx + k
			if !isCtx {
				allNonCtx = append(allNonCtx, idx)
				if !isScalar {
					resourceLike = append(resourceLike, idx)
				}
			}
		}
		paramIdx += count
	}
	if len(resourceLike) > 0 {
		return resourceLike
	}
	return allNonCtx
}

func isContextType(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := vetutil.UnwrapNamedType(t)
	return ok && vetutil.IsPkgSymbol(named.Obj(), "context", "Context")
}

func isBasicScalarType(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := types.Unalias(t).Underlying().(*types.Basic)
	if !ok {
		return false
	}
	return basic.Kind() != types.UnsafePointer
}

func (idx *factIndex) lookupFuncFact(pass *analysis.Pass, fn *types.Func) (borrowedFuncFact, bool) {
	if fn == nil {
		return borrowedFuncFact{}, false
	}
	orig := fn.Origin()
	if f, ok := idx.funcFacts[orig]; ok {
		return *f, true
	}
	var imported borrowedFuncFact
	if pass.ImportObjectFact(orig, &imported) {
		return imported, true
	}
	return borrowedFuncFact{}, false
}

func (idx *factIndex) lookupTypeFact(pass *analysis.Pass, tn *types.TypeName) (borrowedFuncFact, bool) {
	if tn == nil {
		return borrowedFuncFact{}, false
	}
	if f, ok := idx.typeFacts[tn]; ok {
		return *f, true
	}
	var imported borrowedFuncFact
	if pass.ImportObjectFact(tn, &imported) {
		return imported, true
	}
	return borrowedFuncFact{}, false
}

// resolveCallLeaseSpec 仅依据被调方自身的同步/借用契约推导调用规格，
// 不因调用位于 defer 语句而假定其为同步闭包。
func resolveCallLeaseSpec(pass *analysis.Pass, idx *factIndex, call *ast.CallExpr) callLeaseSpec {
	spec := callLeaseSpec{callbackBorrowed: make(map[int][]int)}
	fun := ast.Unparen(call.Fun)
	if _, isLit := fun.(*ast.FuncLit); isLit {
		spec.syncClosure = true
		return spec
	}
	calleeObj := vetutil.ResolveCalledObject(pass.TypesInfo, call)
	if fn, ok := calleeObj.(*types.Func); ok && fn != nil {
		if f, found := idx.lookupFuncFact(pass, fn); found {
			applyFuncFactToSpec(fn, f, len(call.Args), &spec)
		}
		if fn.Name() == "Use" || strings.HasPrefix(fn.Name(), "With") {
			spec.syncClosure = true
		}
		mergeParamTypeFacts(pass, idx, fn, len(call.Args), &spec)
	}
	mergeInlineFuncLitDirectives(pass, idx, call, &spec)
	return spec
}

// applyFuncFactToSpec 将导出事实中的回调借用契约写入调用规格；
// 若目标函数为可变参数且末尾形参为回调函数，则将末尾回调契约展开至全部可变实参位。
func applyFuncFactToSpec(fn *types.Func, f borrowedFuncFact, argCount int, spec *callLeaseSpec) {
	spec.syncClosure = f.SyncClosure
	for k, v := range f.CallbackBorrowed {
		spec.callbackBorrowed[k] = slices.Clone(v)
	}
	sig, ok := fn.Type().Underlying().(*types.Signature)
	if !ok || !sig.Variadic() || sig.Params() == nil || sig.Params().Len() == 0 {
		return
	}
	varIdx := sig.Params().Len() - 1
	varBorrowed := f.CallbackBorrowed[varIdx]
	if len(varBorrowed) == 0 {
		return
	}
	for i := varIdx; i < argCount; i++ {
		spec.callbackBorrowed[i] = mergeIntSlices(spec.callbackBorrowed[i], varBorrowed)
	}
}

func mergeParamTypeFacts(pass *analysis.Pass, idx *factIndex, fn *types.Func, argCount int, spec *callLeaseSpec) {
	sig, ok := fn.Type().Underlying().(*types.Signature)
	if !ok || sig.Params() == nil {
		return
	}
	params := sig.Params()
	for i := range argCount {
		pt := paramTypeAt(params, sig.Variadic(), i)
		if pt == nil {
			continue
		}
		named, ok := types.Unalias(pt).(*types.Named)
		if !ok || named == nil {
			continue
		}
		tf, found := idx.lookupTypeFact(pass, named.Origin().Obj())
		if !found {
			continue
		}
		if tf.SyncClosure {
			spec.syncClosure = true
		}
		if len(tf.DirectBorrowed) > 0 {
			spec.callbackBorrowed[i] = mergeIntSlices(spec.callbackBorrowed[i], tf.DirectBorrowed)
		}
	}
}

func paramTypeAt(params *types.Tuple, variadic bool, i int) types.Type {
	n := params.Len()
	if n == 0 {
		return nil
	}
	if i < n-1 || !variadic {
		if i >= n {
			return nil
		}
		return params.At(i).Type()
	}
	sl, ok := types.Unalias(params.At(n - 1).Type()).(*types.Slice)
	if !ok {
		return nil
	}
	return sl.Elem()
}

func mergeInlineFuncLitDirectives(pass *analysis.Pass, idx *factIndex, call *ast.CallExpr, spec *callLeaseSpec) {
	for i, arg := range call.Args {
		lit, ok := ast.Unparen(arg).(*ast.FuncLit)
		if !ok || lit.Type == nil {
			continue
		}
		comments := idx.commentsFor(pass.Fset, lit.Pos())
		explicit := collectExplicitParamIndices(pass.Fset, comments, lit.Type.Params, vetutil.DirectiveBorrowed)
		if len(explicit) > 0 {
			spec.syncClosure = true
			spec.callbackBorrowed[i] = mergeIntSlices(spec.callbackBorrowed[i], explicit)
		}
	}
}

func mergeIntSlices(a, b []int) []int {
	if len(a) == 0 {
		return slices.Clone(b)
	}
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
