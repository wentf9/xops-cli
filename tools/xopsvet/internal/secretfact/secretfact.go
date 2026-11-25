// Package secretfact 提供 //xops:secretuse 与 //xops:syncclosure 跨包分析事实（analysis.Fact）前置分析器及公共汇点表。
package secretfact

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

const (
	secretPkgPath = vetutil.ModulePrefix + "/core/domain/secret"
	secretBoxName = "SecretBox"
)

// Fact 跨包传播 //xops:secretuse 契约，精确区分声明级（WholeDecl）与参数/回调槽位级来源；
// SyncFact 跨包传播非 secretuse 的 //xops:syncclosure/borrowed 契约（B-3）。
type (
	Fact struct {
		WholeDecl      bool          // true 表示整个函数/方法/命名函数类型声明带有 //xops:secretuse
		CallbackSecret map[int][]int // 外层回调形参索引 -> 内层显式标注 //xops:secretuse 的形参索引（nil 表示该回调全部明文类型形参）
		DirectSecret   []int         // 直接标注 //xops:secretuse 的非回调形参（或命名函数类型自身）索引列表
	}
	SyncFact struct{}
)

// AFact 标记为 go/analysis 跨包事实；String 返回确定性简短标识（保持 "secretuse" 兼容既有契约）。
func (*Fact) AFact()             {}
func (*Fact) String() string     { return "secretuse" }
func (*SyncFact) AFact()         {}
func (*SyncFact) String() string { return "syncclosure" }

// Result 保存当前包及依赖中带有 //xops:secretuse（含槽位来源）与 //xops:syncclosure 契约的函数与命名函数类型集合。
type Result struct {
	pass      *analysis.Pass
	funcFacts map[*types.Func]Fact
	typeFacts map[*types.TypeName]Fact
	syncFuncs map[*types.Func]bool
}

// NewAnalyzer 构造 secretfact 前置分析器实例（cmd/xopsvet 构造单一实例注入 3 个消费分析器）。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:       "secretfact",
		Doc:        "收集并跨包导出 //xops:secretuse 与 //xops:syncclosure 契约，供 secretbox/secrettaint/linearlease 共享",
		FactTypes:  []analysis.Fact{(*Fact)(nil), (*SyncFact)(nil)},
		ResultType: reflect.TypeOf((*Result)(nil)),
		Run:        run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	res := &Result{pass: pass, funcFacts: map[*types.Func]Fact{}, typeFacts: map[*types.TypeName]Fact{}, syncFuncs: map[*types.Func]bool{}}
	if vetutil.IsSyntheticTestMain(pass) || pass.TypesInfo == nil {
		return res, nil
	}
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name != nil && fn.Type != nil {
				hasWholeSecret := vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveSecretUse)
				hasSync := vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveSyncClosure) ||
					vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveBorrowed) ||
					hasParamDir(pass.Fset, file.Comments, fn.Type.Params, vetutil.DirectiveBorrowed)
				recordFuncDeclFact(pass, file.Comments, fn.Name, fn.Type.Params, hasWholeSecret, hasSync, res)
			}
		}
	}
	vetutil.ForEachTypeSpec(pass, func(file *ast.File, gen *ast.GenDecl, ts *ast.TypeSpec) {
		collectTypeSpecFact(pass, file.Comments, gen, ts, res)
	})
	return res, nil
}

func collectTypeSpecFact(pass *analysis.Pass, comments []*ast.CommentGroup, gen *ast.GenDecl, ts *ast.TypeSpec, res *Result) {
	if iface, ok := ast.Unparen(ts.Type).(*ast.InterfaceType); ok {
		collectInterfaceFacts(pass, comments, iface, res)
		return
	}
	tn, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName)
	if !ok || tn == nil {
		return
	}
	if _, isSig := types.Unalias(tn.Type()).Underlying().(*types.Signature); !isSig {
		return
	}
	wholeDecl := vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveSecretUse)
	var directSecret []int
	if ft, ok := ast.Unparen(ts.Type).(*ast.FuncType); ok {
		directSecret = collectParamDirIndices(pass.Fset, comments, ft.Params, vetutil.DirectiveSecretUse)
	}
	if wholeDecl || len(directSecret) > 0 {
		fact := Fact{WholeDecl: wholeDecl, DirectSecret: directSecret}
		res.typeFacts[tn] = fact
		pass.ExportObjectFact(tn, &fact)
	}
}

func collectInterfaceFacts(pass *analysis.Pass, comments []*ast.CommentGroup, iface *ast.InterfaceType, res *Result) {
	if iface.Methods == nil {
		return
	}
	for _, m := range iface.Methods.List {
		if len(m.Names) == 0 {
			continue
		}
		hasWholeSecret := vetutil.FieldHasDirective(m, vetutil.DirectiveSecretUse)
		hasSync := vetutil.FieldHasDirective(m, vetutil.DirectiveSyncClosure) || vetutil.FieldHasDirective(m, vetutil.DirectiveBorrowed)
		var params *ast.FieldList
		if ft, ok := ast.Unparen(m.Type).(*ast.FuncType); ok {
			params = ft.Params
			hasSync = hasSync || hasParamDir(pass.Fset, comments, ft.Params, vetutil.DirectiveBorrowed)
		}
		recordFuncDeclFact(pass, comments, m.Names[0], params, hasWholeSecret, hasSync, res)
	}
}

func recordFuncDeclFact(pass *analysis.Pass, comments []*ast.CommentGroup, ident *ast.Ident, params *ast.FieldList, hasWholeSecret, hasSync bool, res *Result) {
	fnObj, ok := pass.TypesInfo.Defs[ident].(*types.Func)
	if !ok || fnObj == nil {
		return
	}
	cbSecret, directSecret := analyzeSecretFuncParams(pass, comments, params, hasWholeSecret)
	isSecret := hasWholeSecret || len(cbSecret) > 0 || len(directSecret) > 0
	if !isSecret && !hasSync {
		return
	}
	orig := fnObj.Origin()
	if isSecret {
		fact := Fact{WholeDecl: hasWholeSecret, CallbackSecret: cbSecret, DirectSecret: directSecret}
		res.funcFacts[orig] = fact
		pass.ExportObjectFact(orig, &fact)
		return
	}
	res.syncFuncs[orig] = true
	pass.ExportObjectFact(orig, &SyncFact{})
}

func analyzeSecretFuncParams(pass *analysis.Pass, comments []*ast.CommentGroup, fl *ast.FieldList, hasWholeSecret bool) (map[int][]int, []int) {
	if fl == nil {
		return nil, nil
	}
	cbSecret := make(map[int][]int)
	var directSecret []int
	paramIdx := 0
	for fieldIdx, f := range fl.List {
		count := max(len(f.Names), 1)
		fieldHasS := vetutil.ParamFieldHasDirective(pass.Fset, comments, fl, fieldIdx, vetutil.DirectiveSecretUse)
		if ft, isSig := unwrapSecretParamSignature(pass.TypesInfo, f.Type); isSig {
			recordCallbackSecretSlots(pass.Fset, comments, ft, paramIdx, count, hasWholeSecret || fieldHasS, cbSecret)
		} else if fieldHasS {
			directSecret = appendParamIndices(directSecret, paramIdx, count)
		}
		paramIdx += count
	}
	if len(cbSecret) == 0 {
		return nil, directSecret
	}
	return cbSecret, directSecret
}

func recordCallbackSecretSlots(fset *token.FileSet, comments []*ast.CommentGroup, ft *ast.FuncType, start, count int, outerSecret bool, cbSecret map[int][]int) {
	var innerExplicit []int
	if ft != nil {
		innerExplicit = collectParamDirIndices(fset, comments, ft.Params, vetutil.DirectiveSecretUse)
	}
	if !outerSecret && len(innerExplicit) == 0 {
		return
	}
	for k := range count {
		cbSecret[start+k] = slices.Clone(innerExplicit)
	}
}

func appendParamIndices(dst []int, start, count int) []int {
	for k := range count {
		dst = append(dst, start+k)
	}
	return dst
}

func unwrapSecretParamSignature(info *types.Info, expr ast.Expr) (*ast.FuncType, bool) {
	e := ast.Unparen(expr)
	if ell, ok := e.(*ast.Ellipsis); ok {
		e = ast.Unparen(ell.Elt)
	}
	if ft, ok := e.(*ast.FuncType); ok && ft != nil {
		return ft, true
	}
	if info == nil {
		return nil, false
	}
	if t := info.TypeOf(e); t != nil {
		_, isSig := types.Unalias(t).Underlying().(*types.Signature)
		return nil, isSig
	}
	return nil, false
}

func collectParamDirIndices(fset *token.FileSet, comments []*ast.CommentGroup, fl *ast.FieldList, kind vetutil.DirectiveKind) []int {
	if fl == nil {
		return nil
	}
	var out []int
	paramIdx := 0
	for i, f := range fl.List {
		count := max(len(f.Names), 1)
		if vetutil.ParamFieldHasDirective(fset, comments, fl, i, kind) {
			for k := range count {
				out = append(out, paramIdx+k)
			}
		}
		paramIdx += count
	}
	return out
}

func hasParamDir(fset *token.FileSet, comments []*ast.CommentGroup, fl *ast.FieldList, kind vetutil.DirectiveKind) bool {
	return len(collectParamDirIndices(fset, comments, fl, kind)) > 0
}

func (r *Result) lookupFuncFact(fn *types.Func) (Fact, bool) {
	if r == nil || fn == nil {
		return Fact{}, false
	}
	orig := fn.Origin()
	if f, ok := r.funcFacts[orig]; ok {
		return f, true
	}
	var imported Fact
	return imported, r.pass != nil && r.pass.ImportObjectFact(orig, &imported)
}

func (r *Result) lookupTypeFact(tn *types.TypeName) (Fact, bool) {
	if r == nil || tn == nil {
		return Fact{}, false
	}
	if f, ok := r.typeFacts[tn]; ok {
		return f, true
	}
	var imported Fact
	return imported, r.pass != nil && r.pass.ImportObjectFact(tn, &imported)
}

// HasFuncFact 判断函数或方法 fn（自动取 Origin() 兼容泛型）是否带有 //xops:secretuse 契约。
func (r *Result) HasFuncFact(fn *types.Func) bool {
	_, ok := r.lookupFuncFact(fn)
	return ok
}

// IsSyncClosureObject 判断对象是否为跨包/同包 //xops:syncclosure、//xops:borrowed、//xops:secretuse 或 SecretBox.Use。
func (r *Result) IsSyncClosureObject(obj types.Object) bool {
	if r.IsSecretUseObject(obj) {
		return true
	}
	fn, ok := obj.(*types.Func)
	if r == nil || !ok || fn == nil {
		return false
	}
	orig := fn.Origin()
	return r.syncFuncs[orig] || (r.pass != nil && r.pass.ImportObjectFact(orig, new(SyncFact)))
}

// HasTypeFact 判断命名函数类型 tn 是否带有 //xops:secretuse 契约。
func (r *Result) HasTypeFact(tn *types.TypeName) bool {
	_, ok := r.lookupTypeFact(tn)
	return ok
}

// SecretNamedFuncTypeParams 查询命名函数类型（兼容泛型与类型别名）的 //xops:secretuse 显式形参索引；
// ok==true 且返回 nil/空切片表示该回调类型的全部明文类型形参均受 //xops:secretuse 约束。
func (r *Result) SecretNamedFuncTypeParams(t types.Type) ([]int, bool) {
	if r == nil || t == nil {
		return nil, false
	}
	if al, ok := t.(*types.Alias); ok && al != nil && al.Origin() != nil {
		if f, found := r.lookupTypeFact(al.Origin().Obj()); found {
			return f.DirectSecret, true
		}
	}
	if named, ok := types.Unalias(t).(*types.Named); ok && named != nil && named.Origin() != nil {
		if f, found := r.lookupTypeFact(named.Origin().Obj()); found {
			return f.DirectSecret, true
		}
	}
	return nil, false
}

// CallbackSecretSlot 按精确回调槽位查询 fn 的第 argIdx 个用户实参是否为 //xops:secretuse 回调：
// 仅当形参类型为 //xops:secretuse 命名函数类型、fn 为 (*SecretBox).Use(argIdx==0) 或 Fact.CallbackSecret 显式命中
// argIdx（可变参归一化至末槽）时返回 true 及内层显式形参索引（nil 表示该回调的全部明文类型形参）。
func (r *Result) CallbackSecretSlot(fn *types.Func, sig *types.Signature, argIdx int) ([]int, bool) {
	if sig != nil && sig.Params() != nil && r != nil {
		if explicit, ok := r.SecretNamedFuncTypeParams(vetutil.ParamTypeAt(sig.Params(), sig.Variadic(), argIdx)); ok {
			return explicit, true
		}
	}
	if IsSecretBoxUseMethod(fn) && argIdx == 0 {
		return nil, true
	}
	fact, found := r.lookupFuncFact(fn)
	if !found || len(fact.CallbackSecret) == 0 {
		return nil, false
	}
	slotIdx := argIdx
	if sig != nil && sig.Variadic() && sig.Params() != nil && sig.Params().Len() > 0 && slotIdx >= sig.Params().Len() {
		slotIdx = sig.Params().Len() - 1
	}
	explicit, ok := fact.CallbackSecret[slotIdx]
	return explicit, ok
}

// DirectSecretParamIndices 查询直接声明 //xops:secretuse 的函数/方法受约束形参索引；
// ok==true 且返回 nil/空切片表示声明级 //xops:secretuse（覆盖全部明文类型形参）。
func (r *Result) DirectSecretParamIndices(fn *types.Func) ([]int, bool) {
	fact, found := r.lookupFuncFact(fn)
	if !found {
		return nil, false
	}
	if len(fact.DirectSecret) > 0 {
		return fact.DirectSecret, true
	}
	if fact.WholeDecl {
		return nil, true
	}
	return nil, false
}

// CoversDirectSecretSlot 判定调用目标 fn 的第 argIdx 个用户实参槽位是否被 //xops:secretuse 直接形参审计覆盖：
// 仅当该槽位（可变参归一化至末槽）命中显式 DirectSecret 或声明级 WholeDecl，且形参自身满足明文参数类型时返回 true；
// 仅带 CallbackSecret 的函数对非回调槽位一律 Fail-Closed 返回 false。
func (r *Result) CoversDirectSecretSlot(fn *types.Func, sig *types.Signature, argIdx int) bool {
	if r == nil || fn == nil || sig == nil || sig.Params() == nil || argIdx < 0 {
		return false
	}
	fact, found := r.lookupFuncFact(fn)
	if !found {
		return false
	}
	slotIdx := argIdx
	if sig.Variadic() && sig.Params().Len() > 0 && slotIdx >= sig.Params().Len() {
		slotIdx = sig.Params().Len() - 1
	}
	if slotIdx >= sig.Params().Len() || !vetutil.IsPlainSecretParamType(sig.Params().At(slotIdx).Type()) {
		return false
	}
	if len(fact.DirectSecret) > 0 {
		return slices.Contains(fact.DirectSecret, slotIdx)
	}
	return fact.WholeDecl
}

// CoversDirectSecretParams 核验跨包函数或接口方法 fn 的直接 //xops:secretuse 契约是否完整覆盖
// 调用方回调契约所需的全部明文类型用户形参（requiredExplicit 为空表示全部 IsPlainSecretParamType 用户形参）；
// 仅含 CallbackSecret 或仅覆盖部分明文形参的函数严格 Fail-Closed 返回 false。
func (r *Result) CoversDirectSecretParams(fn *types.Func, requiredExplicit []int) bool {
	if r == nil || fn == nil {
		return false
	}
	direct, ok := r.DirectSecretParamIndices(fn)
	if !ok {
		return false
	}
	if len(direct) == 0 {
		return true
	}
	sig, ok := fn.Type().Underlying().(*types.Signature)
	if !ok || sig.Params() == nil {
		return false
	}
	for i := range sig.Params().Len() {
		if (len(requiredExplicit) == 0 || slices.Contains(requiredExplicit, i)) &&
			vetutil.IsPlainSecretParamType(sig.Params().At(i).Type()) &&
			!slices.Contains(direct, i) {
			return false
		}
	}
	return true
}

// RecvNamedType 提取方法声明的接收者具名类型（自动解指针与别名）。
func RecvNamedType(fn *types.Func) (*types.Named, bool) {
	if fn == nil {
		return nil, false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil, false
	}
	return vetutil.UnwrapNamedType(sig.Recv().Type())
}

// IsSecretBoxUseMethod 判断对象是否为 (*secret.SecretBox).Use 或 (secret.SecretBox).Use 方法。
func IsSecretBoxUseMethod(obj types.Object) bool {
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil || fn.Name() != "Use" {
		return false
	}
	named, ok := RecvNamedType(fn)
	return ok && vetutil.IsPkgSymbol(named.Obj(), secretPkgPath, secretBoxName)
}

// IsSecretUseObject 判断对象是否为 SecretBox.Use 或标有 //xops:secretuse 的函数/方法。
func (r *Result) IsSecretUseObject(obj types.Object) bool {
	if IsSecretBoxUseMethod(obj) {
		return true
	}
	fn, ok := obj.(*types.Func)
	return ok && fn != nil && r.HasFuncFact(fn)
}

// HasSecretUseCallbackParam 判断函数或方法的形参列表中是否存在标有 //xops:secretuse 的命名函数类型参数（含可变参）。
func (r *Result) HasSecretUseCallbackParam(obj types.Object) bool {
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil {
		return false
	}
	sig, ok := fn.Type().Underlying().(*types.Signature)
	if !ok || sig.Params() == nil {
		return false
	}
	for i := range sig.Params().Len() {
		if r.IsSecretUseNamedFuncType(vetutil.ParamTypeAt(sig.Params(), sig.Variadic(), i)) {
			return true
		}
	}
	return false
}

// IsSecretUseNamedFuncType 判断类型 t（兼容泛型/别名）是否为标有 //xops:secretuse 的命名函数类型。
func (r *Result) IsSecretUseNamedFuncType(t types.Type) bool {
	_, ok := r.SecretNamedFuncTypeParams(t)
	return ok
}
