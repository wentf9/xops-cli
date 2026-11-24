// Package secretfact 提供 //xops:secretuse 与 //xops:syncclosure 跨包分析事实（analysis.Fact）前置分析器及公共汇点表。
package secretfact

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

const (
	secretPkgPath = vetutil.ModulePrefix + "/core/domain/secret"
	secretBoxName = "SecretBox"
)

// Fact 跨包传播 //xops:secretuse 契约；SyncFact 跨包传播非 secretuse 的 //xops:syncclosure/borrowed 契约（B-3）。
type (
	Fact     struct{}
	SyncFact struct{}
)

// AFact 标记为 go/analysis 跨包事实；String 返回确定性简短标识。
func (*Fact) AFact()             {}
func (*Fact) String() string     { return "secretuse" }
func (*SyncFact) AFact()         {}
func (*SyncFact) String() string { return "syncclosure" }

// Result 保存当前包及依赖中带有 //xops:secretuse 与 //xops:syncclosure 契约的函数与命名函数类型集合。
type Result struct {
	pass      *analysis.Pass
	funcFacts map[*types.Func]bool
	typeFacts map[*types.TypeName]bool
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
	res := &Result{pass: pass, funcFacts: map[*types.Func]bool{}, typeFacts: map[*types.TypeName]bool{}, syncFuncs: map[*types.Func]bool{}}
	if vetutil.IsSyntheticTestMain(pass) || pass.TypesInfo == nil {
		return res, nil
	}
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name != nil && fn.Type != nil {
				isSecret := vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveSecretUse) || hasParamDir(pass.Fset, file.Comments, fn.Type.Params, vetutil.DirectiveSecretUse)
				isSync := isSecret || vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveSyncClosure) ||
					vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveBorrowed) || hasParamDir(pass.Fset, file.Comments, fn.Type.Params, vetutil.DirectiveBorrowed)
				exportDeclFacts(pass, fn.Name, isSecret, isSync, res)
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
	hasSecret := vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveSecretUse)
	if ft, ok := ast.Unparen(ts.Type).(*ast.FuncType); ok {
		hasSecret = hasSecret || hasParamDir(pass.Fset, comments, ft.Params, vetutil.DirectiveSecretUse)
	}
	if hasSecret {
		res.typeFacts[tn] = true
		pass.ExportObjectFact(tn, &Fact{})
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
		isSecret := vetutil.FieldHasDirective(m, vetutil.DirectiveSecretUse)
		isSync := vetutil.FieldHasDirective(m, vetutil.DirectiveSyncClosure) || vetutil.FieldHasDirective(m, vetutil.DirectiveBorrowed)
		if ft, ok := ast.Unparen(m.Type).(*ast.FuncType); ok {
			isSecret = isSecret || hasParamDir(pass.Fset, comments, ft.Params, vetutil.DirectiveSecretUse)
			isSync = isSync || hasParamDir(pass.Fset, comments, ft.Params, vetutil.DirectiveBorrowed)
		}
		exportDeclFacts(pass, m.Names[0], isSecret, isSync || isSecret, res)
	}
}

func exportDeclFacts(pass *analysis.Pass, ident *ast.Ident, isSecret, isSync bool, res *Result) {
	fnObj, ok := pass.TypesInfo.Defs[ident].(*types.Func)
	if (!isSecret && !isSync) || !ok || fnObj == nil {
		return
	}
	orig := fnObj.Origin()
	if isSecret {
		res.funcFacts[orig] = true
		pass.ExportObjectFact(orig, &Fact{})
		return
	}
	res.syncFuncs[orig] = true
	pass.ExportObjectFact(orig, &SyncFact{})
}

func hasParamDir(fset *token.FileSet, comments []*ast.CommentGroup, fl *ast.FieldList, kind vetutil.DirectiveKind) bool {
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

// HasFuncFact 判断函数或方法 fn（自动取 Origin() 兼容泛型）是否带有 //xops:secretuse 契约。
func (r *Result) HasFuncFact(fn *types.Func) bool {
	if r == nil || fn == nil {
		return false
	}
	orig := fn.Origin()
	return r.funcFacts[orig] || (r.pass != nil && r.pass.ImportObjectFact(orig, new(Fact)))
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
	return r != nil && tn != nil && (r.typeFacts[tn] || (r.pass != nil && r.pass.ImportObjectFact(tn, new(Fact))))
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
	if r == nil || t == nil {
		return false
	}
	if al, ok := t.(*types.Alias); ok && al != nil && al.Origin() != nil && r.HasTypeFact(al.Origin().Obj()) {
		return true
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named != nil && named.Origin() != nil && r.HasTypeFact(named.Origin().Obj())
}
