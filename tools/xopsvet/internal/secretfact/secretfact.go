// Package secretfact 提供 //xops:secretuse 跨包分析事实（analysis.Fact）的唯一前置分析器与公共高危汇点分类表。
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

// Fact 用于在 go/analysis 编译单元间跨包传播 //xops:secretuse 契约。
type Fact struct{}

// AFact 标记 Fact 为 go/analysis 跨包分析事实。
func (*Fact) AFact() {}

// String 返回事实的可读简短标识（供 analysistest 核验）。
func (*Fact) String() string { return "secretuse" }

// Result 保存当前包及其直接依赖中带有 //xops:secretuse 契约的函数与命名函数类型集合。
type Result struct {
	pass      *analysis.Pass
	funcFacts map[*types.Func]bool
	typeFacts map[*types.TypeName]bool
}

// NewAnalyzer 构造 secretfact 前置分析器实例（cmd/xopsvet 应构造单一实例注入 3 个消费分析器）。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:       "secretfact",
		Doc:        "收集并跨包导出 //xops:secretuse 明文机密消费契约，供 secretbox/secrettaint/linearlease 共享",
		FactTypes:  []analysis.Fact{(*Fact)(nil)},
		ResultType: reflect.TypeOf((*Result)(nil)),
		Run:        run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	res := &Result{pass: pass, funcFacts: make(map[*types.Func]bool), typeFacts: make(map[*types.TypeName]bool)}
	if vetutil.IsSyntheticTestMain(pass) || pass.TypesInfo == nil {
		return res, nil
	}
	for _, file := range pass.Files {
		collectFileFuncFacts(pass, file, res)
	}
	vetutil.ForEachTypeSpec(pass, func(file *ast.File, gen *ast.GenDecl, ts *ast.TypeSpec) {
		collectTypeSpecFact(pass, file.Comments, gen, ts, res)
	})
	return res, nil
}

func collectFileFuncFacts(pass *analysis.Pass, file *ast.File, res *Result) {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name != nil && fn.Type != nil {
			if vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveSecretUse) || hasAnyParamDirective(pass.Fset, file.Comments, fn.Type.Params) {
				exportFuncFact(pass, fn.Name, res)
			}
		}
	}
}

func collectTypeSpecFact(pass *analysis.Pass, comments []*ast.CommentGroup, gen *ast.GenDecl, ts *ast.TypeSpec, res *Result) {
	switch t := ts.Type.(type) {
	case *ast.InterfaceType:
		collectInterfaceFacts(pass, comments, t, res)
	case *ast.FuncType:
		if vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveSecretUse) {
			if tn, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName); ok && tn != nil {
				res.typeFacts[tn] = true
				pass.ExportObjectFact(tn, &Fact{})
			}
		}
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
		hasDir := vetutil.FieldHasDirective(m, vetutil.DirectiveSecretUse)
		if ft, ok := ast.Unparen(m.Type).(*ast.FuncType); ok {
			hasDir = hasDir || hasAnyParamDirective(pass.Fset, comments, ft.Params)
		}
		if hasDir {
			exportFuncFact(pass, m.Names[0], res)
		}
	}
}

func exportFuncFact(pass *analysis.Pass, ident *ast.Ident, res *Result) {
	if fnObj, ok := pass.TypesInfo.Defs[ident].(*types.Func); ok && fnObj != nil {
		orig := fnObj.Origin()
		res.funcFacts[orig] = true
		pass.ExportObjectFact(orig, &Fact{})
	}
}

func hasAnyParamDirective(fset *token.FileSet, comments []*ast.CommentGroup, fl *ast.FieldList) bool {
	if fl == nil {
		return false
	}
	for i := range fl.List {
		if vetutil.ParamFieldHasDirective(fset, comments, fl, i, vetutil.DirectiveSecretUse) {
			return true
		}
	}
	return false
}

// HasFuncFact 判断函数或方法 fn（自动取 Origin() 兼容泛型实例化）是否带有 //xops:secretuse 契约。
func (r *Result) HasFuncFact(fn *types.Func) bool {
	if r == nil || fn == nil {
		return false
	}
	orig := fn.Origin()
	var f Fact
	return r.funcFacts[orig] || (r.pass != nil && r.pass.ImportObjectFact(orig, &f))
}

// HasTypeFact 判断命名函数类型 tn 是否带有 //xops:secretuse 契约。
func (r *Result) HasTypeFact(tn *types.TypeName) bool {
	if r == nil || tn == nil {
		return false
	}
	var f Fact
	return r.typeFacts[tn] || (r.pass != nil && r.pass.ImportObjectFact(tn, &f))
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

// HasSecretUseCallbackParam 判断函数或方法的形参列表中是否存在标有 //xops:secretuse 的命名函数类型参数。
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
		if r.IsSecretUseNamedFuncType(sig.Params().At(i).Type()) {
			return true
		}
	}
	return false
}

// IsSecretUseNamedFuncType 判断类型 t（解别名后）是否为标有 //xops:secretuse 的命名函数类型。
func (r *Result) IsSecretUseNamedFuncType(t types.Type) bool {
	if r == nil || t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named != nil && named.Origin() != nil && r.HasTypeFact(named.Origin().Obj())
}
