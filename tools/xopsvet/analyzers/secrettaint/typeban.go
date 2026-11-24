package secrettaint

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

func checkSecretBoxTypeAndSinkBan(pass *analysis.Pass) {
	restricted := collectRestrictedStructTypes(pass)
	checkCompositeLitSecretBox(pass, restricted)
	checkFuncSecretBoxSinks(pass)
}

func collectRestrictedStructTypes(pass *analysis.Pass) map[*types.TypeName]bool {
	restricted := make(map[*types.TypeName]bool)
	pkgInfo := vetutil.ClassifyPackage(pass.Pkg.Path())
	ins := vetutil.InspectorOf(pass)
	ins.Preorder([]ast.Node{(*ast.GenDecl)(nil)}, func(n ast.Node) {
		gen, ok := n.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			return
		}
		checkTypeDeclSecretBox(pass, pkgInfo, gen, restricted)
	})
	return restricted
}

func checkTypeDeclSecretBox(
	pass *analysis.Pass,
	pkgInfo vetutil.PkgInfo,
	gen *ast.GenDecl,
	restricted map[*types.TypeName]bool,
) {
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		checkTypeSpecSecretBox(pass, pkgInfo, gen, ts, restricted)
	}
}

func checkTypeSpecSecretBox(
	pass *analysis.Pass,
	pkgInfo vetutil.PkgInfo,
	gen *ast.GenDecl,
	ts *ast.TypeSpec,
	restricted map[*types.TypeName]bool,
) {
	obj := pass.TypesInfo.Defs[ts.Name]
	if obj == nil {
		return
	}
	isErr := vetutil.ImplementsError(obj.Type())
	isDTO := vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveDTO)
	st, isStruct := ts.Type.(*ast.StructType)
	if !isStruct {
		if (isErr || isDTO) && isSecretBoxType(obj.Type()) {
			pass.ReportRangef(ts.Type, "secrettaint: 禁止 secret.SecretBox 进入 error 实现或 //xops:dto 类型")
		}
		return
	}
	hasTags, err := hasSerializationTags(st)
	if err != nil {
		return
	}
	if !isRestrictedContainerStruct(pkgInfo, ts.Name.Name, isErr, isDTO, hasTags) {
		return
	}
	if tn, ok := obj.(*types.TypeName); ok && tn != nil {
		restricted[tn] = true
	}
	checkRestrictedStructFields(pass, st)
}

func isRestrictedContainerStruct(
	pkgInfo vetutil.PkgInfo,
	typeName string,
	isErr, isDTO, hasTags bool,
) bool {
	if isErr || isDTO || hasTags {
		return true
	}
	if isRestrictedContainerPkg(pkgInfo) {
		return true
	}
	return hasRestrictedRoleName(typeName)
}

func isRestrictedContainerPkg(pkgInfo vetutil.PkgInfo) bool {
	switch pkgInfo.Layer {
	case vetutil.LayerCoreEvents, vetutil.LayerCoreMCPRuntime:
		return true
	default:
		switch pkgInfo.BasePath {
		case vetutil.ModulePrefix + "/core/domain/plan",
			vetutil.ModulePrefix + "/internal/host/audit",
			vetutil.ModulePrefix + "/internal/host/store",
			vetutil.ModulePrefix + "/internal/entry/mcpcmd":
			return true
		default:
			return false
		}
	}
}

func hasRestrictedRoleName(name string) bool {
	switch {
	case strings.Contains(name, "Event"),
		strings.Contains(name, "Audit"),
		strings.Contains(name, "Plan"),
		strings.Contains(name, "Error"),
		strings.HasSuffix(name, "Err"),
		strings.Contains(name, "DTO"),
		strings.Contains(name, "Dto"),
		strings.Contains(name, "Entry"),
		strings.Contains(name, "Record"),
		strings.Contains(name, "Report"),
		strings.Contains(name, "Envelope"),
		strings.Contains(name, "Payload"),
		strings.Contains(name, "Message"),
		strings.Contains(name, "Notification"),
		strings.Contains(name, "Journal"),
		strings.Contains(name, "Config"),
		strings.Contains(name, "Request"),
		strings.Contains(name, "Response"):
		return true
	default:
		return false
	}
}

func hasSerializationTags(st *ast.StructType) (bool, error) {
	if st.Fields == nil {
		return false, nil
	}
	for _, f := range st.Fields.List {
		tag, hasTag, err := parseStructTag(f)
		if err != nil {
			return false, err
		}
		if !hasTag {
			continue
		}
		if v, ok := tag.Lookup("json"); ok && v != "-" {
			return true, nil
		}
		if v, ok := tag.Lookup("yaml"); ok && v != "-" {
			return true, nil
		}
	}
	return false, nil
}

func parseStructTag(f *ast.Field) (reflect.StructTag, bool, error) {
	if f == nil || f.Tag == nil {
		return "", false, nil
	}
	raw, err := strconv.Unquote(f.Tag.Value)
	if err != nil {
		return "", false, err
	}
	return reflect.StructTag(raw), true, nil
}

func checkRestrictedStructFields(pass *analysis.Pass, st *ast.StructType) {
	if st.Fields == nil {
		return
	}
	for _, f := range st.Fields.List {
		fieldType := pass.TypesInfo.TypeOf(f.Type)
		if isSecretBoxType(fieldType) {
			pass.ReportRangef(f.Type, "secrettaint: 禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/序列化结构体字段")
		}
	}
}

func checkCompositeLitSecretBox(pass *analysis.Pass, restricted map[*types.TypeName]bool) {
	ins := vetutil.InspectorOf(pass)
	ins.Preorder([]ast.Node{(*ast.CompositeLit)(nil)}, func(n ast.Node) {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return
		}
		if !isRestrictedLitType(pass.TypesInfo.TypeOf(lit), restricted) {
			return
		}
		for _, elt := range lit.Elts {
			val := elt
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				val = kv.Value
			}
			if exprHasSecretBox(pass.TypesInfo, val, nil) {
				pass.ReportRangef(val, "secrettaint: 禁止将 secret.SecretBox 存入 Event/Audit/Plan/Error/序列化结构体字段")
			}
		}
	})
}

func isRestrictedLitType(t types.Type, localRestricted map[*types.TypeName]bool) bool {
	named, ok := vetutil.UnwrapNamedType(t)
	if !ok || named == nil {
		return false
	}
	orig := named.Origin().Obj()
	if localRestricted[orig] {
		return true
	}
	if vetutil.ImplementsError(named) || hasRestrictedRoleName(orig.Name()) {
		return true
	}
	pkgPath := vetutil.ObjectPkgPath(orig)
	if pkgPath == "" {
		return false
	}
	return isRestrictedContainerPkg(vetutil.ClassifyPackage(pkgPath))
}

func checkFuncSecretBoxSinks(pass *analysis.Pass) {
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			checkBlockSecretBoxSinks(pass, fn.Body)
		}
	}
}

func checkBlockSecretBoxSinks(pass *analysis.Pass, body *ast.BlockStmt) {
	boxVars := collectSecretBoxVars(pass.TypesInfo, body)
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		kind := classifyRule1SinkCall(pass.TypesInfo, call)
		if kind == sinkNone {
			return true
		}
		for _, arg := range call.Args {
			if exprHasSecretBox(pass.TypesInfo, arg, boxVars) {
				pass.ReportRangef(arg, "secrettaint: 禁止将 secret.SecretBox 传入%s汇点", kind.label())
			}
		}
		return true
	})
}

func collectSecretBoxVars(info *types.Info, body *ast.BlockStmt) map[*types.Var]bool {
	boxVars := make(map[*types.Var]bool)
	for range 3 {
		changed := false
		ast.Inspect(body, func(n ast.Node) bool {
			switch stmt := n.(type) {
			case *ast.AssignStmt:
				if propagateBoxPairs(info, stmt.Lhs, stmt.Rhs, boxVars) {
					changed = true
				}
			case *ast.ValueSpec:
				if propagateBoxValueSpec(info, stmt, boxVars) {
					changed = true
				}
			}
			return true
		})
		if !changed {
			break
		}
	}
	return boxVars
}

func propagateBoxValueSpec(info *types.Info, vs *ast.ValueSpec, boxVars map[*types.Var]bool) bool {
	if len(vs.Names) != len(vs.Values) {
		return false
	}
	changed := false
	for i := range vs.Names {
		v, ok := info.Defs[vs.Names[i]].(*types.Var)
		if ok && v != nil && exprHasSecretBox(info, vs.Values[i], boxVars) && !boxVars[v] {
			boxVars[v] = true
			changed = true
		}
	}
	return changed
}

func propagateBoxPairs(info *types.Info, lhs, rhs []ast.Expr, boxVars map[*types.Var]bool) bool {
	if len(lhs) != len(rhs) {
		return false
	}
	changed := false
	for i := range lhs {
		id, ok := ast.Unparen(lhs[i]).(*ast.Ident)
		if !ok || id.Name == "_" {
			continue
		}
		v := lookupAssignVar(info, id)
		if v != nil && exprHasSecretBox(info, rhs[i], boxVars) && !boxVars[v] {
			boxVars[v] = true
			changed = true
		}
	}
	return changed
}

func lookupAssignVar(info *types.Info, id *ast.Ident) *types.Var {
	if v, ok := info.Defs[id].(*types.Var); ok && v != nil {
		return v
	}
	if v, ok := info.Uses[id].(*types.Var); ok && v != nil {
		return v
	}
	return nil
}

func exprHasSecretBox(info *types.Info, expr ast.Expr, boxVars map[*types.Var]bool) bool {
	if expr == nil {
		return false
	}
	if isSecretBoxType(info.TypeOf(expr)) {
		return true
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		v, ok := info.Uses[e].(*types.Var)
		return ok && v != nil && boxVars != nil && boxVars[v]
	case *ast.UnaryExpr:
		return exprHasSecretBox(info, e.X, boxVars)
	case *ast.StarExpr:
		return exprHasSecretBox(info, e.X, boxVars)
	case *ast.TypeAssertExpr:
		return exprHasSecretBox(info, e.X, boxVars)
	case *ast.CompositeLit:
		return compositeLitHasSecretBox(info, e, boxVars)
	case *ast.CallExpr:
		return conversionHasSecretBox(info, e, boxVars)
	default:
		return false
	}
}

func compositeLitHasSecretBox(info *types.Info, lit *ast.CompositeLit, boxVars map[*types.Var]bool) bool {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if exprHasSecretBox(info, kv.Key, boxVars) || exprHasSecretBox(info, kv.Value, boxVars) {
				return true
			}
			continue
		}
		if exprHasSecretBox(info, elt, boxVars) {
			return true
		}
	}
	return false
}

func conversionHasSecretBox(info *types.Info, call *ast.CallExpr, boxVars map[*types.Var]bool) bool {
	if len(call.Args) != 1 {
		return false
	}
	tv, ok := info.Types[call.Fun]
	if !ok || !tv.IsType() {
		return false
	}
	return exprHasSecretBox(info, call.Args[0], boxVars)
}
