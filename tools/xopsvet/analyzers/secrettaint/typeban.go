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
		checkRestrictedNonStructType(pass, pkgInfo, ts, obj, isErr, isDTO, restricted)
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

// checkRestrictedNonStructType 检查非结构体命名类型（如切片、指针、映射或别名）
// 在受限包、受限角色名、error 实现或 //xops:dto 场景下是否包含 SecretBox。
func checkRestrictedNonStructType(
	pass *analysis.Pass,
	pkgInfo vetutil.PkgInfo,
	ts *ast.TypeSpec,
	obj types.Object,
	isErr, isDTO bool,
	restricted map[*types.TypeName]bool,
) {
	if !isRestrictedContainerStruct(pkgInfo, ts.Name.Name, isErr, isDTO, false) {
		return
	}
	if tn, ok := obj.(*types.TypeName); ok && tn != nil {
		restricted[tn] = true
	}
	if !isSecretBoxType(obj.Type()) {
		return
	}
	if isErr || isDTO {
		pass.ReportRangef(ts.Type, "secrettaint: 禁止 secret.SecretBox 进入 error 实现或 //xops:dto 类型")
		return
	}
	pass.ReportRangef(ts.Type, "secrettaint: 禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/受限类型")
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
