package secretbox

import (
	"go/ast"
	"go/types"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// checkTypeAndEmbeddingBan 禁止 SecretBox 进入受限/序列化/error 类型，并在全包所有结构体禁止匿名嵌入 SecretBox（CRIT-2）。
func checkTypeAndEmbeddingBan(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) map[*types.TypeName]bool {
	restricted := make(map[*types.TypeName]bool)
	vetutil.ForEachTypeSpec(pass, func(_ *ast.File, gen *ast.GenDecl, ts *ast.TypeSpec) {
		checkTypeSpecSecretBox(pass, pkgInfo, gen, ts, restricted)
	})
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.StructType)(nil)}, func(n ast.Node) {
		if st, ok := n.(*ast.StructType); ok && st.Fields != nil {
			for _, f := range st.Fields.List {
				if len(f.Names) == 0 && isSecretBoxValueType(pass.TypesInfo.TypeOf(f.Type)) {
					pass.ReportRangef(f.Type, "secretbox: 禁止在命名或匿名结构体中嵌入 secret.SecretBox")
				}
			}
		}
	})
	return restricted
}

func checkTypeSpecSecretBox(pass *analysis.Pass, pkgInfo vetutil.PkgInfo, gen *ast.GenDecl, ts *ast.TypeSpec, restricted map[*types.TypeName]bool) {
	obj := pass.TypesInfo.Defs[ts.Name]
	if obj == nil {
		return
	}
	isErr := vetutil.ImplementsError(obj.Type())
	isDTO := vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveDTO)
	st, isStruct := ts.Type.(*ast.StructType)
	hasTags := false
	if isStruct {
		if tags, err := vetutil.StructSerialTags(st); err == nil {
			hasTags = tags.Any()
		}
	}
	if !isRestrictedContainerStruct(pkgInfo, ts.Name.Name, isErr, isDTO, hasTags) {
		return
	}
	if tn, ok := obj.(*types.TypeName); ok && tn != nil {
		restricted[tn] = true
	}
	if isStruct {
		checkRestrictedStructFields(pass, st)
		return
	}
	if isSecretBoxValueType(obj.Type()) {
		if isErr || isDTO {
			pass.ReportRangef(ts.Type, "secretbox: 禁止 secret.SecretBox 进入 error 实现或 //xops:dto 类型")
			return
		}
		pass.ReportRangef(ts.Type, "secretbox: 禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/受限类型")
	}
}

func checkRestrictedStructFields(pass *analysis.Pass, st *ast.StructType) {
	if st.Fields == nil {
		return
	}
	for _, f := range st.Fields.List {
		// 匿名嵌入字段已由 checkAnonymousStructEmbedding 统一拦截，避免对同一字段重复告警。
		if len(f.Names) > 0 && isSecretBoxValueType(pass.TypesInfo.TypeOf(f.Type)) {
			pass.ReportRangef(f.Type, "secretbox: 禁止 secret.SecretBox 进入 Event/Audit/Plan/Error/序列化结构体字段")
		}
	}
}

func isRestrictedContainerStruct(pkgInfo vetutil.PkgInfo, typeName string, isErr, isDTO, hasTags bool) bool {
	return isErr || isDTO || hasTags || isRestrictedContainerPkg(pkgInfo) || hasRestrictedRoleName(typeName)
}

func isRestrictedContainerPkg(pkgInfo vetutil.PkgInfo) bool {
	if pkgInfo.Layer == vetutil.LayerCoreEvents || pkgInfo.Layer == vetutil.LayerCoreMCPRuntime {
		return true
	}
	return slices.Contains([]string{
		vetutil.ModulePrefix + "/core/domain/plan",
		vetutil.ModulePrefix + "/internal/host/audit",
		vetutil.ModulePrefix + "/internal/host/store",
		vetutil.ModulePrefix + "/internal/entry/mcpcmd",
	}, pkgInfo.BasePath)
}

func hasRestrictedRoleName(name string) bool {
	if strings.HasSuffix(name, "Err") {
		return true
	}
	for _, kw := range []string{
		"Event", "Audit", "Plan", "Error", "DTO", "Dto", "Entry", "Record",
		"Report", "Envelope", "Payload", "Message", "Notification", "Journal", "Config", "Request", "Response",
	} {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

func isRestrictedNamedType(t types.Type, localRestricted map[*types.TypeName]bool) bool {
	named, ok := vetutil.UnwrapNamedType(t)
	if !ok || named == nil {
		return false
	}
	orig := named.Origin().Obj()
	if localRestricted[orig] || vetutil.ImplementsError(named) || hasRestrictedRoleName(orig.Name()) {
		return true
	}
	pkgPath := vetutil.ObjectPkgPath(orig)
	return pkgPath != "" && isRestrictedContainerPkg(vetutil.ClassifyPackage(pkgPath))
}

// checkSecretBoxErasure 接入 vetssa.CheckNoErasure 拦截接口/泛型擦除，并按 CRIT-1/N1 精确豁免白盒 json/v2.Marshal* 测试。
func checkSecretBoxErasure(pass *analysis.Pass, s *buildssa.SSA, pkgInfo vetutil.PkgInfo, handledMI map[*ssa.MakeInterface]bool) {
	diags := vetssa.CheckNoErasure(pass, s, vetssa.ErasureConfig{
		MatchType:      isSecretBoxValueType,
		CheckInstances: true,
		AllowMakeInterface: func(fn *ssa.Function, mi *ssa.MakeInterface) bool {
			return handledMI[mi] || isAllowedJSONv2SecretTestMI(pass, s, pkgInfo, fn, mi)
		},
		Message: "secretbox: 禁止将 secret.SecretBox 擦除为接口或作为泛型类型实参传递",
	})
	vetutil.ReportSortedDedup(pass, diags, true)
}

// isAllowedJSONv2SecretTestMI 精确验证 core/domain/secret 白盒 *_test.go 直调 encoding/json/v2.Marshal* 的联合豁免条件。
func isAllowedJSONv2SecretTestMI(pass *analysis.Pass, s *buildssa.SSA, pkgInfo vetutil.PkgInfo, fn *ssa.Function, mi *ssa.MakeInterface) bool {
	if pkgInfo.IsExternalTest || pkgInfo.BasePath != secretPkgPath || !isExactSecretBox(mi.X.Type()) {
		return false
	}
	if mi.Referrers() == nil || len(*mi.Referrers()) != 1 {
		return false
	}
	callInst, ok := (*mi.Referrers())[0].(*ssa.Call)
	return ok && isAllowedJSONv2SecretTestCall(pass, pkgInfo, fn, callInst, vetssa.ResolveCall(s, callInst), mi)
}

func isAllowedJSONv2SecretTestCall(pass *analysis.Pass, pkgInfo vetutil.PkgInfo, fn *ssa.Function, callInst ssa.CallInstruction, rc vetssa.ResolvedCall, boxArg ssa.Value) bool {
	if pkgInfo.IsExternalTest || pkgInfo.BasePath != secretPkgPath || !vetssa.IsInstInTestFile(pass, fn, callInst) ||
		vetutil.ObjectPkgPath(rc.FuncObj) != "encoding/json/v2" {
		return false
	}
	inIdx := -1
	switch rc.FuncObj.Name() {
	case "Marshal":
		inIdx = 0
	case "MarshalWrite", "MarshalEncode":
		inIdx = 1
	}
	if inIdx < 0 || len(rc.UserArgs) <= inIdx || rc.UserArgs[inIdx] != boxArg {
		return false
	}
	if mi, ok := boxArg.(*ssa.MakeInterface); ok {
		return isExactSecretBox(mi.X.Type())
	}
	return isExactSecretBox(boxArg.Type())
}
