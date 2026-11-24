package noimplicit

import (
	"go/ast"
	"go/types"
	"reflect"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

const algebraicPkgPath = vetutil.ModulePrefix + "/core/domain/algebraic"

type dtoFormat struct {
	checkJSON, checkYAML, inMapValue bool
}

// checkDTOs 扫描持久化/序列化 DTO 结构体字段，拦截除 algebraic.Duration 之外的裸 time.Duration 用法。
// 核心不变量：移除全局 *Config 泛化后缀、先查泛型 TypeArgs() 再遇自定义编码器停钻、严格区分 JSON/YAML 语义。
func checkDTOs(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	if pass.TypesInfo == nil || pkgInfo.BasePath == algebraicPkgPath {
		return
	}
	vetutil.ForEachTypeSpec(pass, func(_ *ast.File, gen *ast.GenDecl, ts *ast.TypeSpec) {
		checkTypeSpecDTO(pass, pkgInfo, gen, ts)
	})
}

func checkTypeSpecDTO(pass *analysis.Pass, pkgInfo vetutil.PkgInfo, gen *ast.GenDecl, ts *ast.TypeSpec) {
	st, ok := ts.Type.(*ast.StructType)
	if !ok {
		return
	}
	tags, err := vetutil.StructSerialTags(st)
	if err != nil {
		tags = vetutil.SerialTagFlags{}
	}
	if !isDTOStruct(pkgInfo, ts, vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveDTO) || tags.Any()) {
		return
	}
	checkYAML := tags.HasYAML || pkgInfo.BasePath == vetutil.ModulePrefix+"/internal/host/store"
	mode := dtoFormat{checkJSON: tags.HasJSON || !checkYAML, checkYAML: checkYAML}
	if isTopLevelCustomMarshaler(pass, ts, mode) {
		return
	}
	checkDTOStructFields(pass, st, mode)
}

func isTopLevelCustomMarshaler(pass *analysis.Pass, ts *ast.TypeSpec, mode dtoFormat) bool {
	topNamed, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName)
	if !ok || topNamed == nil {
		return false
	}
	named, isNamed := types.Unalias(topNamed.Type()).(*types.Named)
	return isNamed && canStopAtCustomMarshaler(named, mode)
}

func isDTOStruct(pkgInfo vetutil.PkgInfo, ts *ast.TypeSpec, hasExplicitOrTagged bool) bool {
	if hasExplicitOrTagged {
		return true
	}
	name := ts.Name.Name
	if isDTOPackage(pkgInfo) && ((pkgInfo.Layer == vetutil.LayerCoreEvents && ts.Name.IsExported()) || isDTONameRole(name)) {
		return true
	}
	return ts.Name.IsExported() && hasStrictDTOSuffix(name)
}

func isDTOPackage(pkgInfo vetutil.PkgInfo) bool {
	return pkgInfo.Layer == vetutil.LayerCoreEvents || pkgInfo.Layer == vetutil.LayerCoreMCPRuntime ||
		slices.Contains([]string{
			vetutil.ModulePrefix + "/internal/host/audit",
			vetutil.ModulePrefix + "/internal/host/store",
			vetutil.ModulePrefix + "/internal/entry/mcpcmd",
		}, pkgInfo.BasePath)
}

func isDTONameRole(name string) bool {
	return slices.ContainsFunc([]string{
		"Event", "Audit", "DTO", "Dto", "Config", "Cfg", "Request", "Response", "Input", "Output",
		"Params", "Result", "Payload", "Entry", "Record", "Envelope", "Manifest", "Bundle",
		"Schema", "Message", "Notification", "Journal",
	}, func(kw string) bool { return strings.Contains(name, kw) })
}

// hasStrictDTOSuffix 仅匹配全局精确序列化载荷后缀（移除泛化 *Config 后缀以免误杀纯内存配置参数）。
func hasStrictDTOSuffix(name string) bool {
	return slices.ContainsFunc([]string{"DTO", "Dto", "Event", "AuditEntry", "AuditRecord"},
		func(suf string) bool { return strings.HasSuffix(name, suf) })
}

func checkDTOStructFields(pass *analysis.Pass, st *ast.StructType, mode dtoFormat) {
	if st.Fields == nil {
		return
	}
	for _, f := range st.Fields.List {
		if !isTopFieldSerializable(f) {
			continue
		}
		if tag, hasTag, err := vetutil.ParseStructFieldTag(f); err == nil && hasTag && vetutil.IsTagSkippedForFormat(tag, mode.checkJSON, mode.checkYAML) {
			continue
		}
		if hasBareTimeDuration(pass.TypesInfo.TypeOf(f.Type), mode, make(map[types.Type]bool)) {
			pass.ReportRangef(f.Type, "noimplicit: Event/Audit/MCP/持久化配置 DTO 禁止裸用 time.Duration，请使用 algebraic.Duration")
		}
	}
}

func isTopFieldSerializable(f *ast.Field) bool {
	return len(f.Names) == 0 || slices.ContainsFunc(f.Names, (*ast.Ident).IsExported)
}

func hasBareTimeDuration(t types.Type, mode dtoFormat, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok {
		return namedHasBareTimeDuration(named, mode, seen)
	}
	return compositeHasBareTimeDuration(t, mode, seen)
}

func namedHasBareTimeDuration(named *types.Named, mode dtoFormat, seen map[types.Type]bool) bool {
	obj := named.Obj()
	if vetutil.IsPkgSymbol(obj, algebraicPkgPath, "Duration") {
		return false
	}
	if vetutil.IsPkgSymbol(obj, "time", "Duration") {
		return true
	}
	if seen[named] {
		return false
	}
	seen[named] = true
	// B3a 铁律：必须先递归检查泛型类型实参 TypeArgs()，再判定自定义编码器停钻。
	if typeArgs := named.TypeArgs(); typeArgs != nil {
		argMode := dtoFormat{checkJSON: mode.checkJSON, checkYAML: mode.checkYAML}
		for i := range typeArgs.Len() {
			if hasBareTimeDuration(typeArgs.At(i), argMode, seen) {
				return true
			}
		}
	}
	return !canStopAtCustomMarshaler(named, mode) && hasBareTimeDuration(named.Underlying(), mode, seen)
}

type dtoElemCarrier interface{ Elem() types.Type }

func compositeHasBareTimeDuration(t types.Type, mode dtoFormat, seen map[types.Type]bool) bool {
	elemMode := dtoFormat{checkJSON: mode.checkJSON, checkYAML: mode.checkYAML}
	switch v := t.(type) {
	case *types.Map:
		valMode := dtoFormat{checkJSON: mode.checkJSON, checkYAML: mode.checkYAML, inMapValue: true}
		return hasBareTimeDuration(v.Key(), elemMode, seen) || hasBareTimeDuration(v.Elem(), valMode, seen)
	case dtoElemCarrier:
		return hasBareTimeDuration(v.Elem(), elemMode, seen)
	case *types.Struct:
		return structHasBareTimeDuration(v, mode, seen)
	default:
		return false
	}
}

func structHasBareTimeDuration(st *types.Struct, mode dtoFormat, seen map[types.Type]bool) bool {
	if seen[st] {
		return false
	}
	seen[st] = true
	fieldMode := dtoFormat{checkJSON: mode.checkJSON, checkYAML: mode.checkYAML}
	for i := range st.NumFields() {
		f := st.Field(i)
		if (!f.Exported() && !f.Embedded()) || vetutil.IsTagSkippedForFormat(reflect.StructTag(st.Tag(i)), mode.checkJSON, mode.checkYAML) {
			continue
		}
		if hasBareTimeDuration(f.Type(), fieldMode, seen) {
			return true
		}
	}
	return false
}

// canStopAtCustomMarshaler 按 JSON/v2 与 yaml.v3 真实编码语义判定命名类型是否安全接管了序列化。
func canStopAtCustomMarshaler(named *types.Named, mode dtoFormat) bool {
	ptr := types.NewPointer(named)
	if hasMethodOnType(named, "AppendText", "MarshalText") ||
		((!mode.checkYAML || !mode.inMapValue) && hasMethodOnType(ptr, "AppendText", "MarshalText")) {
		return true
	}
	if mode.checkYAML {
		return hasMethodOnType(named, "MarshalYAML") || (!mode.inMapValue && hasMethodOnType(ptr, "MarshalYAML"))
	}
	return hasMethodOnType(ptr, "MarshalJSON", "MarshalJSONTo")
}

func hasMethodOnType(t types.Type, names ...string) bool {
	ms := types.NewMethodSet(t)
	return slices.ContainsFunc(names, func(name string) bool { return ms.Lookup(nil, name) != nil })
}
