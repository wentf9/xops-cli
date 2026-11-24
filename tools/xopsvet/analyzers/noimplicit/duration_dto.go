package noimplicit

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

const algebraicPkgPath = vetutil.ModulePrefix + "/core/domain/algebraic"

// checkDTOs 扫描 DTO 结构体字段，拦截除 algebraic.Duration 之外的裸 time.Duration 用法。
// core/domain/algebraic 自身负责定义 Duration 包装类型，因此在此豁免。
func checkDTOs(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	if pass.TypesInfo == nil {
		return
	}
	if pkgInfo.BasePath == vetutil.ModulePrefix+"/core/domain/algebraic" {
		return
	}
	ins := vetutil.InspectorOf(pass)
	nodeFilter := []ast.Node{(*ast.GenDecl)(nil)}
	ins.Preorder(nodeFilter, func(n ast.Node) {
		gen, ok := n.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			return
		}
		checkTypeDeclDTOs(pass, pkgInfo, gen)
	})
}

func checkTypeDeclDTOs(pass *analysis.Pass, pkgInfo vetutil.PkgInfo, gen *ast.GenDecl) {
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			continue
		}
		isExplicitDTO := vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveDTO)
		hasTags, tagErr := hasSerializationTags(st)
		if tagErr != nil {
			hasTags = false
		}
		if isDTOStruct(pkgInfo, ts, isExplicitDTO || hasTags) {
			checkDTOStructFields(pass, st)
		}
	}
}

// isDTOStruct 采用三层启发式判定结构体是否属于序列化/配置 DTO：
// 1. 显式标记 //xops:dto 或含非 "-" 的 json/yaml 字段标签；
// 2. 位于事件/MCP/审计/存储等 DTO 专属包内的导出类型或常见载荷命名；
// 3. 仓库内其余包中以严格 DTO/Event/AuditEntry/Config 后缀结尾的导出类型。
func isDTOStruct(pkgInfo vetutil.PkgInfo, ts *ast.TypeSpec, hasExplicitOrTagged bool) bool {
	if hasExplicitOrTagged {
		return true
	}
	name := ts.Name.Name
	if isDTOPackage(pkgInfo) {
		if pkgInfo.Layer == vetutil.LayerCoreEvents && ts.Name.IsExported() {
			return true
		}
		if isDTONameRole(name) {
			return true
		}
	}
	return ts.Name.IsExported() && hasStrictDTOSuffix(name)
}

// hasSerializationTags 检查结构体是否存在非 "-" 的 json/yaml 序列化标签。
// 保留 (bool, error) 签名以满足 failclosed 自检；单字段 tag 解析失败仅记录首个错误并继续扫描，
// 若后续字段命中有效序列化标签仍返回 (true, nil)，防止单个畸形 tag 导致整结构体漏检。
func hasSerializationTags(st *ast.StructType) (bool, error) {
	if st.Fields == nil {
		return false, nil
	}
	var firstErr error
	for _, f := range st.Fields.List {
		tag, hasTag, err := parseStructTag(f)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if hasTag && hasNonIgnoredSerialTag(tag) {
			return true, nil
		}
	}
	return false, firstErr
}

func hasNonIgnoredSerialTag(tag reflect.StructTag) bool {
	if v, ok := tag.Lookup("json"); ok && v != "-" {
		return true
	}
	v, ok := tag.Lookup("yaml")
	return ok && v != "-"
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

func isDTOPackage(pkgInfo vetutil.PkgInfo) bool {
	switch pkgInfo.Layer {
	case vetutil.LayerCoreEvents, vetutil.LayerCoreMCPRuntime:
		return true
	default:
		return pkgInfo.BasePath == vetutil.ModulePrefix+"/internal/host/audit" ||
			pkgInfo.BasePath == vetutil.ModulePrefix+"/internal/host/store" ||
			pkgInfo.BasePath == vetutil.ModulePrefix+"/internal/entry/mcpcmd"
	}
}

func isDTONameRole(name string) bool {
	switch {
	case strings.Contains(name, "Event"),
		strings.Contains(name, "Audit"),
		strings.Contains(name, "DTO"),
		strings.Contains(name, "Dto"),
		strings.Contains(name, "Config"),
		strings.Contains(name, "Cfg"),
		strings.Contains(name, "Request"),
		strings.Contains(name, "Response"),
		strings.Contains(name, "Input"),
		strings.Contains(name, "Output"),
		strings.Contains(name, "Params"),
		strings.Contains(name, "Result"),
		strings.Contains(name, "Payload"),
		strings.Contains(name, "Entry"),
		strings.Contains(name, "Record"),
		strings.Contains(name, "Envelope"),
		strings.Contains(name, "Manifest"),
		strings.Contains(name, "Bundle"),
		strings.Contains(name, "Schema"),
		strings.Contains(name, "Message"),
		strings.Contains(name, "Notification"),
		strings.Contains(name, "Journal"):
		return true
	default:
		return false
	}
}

func hasStrictDTOSuffix(name string) bool {
	return strings.HasSuffix(name, "DTO") ||
		strings.HasSuffix(name, "Dto") ||
		strings.HasSuffix(name, "Event") ||
		strings.HasSuffix(name, "AuditEntry") ||
		strings.HasSuffix(name, "AuditRecord") ||
		strings.HasSuffix(name, "Config")
}

func checkDTOStructFields(pass *analysis.Pass, st *ast.StructType) {
	if st.Fields == nil {
		return
	}
	for _, f := range st.Fields.List {
		skipped, err := isFieldSerializationSkipped(f)
		if err == nil && skipped {
			continue
		}
		fieldType := pass.TypesInfo.TypeOf(f.Type)
		if hasBareTimeDuration(fieldType, make(map[types.Type]bool)) {
			pass.ReportRangef(f.Type, "noimplicit: Event/Audit/MCP/Config DTO 禁止裸用 time.Duration，请使用 algebraic.Duration")
		}
	}
}

// isFieldSerializationSkipped 判断字段是否被序列化标签显式忽略（"-"）。
// 仅当未同时被另一常见序列化格式保留（如 json:"-" yaml:"dur"）时才予豁免。
func isFieldSerializationSkipped(f *ast.Field) (bool, error) {
	tag, hasTag, err := parseStructTag(f)
	if err != nil || !hasTag {
		return false, err
	}
	jsonVal, hasJSON := tag.Lookup("json")
	yamlVal, hasYAML := tag.Lookup("yaml")
	if hasJSON && jsonVal == "-" && (!hasYAML || yamlVal == "-") {
		return true, nil
	}
	return hasYAML && yamlVal == "-" && !hasJSON, nil
}

// hasBareTimeDuration 递归检查 DTO 字段类型是否包含裸 time.Duration。
// 遇到 algebraic.Duration 时视为终止安全类型停止下钻（允许其内部私有封装 d time.Duration），
// 同时继续向下穿透指针、切片、数组、Map、泛型实参（如 Option[time.Duration]）及普通包装结构体。
func hasBareTimeDuration(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok {
		return namedHasBareTimeDuration(named, seen)
	}
	return compositeHasBareTimeDuration(t, seen)
}

func namedHasBareTimeDuration(named *types.Named, seen map[types.Type]bool) bool {
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
	if typeArgs := named.TypeArgs(); typeArgs != nil {
		for i := 0; i < typeArgs.Len(); i++ {
			if hasBareTimeDuration(typeArgs.At(i), seen) {
				return true
			}
		}
	}
	return hasBareTimeDuration(named.Underlying(), seen)
}

func compositeHasBareTimeDuration(t types.Type, seen map[types.Type]bool) bool {
	switch v := t.(type) {
	case *types.Pointer:
		return hasBareTimeDuration(v.Elem(), seen)
	case *types.Slice:
		return hasBareTimeDuration(v.Elem(), seen)
	case *types.Array:
		return hasBareTimeDuration(v.Elem(), seen)
	case *types.Chan:
		return hasBareTimeDuration(v.Elem(), seen)
	case *types.Map:
		return hasBareTimeDuration(v.Key(), seen) || hasBareTimeDuration(v.Elem(), seen)
	case *types.Struct:
		return structHasBareTimeDuration(v, seen)
	default:
		return false
	}
}

func structHasBareTimeDuration(st *types.Struct, seen map[types.Type]bool) bool {
	if seen[st] {
		return false
	}
	seen[st] = true
	for i := 0; i < st.NumFields(); i++ {
		if hasBareTimeDuration(st.Field(i).Type(), seen) {
			return true
		}
	}
	return false
}
