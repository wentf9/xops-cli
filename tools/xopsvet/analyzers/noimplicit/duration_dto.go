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
		isExplicitDTO := vetutil.HasDirective(gen.Doc, vetutil.DirectiveDTO) ||
			vetutil.HasDirective(ts.Doc, vetutil.DirectiveDTO)
		if isDTOStruct(pkgInfo, ts, st, isExplicitDTO) {
			checkDTOStructFields(pass, st)
		}
	}
}

func isDTOStruct(pkgInfo vetutil.PkgInfo, ts *ast.TypeSpec, st *ast.StructType, isExplicitDTO bool) bool {
	if isExplicitDTO || hasSerializationTags(st) {
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

func hasSerializationTags(st *ast.StructType) bool {
	if st.Fields == nil {
		return false
	}
	for _, f := range st.Fields.List {
		if f.Tag == nil {
			continue
		}
		raw, err := strconv.Unquote(f.Tag.Value)
		if err != nil {
			continue
		}
		tag := reflect.StructTag(raw)
		if v, ok := tag.Lookup("json"); ok && v != "-" {
			return true
		}
		if v, ok := tag.Lookup("yaml"); ok && v != "-" {
			return true
		}
	}
	return false
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
		if isFieldSerializationSkipped(f) {
			continue
		}
		fieldType := pass.TypesInfo.TypeOf(f.Type)
		if vetutil.TypeContains(fieldType, isBareTimeDuration) {
			pass.ReportRangef(f.Type, "noimplicit: Event/Audit/MCP/Config DTO 禁止裸用 time.Duration，请使用 algebraic.Duration")
		}
	}
}

func isFieldSerializationSkipped(f *ast.Field) bool {
	if f.Tag == nil {
		return false
	}
	raw, err := strconv.Unquote(f.Tag.Value)
	if err != nil {
		return false
	}
	tag := reflect.StructTag(raw)
	jsonVal, hasJSON := tag.Lookup("json")
	yamlVal, hasYAML := tag.Lookup("yaml")
	if hasJSON && jsonVal == "-" && (!hasYAML || yamlVal == "-") {
		return true
	}
	return hasYAML && yamlVal == "-" && !hasJSON
}

func isBareTimeDuration(n *types.Named) bool {
	return vetutil.IsPkgSymbol(n.Obj(), "time", "Duration")
}
