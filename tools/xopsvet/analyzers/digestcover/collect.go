package digestcover

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

type canonicalTarget struct {
	ts       *ast.TypeSpec
	named    *types.Named
	stType   *types.Struct
	fields   []*types.Var
	fieldSet map[*types.Var]bool
	excluded map[*types.Var]bool
}

func collectTargetsAndFuncs(pass *analysis.Pass) ([]canonicalTarget, map[*types.Named]*ast.FuncDecl, map[*types.Func]*ast.FuncDecl) {
	var targets []canonicalTarget
	writeMethods := make(map[*types.Named]*ast.FuncDecl)
	funcDecls := make(map[*types.Func]*ast.FuncDecl)

	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok == token.TYPE {
					targets = append(targets, collectDeclTargets(pass, d)...)
				}
			case *ast.FuncDecl:
				recordFuncDecl(pass, d, writeMethods, funcDecls)
			}
		}
	}
	return targets, writeMethods, funcDecls
}

func collectDeclTargets(pass *analysis.Pass, gen *ast.GenDecl) []canonicalTarget {
	var targets []canonicalTarget
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		hasCanonical := vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveCanonicalHash)
		astStruct, isStructAST := ts.Type.(*ast.StructType)
		if !isStructAST {
			if hasCanonical {
				pass.ReportRangef(ts.Type, "digestcover: //xops:canonicalhash 仅适用于结构体类型")
			}
			continue
		}
		excludedByField := validateAndCollectExcludes(pass, astStruct)
		if !hasCanonical || ts.Assign.IsValid() {
			continue
		}
		target, ok := buildCanonicalTarget(pass, ts, astStruct, excludedByField)
		if ok {
			targets = append(targets, target)
		}
	}
	return targets
}

// validateAndCollectExcludes 校验所有结构体字段上的 //xops:hash-exclude:<reason> 理由非空，
// 并返回被合法排除的 *ast.Field 集合（在非 canonicalhash 结构体上同样检查空理由以早发现拼写错误）。
func validateAndCollectExcludes(pass *analysis.Pass, astStruct *ast.StructType) map[*ast.Field]bool {
	excluded := make(map[*ast.Field]bool)
	if astStruct.Fields == nil {
		return excluded
	}
	for _, f := range astStruct.Fields.List {
		dir, ok := findHashExclude(f)
		if !ok {
			continue
		}
		if dir.Arg == "" {
			pass.ReportRangef(posTokenRange(dir.Pos), "digestcover: //xops:hash-exclude 必须提供非空排除理由（格式：//xops:hash-exclude:<reason>）")
			continue
		}
		excluded[f] = true
	}
	return excluded
}

func findHashExclude(f *ast.Field) (vetutil.Directive, bool) {
	if dir, ok := vetutil.FindDirective(f.Doc, vetutil.DirectiveHashExclude); ok {
		return dir, true
	}
	return vetutil.FindDirective(f.Comment, vetutil.DirectiveHashExclude)
}

type posTokenRange token.Pos

func (p posTokenRange) Pos() token.Pos { return token.Pos(p) }
func (p posTokenRange) End() token.Pos { return token.Pos(p) }

func buildCanonicalTarget(
	pass *analysis.Pass,
	ts *ast.TypeSpec,
	astStruct *ast.StructType,
	excludedAST map[*ast.Field]bool,
) (canonicalTarget, bool) {
	obj := pass.TypesInfo.Defs[ts.Name]
	if obj == nil {
		return canonicalTarget{}, false
	}
	named, ok := obj.Type().(*types.Named)
	if !ok || named == nil {
		return canonicalTarget{}, false
	}
	stType, ok := named.Underlying().(*types.Struct)
	if !ok || stType == nil {
		return canonicalTarget{}, false
	}
	fields, fieldSet, excludedVars := mapStructFields(astStruct, stType, excludedAST)
	return canonicalTarget{
		ts:       ts,
		named:    named,
		stType:   stType,
		fields:   fields,
		fieldSet: fieldSet,
		excluded: excludedVars,
	}, true
}

func mapStructFields(
	astStruct *ast.StructType,
	stType *types.Struct,
	excludedAST map[*ast.Field]bool,
) ([]*types.Var, map[*types.Var]bool, map[*types.Var]bool) {
	var fields []*types.Var
	fieldSet := make(map[*types.Var]bool)
	excludedVars := make(map[*types.Var]bool)
	if astStruct.Fields == nil {
		return fields, fieldSet, excludedVars
	}
	idx := 0
	for _, f := range astStruct.Fields.List {
		count := len(f.Names)
		if count == 0 {
			count = 1
		}
		isExcluded := excludedAST[f]
		for k := 0; k < count && idx < stType.NumFields(); k++ {
			fv := stType.Field(idx)
			idx++
			if fv.Name() == "_" {
				continue
			}
			fields = append(fields, fv)
			fieldSet[fv] = true
			if isExcluded {
				excludedVars[fv] = true
			}
		}
	}
	return fields, fieldSet, excludedVars
}

func recordFuncDecl(
	pass *analysis.Pass,
	fn *ast.FuncDecl,
	writeMethods map[*types.Named]*ast.FuncDecl,
	funcDecls map[*types.Func]*ast.FuncDecl,
) {
	if fn.Name == nil {
		return
	}
	if fnObj, ok := pass.TypesInfo.Defs[fn.Name].(*types.Func); ok && fnObj != nil {
		funcDecls[fnObj] = fn
	}
	if fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Name.Name != "WriteCanonical" {
		return
	}
	recvType := pass.TypesInfo.TypeOf(fn.Recv.List[0].Type)
	named, ok := vetutil.UnwrapNamedType(recvType)
	if !ok || named.Origin() == nil {
		return
	}
	writeMethods[named.Origin()] = fn
}
