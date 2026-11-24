package digestcover

import (
	"go/ast"
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
	writeMethods, funcDecls := make(map[*types.Named]*ast.FuncDecl), make(map[*types.Func]*ast.FuncDecl)
	vetutil.ForEachTypeSpec(pass, func(_ *ast.File, gen *ast.GenDecl, ts *ast.TypeSpec) {
		if target, ok := inspectCanonicalTypeSpec(pass, gen, ts); ok {
			targets = append(targets, target)
		}
	})
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				recordFuncDecl(pass, fn, writeMethods, funcDecls)
			}
		}
	}
	return targets, writeMethods, funcDecls
}

func inspectCanonicalTypeSpec(pass *analysis.Pass, gen *ast.GenDecl, ts *ast.TypeSpec) (canonicalTarget, bool) {
	hasCanonical := vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveCanonicalHash)
	astStruct, isStructAST := ts.Type.(*ast.StructType)
	if !isStructAST {
		if hasCanonical {
			pass.ReportRangef(ts.Type, "digestcover: //xops:canonicalhash 仅适用于结构体类型")
		}
		return canonicalTarget{}, false
	}
	excludedByField := validateAndCollectExcludes(pass, astStruct)
	if !hasCanonical || ts.Assign.IsValid() {
		return canonicalTarget{}, false
	}
	return buildCanonicalTarget(pass, ts, astStruct, excludedByField)
}

// validateAndCollectExcludes 校验所有结构体字段上的 //xops:hash-exclude:<reason> 理由非空，并返回合法排除集合。
func validateAndCollectExcludes(pass *analysis.Pass, astStruct *ast.StructType) map[*ast.Field]bool {
	excluded := make(map[*ast.Field]bool)
	if astStruct.Fields == nil {
		return excluded
	}
	for _, f := range astStruct.Fields.List {
		dir, ok := vetutil.FindDirective(f.Doc, vetutil.DirectiveHashExclude)
		if !ok {
			dir, ok = vetutil.FindDirective(f.Comment, vetutil.DirectiveHashExclude)
		}
		if !ok {
			continue
		}
		if dir.Arg == "" {
			pass.Report(analysis.Diagnostic{Pos: dir.Pos, End: dir.Pos, Message: "digestcover: //xops:hash-exclude 必须提供非空排除理由（格式：//xops:hash-exclude:<reason>）"})
		} else {
			excluded[f] = true
		}
	}
	return excluded
}

func buildCanonicalTarget(pass *analysis.Pass, ts *ast.TypeSpec, astStruct *ast.StructType, excludedAST map[*ast.Field]bool) (canonicalTarget, bool) {
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
	return canonicalTarget{ts: ts, named: named, stType: stType, fields: fields, fieldSet: fieldSet, excluded: excludedVars}, true
}

func mapStructFields(astStruct *ast.StructType, stType *types.Struct, excludedAST map[*ast.Field]bool) ([]*types.Var, map[*types.Var]bool, map[*types.Var]bool) {
	var fields []*types.Var
	fieldSet, excludedVars := make(map[*types.Var]bool), make(map[*types.Var]bool)
	if astStruct.Fields == nil {
		return fields, fieldSet, excludedVars
	}
	idx := 0
	for _, f := range astStruct.Fields.List {
		for k := 0; k < max(len(f.Names), 1) && idx < stType.NumFields(); k++ {
			fv := stType.Field(idx)
			idx++
			if fv.Name() == "_" {
				continue
			}
			fields = append(fields, fv)
			fieldSet[fv] = true
			if excludedAST[f] {
				excludedVars[fv] = true
			}
		}
	}
	return fields, fieldSet, excludedVars
}

func recordFuncDecl(pass *analysis.Pass, fn *ast.FuncDecl, writeMethods map[*types.Named]*ast.FuncDecl, funcDecls map[*types.Func]*ast.FuncDecl) {
	if fn.Name == nil {
		return
	}
	if fnObj, ok := pass.TypesInfo.Defs[fn.Name].(*types.Func); ok && fnObj != nil {
		funcDecls[fnObj] = fn
	}
	if fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Name.Name != "WriteCanonical" {
		return
	}
	if named, ok := vetutil.UnwrapNamedType(pass.TypesInfo.TypeOf(fn.Recv.List[0].Type)); ok && named.Origin() != nil {
		writeMethods[named.Origin()] = fn
	}
}
