package secretbox

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

func TestCheckTypeSpecSecretBoxDoesNotSkipOnMalformedTag(t *testing.T) {
	fset := token.NewFileSet()
	secretPkg := types.NewPackage(secretPkgPath, "secret")
	boxObj := types.NewTypeName(token.NoPos, secretPkg, secretBoxName, nil)
	types.NewNamed(boxObj, types.NewStruct(nil, nil), nil)
	secretPkg.Scope().Insert(boxObj)
	secretPkg.MarkComplete()

	src := `package sample
import "github.com/wentf9/xops-cli/core/domain/secret"

//xops:dto
type ExplicitSecretDTO struct {
	Broken string
	Box    *secret.SecretBox
}

type TaggedSecretHolder struct {
	Broken string
	Box    *secret.SecretBox ` + "`json:\"box\"`" + `
}
`
	f, err := parser.ParseFile(fset, "sample.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Uses:  make(map[*ast.Ident]types.Object),
		Defs:  make(map[*ast.Ident]types.Object),
	}
	conf := types.Config{Importer: singlePkgImporter{pkg: secretPkg}}
	pkg, err := conf.Check("example.com/sample", fset, []*ast.File{f}, info)
	if err != nil {
		t.Fatal(err)
	}
	injectMalformedFirstTag(f)

	var msgs []string
	pass := &analysis.Pass{
		Fset:      fset,
		Files:     []*ast.File{f},
		Pkg:       pkg,
		TypesInfo: info,
		Report: func(d analysis.Diagnostic) {
			msgs = append(msgs, d.Message)
		},
	}
	checkTypeAndEmbeddingBan(pass, vetutil.ClassifyPackage(pkg.Path()))
	if len(msgs) != 2 {
		t.Fatalf("expected 2 SecretBox diagnostics despite malformed tags, got %d: %v", len(msgs), msgs)
	}
	for _, m := range msgs {
		if !strings.Contains(m, "禁止 secret.SecretBox 进入") {
			t.Fatalf("unexpected diagnostic: %s", m)
		}
	}
}

func injectMalformedFirstTag(f *ast.File) {
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts := spec.(*ast.TypeSpec)
			st := ts.Type.(*ast.StructType)
			st.Fields.List[0].Tag = &ast.BasicLit{
				ValuePos: st.Fields.List[0].End(),
				Kind:     token.STRING,
				Value:    `"unclosed`,
			}
		}
	}
}

type singlePkgImporter struct {
	pkg *types.Package
}

func (i singlePkgImporter) Import(path string) (*types.Package, error) {
	if path == i.pkg.Path() {
		return i.pkg, nil
	}
	return nil, errors.New("unexpected import: " + path)
}
