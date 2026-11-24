package noimplicit

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

func TestHasSerializationTagsMalformedTagTolerance(t *testing.T) {
	stWithLaterValid := &ast.StructType{
		Fields: &ast.FieldList{
			List: []*ast.Field{
				{
					Names: []*ast.Ident{ast.NewIdent("Broken")},
					Type:  ast.NewIdent("string"),
					Tag:   &ast.BasicLit{Kind: token.STRING, Value: `"unclosed`},
				},
				{
					Names: []*ast.Ident{ast.NewIdent("TTL")},
					Type:  ast.NewIdent("int"),
					Tag:   &ast.BasicLit{Kind: token.STRING, Value: "`json:\"ttl\"`"},
				},
			},
		},
	}
	tags, err := vetutil.StructSerialTags(stWithLaterValid)
	if err != nil || !tags.Any() {
		t.Fatalf("expected (true, nil) when later field has valid json tag, got (%+v, %v)", tags, err)
	}

	stOnlyMalformed := &ast.StructType{
		Fields: &ast.FieldList{
			List: []*ast.Field{
				{
					Names: []*ast.Ident{ast.NewIdent("Broken")},
					Type:  ast.NewIdent("string"),
					Tag:   &ast.BasicLit{Kind: token.STRING, Value: `"unclosed`},
				},
			},
		},
	}
	tags, err = vetutil.StructSerialTags(stOnlyMalformed)
	if err == nil || tags.Any() {
		t.Fatalf("expected (false, non-nil err) when only malformed tag exists, got (%+v, %v)", tags, err)
	}
}

func TestCheckTypeDeclDTOsDoesNotSkipStructOnMalformedTag(t *testing.T) {
	fset := token.NewFileSet()
	src := `package sample
import "time"

//xops:dto
type ExplicitConfig struct {
	Broken string
	TTL    time.Duration
}

type TaggedConfig struct {
	Broken string
	TTL    time.Duration ` + "`json:\"ttl\"`" + `
}
`
	f, err := parser.ParseFile(fset, "dto.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Uses:  make(map[*ast.Ident]types.Object),
		Defs:  make(map[*ast.Ident]types.Object),
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("example.com/sample", fset, []*ast.File{f}, info)
	if err != nil {
		t.Fatal(err)
	}
	// 在类型检查之后向两个结构体的首个字段注入畸形 tag，验证不会跳过整个结构体。
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
	checkDTOs(pass, vetutil.ClassifyPackage("example.com/sample"))
	if len(msgs) != 2 {
		t.Fatalf("expected 2 DTO diagnostics despite malformed tags, got %d: %v", len(msgs), msgs)
	}
	for _, m := range msgs {
		if !strings.Contains(m, "禁止裸用 time.Duration") {
			t.Fatalf("unexpected diagnostic: %s", m)
		}
	}
}
