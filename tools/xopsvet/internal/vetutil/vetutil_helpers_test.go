package vetutil_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

func TestFieldAndFuncDeclDirectives(t *testing.T) {
	fset := token.NewFileSet()
	src := `package sample
type Svc interface {
	//xops:borrowed
	WithA(fn func(x int))
	WithB(fn func(x int)) //xops:syncclosure
}
//xops:secretuse
func UseSecret(fn func([]byte)) {}
func PlainFunc(fn func(
	ctx int,
	//xops:borrowed
	x int,
	y int, //xops:borrowed
	/*xops:borrowed*/ z int,
)) {}
`
	f, err := parser.ParseFile(fset, "dir.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	if vetutil.FieldHasDirective(nil, vetutil.DirectiveBorrowed) {
		t.Fatal("nil field should return false")
	}
	if vetutil.FuncDeclHasDirective(nil, vetutil.DirectiveSecretUse) {
		t.Fatal("nil FuncDecl should return false")
	}
	assertParsedFieldAndFuncDirectives(t, fset, f)
}

func assertParsedFieldAndFuncDirectives(t *testing.T, fset *token.FileSet, f *ast.File) {
	t.Helper()
	ts := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.TypeSpec)
	iface := ts.Type.(*ast.InterfaceType)
	if !vetutil.FieldHasDirective(iface.Methods.List[0], vetutil.DirectiveBorrowed) {
		t.Fatal("expected WithA to have DirectiveBorrowed")
	}
	if !vetutil.FieldHasDirective(iface.Methods.List[1], vetutil.DirectiveSyncClosure) {
		t.Fatal("expected WithB trailing comment to have DirectiveSyncClosure")
	}
	fnUse := f.Decls[1].(*ast.FuncDecl)
	if !vetutil.FuncDeclHasDirective(fnUse, vetutil.DirectiveSecretUse) {
		t.Fatal("expected UseSecret to have DirectiveSecretUse")
	}
	fnPlain := f.Decls[2].(*ast.FuncDecl)
	if vetutil.FuncDeclHasDirective(fnPlain, vetutil.DirectiveSecretUse) {
		t.Fatal("PlainFunc should not have DirectiveSecretUse")
	}
	innerFT := fnPlain.Type.Params.List[0].Type.(*ast.FuncType)
	if vetutil.ParamFieldHasDirective(fset, f.Comments, innerFT.Params, 0, vetutil.DirectiveBorrowed) {
		t.Fatal("ctx param should not have DirectiveBorrowed")
	}
	for _, idx := range []int{1, 2, 3} {
		if !vetutil.ParamFieldHasDirective(fset, f.Comments, innerFT.Params, idx, vetutil.DirectiveBorrowed) {
			t.Fatalf("expected inner param idx %d to have DirectiveBorrowed", idx)
		}
	}
}

func TestImplementsError(t *testing.T) {
	fset := token.NewFileSet()
	src := `package errsample
type ValErr struct{}
func (ValErr) Error() string { return "v" }
type PtrErr struct{}
func (*PtrErr) Error() string { return "p" }
type NotErr struct{}
type CustomErrIface interface { Error() string; Code() int }
`
	f, err := parser.ParseFile(fset, "err.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
	}
	conf := types.Config{Importer: importer.Default()}
	if _, err := conf.Check("example.com/errsample", fset, []*ast.File{f}, info); err != nil {
		t.Fatal(err)
	}
	defs := collectTypeDefsByName(f, info)
	if vetutil.ImplementsError(nil) {
		t.Fatal("nil type should return false")
	}
	if !vetutil.ImplementsError(defs["ValErr"]) || !vetutil.ImplementsError(defs["PtrErr"]) {
		t.Fatal("ValErr and PtrErr should implement error")
	}
	if !vetutil.ImplementsError(defs["CustomErrIface"]) {
		t.Fatal("CustomErrIface should implement error")
	}
	if vetutil.ImplementsError(defs["NotErr"]) || vetutil.ImplementsError(types.Typ[types.Int]) {
		t.Fatal("NotErr and int should not implement error")
	}
}
