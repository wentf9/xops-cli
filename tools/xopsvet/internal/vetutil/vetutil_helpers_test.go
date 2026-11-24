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

func TestParamBlockAndSameLineDirectives(t *testing.T) {
	fset := token.NewFileSet()
	src := `package paramsample
func SameLineTrailingA(s int /* //xops:borrowed */, other *int) {}
func SameLineTrailingB(s int /* xops:borrowed */, other *int) {}
func SameLineLeadingSecond(s int, /* //xops:borrowed */ other *int) {}
func SameLineLeadingFirst(/* //xops:borrowed */ s int, other *int) {}
func SingleTrailing(s int /* //xops:borrowed */) {}
func CommentedOutLine(
	// //xops:borrowed
	s int,
) {}
`
	f, err := parser.ParseFile(fset, "params.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		want []bool
	}{
		{name: "SameLineTrailingA", want: []bool{true, false}},
		{name: "SameLineTrailingB", want: []bool{true, false}},
		{name: "SameLineLeadingSecond", want: []bool{false, true}},
		{name: "SameLineLeadingFirst", want: []bool{true, false}},
		{name: "SingleTrailing", want: []bool{true}},
		{name: "CommentedOutLine", want: []bool{false}},
	}
	decls := make(map[string]*ast.FuncDecl, len(f.Decls))
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name != nil {
			decls[fn.Name.Name] = fn
		}
	}
	for _, tc := range cases {
		fn := decls[tc.name]
		if fn == nil {
			t.Fatalf("missing func %s", tc.name)
		}
		for idx, want := range tc.want {
			got := vetutil.ParamFieldHasDirective(fset, f.Comments, fn.Type.Params, idx, vetutil.DirectiveBorrowed)
			if got != want {
				t.Fatalf("%s param[%d] = %v, want %v", tc.name, idx, got, want)
			}
		}
	}
}

func TestIsFreshLocalSliceAlloc(t *testing.T) {
	if vetutil.IsFreshLocalSliceAlloc(nil, nil) {
		t.Fatal("nil inputs should return false")
	}
	fset := token.NewFileSet()
	src := `package slicealloc
type MyBytes []byte
type MyStr string
var outer []byte
func getSlice() []byte { return outer }
func cases(s string, ms MyStr, mb MyBytes) {
	cMakeSlice := make([]byte, 8)
	cMakeNamed := make(MyBytes, 8)
	cMakeMap := make(map[string]int)
	cMakeChan := make(chan int, 1)
	cNilSlice := []byte(nil)
	cNilNamed := MyBytes(nil)
	cStrLit := []byte("hello")
	cStrParen := ([]byte)("world")
	cStrVar := MyBytes(s)
	cNamedStr := []byte(ms)
	cSliceConv := MyBytes(outer)
	cNamedToRaw := []byte(mb)
	cFuncCall := getSlice()
	cAppend := append([]byte(nil), 1)
	_, _, _, _, _, _, _, _, _, _, _, _, _, _ = cMakeSlice, cMakeNamed, cMakeMap, cMakeChan, cNilSlice, cNilNamed, cStrLit, cStrParen, cStrVar, cNamedStr, cSliceConv, cNamedToRaw, cFuncCall, cAppend
}
func shadowedNilCase() {
	var nil []byte
	cShadowedNil := []byte(nil)
	_ = cShadowedNil
}
`
	f, err := parser.ParseFile(fset, "slicealloc.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Uses:  make(map[*ast.Ident]types.Object),
		Defs:  make(map[*ast.Ident]types.Object),
	}
	conf := types.Config{Importer: importer.Default()}
	if _, err := conf.Check("example.com/slicealloc", fset, []*ast.File{f}, info); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"cMakeSlice":   true,
		"cMakeNamed":   true,
		"cMakeMap":     false,
		"cMakeChan":    false,
		"cNilSlice":    true,
		"cNilNamed":    true,
		"cStrLit":      true,
		"cStrParen":    true,
		"cStrVar":      true,
		"cNamedStr":    true,
		"cSliceConv":   false,
		"cNamedToRaw":  false,
		"cFuncCall":    false,
		"cAppend":      false,
		"cShadowedNil": false,
	}
	seen := make(map[string]bool, len(want))
	ast.Inspect(f, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		expected, tracked := want[id.Name]
		if !tracked {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			t.Fatalf("%s rhs is not CallExpr", id.Name)
		}
		seen[id.Name] = true
		if got := vetutil.IsFreshLocalSliceAlloc(info, call); got != expected {
			t.Fatalf("IsFreshLocalSliceAlloc(%s) = %v, want %v", id.Name, got, expected)
		}
		return true
	})
	if len(seen) != len(want) {
		t.Fatalf("checked %d cases, want %d", len(seen), len(want))
	}
}
