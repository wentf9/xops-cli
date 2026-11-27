package vetutil_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

type pkgCase struct {
	name            string
	pkgPath         string
	wantLayer       vetutil.Layer
	wantExtTest     bool
	wantXops        bool
	wantAllowCtx    bool
	wantAllowOSFS   bool
	wantAllowSys    bool
	wantAllowNol    bool
	wantAllowBareGo bool
	wantAllowSecret bool
	wantIsCore      bool
}

func TestClassifyPackageAndWhitelists(t *testing.T) {
	tests := []pkgCase{
		{
			name:       "domain",
			pkgPath:    "github.com/wentf9/xops-cli/core/domain/algebraic",
			wantLayer:  vetutil.LayerCoreDomain,
			wantXops:   true,
			wantIsCore: true,
		},
		{
			name:            "domain_secret_nolint_whitelist",
			pkgPath:         "github.com/wentf9/xops-cli/core/domain/secret",
			wantLayer:       vetutil.LayerCoreDomain,
			wantXops:        true,
			wantAllowNol:    true,
			wantAllowSecret: true,
			wantIsCore:      true,
		},
		{
			name:        "domain_secret_external_test_denied",
			pkgPath:     "github.com/wentf9/xops-cli/core/domain/secret_test",
			wantLayer:   vetutil.LayerCoreDomain,
			wantExtTest: true,
			wantXops:    true,
			wantIsCore:  true,
		},
		{
			name:       "ports_tck",
			pkgPath:    "github.com/wentf9/xops-cli/core/ports/tck",
			wantLayer:  vetutil.LayerCorePortsTCK,
			wantXops:   true,
			wantIsCore: true,
		},
		{
			name:       "ports",
			pkgPath:    "github.com/wentf9/xops-cli/core/ports",
			wantLayer:  vetutil.LayerCorePorts,
			wantXops:   true,
			wantIsCore: true,
		},
		{
			name:          "osfs",
			pkgPath:       "github.com/wentf9/xops-cli/core/osfs",
			wantLayer:     vetutil.LayerCoreOSFS,
			wantXops:      true,
			wantAllowOSFS: true,
			wantAllowNol:  true,
			wantIsCore:    true,
		},
		{
			name:            "conc",
			pkgPath:         "github.com/wentf9/xops-cli/core/conc",
			wantLayer:       vetutil.LayerCoreConc,
			wantXops:        true,
			wantAllowNol:    true,
			wantAllowBareGo: true,
			wantIsCore:      true,
		},
		{
			name:        "conc_external_test_denied",
			pkgPath:     "github.com/wentf9/xops-cli/core/conc_test",
			wantLayer:   vetutil.LayerCoreConc,
			wantExtTest: true,
			wantXops:    true,
			wantIsCore:  true,
		},
		{
			name:       "actor_no_privileges",
			pkgPath:    "github.com/wentf9/xops-cli/core/internal/foundation/actor",
			wantLayer:  vetutil.LayerCoreFoundationActor,
			wantXops:   true,
			wantIsCore: true,
		},
		{
			name:         "trace",
			pkgPath:      "github.com/wentf9/xops-cli/core/internal/foundation/trace",
			wantLayer:    vetutil.LayerCoreFoundationTrace,
			wantXops:     true,
			wantAllowCtx: true,
			wantAllowNol: true,
			wantIsCore:   true,
		},
		{
			name:        "trace_external_test_not_whitelisted",
			pkgPath:     "github.com/wentf9/xops-cli/core/internal/foundation/trace_test",
			wantLayer:   vetutil.LayerCoreFoundationTrace,
			wantExtTest: true,
			wantXops:    true,
			wantIsCore:  true,
		},
		{
			name:         "sys",
			pkgPath:      "github.com/wentf9/xops-cli/internal/host/sys",
			wantLayer:    vetutil.LayerHostSys,
			wantXops:     true,
			wantAllowSys: true,
			wantAllowNol: true,
		},
		{
			name:            "vault",
			pkgPath:         "github.com/wentf9/xops-cli/internal/host/vault",
			wantLayer:       vetutil.LayerHostVault,
			wantXops:        true,
			wantAllowNol:    true,
			wantAllowSecret: true,
		},
		{
			name:            "sshnet_dial",
			pkgPath:         "github.com/wentf9/xops-cli/core/internal/sshnet/dial",
			wantLayer:       vetutil.LayerCoreSSHNetDial,
			wantXops:        true,
			wantAllowNol:    true,
			wantAllowSecret: true,
			wantIsCore:      true,
		},
		{
			name:            "sshnet_priv",
			pkgPath:         "github.com/wentf9/xops-cli/core/internal/sshnet/priv",
			wantLayer:       vetutil.LayerCoreSSHNetPriv,
			wantXops:        true,
			wantAllowNol:    true,
			wantAllowSecret: true,
			wantIsCore:      true,
		},
		{
			name:        "sshnet_priv_external_test_denied",
			pkgPath:     "github.com/wentf9/xops-cli/core/internal/sshnet/priv_test",
			wantLayer:   vetutil.LayerCoreSSHNetPriv,
			wantExtTest: true,
			wantXops:    true,
			wantIsCore:  true,
		},
		{
			name:            "sim_plaintext_without_nolint",
			pkgPath:         "github.com/wentf9/xops-cli/core/internal/sim",
			wantLayer:       vetutil.LayerCoreSim,
			wantXops:        true,
			wantAllowSecret: true,
			wantIsCore:      true,
		},
		{
			name:        "sim_external_test_denied",
			pkgPath:     "github.com/wentf9/xops-cli/core/internal/sim_test",
			wantLayer:   vetutil.LayerCoreSim,
			wantExtTest: true,
			wantXops:    true,
			wantIsCore:  true,
		},
		{
			name:      "internal_i18n_no_privileges",
			pkgPath:   "github.com/wentf9/xops-cli/internal/i18n",
			wantLayer: vetutil.LayerInternalI18n,
			wantXops:  true,
		},
		{
			name:        "internal_i18n_external_test",
			pkgPath:     "github.com/wentf9/xops-cli/internal/i18n_test",
			wantLayer:   vetutil.LayerInternalI18n,
			wantExtTest: true,
			wantXops:    true,
		},
		{
			name:      "cmd_xops_no_nolint",
			pkgPath:   "github.com/wentf9/xops-cli/cmd/xops",
			wantLayer: vetutil.LayerCmdXops,
			wantXops:  true,
		},
		{
			name:       "mcpruntime",
			pkgPath:    "github.com/wentf9/xops-cli/core/internal/mcpruntime",
			wantLayer:  vetutil.LayerCoreMCPRuntime,
			wantXops:   true,
			wantIsCore: true,
		},
		{
			name:       "unknown_core_subpkg_fail_closed",
			pkgPath:    "github.com/wentf9/xops-cli/core/mystery",
			wantLayer:  vetutil.LayerCoreOther,
			wantXops:   true,
			wantIsCore: true,
		},
		{
			name:      "third_party",
			pkgPath:   "golang.org/x/tools/go/analysis",
			wantLayer: vetutil.LayerUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertPkgCase(t, tc)
		})
	}
}

func assertPkgCase(t *testing.T, tc pkgCase) {
	t.Helper()
	info := vetutil.ClassifyPackage(tc.pkgPath)
	if info.Layer != tc.wantLayer || info.IsExternalTest != tc.wantExtTest || info.IsXops != tc.wantXops {
		t.Fatalf("got %+v, want layer=%v ext=%v xops=%v", info, tc.wantLayer, tc.wantExtTest, tc.wantXops)
	}
	if vetutil.AllowContextValue(info) != tc.wantAllowCtx {
		t.Fatalf("AllowContextValue=%v, want %v", !tc.wantAllowCtx, tc.wantAllowCtx)
	}
	if vetutil.AllowOSFSPrimitives(info) != tc.wantAllowOSFS {
		t.Fatalf("AllowOSFSPrimitives=%v, want %v", !tc.wantAllowOSFS, tc.wantAllowOSFS)
	}
	if vetutil.AllowSysExecEnv(info) != tc.wantAllowSys {
		t.Fatalf("AllowSysExecEnv=%v, want %v", !tc.wantAllowSys, tc.wantAllowSys)
	}
	if vetutil.AllowNolint(info) != tc.wantAllowNol {
		t.Fatalf("AllowNolint=%v, want %v", !tc.wantAllowNol, tc.wantAllowNol)
	}
	if vetutil.AllowBareGo(info) != tc.wantAllowBareGo {
		t.Fatalf("AllowBareGo=%v, want %v", !tc.wantAllowBareGo, tc.wantAllowBareGo)
	}
	if vetutil.AllowSecretPlaintext(info) != tc.wantAllowSecret {
		t.Fatalf("AllowSecretPlaintext=%v, want %v", !tc.wantAllowSecret, tc.wantAllowSecret)
	}
	if vetutil.IsCoreLayer(info.Layer) != tc.wantIsCore {
		t.Fatalf("IsCoreLayer=%v, want %v", !tc.wantIsCore, tc.wantIsCore)
	}
}

func TestIsSyntheticTestMainAndStdlib(t *testing.T) {
	testPkg := types.NewPackage("github.com/wentf9/xops-cli/core/domain/foo.test", "main")
	if !vetutil.IsSyntheticTestMain(&analysis.Pass{Pkg: testPkg}) {
		t.Fatal("expected synthetic .test main package to be detected")
	}
	nonMain := types.NewPackage("github.com/wentf9/xops-cli/core/domain/foo_test", "foo_test")
	if vetutil.IsSyntheticTestMain(&analysis.Pass{Pkg: nonMain}) {
		t.Fatal("unexpected match for external _test package")
	}

	if !vetutil.IsStdlibImport("encoding/json/v2") {
		t.Fatal("encoding/json/v2 should be recognized as stdlib")
	}
	if vetutil.IsStdlibImport("golang.org/x/tools/go/analysis") {
		t.Fatal("golang.org/x/tools should not be stdlib")
	}
	if vetutil.IsStdlibImport("C") {
		t.Fatal("C should not be stdlib")
	}
}

func TestDirectivesAndNolintParsing(t *testing.T) {
	cg := &ast.CommentGroup{
		List: []*ast.Comment{
			{Slash: token.Pos(1), Text: "//xops:opaque"},
			{Slash: token.Pos(20), Text: "//xops:failclosed"},
			{Slash: token.Pos(40), Text: "//xops:canonicalhash"},
			{Slash: token.Pos(60), Text: "//xops:hash-exclude: ephemeral cache"},
			{Slash: token.Pos(100), Text: "//xops:borrowed"},
			{Slash: token.Pos(120), Text: "//xops:syncclosure"},
			{Slash: token.Pos(140), Text: "//xops:secretuse"},
			{Slash: token.Pos(160), Text: "//xops:dto"},
			{Slash: token.Pos(180), Text: "//xops:buildvar"},
		},
	}
	dirs := vetutil.ParseCommentGroup(cg)
	if len(dirs) != 9 {
		t.Fatalf("got %d directives, want 9", len(dirs))
	}
	if dirs[3].Kind != vetutil.DirectiveHashExclude || dirs[3].Arg != "ephemeral cache" {
		t.Fatalf("unexpected hash-exclude directive: %+v", dirs[3])
	}
	assertDirectivesPresent(t, cg)
	assertNolintCases(t)
}

func assertDirectivesPresent(t *testing.T, cg *ast.CommentGroup) {
	t.Helper()
	wantKinds := []vetutil.DirectiveKind{
		vetutil.DirectiveOpaque,
		vetutil.DirectiveFailClosed,
		vetutil.DirectiveCanonicalHash,
		vetutil.DirectiveHashExclude,
		vetutil.DirectiveBorrowed,
		vetutil.DirectiveSyncClosure,
		vetutil.DirectiveSecretUse,
		vetutil.DirectiveDTO,
		vetutil.DirectiveBuildVar,
	}
	for _, k := range wantKinds {
		if !vetutil.HasDirective(cg, k) {
			t.Fatalf("HasDirective(%v) returned false", k)
		}
	}
	dir, ok := vetutil.FindDirective(cg, vetutil.DirectiveHashExclude)
	if !ok || dir.Arg != "ephemeral cache" {
		t.Fatalf("FindDirective(hash-exclude) got (%+v, %v), want Arg='ephemeral cache'", dir, ok)
	}
	if _, ok := vetutil.FindDirective(cg, vetutil.DirectiveUnknown); ok {
		t.Fatal("FindDirective(unknown) should return false")
	}
}

func TestTypeSpecHasDirectiveAndTypeHelpers(t *testing.T) {
	fset := token.NewFileSet()
	src := `package sample
type ErrAlias = error
type Item struct{}
//xops:opaque
type SingleDoc struct{}
type (
	//xops:failclosed
	First int
	Second int
)
type Trailing int //xops:failclosed
`
	f, err := parser.ParseFile(fset, "sample.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
	}
	conf := types.Config{Importer: importer.Default()}
	if _, err := conf.Check("example.com/sample", fset, []*ast.File{f}, info); err != nil {
		t.Fatal(err)
	}
	pass := &analysis.Pass{Fset: fset, Files: []*ast.File{f}, TypesInfo: info}
	if vetutil.IsPosInTestFile(pass, f.Package) {
		t.Fatal("sample.go should not be treated as a test file")
	}
	assertTypeSpecDirectives(t, f)
	assertUnwrapAndErrorHelpers(t, f, info)
}

func assertTypeSpecDirectives(t *testing.T, f *ast.File) {
	t.Helper()
	got := make(map[string]bool)
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts := spec.(*ast.TypeSpec)
			got[ts.Name.Name+":opaque"] = vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveOpaque)
			got[ts.Name.Name+":failclosed"] = vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveFailClosed)
		}
	}
	if !got["SingleDoc:opaque"] || !got["First:failclosed"] || got["Second:failclosed"] || !got["Trailing:failclosed"] {
		t.Fatalf("unexpected TypeSpecHasDirective results: %+v", got)
	}
}

func assertUnwrapAndErrorHelpers(t *testing.T, f *ast.File, info *types.Info) {
	t.Helper()
	defs := collectTypeDefsByName(f, info)
	if !vetutil.IsErrorInterfaceType(defs["ErrAlias"]) {
		t.Fatal("ErrAlias should satisfy IsErrorInterfaceType")
	}
	named, ok := vetutil.UnwrapNamedType(types.NewPointer(defs["Item"]))
	if !ok || named.Obj().Name() != "Item" {
		t.Fatalf("UnwrapNamedType(*Item) got (%v, %v)", named, ok)
	}
	if vetutil.IsErrorInterfaceType(types.Typ[types.Int]) {
		t.Fatal("int should not satisfy IsErrorInterfaceType")
	}
}

func collectTypeDefsByName(f *ast.File, info *types.Info) map[string]types.Type {
	out := make(map[string]types.Type)
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts := spec.(*ast.TypeSpec)
			out[ts.Name.Name] = info.Defs[ts.Name].Type()
		}
	}
	return out
}

func assertNolintCases(t *testing.T) {
	t.Helper()
	nolintTests := []struct {
		text string
		want bool
	}{
		{text: "//nolint:errcheck", want: true},
		{text: "// nolint:all", want: true},
		{text: "//nolint", want: true},
		{text: "/* nolint:govet */", want: true},
		{text: "/*\n * nolint:unused\n */", want: true},
		{text: "// 禁止在白名单外使用 //nolint: 注释", want: false},
		{text: "// nolinting allowed here", want: false},
	}
	for _, tc := range nolintTests {
		c := &ast.Comment{Text: tc.text}
		if got := vetutil.HasNolintComment(c); got != tc.want {
			t.Fatalf("HasNolintComment(%q) = %v, want %v", tc.text, got, tc.want)
		}
	}
}

func TestTypeContainsAndResolveCalledObject(t *testing.T) {
	fset := token.NewFileSet()
	src := `package sample
import "strings"
type Node struct { Next *Node }
func f(s string) string { return strings.TrimSpace(s) }
`
	f, err := parser.ParseFile(fset, "sample_test.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Uses:       make(map[*ast.Ident]types.Object),
		Defs:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	conf := types.Config{Importer: importer.Default()}
	if _, err := conf.Check("example.com/sample", fset, []*ast.File{f}, info); err != nil {
		t.Fatal(err)
	}
	pass := &analysis.Pass{Fset: fset, Files: []*ast.File{f}, TypesInfo: info}
	if !vetutil.IsTestFile(pass, f) {
		t.Fatal("expected IsTestFile=true for sample_test.go")
	}
	if vetutil.InspectorOf(pass) == nil {
		t.Fatal("expected non-nil InspectorOf")
	}
	assertTrimSpaceCall(t, f, info)
	assertNodeCycle(t)
}

func assertTrimSpaceCall(t *testing.T, f *ast.File, info *types.Info) {
	t.Helper()
	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		obj := vetutil.ResolveCalledObject(info, call)
		if vetutil.IsPkgSymbol(obj, "strings", "TrimSpace") {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("ResolveCalledObject did not resolve strings.TrimSpace")
	}
}

func assertNodeCycle(t *testing.T) {
	t.Helper()
	pkg := types.NewPackage("example.com/p", "p")
	targetPkg := types.NewPackage("time", "time")
	durName := types.NewTypeName(token.NoPos, targetPkg, "Duration", nil)
	durType := types.NewNamed(durName, types.Typ[types.Int64], nil)

	nodeName := types.NewTypeName(token.NoPos, pkg, "Node", nil)
	nodeType := types.NewNamed(nodeName, nil, nil)
	nodeStruct := types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "Next", types.NewPointer(nodeType), false),
	}, nil)
	nodeType.SetUnderlying(nodeStruct)

	if vetutil.TypeContainsNamed(nodeType, "time", "Duration") {
		t.Fatal("recursive struct without time.Duration should return false")
	}
	wrapStruct := types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "Next", types.NewPointer(nodeType), false),
		types.NewField(token.NoPos, pkg, "TTL", durType, false),
	}, nil)
	if !vetutil.TypeContainsNamed(wrapStruct, "time", "Duration") {
		t.Fatal("struct containing time.Duration should return true")
	}
}

func TestHardeningV233Regressions(t *testing.T) {
	fset := token.NewFileSet()
	src := `package sample
type SecretBox struct{}
type Pair[A, B any] struct { Rev *Pair[B, A] }
type Holder struct { P Pair[int, string] }
type LeasePort[T any] interface { With(func(T) error) error }
type Svc struct { Vault LeasePort[*SecretBox] }
type GenericFn[T any] func(T)
type FnHolder struct { F GenericFn[*SecretBox] }
func indexCall(fns []func()) { fns[0]() }
`
	f, err := parser.ParseFile(fset, "sample.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Uses:       make(map[*ast.Ident]types.Object),
		Defs:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Instances:  make(map[*ast.Ident]types.Instance),
	}
	pkg, err := (&types.Config{}).Check("example.com/sample", fset, []*ast.File{f}, info)
	if err != nil {
		t.Fatal(err)
	}
	assertPolyAndValueLayout(t, pkg)
	assertDirectivesAndIndexCall(t, f, info)
}

func assertPolyAndValueLayout(t *testing.T, pkg *types.Package) {
	t.Helper()
	if vetutil.TypeContainsNamed(pkg.Scope().Lookup("Holder").Type(), "example.com/sample", "SecretBox") ||
		vetutil.ContainsValueNamed(pkg.Scope().Lookup("Holder").Type(), "example.com/sample", "SecretBox") {
		t.Fatal("Holder(Pair[int,string]) must not match SecretBox")
	}
	polyPkg := types.NewPackage("example.com/poly", "poly")
	tParam := types.NewTypeParam(types.NewTypeName(token.NoPos, polyPkg, "T", nil), types.Universe.Lookup("any").Type())
	polyNamed := types.NewNamed(types.NewTypeName(token.NoPos, polyPkg, "Poly", nil), nil, nil)
	polyNamed.SetTypeParams([]*types.TypeParam{tParam})
	polySliceT, err := types.Instantiate(nil, polyNamed, []types.Type{types.NewSlice(tParam)}, false)
	if err != nil {
		t.Fatal(err)
	}
	polyNamed.SetUnderlying(types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, polyPkg, "Next", types.NewPointer(polySliceT), false),
	}, nil))
	polyInt, err := types.Instantiate(nil, polyNamed, []types.Type{types.Typ[types.Int]}, false)
	if err != nil {
		t.Fatal(err)
	}
	if vetutil.TypeContainsNamed(polyInt, "example.com/sample", "SecretBox") ||
		vetutil.ContainsValueNamed(polyInt, "example.com/sample", "SecretBox") {
		t.Fatal("polymorphic recursive Poly[int] must terminate cleanly")
	}
	if vetutil.ContainsValueNamed(pkg.Scope().Lookup("Svc").Type(), "example.com/sample", "SecretBox") ||
		vetutil.ContainsValueNamed(pkg.Scope().Lookup("FnHolder").Type(), "example.com/sample", "SecretBox") {
		t.Fatal("ContainsValueType must not match generic interface/func type arg")
	}
}

func assertDirectivesAndIndexCall(t *testing.T, f *ast.File, info *types.Info) {
	t.Helper()
	extTestPkg := types.NewPackage("github.com/wentf9/xops-cli/core/domain/secret_test", "secret_test")
	fakeObj := types.NewTypeName(token.NoPos, extTestPkg, "SecretBox", nil)
	if vetutil.ObjectPkgPath(fakeObj) != "github.com/wentf9/xops-cli/core/domain/secret_test" {
		t.Fatalf("ObjectPkgPath stripped _test suffix: %q", vetutil.ObjectPkgPath(fakeObj))
	}
	for _, txt := range []string{"//nolint//reason", "/* //nolint:errcheck */", "/** nolint */"} {
		if !vetutil.HasNolintComment(&ast.Comment{Text: txt}) {
			t.Fatalf("expected HasNolintComment=true for %q", txt)
		}
	}
	if vetutil.HasDirective(&ast.CommentGroup{List: []*ast.Comment{{Text: "// xops:syncclosure is NOT safe"}}}, vetutil.DirectiveSyncClosure) {
		t.Fatal("prose comment with space after // must not activate //xops:syncclosure")
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if obj := vetutil.ResolveCalledObject(info, call); obj != nil {
				t.Fatalf("expected nil called object for fns[0](), got %v", obj)
			}
		}
		return true
	})
}
