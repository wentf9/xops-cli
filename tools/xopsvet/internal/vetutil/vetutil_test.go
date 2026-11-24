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
	name          string
	pkgPath       string
	wantLayer     vetutil.Layer
	wantExtTest   bool
	wantXops      bool
	wantAllowCtx  bool
	wantAllowOSFS bool
	wantAllowSys  bool
	wantAllowNol  bool
	wantIsCore    bool
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
			name:         "domain_secret_nolint_whitelist",
			pkgPath:      "github.com/wentf9/xops-cli/core/domain/secret",
			wantLayer:    vetutil.LayerCoreDomain,
			wantXops:     true,
			wantAllowNol: true,
			wantIsCore:   true,
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
		},
	}
	dirs := vetutil.ParseCommentGroup(cg)
	if len(dirs) != 8 {
		t.Fatalf("got %d directives, want 8", len(dirs))
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
	}
	for _, k := range wantKinds {
		if !vetutil.HasDirective(cg, k) {
			t.Fatalf("HasDirective(%v) returned false", k)
		}
	}
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
