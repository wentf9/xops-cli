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

func buildTestPass(t *testing.T, pkgPath, filename, src string) (*analysis.Pass, *[]string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	pkg, err := (&types.Config{Importer: importer.Default()}).Check(pkgPath, fset, []*ast.File{f}, info)
	if err != nil {
		t.Fatal(err)
	}
	var diags []string
	pass := &analysis.Pass{
		Fset:      fset,
		Files:     []*ast.File{f},
		Pkg:       pkg,
		TypesInfo: info,
		Report: func(d analysis.Diagnostic) {
			diags = append(diags, d.Message)
		},
	}
	return pass, &diags
}

func TestCollectEmbedVarsValueSpecDocAndMutation(t *testing.T) {
	src := `package i18n
import "embed"
var (
	//go:embed locales/*/*.yaml
	localeFiles embed.FS
	//go:embed other.yaml
	extraFiles embed.FS
)
func touch() {
	_ = localeFiles
	localeFiles = embed.FS{}
	_ = &localeFiles
}
`
	pass, diags := buildTestPass(t, vetutil.ModulePrefix+"/internal/i18n", "embed_fs.go", src)
	pkgInfo := vetutil.ClassifyPass(pass)
	checkPackageDecls(pass, pkgInfo)
	if len(*diags) != 3 {
		t.Fatalf("got %d diagnostics (%v), want 3 (extraFiles decl, mutate, addr)", len(*diags), *diags)
	}
	if !strings.Contains((*diags)[0], "禁止声明可变包级 var") ||
		!strings.Contains((*diags)[1], "禁止在运行期修改只读嵌入文件系统变量 localeFiles") ||
		!strings.Contains((*diags)[2], "禁止对只读嵌入文件系统变量 localeFiles 取地址") {
		t.Fatalf("unexpected diagnostics: %v", *diags)
	}
}

func TestClassifyPassPreventsFakeExternalTestDirBypass(t *testing.T) {
	src := `package fake_test
import "context"
func f(ctx context.Context) any {
	return ctx.Value("k")
}
`
	// 生产文件位于名为 *_test 的子目录中，ClassifyPass 必须按非外置测试包处理且拒绝绕过。
	pass, diags := buildTestPass(t, vetutil.ModulePrefix+"/core/internal/foundation/trace_test", "prod.go", src)
	pkgInfo := vetutil.ClassifyPass(pass)
	if pkgInfo.IsExternalTest {
		t.Fatalf("expected ClassifyPass to treat non-test file in *_test dir as IsExternalTest=false, got %+v", pkgInfo)
	}
	checkContextAndAnonIfaces(pass, pkgInfo)
	if len(*diags) == 0 {
		t.Fatal("expected ctx.Value diagnostic for non-test file in trace_test directory")
	}
}
