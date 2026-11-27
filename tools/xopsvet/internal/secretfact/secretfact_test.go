package secretfact_test

import (
	"go/token"
	"go/types"
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestSecretFactExport(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, secretfact.NewAnalyzer(), "example.com/secretdef")
}

func TestClassifyCommonSinkI18n(t *testing.T) {
	coreI18n := types.NewPackage(vetutil.ModulePrefix+"/core/domain/i18n", "i18n")
	rootI18n := types.NewPackage(vetutil.ModulePrefix+"/internal/i18n", "i18n")
	emptySig := types.NewSignatureType(nil, nil, nil, nil, nil, false)

	tests := []struct {
		name string
		pkg  *types.Package
		sym  string
		want secretfact.SinkKind
	}{
		{name: "core_str", pkg: coreI18n, sym: "Str", want: secretfact.SinkError},
		{name: "core_e", pkg: coreI18n, sym: "E", want: secretfact.SinkError},
		{name: "core_ef", pkg: coreI18n, sym: "EF", want: secretfact.SinkError},
		{name: "core_wrap", pkg: coreI18n, sym: "Wrap", want: secretfact.SinkError},
		{name: "core_wraps", pkg: coreI18n, sym: "WrapS", want: secretfact.SinkError},
		{name: "core_new_message", pkg: coreI18n, sym: "NewMessage", want: secretfact.SinkError},
		{name: "core_new_message_fb", pkg: coreI18n, sym: "NewMessageWithFallback", want: secretfact.SinkError},
		{name: "core_new_plural", pkg: coreI18n, sym: "NewPluralMessage", want: secretfact.SinkError},
		{name: "core_parse_locale_not_sink", pkg: coreI18n, sym: "ParseLocale", want: secretfact.SinkNone},
		{name: "root_e", pkg: rootI18n, sym: "E", want: secretfact.SinkError},
		{name: "root_t", pkg: rootI18n, sym: "T", want: secretfact.SinkError},
		{name: "root_tplural", pkg: rootI18n, sym: "TPlural", want: secretfact.SinkError},
		{name: "root_render", pkg: rootI18n, sym: "Render", want: secretfact.SinkError},
		{name: "root_render_error", pkg: rootI18n, sym: "RenderError", want: secretfact.SinkError},
		{name: "root_load_catalog_not_sink", pkg: rootI18n, sym: "LoadCatalog", want: secretfact.SinkNone},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fn := types.NewFunc(token.NoPos, tc.pkg, tc.sym, emptySig)
			if got := secretfact.ClassifyCommonSink(fn); got != tc.want {
				t.Fatalf("ClassifyCommonSink(%s.%s) = %v, want %v", tc.pkg.Path(), tc.sym, got, tc.want)
			}
		})
	}
}
