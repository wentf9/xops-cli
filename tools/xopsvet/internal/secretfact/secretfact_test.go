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
	analysistest.Run(
		t,
		testdata,
		secretfact.NewAnalyzer(),
		"example.com/secretdef",
		"github.com/wentf9/xops-cli/core/domain/i18n",
	)
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
		{name: "core_bound_str", pkg: coreI18n, sym: "BoundStr", want: secretfact.SinkError},
		{name: "core_bound_display_text", pkg: coreI18n, sym: "BoundDisplayText", want: secretfact.SinkError},
		{name: "core_new_error_fb", pkg: coreI18n, sym: "NewErrorWithFallback", want: secretfact.SinkError},
		{name: "core_canonical_error", pkg: coreI18n, sym: "CanonicalError", want: secretfact.SinkError},
		{name: "core_render_error_chain", pkg: coreI18n, sym: "RenderErrorChain", want: secretfact.SinkError},
		{name: "core_format_template", pkg: coreI18n, sym: "FormatTemplate", want: secretfact.SinkError},
		{name: "core_e", pkg: coreI18n, sym: "E", want: secretfact.SinkError},
		{name: "core_ef", pkg: coreI18n, sym: "EF", want: secretfact.SinkError},
		{name: "core_wrap", pkg: coreI18n, sym: "Wrap", want: secretfact.SinkError},
		{name: "core_wraps", pkg: coreI18n, sym: "WrapS", want: secretfact.SinkError},
		{name: "core_wrap_sentinel", pkg: coreI18n, sym: "WrapSentinel", want: secretfact.SinkError},
		{name: "core_sentinel", pkg: coreI18n, sym: "Sentinel", want: secretfact.SinkError},
		{name: "core_sentinel_fb", pkg: coreI18n, sym: "SentinelWithFallback", want: secretfact.SinkError},
		{name: "core_new_message", pkg: coreI18n, sym: "NewMessage", want: secretfact.SinkError},
		{name: "core_new_message_fb", pkg: coreI18n, sym: "NewMessageWithFallback", want: secretfact.SinkError},
		{name: "core_new_plural", pkg: coreI18n, sym: "NewPluralMessage", want: secretfact.SinkError},
		{name: "core_new_plural_fb", pkg: coreI18n, sym: "NewPluralMessageWithFallback", want: secretfact.SinkError},
		{name: "core_deleted_e_fb_not_sink", pkg: coreI18n, sym: "EWithFallback", want: secretfact.SinkNone},
		{name: "core_deleted_ef_fb_not_sink", pkg: coreI18n, sym: "EFWithFallback", want: secretfact.SinkNone},
		{name: "core_deleted_wrap_fb_not_sink", pkg: coreI18n, sym: "WrapWithFallback", want: secretfact.SinkNone},
		{name: "core_deleted_wraps_fb_not_sink", pkg: coreI18n, sym: "WrapSWithFallback", want: secretfact.SinkNone},
		{name: "core_parse_locale_not_sink", pkg: coreI18n, sym: "ParseLocale", want: secretfact.SinkNone},
		{name: "root_str", pkg: rootI18n, sym: "Str", want: secretfact.SinkError},
		{name: "root_bound_str", pkg: rootI18n, sym: "BoundStr", want: secretfact.SinkError},
		{name: "root_int", pkg: rootI18n, sym: "Int", want: secretfact.SinkError},
		{name: "root_int64", pkg: rootI18n, sym: "Int64", want: secretfact.SinkError},
		{name: "root_uint64", pkg: rootI18n, sym: "Uint64", want: secretfact.SinkError},
		{name: "root_float", pkg: rootI18n, sym: "Float", want: secretfact.SinkError},
		{name: "root_bool", pkg: rootI18n, sym: "Bool", want: secretfact.SinkError},
		{name: "root_dur", pkg: rootI18n, sym: "Dur", want: secretfact.SinkError},
		{name: "root_dur_nanos", pkg: rootI18n, sym: "DurNanos", want: secretfact.SinkError},
		{name: "root_msg", pkg: rootI18n, sym: "Msg", want: secretfact.SinkError},
		{name: "root_sentinel", pkg: rootI18n, sym: "Sentinel", want: secretfact.SinkError},
		{name: "root_e", pkg: rootI18n, sym: "E", want: secretfact.SinkError},
		{name: "root_ef", pkg: rootI18n, sym: "EF", want: secretfact.SinkError},
		{name: "root_wrap", pkg: rootI18n, sym: "Wrap", want: secretfact.SinkError},
		{name: "root_wraps", pkg: rootI18n, sym: "WrapS", want: secretfact.SinkError},
		{name: "root_new_message", pkg: rootI18n, sym: "NewMessage", want: secretfact.SinkError},
		{name: "root_new_plural", pkg: rootI18n, sym: "NewPluralMessage", want: secretfact.SinkError},
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
