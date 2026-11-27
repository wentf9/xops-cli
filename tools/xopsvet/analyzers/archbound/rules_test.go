package archbound

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

func TestCheckImportAllowedDomainSubpackageStdlibAndNorm(t *testing.T) {
	tests := []struct {
		name    string
		pkgPath string
		isTest  bool
		impPath string
		wantOK  bool
	}{
		{
			name:    "domain_secret_allows_runtime_secret_prod",
			pkgPath: vetutil.ModulePrefix + "/core/domain/secret",
			impPath: "runtime/secret",
			wantOK:  true,
		},
		{
			name:    "domain_secret_allows_runtime_secret_test",
			pkgPath: vetutil.ModulePrefix + "/core/domain/secret_test",
			isTest:  true,
			impPath: "runtime/secret",
			wantOK:  true,
		},
		{
			name:    "domain_secret_denies_crypto_sha1",
			pkgPath: vetutil.ModulePrefix + "/core/domain/secret",
			impPath: "crypto/sha1",
			wantOK:  false,
		},
		{
			name:    "domain_option_allows_crypto_sha1",
			pkgPath: vetutil.ModulePrefix + "/core/domain/option",
			impPath: "crypto/sha1",
			wantOK:  true,
		},
		{
			name:    "domain_option_denies_runtime_secret",
			pkgPath: vetutil.ModulePrefix + "/core/domain/option",
			impPath: "runtime/secret",
			wantOK:  false,
		},
		{
			name:    "domain_other_denies_runtime_secret_and_sha1",
			pkgPath: vetutil.ModulePrefix + "/core/domain/algebraic",
			impPath: "runtime/secret",
			wantOK:  false,
		},
		{
			name:    "domain_other_denies_crypto_sha1",
			pkgPath: vetutil.ModulePrefix + "/core/domain/algebraic",
			impPath: "crypto/sha1",
			wantOK:  false,
		},
		{
			name:    "domain_allows_unicode_norm",
			pkgPath: vetutil.ModulePrefix + "/core/domain/pathalg",
			impPath: "golang.org/x/text/unicode/norm",
			wantOK:  true,
		},
		{
			name:    "domain_test_denies_conc",
			pkgPath: vetutil.ModulePrefix + "/core/domain/pathalg",
			isTest:  true,
			impPath: vetutil.ModulePrefix + "/core/conc",
			wantOK:  false,
		},
		{
			name:    "domain_test_denies_sim",
			pkgPath: vetutil.ModulePrefix + "/core/domain/pathalg",
			isTest:  true,
			impPath: vetutil.ModulePrefix + "/core/internal/sim",
			wantOK:  false,
		},
		{
			name:    "domain_test_denies_goleak",
			pkgPath: vetutil.ModulePrefix + "/core/domain/pathalg",
			isTest:  true,
			impPath: "go.uber.org/goleak",
			wantOK:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := vetutil.ClassifyPackage(tc.pkgPath)
			reason, ok := checkImportAllowed(src, tc.isTest, tc.impPath)
			if ok != tc.wantOK {
				t.Fatalf("checkImportAllowed(%s, test=%v, %s) = (%q, %v), want %v", tc.pkgPath, tc.isTest, tc.impPath, reason, ok, tc.wantOK)
			}
		})
	}
}

func TestCheckImportAllowedConcActorEngineAndLayers(t *testing.T) {
	tests := []struct {
		name    string
		pkgPath string
		isTest  bool
		impPath string
		wantOK  bool
	}{
		{
			name:    "conc_allows_runtime_debug_and_time",
			pkgPath: vetutil.ModulePrefix + "/core/conc",
			impPath: "runtime/debug",
			wantOK:  true,
		},
		{
			name:    "conc_denies_os",
			pkgPath: vetutil.ModulePrefix + "/core/conc",
			impPath: "os",
			wantOK:  false,
		},
		{
			name:    "conc_denies_math_rand_v2",
			pkgPath: vetutil.ModulePrefix + "/core/conc",
			impPath: "math/rand/v2",
			wantOK:  false,
		},
		{
			name:    "conc_denies_domain",
			pkgPath: vetutil.ModulePrefix + "/core/conc",
			impPath: vetutil.ModulePrefix + "/core/domain/algebraic",
			wantOK:  false,
		},
		{
			name:    "conc_test_allows_goleak",
			pkgPath: vetutil.ModulePrefix + "/core/conc",
			isTest:  true,
			impPath: "go.uber.org/goleak",
			wantOK:  true,
		},
		{
			name:    "conc_test_denies_sim",
			pkgPath: vetutil.ModulePrefix + "/core/conc",
			isTest:  true,
			impPath: vetutil.ModulePrefix + "/core/internal/sim",
			wantOK:  false,
		},
		{
			name:    "actor_prod_allows_runtime_debug",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/actor",
			impPath: "runtime/debug",
			wantOK:  true,
		},
		{
			name:    "actor_prod_denies_net",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/actor",
			impPath: "net",
			wantOK:  false,
		},
		{
			name:    "actor_prod_denies_reflect",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/actor",
			impPath: "reflect",
			wantOK:  false,
		},
		{
			name:    "actor_prod_denies_conc",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/actor",
			impPath: vetutil.ModulePrefix + "/core/conc",
			wantOK:  false,
		},
		{
			name:    "actor_test_allows_conc",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/actor",
			isTest:  true,
			impPath: vetutil.ModulePrefix + "/core/conc",
			wantOK:  true,
		},
		{
			name:    "actor_test_allows_sim",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/actor",
			isTest:  true,
			impPath: vetutil.ModulePrefix + "/core/internal/sim",
			wantOK:  true,
		},
		{
			name:    "engine_prod_denies_tck",
			pkgPath: vetutil.ModulePrefix + "/core/engine",
			impPath: vetutil.ModulePrefix + "/core/ports/tck",
			wantOK:  false,
		},
		{
			name:    "engine_prod_denies_sim",
			pkgPath: vetutil.ModulePrefix + "/core/engine",
			impPath: vetutil.ModulePrefix + "/core/internal/sim",
			wantOK:  false,
		},
		{
			name:    "engine_prod_allows_conc_and_sshnet_priv",
			pkgPath: vetutil.ModulePrefix + "/core/engine",
			impPath: vetutil.ModulePrefix + "/core/internal/sshnet/priv",
			wantOK:  true,
		},
		{
			name:    "engine_test_allows_sim",
			pkgPath: vetutil.ModulePrefix + "/core/engine",
			isTest:  true,
			impPath: vetutil.ModulePrefix + "/core/internal/sim",
			wantOK:  true,
		},
		{
			name:    "osfs_prod_denies_conc",
			pkgPath: vetutil.ModulePrefix + "/core/osfs",
			impPath: vetutil.ModulePrefix + "/core/conc",
			wantOK:  false,
		},
		{
			name:    "osfs_test_allows_conc",
			pkgPath: vetutil.ModulePrefix + "/core/osfs",
			isTest:  true,
			impPath: vetutil.ModulePrefix + "/core/conc",
			wantOK:  true,
		},
		{
			name:    "ports_prod_denies_conc",
			pkgPath: vetutil.ModulePrefix + "/core/ports",
			impPath: vetutil.ModulePrefix + "/core/conc",
			wantOK:  false,
		},
		{
			name:    "events_prod_denies_conc",
			pkgPath: vetutil.ModulePrefix + "/core/events",
			impPath: vetutil.ModulePrefix + "/core/conc",
			wantOK:  false,
		},
		{
			name:    "trace_prod_denies_conc",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/trace",
			impPath: vetutil.ModulePrefix + "/core/conc",
			wantOK:  false,
		},
		{
			name:    "tck_allows_conc_and_goleak",
			pkgPath: vetutil.ModulePrefix + "/core/ports/tck",
			impPath: "go.uber.org/goleak",
			wantOK:  true,
		},
		{
			name:    "sshnet_priv_test_allows_tck",
			pkgPath: vetutil.ModulePrefix + "/core/internal/sshnet/priv",
			isTest:  true,
			impPath: vetutil.ModulePrefix + "/core/ports/tck",
			wantOK:  true,
		},
		{
			name:    "host_allows_conc",
			pkgPath: vetutil.ModulePrefix + "/internal/host/sys",
			impPath: vetutil.ModulePrefix + "/core/conc",
			wantOK:  true,
		},
		{
			name:    "entry_allows_conc",
			pkgPath: vetutil.ModulePrefix + "/internal/entry/cli",
			impPath: vetutil.ModulePrefix + "/core/conc",
			wantOK:  true,
		},
		{
			name:    "cmd_xops_allows_conc",
			pkgPath: vetutil.ModulePrefix + "/cmd/xops",
			impPath: vetutil.ModulePrefix + "/core/conc",
			wantOK:  true,
		},
		{
			name:    "trace_prod_denies_crypto_rand",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/trace",
			impPath: "crypto/rand",
			wantOK:  false,
		},
		{
			name:    "trace_test_denies_crypto_rand",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/trace",
			isTest:  true,
			impPath: "crypto/rand",
			wantOK:  false,
		},
		{
			name:    "trace_prod_denies_actor",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/trace",
			impPath: vetutil.ModulePrefix + "/core/internal/foundation/actor",
			wantOK:  false,
		},
		{
			name:    "foundation_other_src_denied",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/rogue",
			impPath: "errors",
			wantOK:  false,
		},
		{
			name:    "foundation_other_dst_denied_from_engine",
			pkgPath: vetutil.ModulePrefix + "/core/engine",
			impPath: vetutil.ModulePrefix + "/core/internal/foundation/rogue",
			wantOK:  false,
		},
		{
			name:    "foundation_other_test_denied_sim",
			pkgPath: vetutil.ModulePrefix + "/core/internal/foundation/rogue",
			isTest:  true,
			impPath: vetutil.ModulePrefix + "/core/internal/sim",
			wantOK:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := vetutil.ClassifyPackage(tc.pkgPath)
			reason, ok := checkImportAllowed(src, tc.isTest, tc.impPath)
			if ok != tc.wantOK {
				t.Fatalf("checkImportAllowed(%s, test=%v, %s) = (%q, %v), want %v", tc.pkgPath, tc.isTest, tc.impPath, reason, ok, tc.wantOK)
			}
		})
	}
}

func TestCheckImportAllowedInternalI18n(t *testing.T) {
	tests := []struct {
		name    string
		pkgPath string
		isTest  bool
		impPath string
		wantOK  bool
	}{
		{name: "i18n_allows_embed", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "embed", wantOK: true},
		{name: "i18n_allows_io_fs", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "io/fs", wantOK: true},
		{name: "i18n_allows_context", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "context", wantOK: true},
		{name: "i18n_allows_sync_atomic", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "sync/atomic", wantOK: true},
		{name: "i18n_allows_json_v2", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "encoding/json/v2", wantOK: true},
		{name: "i18n_allows_yaml_v3", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "go.yaml.in/yaml/v3", wantOK: true},
		{name: "i18n_denies_other_thirdparty", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "gopkg.in/yaml.v3", wantOK: false},
		{name: "i18n_denies_os", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "os", wantOK: false},
		{name: "i18n_denies_os_exec", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "os/exec", wantOK: false},
		{name: "i18n_denies_net", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "net", wantOK: false},
		{name: "i18n_denies_net_http", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "net/http", wantOK: false},
		{name: "i18n_denies_syscall", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "syscall", wantOK: false},
		{name: "i18n_denies_unsafe", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "unsafe", wantOK: false},
		{name: "i18n_denies_reflect", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "reflect", wantOK: false},
		{name: "i18n_denies_log", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "log", wantOK: false},
		{name: "i18n_denies_log_slog", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "log/slog", wantOK: false},
		{name: "i18n_denies_plugin", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "plugin", wantOK: false},
		{name: "i18n_denies_math_rand", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "math/rand", wantOK: false},
		{name: "i18n_denies_crypto_rand", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "crypto/rand", wantOK: false},
		{name: "i18n_denies_filepath", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "path/filepath", wantOK: false},
		{name: "i18n_denies_flag", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "flag", wantOK: false},
		{name: "i18n_denies_mime", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: "mime", wantOK: false},
		{name: "i18n_allows_core_domain", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: vetutil.ModulePrefix + "/core/domain/i18n", wantOK: true},
		{name: "i18n_allows_core_conc", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: vetutil.ModulePrefix + "/core/conc", wantOK: true},
		{name: "i18n_allows_self_subpkg", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: vetutil.ModulePrefix + "/internal/i18n/sub", wantOK: true},
		{name: "i18n_denies_core_ports", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: vetutil.ModulePrefix + "/core/ports", wantOK: false},
		{name: "i18n_denies_core_engine", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: vetutil.ModulePrefix + "/core/engine", wantOK: false},
		{name: "i18n_denies_host_sys", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: vetutil.ModulePrefix + "/internal/host/sys", wantOK: false},
		{name: "i18n_denies_entry_cli", pkgPath: vetutil.ModulePrefix + "/internal/i18n", impPath: vetutil.ModulePrefix + "/internal/entry/cli", wantOK: false},
		{name: "i18n_test_allows_fstest", pkgPath: vetutil.ModulePrefix + "/internal/i18n", isTest: true, impPath: "testing/fstest", wantOK: true},
		{name: "entry_allows_internal_i18n", pkgPath: vetutil.ModulePrefix + "/internal/entry/cli", impPath: vetutil.ModulePrefix + "/internal/i18n", wantOK: true},
		{name: "host_sys_allows_internal_i18n", pkgPath: vetutil.ModulePrefix + "/internal/host/sys/interact", impPath: vetutil.ModulePrefix + "/internal/i18n", wantOK: true},
		{name: "host_vault_allows_internal_i18n", pkgPath: vetutil.ModulePrefix + "/internal/host/vault", impPath: vetutil.ModulePrefix + "/internal/i18n", wantOK: true},
		{name: "host_other_allows_internal_i18n", pkgPath: vetutil.ModulePrefix + "/internal/host/store", impPath: vetutil.ModulePrefix + "/internal/i18n", wantOK: true},
		{name: "cmd_xops_allows_internal_i18n", pkgPath: vetutil.ModulePrefix + "/cmd/xops", impPath: vetutil.ModulePrefix + "/internal/i18n", wantOK: true},
		{name: "conc_denies_internal_i18n", pkgPath: vetutil.ModulePrefix + "/core/conc", impPath: vetutil.ModulePrefix + "/internal/i18n", wantOK: false},
		{name: "core_engine_denies_internal_i18n", pkgPath: vetutil.ModulePrefix + "/core/engine", impPath: vetutil.ModulePrefix + "/internal/i18n", wantOK: false},
		{name: "core_domain_denies_internal_i18n", pkgPath: vetutil.ModulePrefix + "/core/domain/i18n", impPath: vetutil.ModulePrefix + "/internal/i18n", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := vetutil.ClassifyPackage(tc.pkgPath)
			reason, ok := checkImportAllowed(src, tc.isTest, tc.impPath)
			if ok != tc.wantOK {
				t.Fatalf("checkImportAllowed(%s, test=%v, %s) = (%q, %v), want %v", tc.pkgPath, tc.isTest, tc.impPath, reason, ok, tc.wantOK)
			}
		})
	}
}

func TestCheckRestrictedNetCompositeLitRejectsUnkeyed(t *testing.T) {
	lit := &ast.CompositeLit{
		Elts: []ast.Expr{
			&ast.BasicLit{ValuePos: token.Pos(10), Kind: token.INT, Value: "1"},
		},
	}
	var got []string
	checkRestrictedNetCompositeLit(lit, "Dialer", func(_, _ token.Pos, msg string) {
		got = append(got, msg)
	})
	if len(got) != 1 || !strings.Contains(got[0], "无键位置字面量") {
		t.Fatalf("expected unkeyed composite lit diagnostic, got %v", got)
	}
}
