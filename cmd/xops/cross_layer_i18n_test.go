package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/host/store/yamlcodec"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type crossLayerErrorCheck struct {
	name     string
	err      error
	wantEn   []string
	wantZh   []string
	forbidZh []string
}

func TestCrossLayerRealErrors_BilingualZeroMixedLanguage(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)

	catalog, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	enLoc := catalog.For(domi18n.LocaleEn)
	zhLoc := catalog.For(domi18n.LocaleZh)
	ctx := context.Background()

	assertRealDomainErrors(t, enLoc, zhLoc)
	assertRealPortsAuditErrors(t, enLoc, zhLoc)
	assertRealYAMLCodecErrors(t, enLoc, zhLoc)
	assertRealGateChallengeAndEngineErrors(t, ctx, xopsHome, enLoc, zhLoc)
	assertRealGateOutcomeErrorViaStreamLogs(t, ctx, homeDir, xopsHome, enLoc, zhLoc)
	assertZeroRemainingLocks(t, xopsHome)
}

func assertRealDomainErrors(t *testing.T, enLoc, zhLoc *i18n.Localizer) {
	t.Helper()
	_, hpErr := netaddr.ParseHostPort("bad-host-no-port")
	_, rpErr := pathalg.ParseRemotePath("rel/bad\x00path")
	_, durErr := algebraic.ParseDuration("not-a-duration")

	nid, _ := inventory.ParseNodeID("web-1")
	hid, _ := inventory.ParseHostID("missing-host")
	iid, _ := inventory.ParseIdentityID("missing-ident")
	node, err := inventory.NewNode(inventory.NodeSpec{ID: nid, HostRef: hid, IdentityRef: iid, Origin: inventory.NewOriginManaged()})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	_, graphErr := inventory.NewGraph(inventory.GraphSpec{Nodes: []inventory.Node{node}})

	for _, tc := range []crossLayerErrorCheck{
		{"domain/netaddr.ParseHostPort", hpErr, []string{"address bad-host-no-port must be in <host>:<port> or [<ipv6>]:<port> format"}, []string{"地址 bad-host-no-port 必须符合 <host>:<port> 或 [<ipv6>]:<port> 格式"}, []string{"netaddr:", "must be in"}},
		{"domain/pathalg.ParseRemotePath", rpErr, []string{"remote_path", "control characters"}, []string{"remote_path", "控制字符"}, []string{"pathalg:", "control characters"}},
		{"domain/algebraic.ParseDuration", durErr, []string{"invalid duration: not-a-duration"}, []string{"duration 无效", "not-a-duration"}, []string{"algebraic:", "invalid duration: not-a-duration"}},
		{"domain/inventory.NewGraph", graphErr, []string{"invalid node: web-1"}, []string{"node 无效：web-1"}, []string{"inventory:", "invalid node:"}},
	} {
		assertRealBilingualParity(t, tc, enLoc, zhLoc)
	}
}

func assertRealPortsAuditErrors(t *testing.T, enLoc, zhLoc *i18n.Localizer) {
	t.Helper()
	opID, err := security.NewOperationIDFrom(sys.NewCryptoEntropy())
	if err != nil {
		t.Fatalf("NewOperationIDFrom: %v", err)
	}
	pwWithCause, err := ports.NewAuditPostWriteError(opID, ports.ErrClosed)
	if err != nil {
		t.Fatalf("NewAuditPostWriteError(cause): %v", err)
	}
	pwDefault, err := ports.NewAuditPostWriteError(opID, nil)
	if err != nil {
		t.Fatalf("NewAuditPostWriteError(nil): %v", err)
	}

	for _, tc := range []crossLayerErrorCheck{
		{"ports.AuditPostWriteError(with-cause)", pwWithCause, []string{"ports: audit post-write failed", opID.String(), "ports: port or session is closed"}, []string{"审计终态回写失败", opID.String(), "端口或会话已关闭"}, []string{"ports:", "audit post-write", "port or session is closed"}},
		{"ports.AuditPostWriteError(default-suppressed)", pwDefault, []string{"ports: audit post-write failed", opID.String()}, []string{"审计终态回写失败", opID.String()}, []string{"ports:", "audit post-write", "审计终态回写记录失败"}},
	} {
		assertRealBilingualParity(t, tc, enLoc, zhLoc)
	}
}

func assertRealYAMLCodecErrors(t *testing.T, enLoc, zhLoc *i18n.Localizer) {
	t.Helper()
	_, _, unknownFieldErr := yamlcodec.DecodeConfigDocumentYAML([]byte("version: 2\nunknown_top_key: true\n"))
	_, _, badVerErr := yamlcodec.DecodeConfigDocumentYAML([]byte("version: 1\ninventory: {}\n"))
	_, _, badDefaultVaultErr := yamlcodec.DecodeConfigDocumentYAML([]byte("version: 2\nvault:\n  default_store: ghost\n  stores:\n    main:\n      kind: offline_aead\n"))

	for _, tc := range []crossLayerErrorCheck{
		{"yamlcodec/unknown-field", unknownFieldErr, []string{"failed to decode YAML vNext document"}, []string{"解析 YAML vNext 配置文档失败"}, []string{"ports:", "yamlcodec:", "failed to decode YAML"}},
		{"yamlcodec/unsupported-version", badVerErr, []string{"unsupported schema version 1"}, []string{"不支持的 schema 版本 1"}, []string{"ports:", "yamlcodec:", "unsupported schema version"}},
		{"yamlcodec/undeclared-default-store", badDefaultVaultErr, []string{"vault.default_store=ghost is not declared"}, []string{"vault.default_store=ghost 未在 vault.stores 中声明"}, []string{"ports:", "yamlcodec:", "is not declared"}},
	} {
		assertRealBilingualParity(t, tc, enLoc, zhLoc)
	}
}

func assertRealGateChallengeAndEngineErrors(
	t *testing.T,
	ctx context.Context,
	xopsHome pathalg.LocalDir,
	enLoc, zhLoc *i18n.Localizer,
) {
	t.Helper()
	cfgPath := filepath.Join(filepath.FromSlash(xopsHome.String()), "config.yaml")
	cfgYAML := `version: 2
policy:
  mcp_default: strict_agent
  guardrail:
    approval_threshold: moderate
    no_elicit_fallback: challenge
inventory:
  hosts:
    h1:
      address: 127.0.0.1
      port: 22
  identities:
    i1:
      user: ops
      auth:
        kind: agent
  nodes:
    n1:
      host: h1
      identity: i1
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("WriteFile(config.yaml): %v", err)
	}

	rt, err := wireRuntimeWithLocalizer(ctx, cli.EngineInitOptions{
		OpenSSHConfigFile: "none",
		Locale:            domi18n.LocaleZh,
	}, runtimeModeMCP, strings.NewReader(""), io.Discard, zhLoc)
	if err != nil {
		t.Fatalf("wireRuntimeWithLocalizer(MCP): %v", err)
	}
	defer func() {
		if cErr := rt.Close(ctx); cErr != nil {
			t.Errorf("rt.Close(MCP): %v", cErr)
		}
	}()

	// 1. 真实 *gate.ApprovalChallengeError 经 engine.mapEngineError 分组包装（抑制 gate.ErrApprovalRequired）。
	var out bytes.Buffer
	_, chErr := rt.engine.Exec(ctx, engine.ExecRequest{
		TargetSpec: "n1",
		Command:    "uname -a",
		Stdout:     &out,
	})
	if !errors.Is(chErr, engine.ErrApprovalRequired) {
		t.Fatalf("期望 engine.ErrApprovalRequired，实际=%v", chErr)
	}
	if ch, ok := engine.ExtractApprovalChallenge(chErr); !ok || !ch.IsValid() {
		t.Fatalf("期望可提取有效 ApprovalChallenge，实际 ok=%v", ok)
	}
	assertRealBilingualParity(t, crossLayerErrorCheck{
		name:     "gate.ApprovalChallengeError+engine.mapEngineError",
		err:      chErr,
		wantEn:   []string{"engine: operation requires two-step approval confirmation", "gate: approval challenge required"},
		wantZh:   []string{"操作需要两阶段人工审批确认", "需要人工审批"},
		forbidZh: []string{"engine:", "gate:", "approval challenge required", "requires two-step approval"},
	}, enLoc, zhLoc)

	// 2. 真实 engine.mapEngineError 分组抑制：GetNode(missing) -> engine.ErrNotFound 折叠 ucinv.ErrAssetNotFound。
	missingID, _ := inventory.ParseNodeID("missing-node")
	_, _, notFoundErr := rt.engine.GetNode(ctx, missingID, engine.InventoryQueryRequest{})
	if !errors.Is(notFoundErr, engine.ErrNotFound) {
		t.Fatalf("期望 engine.ErrNotFound，实际=%v", notFoundErr)
	}
	assertRealBilingualParity(t, crossLayerErrorCheck{
		name:     "engine.GetNode/ErrNotFound",
		err:      notFoundErr,
		wantEn:   []string{"engine: target resource not found"},
		wantZh:   []string{"目标资源不存在"},
		forbidZh: []string{"engine:", "usecase/inventory:", "ports:", "target resource not found"},
	}, enLoc, zhLoc)

	// 3. 真实 engine.DeleteHost(referenced) -> engine.ErrStillReferenced 包装 *ucinv.AssetReferencedError。
	_, refErr := rt.engine.DeleteHost(ctx, engine.DeleteAssetRequest{
		ID:           "h1",
		ScopeSummary: "delete referenced host h1",
		CallOptions:  engine.CallOptions{Risk: algebraic.Some(security.RiskSafe)},
	})
	if !errors.Is(refErr, engine.ErrStillReferenced) {
		t.Fatalf("期望 engine.ErrStillReferenced，实际=%v", refErr)
	}
	assertRealBilingualParity(t, crossLayerErrorCheck{
		name:     "engine.DeleteHost/AssetReferencedError",
		err:      refErr,
		wantEn:   []string{"engine: target asset or secret is still referenced", "host h1 is still referenced"},
		wantZh:   []string{"目标资产或凭据仍被引用", "host h1 仍被"},
		forbidZh: []string{"engine:", "usecase/inventory:", "is still referenced"},
	}, enLoc, zhLoc)
}

type cancelOnWriteWriter struct {
	cancel context.CancelFunc
}

func (w *cancelOnWriteWriter) Write(p []byte) (int, error) {
	if len(p) > 0 && w.cancel != nil {
		w.cancel()
	}
	return len(p), nil
}

func assertRealGateOutcomeErrorViaStreamLogs(
	t *testing.T,
	ctx context.Context,
	homeDir, xopsHome pathalg.LocalDir,
	enLoc, zhLoc *i18n.Localizer,
) {
	t.Helper()
	clientKey, keyPEM := generateGracefulEd25519Key(t)
	keyPath := spWriteTestKey(t, homeDir, "id_outcome_unknown", keyPEM)

	// 服务端先写出首行输出证明 Start 已完成，客户端收到输出后确定性取消上下文，
	// 迫使远端会话在运行期返回真实 OutcomeUnknown + *gate.OutcomeError（零 time.Sleep）。
	srv := startSPSSHServer(t, clientKey.PublicKey(), func(hCtx context.Context, ch ssh.Channel, _ spExecRecord) {
		_, _ = io.WriteString(ch, "stream-started\n")
		<-hCtx.Done()
	})
	defer srv.Close()

	cfgPath := filepath.Join(filepath.FromSlash(xopsHome.String()), "config.yaml")
	cfgYAML := "version: 2\npolicy:\n  cli_default: direct_operator\noptions:\n  strict_host_key_checking: accept-new\n  identities_only: true\ninventory:\n  hosts:\n    hdrop:\n      address: 127.0.0.1\n      port: " + srv.port + "\n  identities:\n    idrop:\n      user: deploy\n      auth:\n        kind: private_key\n        key_paths:\n          - " + filepath.ToSlash(keyPath) + "\n  nodes:\n    ndrop:\n      host: hdrop\n      identity: idrop\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("WriteFile(stream_logs config.yaml): %v", err)
	}

	rt, err := wireRuntimeWithLocalizer(ctx, cli.EngineInitOptions{
		OpenSSHConfigFile: "none",
		Locale:            domi18n.LocaleZh,
	}, runtimeModeCLI, strings.NewReader(""), io.Discard, zhLoc)
	if err != nil {
		t.Fatalf("wireRuntimeWithLocalizer(CLI): %v", err)
	}
	defer func() {
		if cErr := rt.Close(ctx); cErr != nil {
			t.Errorf("rt.Close(CLI): %v", cErr)
		}
	}()

	prof, err := execution.NewLaunchProfile(execution.LaunchProfileSpec{
		Dialect:     algebraic.Some(execution.DialectPOSIX),
		Interpreter: execution.InterpreterSH,
		Login:       execution.LoginModeDisabled,
	})
	if err != nil {
		t.Fatalf("NewLaunchProfile: %v", err)
	}
	target, err := engine.NewDockerLogTarget("nginx")
	if err != nil {
		t.Fatalf("NewDockerLogTarget: %v", err)
	}

	logCtx, logCancel := context.WithCancel(ctx)
	defer logCancel()
	_, obsErr := rt.engine.StreamLogs(logCtx, engine.LogStreamRequest{
		RemoteCall: engine.RemoteCall{TargetSpec: "ndrop"},
		Profile:    algebraic.Some(prof),
		Target:     target,
		Output:     &cancelOnWriteWriter{cancel: logCancel},
	})
	if !errors.Is(obsErr, engine.ErrOutcomeUnknown) {
		t.Fatalf("期望运行期取消后返回 engine.ErrOutcomeUnknown，实际=%v", obsErr)
	}
	assertRealBilingualParity(t, crossLayerErrorCheck{
		name:     "gate.OutcomeError+engine.mapEngineError",
		err:      obsErr,
		wantEn:   []string{"engine: side-effect outcome is unknown", "gate: execution outcome=unknown", "context canceled"},
		wantZh:   []string{"副作用终态未知", "执行终态=unknown", "上下文已取消"},
		forbidZh: []string{"engine:", "gate:", "usecase/observability:", "execution outcome="},
	}, enLoc, zhLoc)
}

func TestRunProcess_InvalidConfigYAML_BilingualTextAndJSON(t *testing.T) {
	defer goleak.VerifyNone(t)
	_, xopsHome := setupIsolatedRootEnv(t)
	setProcessLocaleEnv(t, "en", "", "", "en_US.UTF-8")

	cfgPath := filepath.Join(filepath.FromSlash(xopsHome.String()), "config.yaml")
	cases := []struct {
		name     string
		content  string
		wantEn   []string
		wantZh   []string
		forbidZh []string
	}{
		{
			name:     "unknown-yaml-field",
			content:  "version: 2\nunknown_top_field: true\n",
			wantEn:   []string{"failed to load config.yaml", "failed to decode YAML vNext document"},
			wantZh:   []string{"加载 config.yaml 失败", "解析 YAML vNext 配置文档失败"},
			forbidZh: []string{"failed to load config.yaml", "failed to decode YAML", "ports:", "yamlcodec:"},
		},
		{
			name:     "unsupported-schema-version",
			content:  "version: 1\ninventory: {}\n",
			wantEn:   []string{"failed to load config.yaml", "unsupported schema version 1"},
			wantZh:   []string{"加载 config.yaml 失败", "不支持的 schema 版本 1"},
			forbidZh: []string{"failed to load config.yaml", "unsupported schema version", "ports:", "yamlcodec:"},
		},
		{
			name:     "missing-inventory-graph-ref",
			content:  "version: 2\ninventory:\n  nodes:\n    n1:\n      host: ghost-h\n      identity: ghost-i\n",
			wantEn:   []string{"failed to load config.yaml", "invalid node: n1"},
			wantZh:   []string{"加载 config.yaml 失败", "持久化数据损坏或完整性校验失败", "node 无效：n1"},
			forbidZh: []string{"failed to load config.yaml", "invalid node:", "inventory:", "ports:"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(cfgPath, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("WriteFile(%s): %v", tc.name, err)
			}
			assertInvalidConfigTextMode(t, tc.name, tc.wantEn, tc.wantZh, tc.forbidZh)
			assertInvalidConfigJSONMode(t, tc.name, tc.wantEn, tc.wantZh, tc.forbidZh)
		})
	}
	assertZeroRemainingLocks(t, xopsHome)
}

func assertInvalidConfigTextMode(t *testing.T, name string, wantEn, wantZh, forbidZh []string) {
	t.Helper()
	enCode, enOut, enErr := runCLIInProc("--lang", "en", "hosts", "list")
	zhCode, zhOut, zhErr := runCLIInProc("--lang", "zh", "hosts", "list")
	if enCode == 0 || zhCode == 0 || enCode != zhCode {
		t.Fatalf("%s text exit codes invalid: en=%d zh=%d", name, enCode, zhCode)
	}
	if enOut != "" || zhOut != "" {
		t.Fatalf("%s text mode expected empty stdout: en=%q zh=%q", name, enOut, zhOut)
	}
	assertEnglishCleanText(t, name+" text EN", enErr, wantEn)
	assertChineseCleanText(t, name+" text ZH", zhErr, wantZh, forbidZh)
}

func assertInvalidConfigJSONMode(t *testing.T, name string, wantEn, wantZh, forbidZh []string) {
	t.Helper()
	enCode, enOut, enErr := runCLIInProc("--lang", "en", "--json", "hosts", "list")
	zhCode, zhOut, zhErr := runCLIInProc("--lang", "zh", "--json", "hosts", "list")
	if enCode == 0 || zhCode == 0 || enCode != zhCode || enErr != "" || zhErr != "" {
		t.Fatalf("%s json mode failed: en=(%d,%q) zh=(%d,%q)", name, enCode, enErr, zhCode, zhErr)
	}
	enEnv := decodeTestErrorEnvelope(t, name+" EN", enOut)
	zhEnv := decodeTestErrorEnvelope(t, name+" ZH", zhOut)
	if enEnv.OK || zhEnv.OK || enEnv.ExitCode != enCode || zhEnv.ExitCode != zhCode {
		t.Fatalf("%s envelope status mismatch: en=%+v zh=%+v", name, enEnv, zhEnv)
	}
	if enEnv.ErrorCode == "" || enEnv.ErrorCode != zhEnv.ErrorCode || containsForbiddenCJKInCmd(enEnv.ErrorCode) {
		t.Fatalf("%s error_code must be invariant ASCII English: en=%q zh=%q", name, enEnv.ErrorCode, zhEnv.ErrorCode)
	}
	assertEnglishCleanText(t, name+" json EN", enEnv.Error, wantEn)
	assertChineseCleanText(t, name+" json ZH", zhEnv.Error, wantZh, forbidZh)
}

type testErrorEnvelope struct {
	OK        bool   `json:"ok"`
	ExitCode  int    `json:"exit_code"`
	ErrorCode string `json:"error_code"`
	Error     string `json:"error"`
}

func decodeTestErrorEnvelope(t *testing.T, label, raw string) testErrorEnvelope {
	t.Helper()
	var env testErrorEnvelope
	if err := jsonv2.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("%s JSON unmarshal failed: err=%v raw=%q", label, err, raw)
	}
	return env
}

func assertRealBilingualParity(t *testing.T, tc crossLayerErrorCheck, enLoc, zhLoc *i18n.Localizer) {
	t.Helper()
	if tc.err == nil {
		t.Fatalf("%s: expected non-nil error", tc.name)
	}
	enText := enLoc.RenderError(tc.err)
	if enText != tc.err.Error() {
		t.Fatalf("%s: enLoc.RenderError != err.Error():\nRenderError: %q\nerr.Error(): %q", tc.name, enText, tc.err.Error())
	}
	assertEnglishCleanText(t, tc.name+" EN", enText, tc.wantEn)
	assertChineseCleanText(t, tc.name+" ZH", zhLoc.RenderError(tc.err), tc.wantZh, tc.forbidZh)
}

func assertEnglishCleanText(t *testing.T, label, got string, wants []string) {
	t.Helper()
	if containsForbiddenCJKInCmd(got) {
		t.Fatalf("%s must contain zero CJK/full-width runes: %q", label, got)
	}
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("%s missing %q: got=%q", label, want, got)
		}
	}
}

func assertChineseCleanText(t *testing.T, label, got string, wants, forbids []string) {
	t.Helper()
	if !containsHanInCmd(got) {
		t.Fatalf("%s must contain Simplified Chinese characters: %q", label, got)
	}
	if hasRawPlaceholderInCmd(got) {
		t.Fatalf("%s must not leak raw {key} placeholders: %q", label, got)
	}
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("%s missing %q: got=%q", label, want, got)
		}
	}
	for _, forbid := range forbids {
		if strings.Contains(got, forbid) {
			t.Fatalf("%s leaked untranslated English template %q: got=%q", label, forbid, got)
		}
	}
}

func containsForbiddenCJKInCmd(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		return unicode.Is(unicode.Han, r) || (r >= 0x3000 && r <= 0x303F) || (r >= 0xFF00 && r <= 0xFFEF)
	})
}

func containsHanInCmd(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.Is(unicode.Han, r) })
}

func hasRawPlaceholderInCmd(s string) bool {
	for i := range len(s) {
		if s[i] != '{' {
			continue
		}
		if end := strings.IndexByte(s[i+1:], '}'); end > 0 && isPlaceholderIdentInCmd(s[i+1:i+1+end]) {
			return true
		}
	}
	return false
}

func isPlaceholderIdentInCmd(k string) bool {
	for i := range len(k) {
		c := k[i]
		isValid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
		if !isValid {
			return false
		}
	}
	return len(k) > 0
}
