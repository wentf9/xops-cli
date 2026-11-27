package openssh_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/openssh"
	"github.com/wentf9/xops-cli/internal/i18n"
	"go.uber.org/goleak"
)

// 编译期接口契约断言（ADR-004）。
var _ ports.OpenSSHConfigSource = (*openssh.ConfigSource)(nil)

func mustSourcePath(t *testing.T, raw string) pathalg.LocalSourcePath {
	t.Helper()
	p, err := pathalg.ParseLocalSourcePath(raw)
	if err != nil {
		t.Fatalf("ParseLocalSourcePath(%q) 失败: %v", raw, err)
	}
	return p
}

func mustOrigHost(t *testing.T, raw string) option.OriginalHostSpec {
	t.Helper()
	h, err := option.ParseOriginalHost(raw)
	if err != nil {
		t.Fatalf("ParseOriginalHost(%q) 失败: %v", raw, err)
	}
	return h
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%q) 失败: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) 失败: %v", path, err)
	}
}

func newTestSource(t *testing.T, cfgPath string, policy pathalg.SymlinkPolicy, maxDepth int) *openssh.ConfigSource {
	t.Helper()
	idInfo, err := ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{
		LocalHost: "devbox.local",
		LocalUser: "tester",
		LocalUID:  "1000",
		HomeDir:   filepath.ToSlash(filepath.Dir(cfgPath)),
	})
	if err != nil {
		t.Fatalf("NewLocalIdentityInfo 失败: %v", err)
	}
	src, err := openssh.NewConfigSource(openssh.SourceSpec{
		ConfigPath:      mustSourcePath(t, cfgPath),
		LocalIdentity:   algebraic.Some(idInfo),
		Reader:          osfs.NewOperatorReadFS(),
		ScopedFS:        osfs.NewScopedRootFS(),
		SymlinkPolicy:   policy,
		MaxIncludeDepth: maxDepth,
	})
	if err != nil {
		t.Fatalf("NewConfigSource 失败: %v", err)
	}
	return src
}

// TestTCKOpenSSHConfigSource 验证真实 OpenSSHConfigSource 完整通过 core/ports/tck 契约套件。
func TestTCKOpenSSHConfigSource(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")
	writeTestFile(t, cfgPath, `
Include conf.d/*.conf

Host prod-app
  HostName 10.20.30.40
  Port 2222
  User deploy
  ProxyJump bastion
  SendEnv LANG LC_*

Host *
  SendEnv -LC_TIME
  ServerAliveInterval 30
`)
	writeTestFile(t, filepath.Join(dir, "conf.d", "01-bastion.conf"), `
Host bastion
  HostName 198.51.100.1
  User jump
`)

	tck.RunOpenSSHConfigSourceSuite(t, tck.OpenSSHConfigFixture{
		NewSource: func(t *testing.T) ports.OpenSSHConfigSource {
			return newTestSource(t, cfgPath, pathalg.SymlinkReject, 0)
		},
		TargetHost: mustOrigHost(t, "prod-app"),
		Endpoint:   tck.MustEndpoint(t, "10.20.30.40", 2222),
	})
}

// TestZeroValueAndInvalidSpecsFailClosed 验证零值 ConfigSource 与非法构造规格均严格失败关闭。
func TestZeroValueAndInvalidSpecsFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	var zero openssh.ConfigSource
	if _, err := zero.ListVirtualHosts(context.Background()); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 ListVirtualHosts = %v, 期望 ErrInvalidArgument", err)
	}
	if _, err := zero.ResolveTier4(context.Background(), mustOrigHost(t, "app"), algebraic.None[netaddr.Endpoint]()); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 ResolveTier4 = %v, 期望 ErrInvalidArgument", err)
	}

	dir := t.TempDir()
	cfgPath := mustSourcePath(t, filepath.Join(dir, "config"))
	for _, spec := range []openssh.SourceSpec{
		{Reader: osfs.NewOperatorReadFS()},
		{ConfigPath: cfgPath},
		{ConfigPath: cfgPath, Reader: osfs.NewOperatorReadFS(), MaxFileBytes: -1},
		{ConfigPath: cfgPath, Reader: osfs.NewOperatorReadFS(), MaxIncludeDepth: -1},
		{ConfigPath: cfgPath, Reader: osfs.NewOperatorReadFS(), MaxIncludedFiles: -1},
	} {
		if _, err := openssh.NewConfigSource(spec); !errors.Is(err, ports.ErrInvalidArgument) {
			t.Fatalf("NewConfigSource(%+v) = %v, 期望 ErrInvalidArgument", spec, err)
		}
	}
}

// TestMissingConfigReturnsEmptyWithoutError 验证缺失主配置文件时安全返回空虚拟节点列表与 Unset OptionLayer。
func TestMissingConfigReturnsEmptyWithoutError(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	src := newTestSource(t, filepath.Join(dir, "nonexistent"), pathalg.SymlinkReject, 0)
	hosts, err := src.ListVirtualHosts(context.Background())
	if err != nil || len(hosts) != 0 {
		t.Fatalf("ListVirtualHosts(missing) = (%v, %v), 期望空且 nil", hosts, err)
	}
	layer, err := src.ResolveTier4(context.Background(), mustOrigHost(t, "any-host"), algebraic.None[netaddr.Endpoint]())
	if err != nil || !layer.IsUnset() {
		t.Fatalf("ResolveTier4(missing) = (unset=%v, %v), 期望 Unset 且 nil", layer.IsUnset(), err)
	}
}

// TestIncludeCycleAndDepthGuards 验证递归 Include 循环检测与最大深度熔断保护。
func TestIncludeCycleAndDepthGuards(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("CycleDetected", func(t *testing.T) {
		dir := t.TempDir()
		aPath, bPath := filepath.Join(dir, "a.conf"), filepath.Join(dir, "b.conf")
		writeTestFile(t, aPath, "Include b.conf\nHost a\n  User ua\n")
		writeTestFile(t, bPath, "Include a.conf\nHost b\n  User ub\n")
		src := newTestSource(t, aPath, pathalg.SymlinkReject, 0)
		if _, err := src.ListVirtualHosts(context.Background()); !errors.Is(err, openssh.ErrIncludeCycle) {
			t.Fatalf("循环 Include = %v, 期望 ErrIncludeCycle", err)
		}
	})

	t.Run("MaxDepthExceeded", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "c0.conf"), "Include c1.conf\n")
		writeTestFile(t, filepath.Join(dir, "c1.conf"), "Include c2.conf\n")
		writeTestFile(t, filepath.Join(dir, "c2.conf"), "Host deep\n  User u\n")
		src := newTestSource(t, filepath.Join(dir, "c0.conf"), pathalg.SymlinkReject, 1)
		if _, err := src.ResolveTier4(context.Background(), mustOrigHost(t, "deep"), algebraic.None[netaddr.Endpoint]()); !errors.Is(err, openssh.ErrIncludeDepthExceeded) {
			t.Fatalf("超深 Include = %v, 期望 ErrIncludeDepthExceeded", err)
		}
	})
}

// TestSingleLayerTopDownFoldAndMatchFailClosed 验证单层 t4 自上而下折叠、条件 Include、Match host/user 与 !exec 失败关闭。
func TestSingleLayerTopDownFoldAndMatchFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")
	writeTestFile(t, cfgPath, `
Host web-* !web-canary
  HostName %h.internal.example
  User webops
  SendEnv LANG LC_ALL LC_TIME CUSTOM_A
  IdentityFile ~/.ssh/id_first

Match host *.internal.example user webops
  SendEnv -LC_TIME CUSTOM_B
  IdentityFile ~/.ssh/id_second
  IdentityFile none

Match !exec "echo pwn"
  User pwned
  Port 9999

Host *
  SendEnv -CUSTOM_A EXTRA_OK
  IdentityFile ~/.ssh/id_ignored_after_none
  Port 2200
`)
	src := newTestSource(t, cfgPath, pathalg.SymlinkReject, 0)
	layer, err := src.ResolveTier4(context.Background(), mustOrigHost(t, "web-01"), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(web-01) 失败: %v", err)
	}
	if u, ok := layer.User().Get(); !ok || u.String() != "webops" {
		t.Fatalf("User = (%v, %v), 期望 webops", u, ok)
	}
	if p, ok := layer.Port().Get(); !ok || p != 2200 {
		t.Fatalf("Port = (%d, %v), 期望 2200（!exec 必须失败关闭不生效）", p, ok)
	}
	wantEnv := []string{"LANG", "LC_ALL", "CUSTOM_B", "EXTRA_OK"}
	if gotEnv := layer.SendEnv().Patterns(); !slices.Equal(gotEnv, wantEnv) {
		t.Fatalf("SendEnv patterns = %v, 期望 %v", gotEnv, wantEnv)
	}
	if layer.SendEnv().Match("LC_TIME") || layer.SendEnv().Match("CUSTOM_A") || !layer.SendEnv().Match("LC_ALL") || !layer.SendEnv().Match("CUSTOM_B") {
		t.Fatalf("SendEnv 减法语义不符合遭遇序折叠: patterns=%v clear=%v", layer.SendEnv().Patterns(), layer.SendEnv().ClearPatterns())
	}
	wantIDs := []string{"~/.ssh/id_first", "~/.ssh/id_second"}
	if gotIDs := layer.IdentityFiles().RawItems(); !slices.Equal(gotIDs, wantIDs) || !layer.IdentityFiles().Terminated() {
		t.Fatalf("IdentityFiles = (%v, terminated=%v), 期望 (%v, true)", gotIDs, layer.IdentityFiles().Terminated(), wantIDs)
	}

	// web-canary 被否定模式 !web-canary 排除，仅命中 Host *。
	canary, err := src.ResolveTier4(context.Background(), mustOrigHost(t, "web-canary"), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(web-canary) 失败: %v", err)
	}
	if canary.User().IsSome() {
		t.Fatalf("web-canary 不应命中被否定排除的 web-* 块: user=%v", canary.User())
	}
}

// TestMatchSyntaxValidationAndCanonicalFinalSemantics 验证：
//   - 畸形 Match 语法（all 尾随/前置条件、!all、all=1、裸 canonical/final、缺参）一律返回 ErrInvalidConfig；
//   - Match canonical 恒失败关闭；
//   - Match final 置于 Host 之前时严格执行两轮折叠，不抢占 Pass 1 Host 的 FirstWins；
//   - Match host / originalhost 大小写不敏感匹配。
func TestMatchSyntaxValidationAndCanonicalFinalSemantics(t *testing.T) {
	defer goleak.VerifyNone(t)
	badConfigs := []string{
		"Match all user nobody\n  Port 2222\n",
		"Match all exec \"echo pwn\"\n  Port 2222\n",
		"Match user ops all\n  Port 2222\n",
		"Match !all\n  Port 2222\n",
		"Match all=1\n  Port 2222\n",
		"Match canonical\n  Port 2222\n",
		"Match final\n  Port 2222\n",
		"Match !canonical all\n  Port 2222\n",
		"Match final=1 all\n  Port 2222\n",
		"Match host foo final\n  Port 2222\n",
		"Match host\n  Port 2222\n",
		"Match user=\n  Port 2222\n",
	}
	for _, cfg := range badConfigs {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "bad.conf")
		writeTestFile(t, cfgPath, cfg)
		src := newTestSource(t, cfgPath, pathalg.SymlinkReject, 0)
		if _, err := src.ResolveTier4(context.Background(), mustOrigHost(t, "prod-01"), algebraic.None[netaddr.Endpoint]()); !errors.Is(err, openssh.ErrInvalidConfig) {
			t.Fatalf("畸形 Match %q 返回 %v, 期望 ErrInvalidConfig", cfg, err)
		}
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "two_pass.conf")
	writeTestFile(t, cfgPath, `
Match canonical all
  User canon-forbidden
  Port 2288

Match final all
  User final-fallback
  Port 2299
  IdentityFile ~/.ssh/id_final

Host prod-01
  HostName app.prod.example
  User host-winner
  IdentityFile ~/.ssh/id_host
  IdentityFile none

Match host APP.PROD.* originalhost PROD-01
  ForwardAgent yes
`)
	src := newTestSource(t, cfgPath, pathalg.SymlinkReject, 0)
	layer, err := src.ResolveTier4(context.Background(), mustOrigHost(t, "prod-01"), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(prod-01) 失败: %v", err)
	}
	if u, ok := layer.User().Get(); !ok || u.String() != "host-winner" {
		t.Fatalf("User = (%v, %v), 期望 host-winner（canonical 失败关闭且 final 不得抢占 Host）", u, ok)
	}
	if p, ok := layer.Port().Get(); !ok || p != 2299 {
		t.Fatalf("Port = (%d, %v), 期望 2299（Pass 2 Match final 填补未设 Port）", p, ok)
	}
	if fa, ok := layer.ForwardAgent().Get(); !ok || !fa {
		t.Fatalf("ForwardAgent = (%v, %v), 期望 true（Match host/originalhost 须大小写不敏感）", fa, ok)
	}
	if gotIDs := layer.IdentityFiles().RawItems(); !slices.Equal(gotIDs, []string{"~/.ssh/id_host"}) {
		t.Fatalf("IdentityFiles = %v, 期望 [~/.ssh/id_host]（Pass 1 none 须阻断 Pass 2 final 追加）", gotIDs)
	}
}

// TestInlineHashCommentsAndWildcardNilScopedFS 验证空白边界行内 # 注释剥离、WholeLineCommand/词元内 # 保留，
// 以及 ScopedFS 为 nil 时遇到通配符 Include 严格失败关闭。
func TestInlineHashCommentsAndWildcardNilScopedFS(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "inline.conf")
	writeTestFile(t, filepath.Join(dir, "sub.conf"), "Host sub-node # comment !sub-node\n  Port 2211 # sub port\n")
	writeTestFile(t, cfgPath, `
Include sub.conf # include comment
Host web-01 # phantom-host !web-01
  Port 2233 # sshd port
  User alice#bob
  ProxyCommand ssh -W %h:%p gw # keep-in-cmd
`)
	src := newTestSource(t, cfgPath, pathalg.SymlinkReject, 0)
	hosts, err := src.ListVirtualHosts(context.Background())
	if err != nil {
		t.Fatalf("ListVirtualHosts 失败: %v", err)
	}
	var names []string
	for _, h := range hosts {
		names = append(names, h.Alias())
	}
	if !slices.Equal(names, []string{"sub-node", "web-01"}) {
		t.Fatalf("行内注释后虚拟主机列表 = %v, 期望 [sub-node web-01]", names)
	}
	layer, err := src.ResolveTier4(context.Background(), mustOrigHost(t, "web-01"), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(web-01) 失败: %v", err)
	}
	if p, ok := layer.Port().Get(); !ok || p != 2233 {
		t.Fatalf("Port = (%d, %v), 期望 2233", p, ok)
	}
	if u, ok := layer.User().Get(); !ok || u.String() != "alice#bob" {
		t.Fatalf("User = (%v, %v), 期望 alice#bob", u, ok)
	}
	pc, ok := layer.Proxy().(*option.ProxyCommandSpec)
	if !ok || pc.Command().String() != "ssh -W %h:%p gw # keep-in-cmd" {
		t.Fatalf("ProxyCommand = (%T, %v), 期望保留整行 #", layer.Proxy(), layer.Proxy())
	}

	// 验证 ScopedFS == nil 时遇到通配符 Include 严格失败关闭（返回 ports.ErrInvalidArgument）。
	globCfg := filepath.Join(dir, "glob_no_scoped.conf")
	writeTestFile(t, globCfg, "Include conf.d/*.conf\nHost a\n  Port 22\n")
	noScopedSrc, err := openssh.NewConfigSource(openssh.SourceSpec{
		ConfigPath:    mustSourcePath(t, globCfg),
		Reader:        osfs.NewOperatorReadFS(),
		SymlinkPolicy: pathalg.SymlinkReject,
	})
	if err != nil {
		t.Fatalf("NewConfigSource(nil ScopedFS) 失败: %v", err)
	}
	if _, err := noScopedSrc.ResolveTier4(context.Background(), mustOrigHost(t, "a"), algebraic.None[netaddr.Endpoint]()); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("ScopedFS==nil 通配符 Include 返回 %v, 期望 ErrInvalidArgument", err)
	}
}

// TestBilingualErrorsAndStreamDiagnostics 验证 OpenSSH 升级后的自包含错误键、无空格组件标识
// 以及 StreamDiagnostic 3 类诊断的双轨本地化（规范英文零漂移 + 中文完整本地化）。
func TestBilingualErrorsAndStreamDiagnostics(t *testing.T) {
	defer goleak.VerifyNone(t)
	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	enLoc := cat.For(domi18n.LocaleEn)
	zhLoc := cat.For(domi18n.LocaleZh)
	assertOpenSSHBilingualErrors(t, enLoc, zhLoc)
	assertOpenSSHStreamDiagBilingual(t, enLoc, zhLoc)
}

func assertOpenSSHBilingualErrors(t *testing.T, enLoc, zhLoc *i18n.Localizer) {
	t.Helper()
	var zero openssh.ConfigSource
	_, zErr := zero.ListVirtualHosts(context.Background())
	assertBilingualErrorMatch(t, enLoc, zhLoc, zErr, ports.ErrInvalidArgument, "OpenSSHConfigSource is not initialized", "OpenSSHConfigSource 尚未初始化")

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "d0.conf"), "Include d1.conf\n")
	writeTestFile(t, filepath.Join(dir, "d1.conf"), "Include d2.conf\n")
	writeTestFile(t, filepath.Join(dir, "d2.conf"), "Host deep\n  User u\n")
	_, depthErr := newTestSource(t, filepath.Join(dir, "d0.conf"), pathalg.SymlinkReject, 1).ResolveTier4(
		context.Background(), mustOrigHost(t, "deep"), algebraic.None[netaddr.Endpoint](),
	)
	assertBilingualErrorMatch(t, enLoc, zhLoc, depthErr, openssh.ErrIncludeDepthExceeded, "Include nesting depth exceeded", "Include 嵌套深度超出上限")

	_, lineErr := openssh.ParseConfigStream("bad.conf", []byte("BrokenKeywordWithoutValue\n"), algebraic.None[ports.LocalIdentityInfo]())
	assertBilingualErrorMatch(t, enLoc, zhLoc, lineErr, openssh.ErrInvalidConfig, "openssh: invalid configuration at bad.conf:1", "OpenSSH 配置文件 bad.conf 第 1 行配置无效")
}

func assertBilingualErrorMatch(t *testing.T, enLoc, zhLoc *i18n.Localizer, err, sentinel error, wantEn, wantZh string) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("错误链缺失哨兵 %v，实际=%v", sentinel, err)
	}
	if enText := enLoc.RenderError(err); enText != err.Error() || !strings.Contains(enText, wantEn) {
		t.Fatalf("EN 渲染异常: en=%q raw=%q wantSubstr=%q", enText, err.Error(), wantEn)
	}
	if zhText := zhLoc.RenderError(err); !strings.Contains(zhText, wantZh) || strings.ContainsAny(zhText, "{}") {
		t.Fatalf("ZH 渲染异常: zh=%q wantSubstr=%q", zhText, wantZh)
	}
}

func assertOpenSSHStreamDiagBilingual(t *testing.T, enLoc, zhLoc *i18n.Localizer) {
	t.Helper()
	res, err := openssh.ParseConfigStream("stream.conf", []byte(
		"Include conf.d/*.conf extra.conf\n"+
			"Match canonical all\n  Port 2201\n"+
			"Match exec \"echo noop\"\n  Port 2202\n"+
			"Host web\n  HostName 192.0.2.1\n",
	), algebraic.None[ports.LocalIdentityInfo]())
	if err != nil {
		t.Fatalf("ParseConfigStream 失败: %v", err)
	}
	wantDiags := map[string][2]string{
		"include_skipped": {
			`line 1: Include "conf.d/*.conf extra.conf" skipped in stream-only import (local files are not expanded)`,
			`第 1 行：纯流式导入已跳过 Include "conf.d/*.conf extra.conf"（不展开本地文件）`,
		},
		"match_canonical_ignored": {
			"line 2: Match canonical block ignored (fail-closed by security policy)",
			"第 2 行：已忽略 Match canonical 代码块（按安全策略失败关闭）",
		},
		"match_exec_ignored": {
			"line 4: Match exec block ignored (fail-closed; external commands are never executed)",
			"第 4 行：已忽略 Match exec 代码块（失败关闭；绝不执行外部命令）",
		},
	}
	if len(res.Diagnostics) != len(wantDiags) {
		t.Fatalf("诊断条数 = %d, 期望 %d: %+v", len(res.Diagnostics), len(wantDiags), res.Diagnostics)
	}
	for _, d := range res.Diagnostics {
		want, ok := wantDiags[d.Code]
		if !ok {
			t.Fatalf("非预期诊断码: %+v", d)
		}
		assertStreamDiagnosticMatch(t, enLoc, zhLoc, d, want[0], want[1])
	}
}

func assertStreamDiagnosticMatch(t *testing.T, enLoc, zhLoc *i18n.Localizer, d openssh.StreamDiagnostic, wantEn, wantZh string) {
	t.Helper()
	if d.Message != wantEn {
		t.Fatalf("诊断 %s 规范英文漂移: got=%q want=%q", d.Code, d.Message, wantEn)
	}
	msg, hasLoc := d.Localized.Get()
	if !hasLoc || !msg.IsValid() || msg.Canonical() != d.Message || enLoc.Render(msg) != d.Message {
		t.Fatalf("诊断 %s Localized 失配: has=%v en=%q msg=%q", d.Code, hasLoc, enLoc.Render(msg), d.Message)
	}
	if gotZh := zhLoc.Render(msg); gotZh != wantZh {
		t.Fatalf("诊断 %s 中文渲染失配: got=%q want=%q", d.Code, gotZh, wantZh)
	}
}
