package openssh_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/openssh"
	"go.uber.org/goleak"
)

// TestSSHG_DifferentialPass2AndBracketGlobOracle 验证 #34 Major #4 与 #35 Major #3/#4 的真实 ssh -G 差分对齐：
//   - (a) Match final -> Include sub.conf 内的 Host * / Match host / 嵌套 Include 在 Pass 2 完整生效；
//   - (b) Pass 2 激活重命名后的顶层 Host <rewritten> 与 Match host <rewritten>（保持 SendEnv 幂等对齐）；
//   - (c) Include POSIX [...] / [!...] 字符类通配符精确匹配且与 ssh -G 一致；
//   - (d) 未命中 Host/Match 块内的非法注册指令在解析期即失败关闭（与 ssh -G 非零退出码一致）。
func TestSSHG_DifferentialPass2AndBracketGlobOracle(t *testing.T) {
	defer goleak.VerifyNone(t)
	sshBin := requireRealOpenSSHClient(t)

	t.Run("MatchFinalIncludeNestedHostAndMatch", func(t *testing.T) {
		verifyDiffMatchFinalNestedInclude(t, sshBin)
	})
	t.Run("Pass2RewrittenHostAndSendEnvIdempotency", func(t *testing.T) {
		verifyDiffPass2RewrittenHost(t, sshBin)
	})
	t.Run("IncludePOSIXBracketGlobAndDotDotSegment", func(t *testing.T) {
		verifyDiffIncludeBracketGlob(t, sshBin)
	})
	t.Run("UnmatchedInvalidDirectiveFailsAtParseTime", func(t *testing.T) {
		verifyDiffUnmatchedInvalidDirective(t, sshBin)
	})
}

func verifyDiffMatchFinalNestedInclude(t *testing.T, sshBin string) {
	t.Helper()
	dir := newPrivateSSHTestDir(t)
	sub2 := filepath.Join(dir, "sub_nested.conf")
	sub1 := filepath.Join(dir, "sub_in_final.conf")
	cfg := filepath.Join(dir, "config")
	writeTestFile(t, sub2, "ServerAliveCountMax 12\n")
	writeTestFile(t, sub1, "Host *\n  Port 2281\nMatch host app.svc.example\n  ServerAliveInterval 77\nInclude \""+filepath.ToSlash(sub2)+"\"\n")
	writeTestFile(t, cfg, "Match final all\n  Include \""+filepath.ToSlash(sub1)+"\"\n\nHost app\n  HostName app.svc.example\n  User ops\n")

	dump := runSSHGDump(t, sshBin, cfg, "app")
	layer, err := newDiffSource(t, cfg).ResolveTier4(context.Background(), mustOrigHost(t, "app"), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(app) 失败: %v", err)
	}
	eff, err := option.ResolveEffectivePolicyWithOriginalHost(
		option.OriginOpenSSHVirtual, mustOrigHost(t, "app"), netaddr.DefaultSSHPort,
		option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), layer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if strconv.Itoa(int(eff.Endpoint().Port())) != dump.single["port"] || eff.Endpoint().Port() != 2281 {
		t.Fatalf("Match final -> Include(Host *) port 失配: got=%d ssh-G=%q", eff.Endpoint().Port(), dump.single["port"])
	}
	if strconv.FormatInt(int64(eff.ServerAliveInterval().Std().Seconds()), 10) != dump.single["serveraliveinterval"] || eff.ServerAliveInterval().Std().Seconds() != 77 {
		t.Fatalf("Match final -> Include(Match host) interval 失配: got=%v ssh-G=%q", eff.ServerAliveInterval(), dump.single["serveraliveinterval"])
	}
	if strconv.FormatUint(uint64(eff.ServerAliveCountMax()), 10) != dump.single["serveralivecountmax"] || eff.ServerAliveCountMax() != 12 {
		t.Fatalf("Match final -> Include(nested Include) countmax 失配: got=%d ssh-G=%q", eff.ServerAliveCountMax(), dump.single["serveralivecountmax"])
	}
}

func verifyDiffPass2RewrittenHost(t *testing.T, sshBin string) {
	t.Helper()
	dir := newPrivateSSHTestDir(t)
	cfg := filepath.Join(dir, "config")
	writeTestFile(t, cfg, `
Host bar
  Port 2299
  SendEnv BAR_VAR

Match host bar
  ServerAliveInterval 66

Host foo
  HostName bar
  SendEnv FOO_VAR

Host *
  SendEnv GLOBAL_VAR

Match final all
  User fin
  SendEnv FINAL_VAR
`)
	dump := runSSHGDump(t, sshBin, cfg, "foo")
	layer, err := newDiffSource(t, cfg).ResolveTier4(context.Background(), mustOrigHost(t, "foo"), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(foo) 失败: %v", err)
	}
	eff, err := option.ResolveEffectivePolicyWithOriginalHost(
		option.OriginOpenSSHVirtual, mustOrigHost(t, "foo"), netaddr.DefaultSSHPort,
		option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), layer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if strconv.Itoa(int(eff.Endpoint().Port())) != dump.single["port"] || eff.Endpoint().Port() != 2299 {
		t.Fatalf("Pass 2 重写后 Host bar 端口失配: got=%d ssh-G=%q", eff.Endpoint().Port(), dump.single["port"])
	}
	if strconv.FormatInt(int64(eff.ServerAliveInterval().Std().Seconds()), 10) != dump.single["serveraliveinterval"] || eff.ServerAliveInterval().Std().Seconds() != 66 {
		t.Fatalf("Pass 2 重写后 Match host bar interval 失配: got=%v ssh-G=%q", eff.ServerAliveInterval(), dump.single["serveraliveinterval"])
	}
	if u, _ := eff.User().Get(); u.String() != dump.single["user"] || u.String() != "fin" {
		t.Fatalf("Pass 2 Match final user 失配: got=%q ssh-G=%q", u.String(), dump.single["user"])
	}
	wantEnv := applySendEnvDiff(dump.multi["sendenv"])
	if gotEnv := layer.SendEnv().Patterns(); !slices.Equal(gotEnv, wantEnv) {
		t.Fatalf("Pass 2 SendEnv 失配: got=%v want=%v (raw=%v)", gotEnv, wantEnv, dump.multi["sendenv"])
	}
}

func verifyDiffIncludeBracketGlob(t *testing.T, sshBin string) {
	t.Helper()
	dir := newPrivateSSHTestDir(t)
	dotDir := filepath.Join(dir, "conf..d")
	writeTestFile(t, filepath.Join(dotDir, "01-hardening.conf"), "Host sec-box\n  HostName 192.0.2.61\n  Port 2241\n")
	writeTestFile(t, filepath.Join(dotDir, "ab-ignored.conf"), "Host sec-box\n  Port 2299\n")
	writeTestFile(t, filepath.Join(dotDir, "b-extra.conf"), "Host sec-box\n  User secops\n")
	cfg := filepath.Join(dir, "config")
	writeTestFile(t, cfg, "Include \""+filepath.ToSlash(filepath.Join(dotDir, "[0-9][0-9]-*.conf"))+"\"\n"+
		"Include \""+filepath.ToSlash(filepath.Join(dotDir, "[!a]-extra.conf"))+"\"\n")

	dump := runSSHGDump(t, sshBin, cfg, "sec-box")
	layer, err := newDiffSource(t, cfg).ResolveTier4(context.Background(), mustOrigHost(t, "sec-box"), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("Include POSIX [...] 展开失败: %v", err)
	}
	if p, ok := layer.Port().Get(); !ok || strconv.Itoa(int(p)) != dump.single["port"] || p != 2241 {
		t.Fatalf("Include [0-9][0-9]-*.conf port 失配: got=(%d,%v) ssh-G=%q", p, ok, dump.single["port"])
	}
	if u, ok := layer.User().Get(); !ok || u.String() != dump.single["user"] || u.String() != "secops" {
		t.Fatalf("Include [!a]-extra.conf user 失配: got=(%v,%v) ssh-G=%q", u, ok, dump.single["user"])
	}
}

func verifyDiffUnmatchedInvalidDirective(t *testing.T, sshBin string) {
	t.Helper()
	dir := newPrivateSSHTestDir(t)
	cfg := filepath.Join(dir, "bad_unmatched.conf")
	writeTestFile(t, cfg, "Host matched\n  HostName 192.0.2.1\nHost unmatched\n  Port not-a-port\n")
	if _, sshErr := runSSHCommandWithFiles(t, sshBin, "-F", cfg, "-G", "matched"); sshErr == nil {
		t.Fatal("预期真实 ssh -G 对未命中块中的非法 Port 返回非零错误")
	}
	if _, err := newDiffSource(t, cfg).ResolveTier4(context.Background(), mustOrigHost(t, "matched"), algebraic.None[netaddr.Endpoint]()); !errors.Is(err, openssh.ErrInvalidConfig) {
		t.Fatalf("未命中块中非法 Port 期望 ErrInvalidConfig，实际=%v", err)
	}
}

// TestReviewRegressionsParserGlobAliasAndStream 验证非 ssh -G 依赖的解析期与流式回归项：
//   - 未闭合 '['、倒置范围 '[z-a]' 与 '..' 路径段失败关闭；
//   - 重复 Match final / canonical 修饰词拒绝；
//   - Host * / Match all 下的 Include 正常发现具体别名；
//   - ParseConfigStream 拒绝仅含 Host * 的非法指令，且 Match user exec 不误报 match_exec_ignored。
func TestReviewRegressionsParserGlobAliasAndStream(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	// 1. 非法通配符与重复修饰词拒绝。
	for _, bad := range []string{
		"Include conf.d/[0-9.conf\n",
		"Include conf.d/[z-a].conf\n",
		"Include ../escape/*.conf\n",
		"Match final final all\n  Port 2222\n",
		"Match canonical canonical all\n  Port 2222\n",
	} {
		p := filepath.Join(dir, "bad_case.conf")
		writeTestFile(t, p, bad)
		src := newTestSource(t, p, pathalg.SymlinkReject, 0)
		if _, err := src.ResolveTier4(context.Background(), mustOrigHost(t, "app"), algebraic.None[netaddr.Endpoint]()); !errors.Is(err, openssh.ErrInvalidConfig) {
			t.Fatalf("非法配置 %q 返回 %v, 期望 ErrInvalidConfig", bad, err)
		}
	}
	// 2. Host * 与 Match all 下的 Include 发现具体别名。
	writeTestFile(t, filepath.Join(dir, "inc_star.conf"), "Host from-star\n  HostName 192.0.2.71\n")
	writeTestFile(t, filepath.Join(dir, "inc_all.conf"), "Host from-all\n  HostName 192.0.2.72\n")
	cfgAlias := filepath.Join(dir, "alias_inc.conf")
	writeTestFile(t, cfgAlias, "Host *\n  Include inc_star.conf\nMatch all\n  Include inc_all.conf\n")
	vhs, err := newTestSource(t, cfgAlias, pathalg.SymlinkReject, 0).ListVirtualHosts(context.Background())
	if err != nil {
		t.Fatalf("ListVirtualHosts 失败: %v", err)
	}
	var names []string
	for _, vh := range vhs {
		names = append(names, vh.Alias())
	}
	if !slices.Equal(names, []string{"from-star", "from-all"}) {
		t.Fatalf("Host */Match all 下 Include 别名发现 = %v, 期望 [from-star from-all]", names)
	}
	// 3. ParseConfigStream：无具体别名的非法指令须失败关闭；Match user exec 不误报 match_exec_ignored。
	if _, err := openssh.ParseConfigStream("bad.conf", []byte("Host *\n  Port not-a-port\n"), algebraic.None[ports.LocalIdentityInfo]()); !errors.Is(err, openssh.ErrInvalidConfig) {
		t.Fatalf("Host *-only 非法指令期望 ErrInvalidConfig，实际=%v", err)
	}
	res, err := openssh.ParseConfigStream("user_exec.conf", []byte("Match user exec\n  Port 2255\nHost app\n  HostName 192.0.2.1\n"), algebraic.None[ports.LocalIdentityInfo]())
	if err != nil {
		t.Fatalf("Match user exec 解析失败: %v", err)
	}
	for _, d := range res.Diagnostics {
		if d.Code == "match_exec_ignored" {
			t.Fatalf("Match user exec 不得误报 match_exec_ignored: %+v", res.Diagnostics)
		}
	}
}
