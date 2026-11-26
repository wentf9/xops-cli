package openssh_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/openssh"
	"go.uber.org/goleak"
)

// TestSSHG_DifferentialComprehensiveOracle 补齐实施计划 §4 #8 全量差分预言机覆盖矩阵：
//   - 规则 (a)：全 4 项算法（Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms）覆盖 exact / + / - 通配 / ^ 与 FirstWins 吸收；
//   - 规则 (b)：IdentityFile / CertificateFile 前置 none 禁用、中途 none 封口与去重截断对齐；
//   - 规则 (c)：多跳 ProxyJump 下 %C（%j 取末跳无方括号规范主机名）与 ControlPersist 0/yes/no/时长对齐；
//   - 规则 (d)：SendEnv 跨多块与条件 Include 的 add -> -PATTERN -> re-add 遭遇序对齐，及四层 INV-D3 高层优先校验；
//   - 覆盖其余全部已注册选项：HostName %h 模板、ProxyJump none 显露低层 ProxyCommand、ProxyCommand none 全禁用、
//     ConnectTimeout、UserKnownHostsFile 多路径与 FirstWins、PermitLocalCommand/LocalCommand、条件 Include + Match final。
func TestSSHG_DifferentialComprehensiveOracle(t *testing.T) {
	defer goleak.VerifyNone(t)
	sshBin := requireRealOpenSSHClient(t)

	t.Run("ConditionalIncludeWithMatchFinalAndSendEnvReadd", func(t *testing.T) {
		verifyDiffConditionalIncludeAndSendEnv(t, sshBin)
	})
	t.Run("ProxyMaskingAndMultiHopPercentC", func(t *testing.T) {
		verifyDiffProxyMaskingAndPercentC(t, sshBin)
	})
	t.Run("AllAlgoOperatorsAndKnownHostsAndLocalCommand", func(t *testing.T) {
		verifyDiffAlgosKnownHostsLocalCmd(t, sshBin)
	})
	t.Run("LeadingIdentityNoneAndFourLayerSendEnvPrecedence", func(t *testing.T) {
		verifyDiffLeadingNoneAndFourLayerSendEnv(t, sshBin)
	})
}

func verifyDiffConditionalIncludeAndSendEnv(t *testing.T, sshBin string) {
	t.Helper()
	dir := newPrivateSSHTestDir(t)
	condFinal := filepath.Join(dir, "cond_final.conf")
	condStale := filepath.Join(dir, "cond_stale.conf")
	finInc := filepath.Join(dir, "inside_final.conf")
	cfgPath := filepath.Join(dir, "config")

	writeTestFile(t, condFinal, `
Match final all
  Port 2266
  SendEnv FINAL_VAR
`)
	writeTestFile(t, condStale, `
Match final all
  Port 2255
`)
	writeTestFile(t, finInc, "ServerAliveCountMax 9\n")
	writeTestFile(t, cfgPath, `
Match final all
  Include "`+filepath.ToSlash(finInc)+`"

Host app-cond
  HostName %h.svc.example
  User svcops
  SendEnv LANG LC_* FOO_1 FOO_2
  SendEnv -LC_TIME -FOO_* BAR
  SendEnv LC_TIME
  Include "`+filepath.ToSlash(condStale)+`"

Host app-cond.svc.example
  Include "`+filepath.ToSlash(condFinal)+`"

Host other-host
  Include "`+filepath.ToSlash(condStale)+`"
`)
	cfgDump := runSSHGDump(t, sshBin, cfgPath, "app-cond")
	src := newDiffSource(t, cfgPath)
	target := mustOrigHost(t, "app-cond")
	layer, err := src.ResolveTier4(context.Background(), target, algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(app-cond) 失败: %v", err)
	}
	eff, err := option.ResolveEffectivePolicyWithOriginalHost(
		option.OriginOpenSSHVirtual, target, netaddr.DefaultSSHPort,
		option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), layer,
	)
	if err != nil {
		t.Fatalf("ResolveEffectivePolicyWithOriginalHost 失败: %v", err)
	}
	if eff.Endpoint().Host().String() != cfgDump.single["hostname"] {
		t.Fatalf("%%h HostName 展开失配: got=%q ssh-G=%q", eff.Endpoint().Host().String(), cfgDump.single["hostname"])
	}
	if strconv.Itoa(int(eff.Endpoint().Port())) != cfgDump.single["port"] || eff.Endpoint().Port() != 2266 {
		t.Fatalf("条件 Include 内 Match final 端口失配: got=%d ssh-G=%q", eff.Endpoint().Port(), cfgDump.single["port"])
	}
	if strconv.FormatUint(uint64(eff.ServerAliveCountMax()), 10) != cfgDump.single["serveralivecountmax"] || eff.ServerAliveCountMax() != 9 {
		t.Fatalf("Match final 内 Include 顶层指令失配: got=%d ssh-G=%q", eff.ServerAliveCountMax(), cfgDump.single["serveralivecountmax"])
	}
	wantEnv := applySendEnvDiff(cfgDump.multi["sendenv"])
	if gotEnv := layer.SendEnv().Patterns(); !slices.Equal(gotEnv, wantEnv) {
		t.Fatalf("SendEnv 重加与 Match final 折叠失配: got=%v want=%v (raw=%v)", gotEnv, wantEnv, cfgDump.multi["sendenv"])
	}
}

func verifyDiffProxyMaskingAndPercentC(t *testing.T, sshBin string) {
	t.Helper()
	dir := newPrivateSSHTestDir(t)
	cfgPath := filepath.Join(dir, "proxy.conf")
	ctrlTpl := filepath.ToSlash(filepath.Join(dir, "mux-%C"))

	writeTestFile(t, cfgPath, `
Host jump-revealed
  HostName 192.0.2.11
  User ops
  ProxyJump none

Host cmd-disabled
  HostName 192.0.2.12
  User ops
  ProxyCommand none

Host multi-hop
  HostName 192.0.2.13
  User deploy
  Port 2222
  ProxyJump u1@bastion1.example:2200,bastion2.example
  ControlMaster auto
  ControlPersist 0
  ControlPath `+ctrlTpl+`

Host *
  ProxyJump fallback-bastion.example
  ProxyCommand ssh -W %h:%p gateway.example
`)
	src := newDiffSource(t, cfgPath)
	// 1. ProxyJump=none 仅消低层 ProxyJump，显露低层 ProxyCommand。
	assertProxyRevealDiff(t, sshBin, cfgPath, src, "jump-revealed")
	// 2. ProxyCommand=none 全禁用，低层 ProxyJump 亦不得生效。
	assertProxyFullDisableDiff(t, sshBin, cfgPath, src, "cmd-disabled")
	// 3. 多跳 ProxyJump 下 %C（%j = bastion2.example）与 ControlPersist=0（永久驻留）对齐 ssh -G。
	assertMultiHopPercentCDiff(t, sshBin, cfgPath, src, "multi-hop")
}

func assertProxyRevealDiff(t *testing.T, sshBin, cfgPath string, src *openssh.ConfigSource, alias string) {
	t.Helper()
	dump := runSSHGDump(t, sshBin, cfgPath, alias)
	layer, err := src.ResolveTier4(context.Background(), mustOrigHost(t, alias), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(%s) 失败: %v", alias, err)
	}
	pc, ok := layer.Proxy().(*option.ProxyCommandSpec)
	// 当 ProxyJump=none 取消低层 ProxyJump 并显露低层 ProxyCommand 时，ssh -G 输出 proxycommand 且省略或输出 proxyjump=none。
	pj := dump.single["proxyjump"]
	if !ok || pc.Command().String() != dump.single["proxycommand"] || (pj != "" && !strings.EqualFold(pj, "none")) {
		t.Fatalf("ProxyJump=none 显露低层 ProxyCommand 失配: got=(%T,%v) ssh-G=(jump=%q,cmd=%q)", layer.Proxy(), layer.Proxy(), pj, dump.single["proxycommand"])
	}
}

func assertProxyFullDisableDiff(t *testing.T, sshBin, cfgPath string, src *openssh.ConfigSource, alias string) {
	t.Helper()
	dump := runSSHGDump(t, sshBin, cfgPath, alias)
	layer, err := src.ResolveTier4(context.Background(), mustOrigHost(t, alias), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(%s) 失败: %v", alias, err)
	}
	pd, ok := layer.Proxy().(*option.ProxyDisabled)
	// 当 ProxyCommand=none 全禁用时，ssh -G 对 proxycommand / proxyjump 均省略输出或输出 none。
	pj, pc := dump.single["proxyjump"], dump.single["proxycommand"]
	pjOff := pj == "" || strings.EqualFold(pj, "none")
	pcOff := pc == "" || strings.EqualFold(pc, "none")
	if !ok || !pd.IsFullDisable() || !pjOff || !pcOff {
		t.Fatalf("ProxyCommand=none 全禁用失配: got=(%T) ssh-G=(jump=%q,cmd=%q)", layer.Proxy(), pj, pc)
	}
}

func assertMultiHopPercentCDiff(t *testing.T, sshBin, cfgPath string, src *openssh.ConfigSource, alias string) {
	t.Helper()
	dump := runSSHGDump(t, sshBin, cfgPath, alias)
	target := mustOrigHost(t, alias)
	layer, err := src.ResolveTier4(context.Background(), target, algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(%s) 失败: %v", alias, err)
	}
	eff, err := option.ResolveEffectivePolicyWithOriginalHost(
		option.OriginOpenSSHVirtual, target, netaddr.DefaultSSHPort,
		option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), layer,
	)
	if err != nil {
		t.Fatalf("ResolveEffectivePolicyWithOriginalHost(%s) 失败: %v", alias, err)
	}
	localHost, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname 失败: %v", err)
	}
	hash, err := eff.PercentC(localHost, "deploy")
	if err != nil {
		t.Fatalf("PercentC 失败: %v", err)
	}
	wantSuffix := "mux-" + hash
	if !strings.HasSuffix(filepath.ToSlash(dump.single["controlpath"]), wantSuffix) {
		t.Fatalf("多跳 ProxyJump %%C 哈希失配: wantSuffix=%q ssh-G=%q", wantSuffix, dump.single["controlpath"])
	}
	if !layer.Control().EffectivePersist().IsIndefinite() || !strings.EqualFold(dump.single["controlpersist"], "yes") {
		t.Fatalf("ControlPersist=0 永久驻留失配: got=%v ssh-G=%q", layer.Control().EffectivePersist(), dump.single["controlpersist"])
	}
}

func verifyDiffAlgosKnownHostsLocalCmd(t *testing.T, sshBin string) {
	t.Helper()
	dir := newPrivateSSHTestDir(t)
	cfgPath := filepath.Join(dir, "algos.conf")
	kh1 := filepath.ToSlash(filepath.Join(dir, "kh_primary"))
	kh2 := filepath.ToSlash(filepath.Join(dir, "kh_secondary"))
	khIgnored := filepath.ToSlash(filepath.Join(dir, "kh_ignored"))

	writeTestFile(t, cfgPath, `
Host algo-box
  HostName 198.51.100.88
  User secops
  ConnectTimeout 17
  Ciphers aes256-gcm@openssh.com,aes128-ctr
  MACs ^hmac-sha2-512-etm@openssh.com
  KexAlgorithms -*nistp521*
  HostKeyAlgorithms +ssh-ed25519
  UserKnownHostsFile "`+kh1+`" "`+kh2+`"
  PermitLocalCommand yes
  LocalCommand echo connected-%h

Host *
  Ciphers -*ctr*
  MACs hmac-sha2-256
  UserKnownHostsFile "`+khIgnored+`"
  ConnectTimeout 99
`)
	baseDump := runSSHGDump(t, sshBin, emptyBaseConfigPath(t, dir), "algo-box")
	cfgDump := runSSHGDump(t, sshBin, cfgPath, "algo-box")
	src := newDiffSource(t, cfgPath)
	target := mustOrigHost(t, "algo-box")
	layer, err := src.ResolveTier4(context.Background(), target, algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(algo-box) 失败: %v", err)
	}
	eff, err := option.ResolveEffectivePolicyWithOriginalHost(
		option.OriginOpenSSHVirtual, target, netaddr.DefaultSSHPort,
		option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), layer,
	)
	if err != nil {
		t.Fatalf("ResolveEffectivePolicyWithOriginalHost 失败: %v", err)
	}
	verifyDiffAlgos(t, layer, baseDump, cfgDump)
	assertDiffExtraDirectives(t, eff, layer, cfgDump, []string{kh1, kh2})
}

func assertDiffExtraDirectives(t *testing.T, eff option.EffectivePolicy, layer option.OptionLayer, cfgDump sshGDump, wantKH []string) {
	t.Helper()
	ct, hasCT := eff.ConnectTimeout().Get()
	if !hasCT || strconv.FormatInt(int64(ct.Std().Seconds()), 10) != cfgDump.single["connecttimeout"] {
		t.Fatalf("connecttimeout 失配: got=(%v,%v) ssh-G=%q", ct, hasCT, cfgDump.single["connecttimeout"])
	}
	gotKH := layer.UserKnownHostsFiles().RawItems()
	sshGKH := strings.Fields(cfgDump.single["userknownhostsfile"])
	if !slices.Equal(gotKH, wantKH) || !slices.Equal(gotKH, sshGKH) {
		t.Fatalf("userknownhostsfile FirstWins 失配: got=%v want=%v ssh-G=%v", gotKH, wantKH, sshGKH)
	}
	lc, hasLC := eff.LocalCommand().Get()
	if !eff.PermitLocalCommand() || cfgDump.single["permitlocalcommand"] != "yes" || !hasLC || lc.String() != cfgDump.single["localcommand"] {
		t.Fatalf("PermitLocalCommand/LocalCommand 失配: permit=%v lc=(%q,%v) ssh-G=(%q,%q)",
			eff.PermitLocalCommand(), lc.String(), hasLC, cfgDump.single["permitlocalcommand"], cfgDump.single["localcommand"])
	}
}

func verifyDiffLeadingNoneAndFourLayerSendEnv(t *testing.T, sshBin string) {
	t.Helper()
	dir := newPrivateSSHTestDir(t)
	cfgPath := filepath.Join(dir, "none_env.conf")
	writeTestFile(t, cfgPath, `
Host strict-box
  HostName 192.0.2.99
  User ops
  IdentityFile none
  SendEnv LANG LC_ALL LC_TIME
  SendEnv -LC_ALL

Host *
  IdentityFile ~/.ssh/id_never_used
  SendEnv -CLI_ONLY
`)
	cfgDump := runSSHGDump(t, sshBin, cfgPath, "strict-box")
	src := newDiffSource(t, cfgPath)
	target := mustOrigHost(t, "strict-box")
	t4, err := src.ResolveTier4(context.Background(), target, algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(strict-box) 失败: %v", err)
	}
	// 规则 (b)：前置 IdentityFile none -> PathListDisabled，与 ssh -G 截断结果（空列表）一致。
	if !t4.IdentityFiles().IsDisabled() || len(truncateAtFirstNone(cfgDump.multi["identityfile"])) != 0 {
		t.Fatalf("前置 IdentityFile none 失配: disabled=%v ssh-G=%v", t4.IdentityFiles().IsDisabled(), cfgDump.multi["identityfile"])
	}
	// 规则 (d) 单层 SendEnv 对齐 ssh -G：-LC_ALL 清除具体模式 LC_ALL，保留 LANG 与 LC_TIME。
	if gotEnv, wantEnv := t4.SendEnv().Patterns(), applySendEnvDiff(cfgDump.multi["sendenv"]); !slices.Equal(gotEnv, wantEnv) {
		t.Fatalf("SendEnv 单层对齐失配: got=%v want=%v (raw=%v)", gotEnv, wantEnv, cfgDump.multi["sendenv"])
	}
	// 规则 (d) 四层 INV-D3 校验：t1(CLI) 添加的 CLI_ONLY 不得被 t4(OpenSSH) 的 -CLI_ONLY 反向清除。
	t1, err := option.ParseOptionLayer("SendEnv CLI_ONLY")
	if err != nil {
		t.Fatalf("ParseOptionLayer(t1) 失败: %v", err)
	}
	eff, err := option.ResolveEffectivePolicyWithOriginalHost(
		option.OriginOpenSSHVirtual, target, netaddr.DefaultSSHPort,
		t1, option.UnsetOptionLayer(), option.UnsetOptionLayer(), t4,
	)
	if err != nil {
		t.Fatalf("ResolveEffectivePolicyWithOriginalHost 失败: %v", err)
	}
	if !eff.SendEnv().Match("CLI_ONLY") || eff.SendEnv().Match("LC_ALL") || !eff.SendEnv().Match("LANG") || !eff.SendEnv().Match("LC_TIME") {
		t.Fatalf("四层 SendEnv INV-D3 优先级异常: patterns=%v clear=%v", eff.SendEnv().Patterns(), eff.SendEnv().ClearPatterns())
	}
}

// TestMatchNegatedUnknownUserFailClosedAndParseStream 验证未知用户下 Match !user / !localuser 严格失败关闭，
// 以及纯内存 ParseConfigStream 复用同源解析器产出虚拟主机与结构化诊断告警。
func TestMatchNegatedUnknownUserFailClosedAndParseStream(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "neg_user.conf")
	writeTestFile(t, cfgPath, `
Match !user root
  Port 2291

Match !localuser root
  ForwardAgent yes

Host app
  HostName 192.0.2.5
`)
	// 故意不注入 LocalIdentity，确认 Match !user / !localuser 不会在未知用户时取反误放行。
	src, err := openssh.NewConfigSource(openssh.SourceSpec{
		ConfigPath:    mustSourcePath(t, cfgPath),
		Reader:        osfs.NewOperatorReadFS(),
		SymlinkPolicy: pathalg.SymlinkReject,
	})
	if err != nil {
		t.Fatalf("NewConfigSource 失败: %v", err)
	}
	layer, err := src.ResolveTier4(context.Background(), mustOrigHost(t, "app"), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4 失败: %v", err)
	}
	if layer.Port().IsSome() || layer.ForwardAgent().IsSome() {
		t.Fatalf("未知用户时 Match !user / !localuser 必须失败关闭: port=%v fa=%v", layer.Port(), layer.ForwardAgent())
	}

	// 验证纯内存流式解析器复用同源折叠并产出 Include/Match exec 诊断。
	res, err := openssh.ParseConfigStream("inline.conf", []byte(`
Include conf.d/*.conf
Match exec "echo nope"
  Port 9999
Host web-01
  HostName 192.0.2.10
  User deploy
  Port 2202
`), algebraic.None[ports.LocalIdentityInfo]())
	if err != nil {
		t.Fatalf("ParseConfigStream 失败: %v", err)
	}
	if len(res.Hosts) != 1 || res.Hosts[0].Alias() != "web-01" || len(res.Diagnostics) != 2 {
		t.Fatalf("ParseConfigStream 结果异常: hosts=%d diags=%+v", len(res.Hosts), res.Diagnostics)
	}
}
