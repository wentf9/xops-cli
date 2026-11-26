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
	// 1. 通用跨版本场景：ProxyJump=none 取消低层 ProxyJump（无低层 ProxyCommand），所有 OpenSSH 版本均归零直连。
	assertProxyJumpNoneDirectDiff(t, sshBin, dir)
	// 2. XOps RFC §3.6 双槽遮蔽语义（ProxyJump=none 仅消低层跳板并显露低层命令）+ 实测版本对齐的 ssh -G 差分：
	//    OpenSSH 10.x（readconf.c 将 proxy_command="none" 收敛至非 none 分支）显露低层 ProxyCommand；
	//    OpenSSH 9.x（含 FreeBSD / Win32-OpenSSH 9.x）在 oProxyJump 解析 "none" 时一并清空 proxy_command。
	revealsLowerCmd := probeProxyJumpNoneRevealsLowerCmd(t, sshBin, dir)
	assertProxyRevealDiff(t, sshBin, cfgPath, src, "jump-revealed", revealsLowerCmd)
	// 3. ProxyCommand=none 全禁用，低层 ProxyJump 亦不得生效（跨所有 OpenSSH 版本一致）。
	assertProxyFullDisableDiff(t, sshBin, cfgPath, src, "cmd-disabled")
	// 4. 多跳 ProxyJump 下 %C（%j = bastion2.example）与 ControlPersist=0（永久驻留）对齐 ssh -G。
	assertMultiHopPercentCDiff(t, sshBin, dir, cfgPath, src, "multi-hop")
}

func isSSHProxyFieldDisabled(val string) bool {
	return val == "" || strings.EqualFold(val, "none")
}

// probeProxyJumpNoneRevealsLowerCmd 对本机真实 ssh -G 执行最小 4 行探针，实证检测该 OpenSSH 版本
// 对 `ProxyJump none` 遇低层 `ProxyCommand` 的行为：
//   - OpenSSH 10.x 解耦语义：ProxyJump none 不覆盖 proxy_command，返回 true；
//   - OpenSSH 9.x 传统耦合语义：ProxyJump none 同时将 proxy_command 置为 none，返回 false；
//   - 若出现第三种意外输出则立即失败关闭。
func probeProxyJumpNoneRevealsLowerCmd(t *testing.T, sshBin, dir string) bool {
	t.Helper()
	probeCfg := filepath.Join(dir, "probe_pj_none.conf")
	const probeCmd = "ssh -W %h:%p probe.example"
	writeTestFile(t, probeCfg, "Host probe\n  ProxyJump none\n\nHost *\n  ProxyCommand "+probeCmd+"\n")
	dump := runSSHGDump(t, sshBin, probeCfg, "probe")
	pj, pc := dump.single["proxyjump"], dump.single["proxycommand"]
	if !isSSHProxyFieldDisabled(pj) {
		t.Fatalf("ssh -G 探针中 ProxyJump=none 未禁用 proxyjump: jump=%q cmd=%q", pj, pc)
	}
	if pc == probeCmd {
		return true
	}
	if isSSHProxyFieldDisabled(pc) {
		return false
	}
	t.Fatalf("ssh -G 探针返回意外 proxycommand=%q（期望 %q 或禁用态）", pc, probeCmd)
	return false
}

func assertProxyJumpNoneDirectDiff(t *testing.T, sshBin, dir string) {
	t.Helper()
	directCfg := filepath.Join(dir, "proxy_direct.conf")
	writeTestFile(t, directCfg, `
Host jump-direct
  HostName 192.0.2.10
  User ops
  ProxyJump none

Host *
  ProxyJump fallback-bastion.example
`)
	dump := runSSHGDump(t, sshBin, directCfg, "jump-direct")
	layer, err := newDiffSource(t, directCfg).ResolveTier4(context.Background(), mustOrigHost(t, "jump-direct"), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(jump-direct) 失败: %v", err)
	}
	pd, ok := layer.Proxy().(*option.ProxyDisabled)
	pj, pc := dump.single["proxyjump"], dump.single["proxycommand"]
	if !ok || !pd.IsJumpOnly() || !isSSHProxyFieldDisabled(pj) || !isSSHProxyFieldDisabled(pc) {
		t.Fatalf("ProxyJump=none 取消低层 ProxyJump 失配: got=(%T,jumpOnly=%v) ssh-G=(jump=%q,cmd=%q)", layer.Proxy(), ok && pd.IsJumpOnly(), pj, pc)
	}
}

func assertProxyRevealDiff(t *testing.T, sshBin, cfgPath string, src *openssh.ConfigSource, alias string, sshGRevealsCmd bool) {
	t.Helper()
	const wantCmd = "ssh -W %h:%p gateway.example"
	dump := runSSHGDump(t, sshBin, cfgPath, alias)
	layer, err := src.ResolveTier4(context.Background(), mustOrigHost(t, alias), algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(%s) 失败: %v", alias, err)
	}
	// 无条件校验 XOps RFC §3.6 锁定的双槽幺半群语义：ProxyJump=none 仅消低层跳板，必显露低层 ProxyCommand。
	pc, ok := layer.Proxy().(*option.ProxyCommandSpec)
	if !ok || pc.Command().String() != wantCmd {
		t.Fatalf("XOps RFC §3.6 ProxyJump=none 显露低层 ProxyCommand 违例: got=(%T,%v) want=%q", layer.Proxy(), layer.Proxy(), wantCmd)
	}
	// 与实测版本对应的 ssh -G 输出严格比对：两代版本均必须取消低层 ProxyJump，并按探针结果精确校验 proxycommand。
	pj, sshCmd := dump.single["proxyjump"], dump.single["proxycommand"]
	if !isSSHProxyFieldDisabled(pj) {
		t.Fatalf("ssh -G 未取消低层 ProxyJump: jump=%q cmd=%q", pj, sshCmd)
	}
	if sshGRevealsCmd && sshCmd != wantCmd {
		t.Fatalf("OpenSSH 解耦模式下 ProxyJump=none 应显露低层 ProxyCommand: got=%q want=%q", sshCmd, wantCmd)
	}
	if !sshGRevealsCmd && !isSSHProxyFieldDisabled(sshCmd) {
		t.Fatalf("OpenSSH 9.x 耦合模式下 ProxyJump=none 应同时禁用 ProxyCommand: got=%q", sshCmd)
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
	if !ok || !pd.IsFullDisable() || !isSSHProxyFieldDisabled(pj) || !isSSHProxyFieldDisabled(pc) {
		t.Fatalf("ProxyCommand=none 全禁用失配: got=(%T) ssh-G=(jump=%q,cmd=%q)", layer.Proxy(), pj, pc)
	}
}

// probePercentCIncludesJumpHost 对本机真实 ssh -G 执行最小双块探针，实证检测该 OpenSSH 版本
// 的 %C 是否已合入 %j（OpenSSH 9.6 / bz#3610 引入 %j 并合入 %C = SHA1(%l%h%p%r%j)）：
//   - OpenSSH >= 9.6：带 ProxyJump 的 %C 匹配 SHA1(%l%h%p%r%j)，返回 true；
//   - 旧版 OpenSSH <= 9.5（含 Windows 11 内置 Win32-OpenSSH 9.5p1）：%C 仍为 SHA1(%l%h%p%r)，返回 false；
//   - 若无跳板基线或带跳板输出与上述两种规范哈希均不符，立即失败关闭。
func probePercentCIncludesJumpHost(t *testing.T, sshBin, dir, localHost string) (bool, error) {
	t.Helper()
	probeCfg := filepath.Join(dir, "probe_percent_c.conf")
	tpl := filepath.ToSlash(filepath.Join(dir, "p-%C"))
	writeTestFile(t, probeCfg, `
Host c-nojump
  HostName 192.0.2.200
  User probeuser
  Port 2222
  ControlPath `+tpl+`

Host c-withjump
  HostName 192.0.2.200
  User probeuser
  Port 2222
  ProxyJump hop1.example,hop2.example
  ControlPath `+tpl+`
`)
	wantNoJump, err := option.ComputePercentC(localHost, "192.0.2.200", 2222, "probeuser")
	if err != nil {
		return false, err
	}
	wantWithJump, err := option.ComputeConnectionHash(localHost, "192.0.2.200", 2222, "probeuser", "hop2.example")
	if err != nil {
		return false, err
	}
	noJumpPath := filepath.ToSlash(runSSHGDump(t, sshBin, probeCfg, "c-nojump").single["controlpath"])
	if !strings.HasSuffix(noJumpPath, "p-"+wantNoJump) {
		t.Fatalf("无跳板 %%C 探针失配: wantSuffix=%q ssh-G=%q", "p-"+wantNoJump, noJumpPath)
	}
	withJumpPath := filepath.ToSlash(runSSHGDump(t, sshBin, probeCfg, "c-withjump").single["controlpath"])
	if strings.HasSuffix(withJumpPath, "p-"+wantWithJump) {
		return true, nil
	}
	if strings.HasSuffix(withJumpPath, "p-"+wantNoJump) {
		return false, nil
	}
	t.Fatalf("多跳 %%C 探针输出既不匹配含 %%j (%s) 也不匹配无 %%j (%s): ssh-G=%q", wantWithJump, wantNoJump, withJumpPath)
	return false, nil
}

func assertMultiHopPercentCDiff(t *testing.T, sshBin, dir, cfgPath string, src *openssh.ConfigSource, alias string) {
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
	// 无条件校验 XOps RFC §3.6 锁定的 %C = SHA1(%l%h%p%r%j)（末跳无方括号规范主机名 bastion2.example）。
	hash, err := eff.PercentC(localHost, "deploy")
	if err != nil {
		t.Fatalf("PercentC 失败: %v", err)
	}
	wantRFC, err := option.ComputeConnectionHash(localHost, "192.0.2.13", 2222, "deploy", "bastion2.example")
	if err != nil || hash != wantRFC {
		t.Fatalf("XOps RFC §3.6 多跳 %%C 违例: got=%q want=%q err=%v", hash, wantRFC, err)
	}
	// 按本机 ssh -G 探针结果严格校验精确 40 位十六进制 SHA-1 哈希（OpenSSH >= 9.6 含 %j vs <= 9.5 无 %j）。
	includesJump, err := probePercentCIncludesJumpHost(t, sshBin, dir, localHost)
	if err != nil {
		t.Fatalf("probePercentCIncludesJumpHost 失败: %v", err)
	}
	wantSSHHash := hash
	if !includesJump {
		wantSSHHash, err = option.ComputePercentC(localHost, "192.0.2.13", 2222, "deploy")
		if err != nil {
			t.Fatalf("ComputePercentC(legacy) 失败: %v", err)
		}
	}
	wantSuffix := "mux-" + wantSSHHash
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
