package openssh_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/openssh"
	"go.uber.org/goleak"
)

type sshGDump struct {
	single map[string]string
	multi  map[string][]string
}

// newPrivateSSHTestDir 在 t.TempDir() 下经 osfs.EnsureRoot(0o700) 引导受保护私有根目录，
// 确保 Windows 上创建于其下的 ssh_config 与 Include 子配置文件自动继承 Owner-Only DACL，
// 满足 Win32-OpenSSH 对 Include 配置文件的严格权限校验。
func newPrivateSSHTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ssh")
	d, err := pathalg.ParseLocalDir(dir)
	if err != nil {
		t.Fatalf("ParseLocalDir(%q) 失败: %v", dir, err)
	}
	if err := osfs.NewScopedRootFS().EnsureRoot(d, 0o700); err != nil {
		t.Fatalf("EnsureRoot(%q) 失败: %v", dir, err)
	}
	return dir
}

// emptyBaseConfigPath 返回用于提取本机 OpenSSH 原生默认算法集 openSSHDefaultL0 的空白配置文件路径：
// Unix 上遵循 §4 #8 直接使用 /dev/null；Windows 上使用零字节常规文件以规避 Win32-OpenSSH 打开 NUL 字符设备的兼容异常。
func emptyBaseConfigPath(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return os.DevNull
	}
	p := filepath.Join(dir, "empty_ssh_config")
	writeTestFile(t, p, "")
	return p
}

// runSSHGDump 在有界超时与常规磁盘文件重定向（零 NUL Stdin、零匿名管道 writerDescriptor 阻塞）下执行 ssh -F <cfg> -G <target>，
// 规避 Win32-OpenSSH 在 Windows 上因 <NUL 或管道异步写锁死导致 600s 挂起的问题。
func runSSHGDump(t *testing.T, sshBin, cfgPath, target string) sshGDump {
	t.Helper()
	ioDir := t.TempDir()
	inPath := filepath.Join(ioDir, "stdin.empty")
	outPath := filepath.Join(ioDir, "stdout.txt")
	if err := os.WriteFile(inPath, nil, 0o600); err != nil {
		t.Fatalf("创建空 stdin 文件失败: %v", err)
	}
	inFile, err := os.Open(inPath)
	if err != nil {
		t.Fatalf("打开空 stdin 文件失败: %v", err)
	}
	defer func() { _ = inFile.Close() }()
	outFile, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("创建输出捕获文件失败: %v", err)
	}
	defer func() { _ = outFile.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshBin, "-F", cfgPath, "-G", target)
	cmd.Stdin = inFile
	cmd.Stdout = outFile
	cmd.Stderr = outFile
	cmd.WaitDelay = 2 * time.Second

	runErr := cmd.Run()
	_ = outFile.Close()
	out, readErr := os.ReadFile(outPath)
	if runErr != nil {
		t.Fatalf("ssh -F %s -G %s 失败 (ctx=%v, readErr=%v): %v\n%s", cfgPath, target, ctx.Err(), readErr, runErr, string(out))
	}
	if readErr != nil {
		t.Fatalf("读取 ssh -G 输出文件失败: %v", readErr)
	}
	return parseSSHGDump(out)
}

func parseSSHGDump(out []byte) sshGDump {
	dump := sshGDump{single: make(map[string]string), multi: make(map[string][]string)}
	for line := range strings.SplitSeq(string(out), "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if trimmed == "" {
			continue
		}
		k, v, ok := strings.Cut(trimmed, " ")
		if !ok {
			continue
		}
		lk := strings.ToLower(k)
		if _, exists := dump.single[lk]; !exists {
			dump.single[lk] = v
		}
		dump.multi[lk] = append(dump.multi[lk], v)
	}
	return dump
}

// truncateAtFirstNone 按实施计划 §4 #8 在首个 "none" 处截断 raw ssh -G 的 identityfile/certificatefile 列表。
func truncateAtFirstNone(items []string) []string {
	var out []string
	for _, it := range items {
		if strings.EqualFold(strings.TrimSpace(it), "none") {
			break
		}
		if !slices.Contains(out, it) {
			out = append(out, it)
		}
	}
	return out
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for part := range strings.SplitSeq(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func applySendEnvDiff(rawTokens []string) []string {
	envF := option.UnsetEnvFilter()
	for _, line := range rawTokens {
		parsed, err := option.ParseEnvFilter(line)
		if err != nil {
			continue
		}
		envF = parsed.Compose(envF)
	}
	return envF.Patterns()
}

// TestSSHG_DifferentialContract 严格遵循实施计划 §4 #8，与本机真实 ssh -G 执行端到端差分比对：
//   - 通过 ssh -F <DevNull> -G 提取本机 OpenSSH 原生默认算法集 openSSHDefaultL0，再单次 Apply；
//   - 在首个 "none" 处截断 raw ssh -G 的 identityfile / certificatefile；
//   - 将 raw controlmaster / controlpersist 与 ControlPolicy.Master() / Persist() 对齐，同时核验 Effective* 投影；
//   - 验证多块 Host + Include + SendEnv -PATTERN 遭遇序折叠与 ssh -F <cfg> -G 100% 一致。
func TestSSHG_DifferentialContract(t *testing.T) {
	defer goleak.VerifyNone(t)
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("本机未安装 OpenSSH ssh 二进制，跳过 ssh -G 差分测试")
	}

	dir := newPrivateSSHTestDir(t)
	incDir := filepath.Join(dir, "conf.d")
	cfgPath := filepath.Join(dir, "ssh_config")
	writeTestFile(t, filepath.Join(incDir, "10-base.conf"), `
Host app-diff
  HostName 192.0.2.55
  Port 2202
  User deploy
  ProxyJump jump.example.test
  ControlMaster auto
  ControlPersist 10m
  ControlPath none
  Ciphers +aes256-ctr
  MACs -*sha1*
  SendEnv LANG LC_* APP_TOKEN
  IdentityFile ~/.ssh/id_alpha
  CertificateFile ~/.ssh/cert_alpha
`)
	writeTestFile(t, cfgPath, "Include \""+filepath.ToSlash(filepath.Join(incDir, "*.conf"))+"\"\n"+`

Host app-*
  SendEnv -LC_ALL -APP_TOKEN EXTRA_VAR
  IdentityFile ~/.ssh/id_beta
  IdentityFile none
  CertificateFile none
  ServerAliveInterval 45
  ServerAliveCountMax 5
  IdentitiesOnly yes
  BatchMode yes
  StrictHostKeyChecking accept-new
  ForwardAgent yes

Host *
  IdentityFile ~/.ssh/id_after_none
  CertificateFile ~/.ssh/cert_after_none
  ControlMaster no
  ControlPersist no
  Port 2299
`)

	baseDump := runSSHGDump(t, sshBin, emptyBaseConfigPath(t, dir), "app-diff")
	cfgDump := runSSHGDump(t, sshBin, cfgPath, "app-diff")

	src := newDiffSource(t, cfgPath)
	target := mustOrigHost(t, "app-diff")
	layer, err := src.ResolveTier4(context.Background(), target, algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(app-diff) 失败: %v", err)
	}
	eff, err := option.ResolveEffectivePolicyWithOriginalHost(
		option.OriginOpenSSHVirtual, target, netaddr.DefaultSSHPort,
		option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), layer,
	)
	if err != nil {
		t.Fatalf("ResolveEffectivePolicyWithOriginalHost 失败: %v", err)
	}

	verifyDiffScalars(t, eff, cfgDump)
	verifyDiffAlgos(t, layer, baseDump, cfgDump)
	verifyDiffPathsAndEnv(t, layer, cfgDump)
	verifyDiffControlSlots(t, layer, cfgDump)
}

func newDiffSource(t *testing.T, cfgPath string) *openssh.ConfigSource {
	t.Helper()
	src, err := openssh.NewConfigSource(openssh.SourceSpec{
		ConfigPath:    mustSourcePath(t, cfgPath),
		Reader:        osfs.NewOperatorReadFS(),
		ScopedFS:      osfs.NewScopedRootFS(),
		SymlinkPolicy: pathalg.SymlinkFollowOperatorSource,
	})
	if err != nil {
		t.Fatalf("NewConfigSource 失败: %v", err)
	}
	return src
}

func verifyDiffScalars(t *testing.T, eff option.EffectivePolicy, cfgDump sshGDump) {
	t.Helper()
	if eff.Endpoint().Host().String() != cfgDump.single["hostname"] {
		t.Fatalf("hostname = %q, ssh -G = %q", eff.Endpoint().Host().String(), cfgDump.single["hostname"])
	}
	if strconv.Itoa(int(eff.Endpoint().Port())) != cfgDump.single["port"] {
		t.Fatalf("port = %d, ssh -G = %q", eff.Endpoint().Port(), cfgDump.single["port"])
	}
	if u, _ := eff.User().Get(); u.String() != cfgDump.single["user"] {
		t.Fatalf("user = %q, ssh -G = %q", u.String(), cfgDump.single["user"])
	}
	if eff.StrictHostKeyChecking().String() != cfgDump.single["stricthostkeychecking"] {
		t.Fatalf("stricthostkeychecking = %q, ssh -G = %q", eff.StrictHostKeyChecking().String(), cfgDump.single["stricthostkeychecking"])
	}
	if strconv.FormatUint(uint64(eff.ServerAliveCountMax()), 10) != cfgDump.single["serveralivecountmax"] {
		t.Fatalf("serveralivecountmax = %d, ssh -G = %q", eff.ServerAliveCountMax(), cfgDump.single["serveralivecountmax"])
	}
	if strconv.FormatInt(int64(eff.ServerAliveInterval().Std().Seconds()), 10) != cfgDump.single["serveraliveinterval"] {
		t.Fatalf("serveraliveinterval = %v, ssh -G = %q", eff.ServerAliveInterval(), cfgDump.single["serveraliveinterval"])
	}
	if !eff.IdentitiesOnly() || cfgDump.single["identitiesonly"] != "yes" {
		t.Fatalf("identitiesonly = %v, ssh -G = %q", eff.IdentitiesOnly(), cfgDump.single["identitiesonly"])
	}
	if !eff.BatchMode() || cfgDump.single["batchmode"] != "yes" {
		t.Fatalf("batchmode = %v, ssh -G = %q", eff.BatchMode(), cfgDump.single["batchmode"])
	}
	if !eff.ForwardAgent() || cfgDump.single["forwardagent"] != "yes" {
		t.Fatalf("forwardagent = %v, ssh -G = %q", eff.ForwardAgent(), cfgDump.single["forwardagent"])
	}
	jc, ok := eff.Proxy().(*option.ProxyJumpChain)
	if !ok {
		t.Fatalf("proxyjump = %T, ssh -G = %q", eff.Proxy(), cfgDump.single["proxyjump"])
	}
	head, hasHead := jc.Hops().Head()
	if !hasHead || head.String() != cfgDump.single["proxyjump"] {
		t.Fatalf("proxyjump = (%q, %v), ssh -G = %q", head.String(), hasHead, cfgDump.single["proxyjump"])
	}
}

func verifyDiffAlgos(t *testing.T, layer option.OptionLayer, baseDump, cfgDump sshGDump) {
	t.Helper()
	for _, tc := range []struct {
		key string
		pol option.AlgoPolicy
	}{
		{"ciphers", layer.Ciphers()},
		{"macs", layer.MACs()},
		{"kexalgorithms", layer.KexAlgorithms()},
		{"hostkeyalgorithms", layer.HostKeyAlgorithms()},
	} {
		defaultL0 := splitCSV(baseDump.single[tc.key])
		if len(defaultL0) == 0 {
			t.Fatalf("ssh -F %s -G 未输出默认 %s", os.DevNull, tc.key)
		}
		got, err := tc.pol.Apply(defaultL0)
		if err != nil {
			t.Fatalf("%s AlgoPolicy.Apply(openSSHDefaultL0) 失败: %v", tc.key, err)
		}
		want := splitCSV(cfgDump.single[tc.key])
		if !slices.Equal(got, want) {
			t.Fatalf("%s 差分失配:\n got=%v\nwant=%v", tc.key, got, want)
		}
	}
}

func verifyDiffPathsAndEnv(t *testing.T, layer option.OptionLayer, cfgDump sshGDump) {
	t.Helper()
	wantIDs := truncateAtFirstNone(cfgDump.multi["identityfile"])
	if gotIDs := layer.IdentityFiles().RawItems(); !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("identityfile 截断对齐失配: got=%v want=%v (raw=%v)", gotIDs, wantIDs, cfgDump.multi["identityfile"])
	}
	wantCerts := truncateAtFirstNone(cfgDump.multi["certificatefile"])
	if gotCerts := layer.CertificateFiles().RawItems(); !slices.Equal(gotCerts, wantCerts) {
		t.Fatalf("certificatefile 截断对齐失配: got=%v want=%v (raw=%v)", gotCerts, wantCerts, cfgDump.multi["certificatefile"])
	}
	wantSendEnv := applySendEnvDiff(cfgDump.multi["sendenv"])
	if gotSendEnv := layer.SendEnv().Patterns(); !slices.Equal(gotSendEnv, wantSendEnv) {
		t.Fatalf("sendenv 单文件遭遇序折叠失配: got=%v want=%v (raw=%v)", gotSendEnv, wantSendEnv, cfgDump.multi["sendenv"])
	}
}

func verifyDiffControlSlots(t *testing.T, layer option.OptionLayer, cfgDump sshGDump) {
	t.Helper()
	rawMaster, err := option.ParseControlMasterMode(cfgDump.single["controlmaster"])
	if err != nil {
		t.Fatalf("解析 ssh -G controlmaster=%q 失败: %v", cfgDump.single["controlmaster"], err)
	}
	if layer.Control().Master() != rawMaster {
		t.Fatalf("ControlPolicy.Master() = %v, ssh -G = %v", layer.Control().Master(), rawMaster)
	}
	rawPersist, err := option.ParseControlPersist(cfgDump.single["controlpersist"])
	if err != nil {
		t.Fatalf("解析 ssh -G controlpersist=%q 失败: %v", cfgDump.single["controlpersist"], err)
	}
	if !layer.Control().Persist().Equal(rawPersist) {
		t.Fatalf("ControlPolicy.Persist() = %v, ssh -G = %v", layer.Control().Persist(), rawPersist)
	}
	// 当 ControlPath=none 时，运行期失败关闭投影 EffectiveMaster/EffectivePersist 必须归零禁用（§4 #8）。
	if layer.Control().Path().IsEnabled() || layer.Control().EffectiveMaster() != option.ControlMasterNo || layer.Control().EffectivePersist().IsEnabled() {
		t.Fatalf("ControlPath=none 时 EffectiveMaster/EffectivePersist 必须归零禁用: path=%v effMaster=%v effPersist=%v",
			layer.Control().Path(), layer.Control().EffectiveMaster(), layer.Control().EffectivePersist())
	}
}

// TestSSHG_DifferentialMatchAndProxyModes 补充校验 Match host/originalhost/user、ProxyCommand、
// Ciphers ^ 前置、KexAlgorithms 扣减以及启用态 ControlPath + ControlMaster + ControlPersist 的 ssh -G 差分一致性。
func TestSSHG_DifferentialMatchAndProxyModes(t *testing.T) {
	defer goleak.VerifyNone(t)
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("本机未安装 OpenSSH ssh 二进制，跳过 ssh -G 差分测试")
	}
	dir := newPrivateSSHTestDir(t)
	cfgPath := filepath.Join(dir, "ssh_match_config")
	ctrlTpl := filepath.ToSlash(filepath.Join(dir, "cm-%C"))
	writeTestFile(t, cfgPath, `
Host bastion-edge
  HostName 198.51.100.42
  User ops

Match originalhost bastion-edge
  Port 2244
  ProxyCommand ssh -W %h:%p gateway.example.test

Match host 198.51.100.* user ops
  Ciphers ^chacha20-poly1305@openssh.com
  ControlMaster autoask
  ControlPersist yes
  ControlPath `+ctrlTpl+`
  StrictHostKeyChecking yes

Host *
  ProxyJump ignored.example.test
  Port 2200
`)
	baseDump := runSSHGDump(t, sshBin, emptyBaseConfigPath(t, dir), "bastion-edge")
	cfgDump := runSSHGDump(t, sshBin, cfgPath, "bastion-edge")

	src := newDiffSource(t, cfgPath)
	target := mustOrigHost(t, "bastion-edge")
	layer, err := src.ResolveTier4(context.Background(), target, algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(bastion-edge) 失败: %v", err)
	}
	eff, err := option.ResolveEffectivePolicyWithOriginalHost(
		option.OriginOpenSSHVirtual, target, netaddr.DefaultSSHPort,
		option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), layer,
	)
	if err != nil {
		t.Fatalf("ResolveEffectivePolicyWithOriginalHost 失败: %v", err)
	}
	if eff.Endpoint().Host().String() != cfgDump.single["hostname"] || strconv.Itoa(int(eff.Endpoint().Port())) != cfgDump.single["port"] {
		t.Fatalf("endpoint = %v, ssh -G = %s:%s", eff.Endpoint(), cfgDump.single["hostname"], cfgDump.single["port"])
	}
	pc, ok := eff.Proxy().(*option.ProxyCommandSpec)
	if !ok || pc.Command().String() != cfgDump.single["proxycommand"] {
		t.Fatalf("proxycommand = (%T, %v), ssh -G = %q", eff.Proxy(), eff.Proxy(), cfgDump.single["proxycommand"])
	}
	verifyDiffAlgos(t, layer, baseDump, cfgDump)
	if layer.Control().EffectiveMaster() != option.ControlMasterAutoAsk || !layer.Control().EffectivePersist().IsIndefinite() {
		t.Fatalf("启用态 ControlPolicy 异常: master=%v persist=%v", layer.Control().EffectiveMaster(), layer.Control().EffectivePersist())
	}
	localHost, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname 失败: %v", err)
	}
	expandedPath, err := option.ExpandPathTokens(layer.Control().Path().String(), option.TokenContext{
		LocalHost:  localHost,
		TargetHost: eff.Endpoint().Host().String(),
		Port:       eff.Endpoint().Port(),
		RemoteUser: "ops",
	})
	if err != nil {
		t.Fatalf("ExpandPathTokens(%q) 失败: %v", layer.Control().Path().String(), err)
	}
	if filepath.ToSlash(expandedPath) != filepath.ToSlash(cfgDump.single["controlpath"]) {
		t.Fatalf("controlpath %%C 展开差分失配: got=%q, ssh -G=%q", expandedPath, cfgDump.single["controlpath"])
	}
}

// TestSSHG_DifferentialMatchFinalCanonicalAndInlineComments 与真实 ssh -G 差分校验：
//   - 独立无 final 配置中的 Match canonical all 与默认 ssh -G 一致不生效（失败关闭）；
//   - Match final all 位于 Host 之前时的两轮折叠顺序、Match host 大小写不敏感匹配与行内 # 注释语义。
func TestSSHG_DifferentialMatchFinalCanonicalAndInlineComments(t *testing.T) {
	defer goleak.VerifyNone(t)
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("本机未安装 OpenSSH ssh 二进制，跳过 ssh -G 差分测试")
	}
	dir := newPrivateSSHTestDir(t)
	target := mustOrigHost(t, "prod-01")

	// 1. 无 canonicalization 且无 final 触发二轮时，OpenSSH ssh -G 与本实现均不激活 Match canonical all。
	canonCfg := filepath.Join(dir, "ssh_canonical_config")
	writeTestFile(t, canonCfg, "Match canonical all\n  Port 2288\n  ServerAliveInterval 99\n")
	canonDump := runSSHGDump(t, sshBin, canonCfg, "prod-01")
	canonLayer, err := newDiffSource(t, canonCfg).ResolveTier4(context.Background(), target, algebraic.None[netaddr.Endpoint]())
	if err != nil || canonLayer.Port().IsSome() || canonDump.single["port"] != "22" {
		t.Fatalf("Match canonical all 须不生效: layerPort=%v ssh-G=%q err=%v", canonLayer.Port(), canonDump.single["port"], err)
	}

	// 2. Match final all 位于 Host prod-01 之前 + 大小写不敏感 Match host/originalhost + 行内 # 注释。
	cfgPath := filepath.Join(dir, "ssh_final_inline_config")
	writeTestFile(t, cfgPath, `
Match final all
  User final-fallback
  Port 2277 # final port comment
  IdentityFile ~/.ssh/id_final

Host prod-01 # host comment !prod-01
  HostName 198.51.100.77 # ip comment
  User alice#bob
  ProxyCommand ssh -W %h:%p gw # keep-hash
  IdentityFile ~/.ssh/id_host
  IdentityFile none

Match host 198.51.100.* originalhost PROD-01
  ForwardAgent yes # inline comment
`)
	cfgDump := runSSHGDump(t, sshBin, cfgPath, "prod-01")
	layer, err := newDiffSource(t, cfgPath).ResolveTier4(context.Background(), target, algebraic.None[netaddr.Endpoint]())
	if err != nil {
		t.Fatalf("ResolveTier4(prod-01) 失败: %v", err)
	}
	eff, err := option.ResolveEffectivePolicyWithOriginalHost(
		option.OriginOpenSSHVirtual, target, netaddr.DefaultSSHPort,
		option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), layer,
	)
	if err != nil {
		t.Fatalf("ResolveEffectivePolicyWithOriginalHost 失败: %v", err)
	}
	if u, _ := eff.User().Get(); u.String() != cfgDump.single["user"] || u.String() != "alice#bob" {
		t.Fatalf("user = %q, ssh -G = %q", u.String(), cfgDump.single["user"])
	}
	if strconv.Itoa(int(eff.Endpoint().Port())) != cfgDump.single["port"] || eff.Endpoint().Port() != 2277 {
		t.Fatalf("port = %d, ssh -G = %q", eff.Endpoint().Port(), cfgDump.single["port"])
	}
	if !eff.ForwardAgent() || cfgDump.single["forwardagent"] != "yes" {
		t.Fatalf("forwardagent = %v, ssh -G = %q", eff.ForwardAgent(), cfgDump.single["forwardagent"])
	}
	pc, ok := eff.Proxy().(*option.ProxyCommandSpec)
	if !ok || pc.Command().String() != cfgDump.single["proxycommand"] {
		t.Fatalf("proxycommand = (%T, %v), ssh -G = %q", eff.Proxy(), eff.Proxy(), cfgDump.single["proxycommand"])
	}
	if gotIDs, wantIDs := layer.IdentityFiles().RawItems(), truncateAtFirstNone(cfgDump.multi["identityfile"]); !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("identityfile 差分失配: got=%v want=%v", gotIDs, wantIDs)
	}
}

var _ ports.OperatorReadFS = (*osfs.OperatorFS)(nil)
