package option

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

func mustPathEntry(t *testing.T, raw string) PathEntry {
	t.Helper()
	e, err := ParsePathEntry(raw)
	if err != nil {
		t.Fatalf("ParsePathEntry(%q) 失败: %v", raw, err)
	}
	return e
}

func mustPathList(t *testing.T, items ...string) PathList {
	t.Helper()
	pl, err := ParsePathListEntries(items)
	if err != nil {
		t.Fatalf("ParsePathListEntries(%v) 失败: %v", items, err)
	}
	return pl
}

func mustKnownHosts(t *testing.T, items ...string) KnownHostsList {
	t.Helper()
	kh, err := ParseKnownHostsList(items)
	if err != nil {
		t.Fatalf("ParseKnownHostsList(%v) 失败: %v", items, err)
	}
	return kh
}

func mustAlgoPolicy(t *testing.T, raw string) AlgoPolicy {
	t.Helper()
	ap, err := ParseAlgoPolicy(raw)
	if err != nil {
		t.Fatalf("ParseAlgoPolicy(%q) 失败: %v", raw, err)
	}
	return ap
}

func mustEnvFilter(t *testing.T, raw string) EnvFilter {
	t.Helper()
	ef, err := ParseEnvFilter(raw)
	if err != nil {
		t.Fatalf("ParseEnvFilter(%q) 失败: %v", raw, err)
	}
	return ef
}

func mustHop(t *testing.T, raw string) HopTarget {
	t.Helper()
	h, err := ParseHopTarget(raw)
	if err != nil {
		t.Fatalf("ParseHopTarget(%q) 失败: %v", raw, err)
	}
	return h
}

func mustProxyJump(t *testing.T, raw string) ProxyRoute {
	t.Helper()
	r, err := ParseProxyJump(raw)
	if err != nil {
		t.Fatalf("ParseProxyJump(%q) 失败: %v", raw, err)
	}
	return r
}

func mustProxyCmd(t *testing.T, raw string) ProxyRoute {
	t.Helper()
	r, err := ParseProxyCommand(raw)
	if err != nil {
		t.Fatalf("ParseProxyCommand(%q) 失败: %v", raw, err)
	}
	return r
}

func assertMonoidLaws[T any](t *testing.T, name string, id T, universe []T, combine func(T, T) T, equal func(T, T) bool) {
	t.Helper()
	for i, a := range universe {
		if !equal(combine(id, a), a) || !equal(combine(a, id), a) {
			t.Fatalf("%s 单位元违例: idx=%d", name, i)
		}
		assertAssociativeForLeft(t, name, i, a, universe, combine, equal)
	}
}

func assertAssociativeForLeft[T any](t *testing.T, name string, i int, a T, universe []T, combine func(T, T) T, equal func(T, T) bool) {
	t.Helper()
	for j, b := range universe {
		ab := combine(a, b)
		for k, c := range universe {
			if !equal(combine(ab, c), combine(a, combine(b, c))) {
				t.Fatalf("%s 结合律违例: (%d,%d,%d)", name, i, j, k)
			}
		}
	}
}

func TestPathListMonoidLaws(t *testing.T) {
	eA := mustPathEntry(t, "~/.ssh/id_ed25519")
	eB := mustPathEntry(t, "~/.ssh/id_%r")
	eC := mustPathEntry(t, "${HOME}/.ssh/id_prod")
	if eA.IsTemplate() || !eB.IsTemplate() || !eC.IsTemplate() {
		t.Fatalf("PathEntry 模板分类错误: a=%v b=%v c=%v", eA.Kind(), eB.Kind(), eC.Kind())
	}

	universe := []PathList{
		UnsetPathList(),
		DisabledPathList(),
		mustPathList(t, "~/.ssh/id_ed25519"),
		mustPathList(t, "~/.ssh/id_%r", "~/.ssh/id_ed25519"),
		mustPathList(t, "~/.ssh/id_ed25519", "none"),
		mustPathList(t, "${HOME}/.ssh/id_prod", "~/.ssh/id_%r", "none", "~/.ssh/ignored"),
	}
	assertMonoidLaws(t, "PathList", UnsetPathList(), universe, PathList.Compose, PathList.Equal)

	for i, x := range universe {
		if !DisabledPathList().Compose(x).Equal(DisabledPathList()) {
			t.Fatalf("PathList Disabled 左吸收失败: idx=%d", i)
		}
	}
	sealed := FoldPathLists(mustPathList(t, "~/.ssh/a"), DisabledPathList(), mustPathList(t, "~/.ssh/b"))
	if !sealed.IsSet() || !sealed.Terminated() || sealed.DefaultsAllowed() || !slices.Equal(sealed.RawItems(), []string{"~/.ssh/a"}) {
		t.Fatalf("PathList 封口语义错误: state=%v term=%v items=%v", sealed.State(), sealed.Terminated(), sealed.RawItems())
	}
	items := sealed.Items()
	items[0] = eB
	if !slices.Equal(sealed.RawItems(), []string{"~/.ssh/a"}) {
		t.Fatalf("PathList.Items 未执行防御性拷贝")
	}
}

func TestPathListAndKnownHostsFailClosed(t *testing.T) {
	for _, bad := range []string{"", "   ", "none", "NONE", "~/.ssh/bad\nkey", "~/.ssh/%z", "~/.ssh/${1BAD}", "~/.ssh/${UNCLOSED"} {
		if _, err := ParsePathEntry(bad); !errors.Is(err, ErrInvalidPathList) {
			t.Fatalf("ParsePathEntry(%q) 应返回 ErrInvalidPathList，实际 %v", bad, err)
		}
	}
	if pl, err := NewPathList(PathEntry{}); !errors.Is(err, ErrInvalidPathList) || !pl.IsUnset() || !pl.IsZero() {
		t.Fatalf("NewPathList(zero) 应失败关闭并返回 Unset，实际 pl=%+v err=%v", pl, err)
	}
	if kh, err := NewKnownHostsList(PathEntry{}); !errors.Is(err, ErrInvalidPathList) || !kh.IsUnset() || !kh.IsZero() {
		t.Fatalf("NewKnownHostsList(zero) 应失败关闭并返回 Unset，实际 kh=%+v err=%v", kh, err)
	}
	for _, badKH := range [][]string{{"none", "~/.ssh/kh2"}, {"~/.ssh/kh1", "none"}, {"none", "none"}, {"NONE", "~/.ssh/kh"}, {""}, {"~/.ssh/bad\n"}} {
		if _, err := ParseKnownHostsList(badKH); !errors.Is(err, ErrInvalidPathList) {
			t.Fatalf("ParseKnownHostsList(%v) 应失败关闭，实际 %v", badKH, err)
		}
	}
}

func TestKnownHostsListFirstWinsMonoidLaws(t *testing.T) {
	kh1 := mustKnownHosts(t, "/etc/xops/pinned_kh")
	kh2 := mustKnownHosts(t, "~/.ssh/known_hosts", "~/.ssh/known_hosts2")
	khNone := mustKnownHosts(t, "none")
	if !khNone.IsDisabled() || khNone.DefaultsAllowed() || !UnsetKnownHostsList().DefaultsAllowed() {
		t.Fatalf("KnownHostsList 状态谓词错误")
	}
	universe := []KnownHostsList{UnsetKnownHostsList(), DisabledKnownHostsList(), kh1, kh2}
	assertMonoidLaws(t, "KnownHostsList", UnsetKnownHostsList(), universe, KnownHostsList.Compose, KnownHostsList.Equal)

	for i, a := range universe {
		if a.IsUnset() {
			continue
		}
		if !a.Compose(a).Equal(a) {
			t.Fatalf("KnownHostsList 幂等律违例: idx=%d", i)
		}
		for j, b := range universe {
			if !a.Compose(b).Equal(a) {
				t.Fatalf("KnownHostsList FirstWins 左吸收违例: (%d,%d)", i, j)
			}
		}
	}
	folded := FoldKnownHostsLists(UnsetKnownHostsList(), kh1, kh2)
	if !folded.Equal(kh1) || !slices.Equal(folded.RawItems(), []string{"/etc/xops/pinned_kh"}) {
		t.Fatalf("KnownHostsList 跨层不得污染高层信任锚点: got=%v", folded.RawItems())
	}
	items := kh1.Items()
	items[0] = mustPathEntry(t, "~/.ssh/tampered")
	if !slices.Equal(kh1.RawItems(), []string{"/etc/xops/pinned_kh"}) {
		t.Fatalf("KnownHostsList.Items 未执行防御性拷贝")
	}
}

func TestAlgoPolicyFirstWinsAndGlobLaws(t *testing.T) {
	pExact := mustAlgoPolicy(t, "a,b")
	pAppend := mustAlgoPolicy(t, "+c,a")
	pRemove := mustAlgoPolicy(t, "-b")
	pGlob := mustAlgoPolicy(t, "-*-cbc,aes???-ctr")
	pPrepend := mustAlgoPolicy(t, "^d,b")

	universe := []AlgoPolicy{UnsetAlgoPolicy(), pExact, pAppend, pRemove, pGlob, pPrepend}
	assertMonoidLaws(t, "AlgoPolicy", UnsetAlgoPolicy(), universe, AlgoPolicy.Compose, AlgoPolicy.Equal)
	assertAlgoFirstWinsLaws(t, universe)

	// 验证与 OpenSSH ssh -G 一致：高层 +aes256-ctr 遮蔽低层 -aes128-ctr，不移除 aes128-ctr。
	won := mustAlgoPolicy(t, "+aes256-ctr").Compose(mustAlgoPolicy(t, "-aes128-ctr"))
	resolved, err := won.Apply(DefaultCiphers())
	if err != nil || !slices.Contains(resolved, "aes128-ctr") || !slices.Contains(resolved, "aes256-ctr") {
		t.Fatalf("AlgoPolicy FirstWins 与 ssh -G 语义不符: err=%v got=%v", err, resolved)
	}
	// 验证 Remove 算子独占支持 */? 通配符。
	filtered, err := pGlob.Apply([]string{"aes128-cbc", "3des-cbc", "aes128-ctr", "chacha20-poly1305@openssh.com"})
	if err != nil || !slices.Equal(filtered, []string{"chacha20-poly1305@openssh.com"}) {
		t.Fatalf("AlgoPolicy Remove 通配符过滤错误: err=%v got=%v", err, filtered)
	}
	prepended, err := pPrepend.Apply([]string{"a", "b", "c"})
	if err != nil || !slices.Equal(prepended, []string{"d", "b", "a", "c"}) {
		t.Fatalf("AlgoPolicy Prepend 去重前置错误: err=%v got=%v", err, prepended)
	}
	if pGlob.Op() != AlgoOpRemove || pGlob.String() != "-*-cbc,aes???-ctr" {
		t.Fatalf("AlgoPolicy 元数据表示异常: op=%v str=%q", pGlob.Op(), pGlob.String())
	}
	toks := pExact.Tokens()
	toks[0] = "tampered"
	if !slices.Equal(pExact.Tokens(), []string{"a", "b"}) {
		t.Fatalf("AlgoPolicy.Tokens 未执行防御性拷贝")
	}
}

func assertAlgoFirstWinsLaws(t *testing.T, universe []AlgoPolicy) {
	t.Helper()
	for i, a := range universe {
		if a.IsUnset() {
			continue
		}
		if !a.Compose(a).Equal(a) {
			t.Fatalf("AlgoPolicy 幂等律违例: idx=%d", i)
		}
		for j, b := range universe {
			if !a.Compose(b).Equal(a) || !FoldAlgoPolicies(a, b).Equal(a) {
				t.Fatalf("AlgoPolicy FirstWins 左吸收违例: (%d,%d)", i, j)
			}
		}
	}
}

func TestAlgoPolicyFailClosed(t *testing.T) {
	if _, err := mustAlgoPolicy(t, "-a,b").Apply([]string{"a", "b"}); !errors.Is(err, ErrEmptyAlgorithmList) {
		t.Fatalf("AlgoPolicy(\"-a,b\").Apply 空结果应返回 ErrEmptyAlgorithmList，实际 %v", err)
	}
	for _, wipe := range []string{"-*", "-?*", "-a*"} {
		if _, err := mustAlgoPolicy(t, wipe).Apply([]string{"a", "ab"}); !errors.Is(err, ErrEmptyAlgorithmList) {
			t.Fatalf("AlgoPolicy(%q).Apply 空结果应返回 ErrEmptyAlgorithmList，实际 %v", wipe, err)
		}
	}
	badInputs := []string{
		"", " ", "+", "-", "^", "a,,b", "+bad$algo", "a\nb", "a\u200bb",
		"aes*", "aes?", "*", "?", "+aes*", "+a,b?", "^aes*", "^?es128-ctr", "--foo", "-.foo",
	}
	for _, bad := range badInputs {
		if _, err := ParseAlgoPolicy(bad); !errors.Is(err, ErrInvalidAlgoPolicy) {
			t.Fatalf("ParseAlgoPolicy(%q) 应返回 ErrInvalidAlgoPolicy，实际 %v", bad, err)
		}
	}
}

func TestProxyRouteMonoidAndShadowingLaws(t *testing.T) {
	j1 := mustProxyJump(t, "bastion1.example.com")
	j2 := mustProxyJump(t, "alice@bastion1.example.com:2222,[2001:db8::1]:2200,prod_hop-1")
	c1 := mustProxyCmd(t, "ssh -W %h:%p gateway.example.com")
	c2 := mustProxyCmd(t, "nc -X connect %h %p")
	shadowedCmd := ComposeProxyRoute(j1, c1)
	shadowedOff := ComposeProxyRoute(j1, NewProxyDisabled())

	universe := []ProxyRoute{
		NewProxyUnset(), NewProxyDisabled(), NewProxyJumpDisabled(),
		j1, j2, c1, c2, shadowedCmd, shadowedOff,
	}
	assertMonoidLaws[ProxyRoute](t, "ProxyRoute", NewProxyUnset(), universe, ComposeProxyRoute, EqualProxyRoute)

	lhs := ComposeProxyRoute(NewProxyJumpDisabled(), ComposeProxyRoute(j1, c1))
	rhs := ComposeProxyRoute(ComposeProxyRoute(NewProxyJumpDisabled(), j1), c1)
	if !EqualProxyRoute(lhs, c1) || !EqualProxyRoute(rhs, c1) {
		t.Fatalf("ProxyRoute 双槽遮蔽结合律错误: lhs=%T rhs=%T", lhs, rhs)
	}
	for i, x := range universe {
		if !EqualProxyRoute(ComposeProxyRoute(NewProxyDisabled(), x), NewProxyDisabled()) ||
			!EqualProxyRoute(ComposeProxyRoute(c1, x), c1) {
			t.Fatalf("ProxyDisabled(all) 或 ProxyCommandSpec 左吸收失败: idx=%d", i)
		}
	}
	if !EqualProxyRoute(nil, NewProxyUnset()) || !EqualProxyRoute(FoldProxyRoutes(nil, j1, c1), shadowedCmd) {
		t.Fatalf("nil ProxyRoute 应等价于 ProxyUnset")
	}
}

func TestHopTargetCanonicalization(t *testing.T) {
	// 无端口 IPv6 跳板必须保留方括号，而 Host() 保持无方括号供 %j 使用。
	v6Hop := mustHop(t, "alice@[2001:db8::1]")
	if v6Hop.String() != "alice@[2001:db8::1]" || v6Hop.Host() != "2001:db8::1" {
		t.Fatalf("无端口 IPv6 HopTarget 规范化错误: str=%q host=%q", v6Hop.String(), v6Hop.Host())
	}
	zonedHop := mustHop(t, "[fe80::1%eth0]:2200")
	if zonedHop.String() != "[fe80::1%eth0]:2200" || zonedHop.Host() != "fe80::1%eth0" {
		t.Fatalf("带区 IPv6 HopTarget 规范化错误: str=%q host=%q", zonedHop.String(), zonedHop.Host())
	}
	// OpenSSH Host 别名大小写敏感（ProdBastion / Prod_Bastion）必须原样保留，IPv4 返回规范文本。
	for _, tc := range [][2]string{{"ProdBastion", "ProdBastion"}, {"Prod_Bastion", "Prod_Bastion"}, {"192.0.2.1", "192.0.2.1"}} {
		h := mustHop(t, tc[0])
		if h.Host() != tc[1] || h.String() != tc[1] {
			t.Fatalf("HopTarget(%q) 大小写或规范化异常: host=%q str=%q", tc[0], h.Host(), h.String())
		}
	}
}

func TestProxyRouteFailClosedAndInjection(t *testing.T) {
	for _, r := range []ProxyRoute{(*ProxyDisabled)(nil), (*ProxyJumpChain)(nil), (*ProxyCommandSpec)(nil), &ProxyJumpChain{}, &ProxyCommandSpec{}} {
		if err := ValidateProxyRoute(r); !errors.Is(err, ErrInvalidProxyRoute) {
			t.Fatalf("ValidateProxyRoute(%#v) 应返回 ErrInvalidProxyRoute，实际 %v", r, err)
		}
		if EqualProxyRoute(r, NewProxyDisabled()) || EqualProxyRoute(r, r) {
			t.Fatalf("无效 ProxyRoute 不得判定为相等: %#v", r)
		}
	}
	badHops := []string{
		"", "none", "-oProxyCommand=id", "user@-host", "-user@host", "a;id", "a/b", "..",
		"[2001:db8::1]:0", "h:022", "h:70000", "a@b@c",
		"::1", "2001:db8::1", "fe80::1%eth0", "alice@2001:db8::1", "[example.com]",
		"../evil@bastion.example.com", ".@bastion.example.com", "..@bastion.example.com", "a:b@bastion.example.com", "a[0]@bastion.example.com",
		"127.1", "0177.0.0.1", "0x7f000001", "999.999.999.999", "example.com.", "bad-.example.com",
	}
	for _, badHop := range badHops {
		if _, err := ParseHopTarget(badHop); !errors.Is(err, ErrInvalidProxyRoute) {
			t.Fatalf("ParseHopTarget(%q) 应失败关闭，实际 %v", badHop, err)
		}
	}
	assertBadUserAndCmdFailClosed(t)
}

func assertBadUserAndCmdFailClosed(t *testing.T) {
	t.Helper()
	for _, badUser := range []string{"", ".", "..", "../root", "a/b", "a:b", "a[0]", "a]b", "-root", "a@b"} {
		if _, err := ParseUsername(badUser); !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("ParseUsername(%q) 应失败关闭，实际 %v", badUser, err)
		}
	}
	for _, badCmd := range []string{"", "none", "nc %h %p\nrm -rf /", "nc %h %z", "nc %h %u", "nc %h %j", "nc %h %C", "nc %h \u202e%p"} {
		if _, err := NewProxySanitizedCmd(badCmd); !errors.Is(err, ErrInvalidProxyRoute) {
			t.Fatalf("NewProxySanitizedCmd(%q) 应失败关闭，实际 %v", badCmd, err)
		}
	}
	if _, err := NewLocalSanitizedCmd("echo %C %d %h %i %j %L %l %n %p %r %u %%"); err != nil {
		t.Fatalf("NewLocalSanitizedCmd 合法占位符应通过: %v", err)
	}
	if _, err := NewLocalSanitizedCmd("echo %z"); !errors.Is(err, ErrInvalidOption) || !errors.Is(err, ErrInvalidPercentInput) {
		t.Fatalf("NewLocalSanitizedCmd 非法占位符应失败关闭，实际 %v", err)
	}
	if _, err := ParseProxyJump("none,none"); !errors.Is(err, ErrInvalidProxyRoute) {
		t.Fatalf("ParseProxyJump(\"none,none\") 应失败关闭，实际 %v", err)
	}
	assertSanitizedCmdTokenInvariants(t)
}

func assertSanitizedCmdTokenInvariants(t *testing.T) {
	t.Helper()
	for _, bad := range []string{"echo %z", "echo %"} {
		if _, err := NewSanitizedCmd(bad); !errors.Is(err, ErrInvalidProxyRoute) || !errors.Is(err, ErrInvalidPercentInput) {
			t.Fatalf("NewSanitizedCmd(%q) 应拒绝非法/悬尾 %% 占位符，实际 %v", bad, err)
		}
	}
	for _, nonProxy := range []string{"nc %h %p %u", "nc %h %p %j", "nc %h %p %C"} {
		cmd, err := NewSanitizedCmd(nonProxy)
		if err != nil {
			t.Fatalf("NewSanitizedCmd(%q) 作为通用 INV-D4 命令应合法: %v", nonProxy, err)
		}
		if _, err := NewProxyCommandSpec(cmd); !errors.Is(err, ErrInvalidProxyRoute) {
			t.Fatalf("NewProxyCommandSpec(%q) 必须强制 %%hnpr 白名单，实际 %v", nonProxy, err)
		}
		direct := &ProxyCommandSpec{cmd: cmd}
		if direct.IsValid() || ValidateProxyRoute(direct) == nil {
			t.Fatalf("含非 %%hnpr 占位符的 ProxyCommandSpec 不得有效: %q", nonProxy)
		}
		ne, _ := algebraic.NonEmptyFromSlice([]HopTarget{mustHop(t, "bastion.example.com")})
		badShadow := &ProxyJumpChain{hops: ne, cmdSlot: proxyCmdSlotActive, cmdValue: cmd}
		if ValidateProxyRoute(badShadow) == nil {
			t.Fatalf("含非 %%hnpr 遮蔽命令的 ProxyJumpChain 必须失败关闭: %q", nonProxy)
		}
	}
}

func TestControlPolicyMonoidAndEffectiveGating(t *testing.T) {
	p1, err := ParseControlPath("~/.ssh/cm-%C")
	if err != nil {
		t.Fatalf("ParseControlPath 失败: %v", err)
	}
	pLit, err := NewLiteralControlPath("/run/xops/cm-abc")
	if err != nil || !pLit.IsLiteral() {
		t.Fatalf("NewLiteralControlPath 失败: %v", err)
	}
	per1 := mustControlPersist(t, "1h30m", 90*time.Minute)
	_ = mustControlPersist(t, "2d1w5s", 9*24*time.Hour+5*time.Second)
	for _, zeroSpec := range []string{"0", "00", "0s", "0m"} {
		perZero, err := ParseControlPersist(zeroSpec)
		if err != nil || !perZero.IsIndefinite() {
			t.Fatalf("ControlPersist(%q) 应为无限期驻留: err=%v kind=%v", zeroSpec, err, perZero.Kind())
		}
	}

	universe := []ControlPolicy{
		UnsetControlPolicy(),
		UnsetControlPolicy().WithMaster(ControlMasterAuto),
		UnsetControlPolicy().WithPath(p1).WithPersist(per1),
		UnsetControlPolicy().WithMaster(ControlMasterNo).WithPath(DisabledControlPath()).WithPersist(DisabledControlPersist()),
		UnsetControlPolicy().WithMaster(ControlMasterYes).WithPath(pLit).WithPersist(IndefiniteControlPersist()),
	}
	assertMonoidLaws(t, "ControlPolicy", UnsetControlPolicy(), universe, ControlPolicy.Compose, ControlPolicy.Equal)

	// 验证 !IsEnabled() 时运行期投影 EffectiveMaster / EffectivePersist 一律归零。
	noPath := UnsetControlPolicy().WithMaster(ControlMasterAuto).WithPersist(per1)
	if noPath.Master() != ControlMasterAuto || noPath.EffectiveMaster() != ControlMasterNo || !noPath.EffectivePersist().Equal(DisabledControlPersist()) {
		t.Fatalf("无 ControlPath 时运行期投影必须归零: effM=%v effP=%v", noPath.EffectiveMaster(), noPath.EffectivePersist())
	}
	disPath := UnsetControlPolicy().WithMaster(ControlMasterYes).WithPath(DisabledControlPath()).WithPersist(IndefiniteControlPersist())
	if disPath.EffectiveMaster() != ControlMasterNo || !disPath.EffectivePersist().Equal(DisabledControlPersist()) {
		t.Fatalf("ControlPath=none 时运行期投影必须归零: effM=%v effP=%v", disPath.EffectiveMaster(), disPath.EffectivePersist())
	}
	enabled := UnsetControlPolicy().WithMaster(ControlMasterAuto).WithPath(p1).WithPersist(per1)
	if enabled.EffectiveMaster() != ControlMasterAuto || !enabled.EffectivePersist().Equal(per1) {
		t.Fatalf("启用 ControlPath 时运行期投影异常: effM=%v effP=%v", enabled.EffectiveMaster(), enabled.EffectivePersist())
	}
	enabledNoPersist := UnsetControlPolicy().WithMaster(ControlMasterAuto).WithPath(p1)
	if !enabledNoPersist.EffectivePersist().Equal(DisabledControlPersist()) {
		t.Fatalf("未设置 ControlPersist 时 EffectivePersist 应回退 Disabled")
	}
}

func mustControlPersist(t *testing.T, raw string, want time.Duration) ControlPersistSpec {
	t.Helper()
	p, err := ParseControlPersist(raw)
	if err != nil {
		t.Fatalf("ParseControlPersist(%q) 失败: %v", raw, err)
	}
	if d, ok := p.Timeout(); !ok || d.Std() != want {
		t.Fatalf("ParseControlPersist(%q) 时长错误: got=%v want=%v", raw, d, want)
	}
	return p
}

func TestControlPolicyFailClosed(t *testing.T) {
	if _, err := TimeoutControlPersist(algebraic.FromStdDuration(500 * time.Millisecond)); !errors.Is(err, ErrInvalidControlPolicy) {
		t.Fatalf("TimeoutControlPersist(500ms) 应拒绝非整秒")
	}
	for _, bad := range []string{"", "-5s", "10x", "999999999999999999999w", "10s\n"} {
		if _, err := ParseControlPersist(bad); !errors.Is(err, ErrInvalidControlPolicy) {
			t.Fatalf("ParseControlPersist(%q) 应失败关闭，实际 %v", bad, err)
		}
	}
	if _, err := ParseControlPath("/tmp/%z"); !errors.Is(err, ErrInvalidControlPolicy) {
		t.Fatalf("ParseControlPath 非法占位符应失败关闭")
	}
	if _, err := NewLiteralControlPath(strings.Repeat(" ", maxTokenLen) + "/a"); !errors.Is(err, ErrInvalidControlPolicy) {
		t.Fatalf("NewLiteralControlPath 超长含空白原始路径应失败关闭，实际 %v", err)
	}
}

func TestEnvFilterMonoidAndSubtractionLaws(t *testing.T) {
	universe := []EnvFilter{
		UnsetEnvFilter(),
		mustEnvFilter(t, "LANG LC_*"),
		mustEnvFilter(t, "-L*"),
		mustEnvFilter(t, "-*"),
		mustEnvFilter(t, "-FOO FOO"),
		mustEnvFilter(t, "FOO BAR -FOO"),
		mustEnvFilter(t, "APP_? TRACE_* -APP_1"),
	}
	assertMonoidLaws(t, "EnvFilter", UnsetEnvFilter(), universe, EnvFilter.Compose, EnvFilter.Equal)

	merged := mustEnvFilter(t, "-L* FOO").Compose(mustEnvFilter(t, "LANG LC_ALL COLORTERM"))
	if !slices.Equal(merged.Patterns(), []string{"COLORTERM", "FOO"}) {
		t.Fatalf("SendEnv -L* 减法结果错误: got=%v", merged.Patterns())
	}
	if !merged.Match("COLORTERM") || !merged.Match("FOO") || merged.Match("LANG") || merged.Match("1INVALID") {
		t.Fatalf("EnvFilter.Match 判定异常")
	}
	gotSorted := merged.FilterSorted(map[string]string{"FOO": "1", "COLORTERM": "truecolor", "LANG": "C", "BAD=NAME": "x"})
	if !slices.Equal(gotSorted, []string{"COLORTERM", "FOO"}) {
		t.Fatalf("EnvFilter.FilterSorted 不确定或含非法名: %v", gotSorted)
	}
	gotMap := merged.Filter(map[string]string{"FOO": "1", "LANG": "C"})
	if len(gotMap) != 1 || gotMap["FOO"] != "1" || !mustEnvFilter(t, "-FOO FOO").Match("FOO") {
		t.Fatalf("EnvFilter.Filter 或先减后加语义错误: %v", gotMap)
	}
	for _, bad := range []string{"", "   ", "-", "FOO=BAR", "BAD$VAR", "LANG\n"} {
		if _, err := ParseEnvFilter(bad); !errors.Is(err, ErrInvalidEnvFilter) {
			t.Fatalf("ParseEnvFilter(%q) 应失败关闭，实际 %v", bad, err)
		}
	}
}

func TestOptionLayerMonoidLaws(t *testing.T) {
	l1 := mustOptionLayer(t, "HostName %h.prod.example.com", "Port 2222", "User alice", "ProxyJump bastion1.example.com",
		"ControlMaster auto", "Ciphers +aes128-ctr", "IdentityFile ~/.ssh/id_a", "UserKnownHostsFile ~/.ssh/kh1",
		"SendEnv LANG LC_*", "PermitLocalCommand yes", "LocalCommand echo ok")
	l2 := mustOptionLayer(t, "Port 2200", "ProxyCommand ssh -W %h:%p gw.example.com", "ControlPath ~/.ssh/cm-%C",
		"ControlPersist 10m", "Ciphers -aes256-ctr", "IdentityFile none", "UserKnownHostsFile none",
		"SendEnv -LC_* TERM", "ForwardAgent yes")
	l3 := mustOptionLayer(t, "ProxyJump none", "Ciphers chacha20-poly1305@openssh.com", "IdentityFile ~/.ssh/id_b",
		"UserKnownHostsFile ~/.ssh/kh2 ~/.ssh/kh3", "SendEnv -* APP_*", "BatchMode yes", "IdentitiesOnly yes",
		"StrictHostKeyChecking accept-new")
	universe := []OptionLayer{UnsetOptionLayer(), l1, l2, l3, DefaultOptionLayer()}
	assertMonoidLaws(t, "OptionLayer", UnsetOptionLayer(), universe, OptionLayer.Compose, OptionLayer.Equal)
}

func mustOptionLayer(t *testing.T, directives ...string) OptionLayer {
	t.Helper()
	l, err := ParseOptionLayer(directives...)
	if err != nil {
		t.Fatalf("ParseOptionLayer 失败: %v", err)
	}
	return l
}
