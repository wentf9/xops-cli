package pathalg

import (
	"errors"
	"slices"
	"testing"
)

func TestProtectedPathMatcherZeroAndRuleValidation(t *testing.T) {
	var zeroMatcher ProtectedPathMatcher
	if zeroMatcher.IsValid() || !zeroMatcher.IsZero() || zeroMatcher.RuleCount() != 0 {
		t.Fatal("零值 ProtectedPathMatcher 必须无效")
	}
	if _, err := zeroMatcher.Match("/etc/passwd"); !errors.Is(err, ErrInvalidProtectedRule) {
		t.Fatalf("零值 Match = %v, 期望 ErrInvalidProtectedRule", err)
	}
	if _, err := zeroMatcher.MatchRecursive("/"); !errors.Is(err, ErrInvalidProtectedRule) {
		t.Fatalf("零值 MatchRecursive = %v, 期望 ErrInvalidProtectedRule", err)
	}

	var zeroMatch ProtectedMatch
	if zeroMatch.IsValid() || zeroMatch.Matched() || zeroMatch.SameZones(zeroMatch) || !zeroMatch.IntroducesNewZoneOver(zeroMatch) {
		t.Fatal("零值 ProtectedMatch 必须在安全比较谓词中失败关闭")
	}

	badRules := []string{
		"", "etc/passwd", "relative/**", "/etc/[unclosed", "/etc/[z-a]",
		"/bad\x00rule", "/bidi\u202erule", "//onlyserver", string([]byte{'/', 0xff}),
	}
	for _, pat := range badRules {
		if _, err := ParseProtectedRule(pat); !errors.Is(err, ErrInvalidProtectedRule) {
			t.Fatalf("ParseProtectedRule(%q) = %v, 期望 ErrInvalidProtectedRule", pat, err)
		}
	}
}

func TestProtectedPathMatcherPOSIXGlobAndNFC(t *testing.T) {
	matcher, err := NewProtectedPathMatcher([]string{
		"/etc/**",
		"/root/**",
		"/var/log/auth-?.log",
		"/opt/app/*.[ck]fg",
		"/srv/caf\u00e9/**",
		"**/.ssh/**",
	})
	if err != nil {
		t.Fatalf("NewProtectedPathMatcher 失败: %v", err)
	}

	mustHit := []string{
		"/etc", "/etc/passwd", "/etc/ssh/sshd_config", "/tmp/../etc/shadow",
		`\etc\passwd`, `/tmp/\../etc/passwd`,
		"/root", "/root/.bashrc",
		"/var/log/auth-1.log", "/var/log/auth-日.log",
		"/opt/app/db.cfg", "/opt/app/web.kfg",
		"/srv/cafe\u0301/secret.key", // NFD 命中 NFC 规则
		"/home/alice/.ssh", "/home/alice/.ssh/id_ed25519",
		".ssh/authorized_keys",
	}
	for _, target := range mustHit {
		res, err := matcher.Match(target)
		if err != nil || !res.Matched() {
			t.Fatalf("Match(%q) = (matched=%v, err=%v), 期望命中", target, res.Matched(), err)
		}
	}

	mustMiss := []string{
		"/etc2/passwd", "/rootkit/a", "/var/log/auth-12.log", "/var/log/sub/auth-1.log",
		"/opt/app/sub/db.cfg", "/opt/app/db.xfg", "/tmp/safe.txt",
	}
	for _, target := range mustMiss {
		res, err := matcher.Match(target)
		if err != nil || res.Matched() {
			t.Fatalf("Match(%q) = (matched=%v, rules=%v, err=%v), 期望不命中", target, res.Matched(), res.Rules(), err)
		}
	}

	// POSIX 字面反斜杠保真测试（INV-E3）：Linux 路径 "/opt/protected/\../drop" 仍留在 /opt/protected 下。
	posixMatcher, err := NewProtectedPathMatcher([]string{"/opt/protected/**"})
	if err != nil {
		t.Fatalf("NewProtectedPathMatcher 失败: %v", err)
	}
	res, err := posixMatcher.Match(`/opt/protected/\../drop`)
	if err != nil || !res.Matched() {
		t.Fatalf("POSIX 字面反斜杠路径应保真命中: matched=%v err=%v", res.Matched(), err)
	}
}

func TestProtectedPathMatcherWin32AndLoopbackObfuscations(t *testing.T) {
	matcher, err := NewProtectedPathMatcher([]string{
		"C:/Windows/**",
		`//filesrv/secrets/**`,
		"**/.ssh/**",
	})
	if err != nil {
		t.Fatalf("NewProtectedPathMatcher 失败: %v", err)
	}

	winTargets := []string{
		`C:\Windows`,
		`C:\Windows\System32\config\SAM`,
		"c:/windows/win.ini",
		`/C:/Windows/System32/drivers/etc/hosts`,
		`/tmp/../C:/Windows/win.ini`,
		`\\?\C:\Windows\System32\cmd.exe`,
		`\\.\C:\Windows\win.ini`,
		`\??\C:\Windows\win.ini`,
		`//?/C:/Windows/win.ini`,
		`\\localhost\C$\Windows\System32`,
		`\\localhost.\c$\windows\win.ini`,
		`\\127.0.0.1\C$\Windows\System32`,
		`\\127.9.8.7\c$\Windows\win.ini`,
		`\\[::1]\C$\Windows\System32`,
		`\\[0:0:0:0:0:0:0:1]\C$\Windows\win.ini`,
		`\\[::ffff:127.0.0.1]\C$\Windows\win.ini`,
		`\\?\UNC\127.0.0.1\C$\Windows\System32`,
		`\\?\GLOBALROOT\??\C:\Windows\System32\cmd.exe`,
		`\\.\GLOBALROOT\DosDevices\C:\Windows\win.ini`,
		`\\?\GLOBALROOT\??\UNC\127.0.0.1\C$\Windows\win.ini`,
		`\\?\GLOBAL\C:\Windows\win.ini`,
		`\\?/C:\Windows\win.ini`,
		`/\?\C:\Windows\win.ini`,
		`\/?\C:\Windows\win.ini`,
		`/\.\C:\Windows\win.ini`,
		`\??/C:\Windows\win.ini`,
		`/\localhost\C$\Windows\System32`,
		`\/localhost/C$/Windows/System32`,
		`/\127.0.0.1\C$\Windows\win.ini`,
		`/\C:\Windows\win.ini`,
		`/tmp/../\?\C:\Windows\win.ini`,
		`//\?\C:\Windows\win.ini`,
		`/tmp/../\localhost\C$\Windows\win.ini`,
		`\tmp\..\C:\Windows\win.ini`,
		`C:\Temp\.. \Windows\win.ini`,
		`C:\Temp\..:$DATA\Windows\win.ini`,
		`\\[::1%1]\C$\Windows\System32`,
		`\\[::1%lo]\C$\Windows\win.ini`,
		`\\--1.ipv6-literal.net\C$\Windows\win.ini`,
		`\\0-0-0-0-0-0-0-1.ipv6-literal.net\C$\Windows\win.ini`,
		`\\--1s1.ipv6-literal.net\C$\Windows\win.ini`,
		`\\--ffff-7f00-1.ipv6-literal.net\C$\Windows\win.ini`,
		`\\127.1\C$\Windows\win.ini`,
		`\\0177.0.0.1\C$\Windows\win.ini`,
		`\\0x7f000001\C$\Windows\win.ini`,
		`\\2130706433\C$\Windows\win.ini`,
		`C:\Windows.\System32 \hosts:$DATA`,
		`C:\Windows::$INDEX_ALLOCATION\System32`,
		`\\filesrv\secrets\prod.key`,
		`/\filesrv\secrets\prod.key`,
		`\\?\UNC\FILESRV\SECRETS\prod.key`,
		`D:\Users\alice\.ssh\id_ed25519`,
	}
	for _, target := range winTargets {
		res, err := matcher.Match(target)
		if err != nil || !res.Matched() {
			t.Fatalf("Win32 路径 %q 应命中受保护规则: matched=%v err=%v", target, res.Matched(), err)
		}
	}

	// 不同盘符与非回环远端 UNC 共享（含合法远端主机与非回环 ipv6-literal.net）不得误命中 C:/Windows/**
	for _, target := range []string{
		`D:\Windows\System32`, `\\192.0.2.10\C$\Windows`, `\\filesrv\C$\Windows`,
		`\\2001-db8--1.ipv6-literal.net\C$\Windows`, `\\srv2\public\a.txt`,
	} {
		res, err := matcher.Match(target)
		if err != nil || res.Matched() {
			t.Fatalf("非目标盘符/非回环 UNC %q 不应命中: matched=%v rules=%v err=%v", target, res.Matched(), res.Rules(), err)
		}
	}
}

func TestProtectedPathMatcherWin32RuleSymmetryAndPOSIXFidelity(t *testing.T) {
	// Win32 设备与扩展前缀规则必须对称规范化并准确匹配自身与等价写法。
	matcher, err := NewProtectedPathMatcher([]string{
		`\\.\PhysicalDrive0`,
		`\\?\C:\Windows\**`,
		`\\?\UNC\filesrv\secrets\**`,
		"/opt/**",
	})
	if err != nil {
		t.Fatalf("NewProtectedPathMatcher(Win32 扩展规则): %v", err)
	}
	assertMatcherHitsAndMisses(
		t, matcher,
		[]string{
			`\\.\PhysicalDrive0`, `//./physicaldrive0`, `\??\PhysicalDrive0`,
			`\\?\C:\Windows\System32`, `C:\Windows\win.ini`,
			`\\?\UNC\filesrv\secrets\a.key`, `\\filesrv\secrets\a.key`,
			"/opt/app",
		},
		[]string{
			`\\.\PhysicalDrive1`,
			"//?/opt/x", // POSIX 路径与设备命名空间隔离，绝不误命中 POSIX 规则 /opt/**
		},
	)
	if _, err := ParseProtectedRule(`\\.\`); !errors.Is(err, ErrInvalidProtectedRule) {
		t.Fatalf("空 Win32 设备规则必须拒绝: %v", err)
	}
}

func mustClassifiedMatcher(t *testing.T) ProtectedPathMatcher {
	t.Helper()
	specs := [][2]string{
		{"C:/Windows/**", "zone:win-os"},
		{"/root/**", "zone:root"},
		{"/etc/**", "zone:etc"},
		{"/home/*/.ssh/**", "zone:user-ssh"},
	}
	rules := make([]ProtectedRule, 0, len(specs))
	for _, sp := range specs {
		r, err := NewProtectedRule(sp[0], sp[1])
		if err != nil {
			t.Fatalf("NewProtectedRule(%q, %q): %v", sp[0], sp[1], err)
		}
		rules = append(rules, r)
	}
	matcher, err := NewClassifiedProtectedPathMatcher(rules)
	if err != nil {
		t.Fatalf("NewClassifiedProtectedPathMatcher: %v", err)
	}
	return matcher
}

func TestProtectedPathMatcherZoneRedirect(t *testing.T) {
	matcher := mustClassifiedMatcher(t)

	// Protected-A (/etc/**) -> Protected-B (/root/**) 软链重定向检测
	preA, err := matcher.MatchRemotePath(mustRemotePath(t, "/etc/my-link"))
	if err != nil || !preA.Matched() {
		t.Fatalf("preA 应命中 zone:etc: %v", err)
	}
	postA, err := matcher.MatchRemotePath(mustRemotePath(t, "/etc/ssh/sshd_config"))
	if err != nil || !postA.Matched() {
		t.Fatalf("postA 应命中 zone:etc: %v", err)
	}
	postB, err := matcher.MatchRemotePath(mustRemotePath(t, "/root/.ssh/authorized_keys"))
	if err != nil || !postB.Matched() {
		t.Fatalf("postB 应命中 zone:root: %v", err)
	}
	if !preA.SameZones(postA) || postA.IntroducesNewZoneOver(preA) {
		t.Fatal("同区重解析不应触发区域变更升级")
	}
	if preA.SameZones(postB) || !postB.IntroducesNewZoneOver(preA) {
		t.Fatal("Protected-A -> Protected-B 软链重定向必须触发 IntroducesNewZoneOver == true")
	}

	preUnprot, err := matcher.Match("/tmp/link")
	if err != nil || preUnprot.Matched() {
		t.Fatalf("preUnprot 不应命中: %v", err)
	}
	if !postA.IntroducesNewZoneOver(preUnprot) {
		t.Fatal("非保护 -> 保护必须触发 IntroducesNewZoneOver == true")
	}
}

func TestProtectedPathMatcherAncestors(t *testing.T) {
	matcher := mustClassifiedMatcher(t)

	ancRoot, err := matcher.MatchRecursive("/")
	if err != nil || !ancRoot.Matched() {
		t.Fatalf("MatchRecursive('/') 应命中祖先规则: %v", err)
	}
	if !slices.Equal(ancRoot.Zones(), []string{"zone:etc", "zone:root", "zone:user-ssh"}) {
		t.Fatalf("MatchRecursive('/') 命中区域序不符合确定性期望: %v", ancRoot.Zones())
	}
	primary, ok := ancRoot.PrimaryRule()
	if !ok || primary.Kind() != MatchAncestorContainsProtected {
		t.Fatalf("MatchRecursive('/') 应为祖先命中: %+v", primary)
	}

	ancHome, err := matcher.MatchRecursive("/home/alice")
	if err != nil || !ancHome.Matched() || !slices.Equal(ancHome.Zones(), []string{"zone:user-ssh"}) {
		t.Fatalf("MatchRecursive('/home/alice') 应命中 /home/*/.ssh/** 祖先: zones=%v err=%v", ancHome.Zones(), err)
	}
	ancWin, err := matcher.MatchRecursive(`C:\`)
	if err != nil || !ancWin.Matched() || !slices.Equal(ancWin.Zones(), []string{"zone:win-os"}) {
		t.Fatalf("MatchRecursive('C:\\') 应命中 C:/Windows/** 祖先: zones=%v err=%v", ancWin.Zones(), err)
	}
}

func TestProtectedPathMatcherLiteralPrefixAndCharClass(t *testing.T) {
	if MatchNone.String() != "none" || MatchDirect.String() != "direct" ||
		MatchAncestorContainsProtected.String() != "ancestor_contains_protected" {
		t.Fatal("MatchKind.String() 返回值异常")
	}

	rLit, err := ParseProtectedRule("/etc")
	if err != nil || !rLit.IsValid() || rLit.Canonical() != "/etc" || rLit.Class() != "/etc" {
		t.Fatalf("ParseProtectedRule('/etc') 异常: %+v %v", rLit, err)
	}
	matcher, err := NewProtectedPathMatcher([]string{"/etc", "/etc", "/opt/[!0-9]*.conf", "C:/[A-Z]*/secret"})
	if err != nil || matcher.RuleCount() != 3 {
		t.Fatalf("规则去重或构造异常: count=%d err=%v", matcher.RuleCount(), err)
	}

	res, err := matcher.Match("/etc/shadow")
	if err != nil || !res.Matched() || len(res.Rules()) != 1 {
		t.Fatalf("字面规则 '/etc' 应命中 '/etc/shadow': %v %v", res.Rules(), err)
	}
	first := res.Rules()[0]
	if !first.IsValid() || first.CanonicalRule() != "/etc" || first.Class() != "/etc" {
		t.Fatalf("ProtectedRuleMatch 字段异常: %+v", first)
	}
	assertMatcherHitsAndMisses(t, matcher, []string{"/opt/app.conf", `c:\alpha\secret`}, []string{"/etc2/shadow", "/opt/9app.conf"})
}

func TestProtectedPathMatcherRootAllNamespaces(t *testing.T) {
	// 根规则 "/" 保护全部有根命名空间（POSIX / Win32 盘符 / UNC / 设备命名空间），不误匹配裸相对路径。
	rootMatcher, err := NewProtectedPathMatcher([]string{"/"})
	if err != nil {
		t.Fatalf("NewProtectedPathMatcher('/'): %v", err)
	}
	assertMatcherHitsAndMisses(
		t, rootMatcher,
		[]string{"/any", `C:\Temp\a`, `\\.\PhysicalDrive0`, `\\?\GLOBALROOT\Device\HarddiskVolume1`},
		[]string{"rel/file"},
	)
}

func assertMatcherHitsAndMisses(t *testing.T, matcher ProtectedPathMatcher, hits, misses []string) {
	t.Helper()
	for _, target := range hits {
		if m, err := matcher.Match(target); err != nil || !m.Matched() {
			t.Fatalf("期望命中 %q: matched=%v err=%v", target, m.Matched(), err)
		}
	}
	for _, target := range misses {
		if m, err := matcher.Match(target); err != nil || m.Matched() {
			t.Fatalf("期望不命中 %q: matched=%v err=%v", target, m.Matched(), err)
		}
	}
}
