package pathalg

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseRemotePath 模糊测试远端 POSIX 路径解析的幂等性、UTF-8 合法性与往返一致性。
func FuzzParseRemotePath(f *testing.F) {
	seeds := []string{
		"/", "/etc/passwd", "/a/b/../c", ".", "..", "rel/path",
		"/tmp/cafe\u0301", "/etc//ssh/./config", "", "/bad\x00", "/bidi\u202e",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		checkFuzzRemotePath(t, raw)
	})
}

func checkFuzzRemotePath(t *testing.T, raw string) {
	t.Helper()
	p, err := ParseRemotePath(raw)
	if err != nil {
		if p.IsValid() {
			t.Fatalf("失败返回有效 RemotePath: %+v", p)
		}
		return
	}
	if !p.IsValid() || !utf8.ValidString(p.String()) || hasForbiddenPathText(p.String()) {
		t.Fatalf("有效 RemotePath 违反基本不变量: %q", p.String())
	}
	p2, err := ParseRemotePath(p.String())
	if err != nil || !p.Equal(p2) {
		t.Fatalf("RemotePath 幂等律破坏: %q -> %q (err=%v)", raw, p.String(), err)
	}
	if base, ok := p.Base(); ok && (!base.IsValid() || strings.ContainsRune(base.String(), '/')) {
		t.Fatalf("非法 Base: %q", base.String())
	}
}

// FuzzParseLocalRootedDest 模糊测试沙箱相对目标路径的幂等性、组件安全性与无逃逸不变量。
func FuzzParseLocalRootedDest(f *testing.F) {
	seeds := []string{
		"file.txt", "a/b/c.log", "caf\u00e9/cafe\u0301", "", ".", "..",
		"/etc/passwd", `a\b`, "a/../b", "CON.txt", "dir/file:$DATA", "a/b.",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		checkFuzzLocalRootedDest(t, raw)
	})
}

func checkFuzzLocalRootedDest(t *testing.T, raw string) {
	t.Helper()
	d, err := ParseLocalRootedDest(raw)
	if err != nil {
		if d.IsValid() {
			t.Fatalf("失败返回有效 LocalRootedDest: %+v", d)
		}
		return
	}
	s := d.String()
	if strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") || strings.ContainsAny(s, `\:`) {
		t.Fatalf("有效 LocalRootedDest 含非法分隔符或冒号: %q", s)
	}
	for _, seg := range d.Segments() {
		if err := ValidateLocalComponent(seg); err != nil {
			t.Fatalf("LocalRootedDest 分量 %q 未通过 ValidateLocalComponent: %v", seg, err)
		}
	}
	d2, err := ParseLocalRootedDest(s)
	if err != nil || !d.Equal(d2) {
		t.Fatalf("LocalRootedDest 幂等律破坏: %q (err=%v)", s, err)
	}
}

// FuzzValidateLocalComponent 模糊测试跨平台单分量校验的失败关闭不变量。
func FuzzValidateLocalComponent(f *testing.F) {
	seeds := []string{
		"", ".", "..", "a.txt", "CON", "con .txt", "COM\u00b9", "LPT9.log",
		"file:$DATA", "a/b", `a\b`, "bad\x00", "bidi\u202e", "trail.", "trail ",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if ValidateLocalComponent(name) != nil {
			return
		}
		if name == "" || name == "." || name == ".." || len(name) > MaxComponentBytes ||
			!utf8.ValidString(name) || hasForbiddenPathText(name) ||
			strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") ||
			strings.ContainsAny(name, `/\:*?"<>|`) {
			t.Fatalf("ValidateLocalComponent 错误放行非法分量 %q", name)
		}
	})
}

// FuzzProtectedPathMatcher 模糊测试受保护路径编译、匹配、NFC 等价性与确定性。
func FuzzProtectedPathMatcher(f *testing.F) {
	f.Add("/etc/**", "/etc/passwd")
	f.Add("C:/Windows/**", `\\127.0.0.1\C$\Windows\System32`)
	f.Add("/srv/caf\u00e9/**", "/srv/cafe\u0301/a")
	f.Add("**/.ssh/**", "/home/u/.ssh/id_ed25519")
	f.Add("/opt/*.[a-z]", "/opt/x.a")
	f.Fuzz(func(t *testing.T, pattern, target string) {
		checkFuzzProtectedPathMatcher(t, pattern, target)
	})
}

func checkFuzzProtectedPathMatcher(t *testing.T, pattern, target string) {
	t.Helper()
	matcher, err := NewProtectedPathMatcher([]string{pattern})
	if err != nil {
		return
	}
	r1, err1 := matcher.Match(target)
	r2, err2 := matcher.Match(target)
	if (err1 == nil) != (err2 == nil) {
		t.Fatalf("Match 确定性破坏: err1=%v err2=%v", err1, err2)
	}
	if err1 != nil {
		return
	}
	if !r1.SameZones(r2) || r1.IntroducesNewZoneOver(r2) {
		t.Fatalf("同输入匹配区域不一致: %v vs %v", r1.Zones(), r2.Zones())
	}
	if nfcTarget, err := NormalizeNFC(target); err == nil {
		rNFC, errNFC := matcher.Match(nfcTarget)
		if errNFC != nil || !r1.SameZones(rNFC) {
			t.Fatalf("NFC 目标匹配不一致: target=%q nfc=%q err=%v", target, nfcTarget, errNFC)
		}
	}
}

// FuzzFoldCollisionKey 模糊证明 FoldCollisionKey 在任意合法 UTF-8 上满足幂等律与 NFC/NFD 不变律。
func FuzzFoldCollisionKey(f *testing.F) {
	for _, s := range []string{"", "caf\u00e9", "cafe\u0301", "STRASSE", "stra\u00dfe", "\u212a", "\u017f", "\u03c2", "\u0130", "\ufb01"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		checkFuzzFoldCollisionKey(t, raw)
	})
}

func checkFuzzFoldCollisionKey(t *testing.T, raw string) {
	t.Helper()
	k1, err := FoldCollisionKey(raw)
	if err != nil {
		if utf8.ValidString(raw) {
			t.Fatalf("合法 UTF-8 %q 折叠失败: %v", raw, err)
		}
		return
	}
	k2, err := FoldCollisionKey(k1)
	if err != nil || k1 != k2 {
		t.Fatalf("FoldCollisionKey 幂等律破坏: %q -> %q -> %q (err=%v)", raw, k1, k2, err)
	}
	nfc, _ := NormalizeNFC(raw)
	nfd, _ := NormalizeNFD(raw)
	knfc, _ := FoldCollisionKey(nfc)
	knfd, _ := FoldCollisionKey(nfd)
	if knfc != knfd {
		t.Fatalf("NFC/NFD 折叠不等价: raw=%q knfc=%q knfd=%q", raw, knfc, knfd)
	}
}
