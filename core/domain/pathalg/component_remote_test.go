package pathalg

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
)

func TestValidateLocalComponentCrossOS(t *testing.T) {
	validNames := []string{
		"a", "file.txt", ".gitignore", ".ssh", "..hidden", "a..b",
		"café.txt", "cafe\u0301.txt", "中文文件.log", "com0.txt", "lpt0",
		"console.txt", "auxiliary", "null.json", "con1", "com10.txt",
		"normal-file_123+v2.tar.gz", strings.Repeat("a", MaxComponentBytes),
	}
	for _, name := range validNames {
		if err := ValidateLocalComponent(name); err != nil {
			t.Fatalf("ValidateLocalComponent(%q) 意外失败: %v", name, err)
		}
	}

	invalidNames := []string{
		"", ".", "..",
		"a/b", "a\\b", "/etc", "\\win",
		"C:", "file:stream", "file.txt:$DATA",
		"a*b", "a?b", `a"b`, "a<b", "a>b", "a|b",
		"bad\x00name", "bad\nname", "bad\rname", "bad\tname", "bad\x1fname", "bad\x7fname",
		"bad\u0085name", "bad\u2028name", "bad\u2029name",
		"bidi\u202etxt", "zwsp\u200bname", "bom\ufeffname", "lri\u2066name",
		string([]byte{0xff, 0xfe}),
		"trailing.", "trailing ", "trailing. ", "trailing .",
		"CON", "con", "Con.txt", "CON .txt", "PRN", "prn.log",
		"AUX", "aux.dat", "NUL", "nul.tar.gz", "NUL   .txt",
		"CONIN$", "conin$.txt", "CONOUT$", "conout$.log",
		"COM1", "com9", "COM5.txt", "LPT1", "lpt9.dat",
		"COM\u00b9", "com\u00b2.txt", "COM\u00b3", "LPT\u00b9", "lpt\u00b2.cfg", "LPT\u00b3",
		strings.Repeat("x", MaxComponentBytes+1),
	}
	for _, name := range invalidNames {
		err := ValidateLocalComponent(name)
		if !errors.Is(err, ErrInvalidComponent) {
			t.Fatalf("ValidateLocalComponent(%q) = %v, 期望包装 ErrInvalidComponent", name, err)
		}
	}
}

func TestRemoteNameLifecycleAndCodec(t *testing.T) {
	var zero RemoteName
	if zero.IsValid() || !zero.IsZero() || zero.String() != "" || zero.Equal(zero) {
		t.Fatal("零值 RemoteName 必须失败关闭")
	}
	if _, err := zero.MarshalText(); !errors.Is(err, ErrInvalidRemoteName) {
		t.Fatalf("零值 RemoteName.MarshalText = %v, 期望 ErrInvalidRemoteName", err)
	}
	var nilPtr *RemoteName
	if err := nilPtr.UnmarshalText([]byte("ok")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil UnmarshalText = %v, 期望 ErrNilReceiver", err)
	}

	// POSIX 远端文件名允许包含 ':' 与 '\'（仅在桥接至 LocalRootedDest 时施加本地组件约束）。
	validNames := []string{"passwd", "foo:bar", `lit\slash`, "café", "cafe\u0301", strings.Repeat("r", MaxComponentBytes)}
	for _, raw := range validNames {
		n, err := ParseRemoteName(raw)
		if err != nil || !n.IsValid() || n.IsZero() || n.String() != raw {
			t.Fatalf("ParseRemoteName(%q) = (%v, %v)", raw, n, err)
		}
		assertTextAndJSONRoundTrip(t, n, raw)
	}

	badNames := []string{
		"", ".", "..", "a/b", "/", "bad\x00", "bad\n", "bidi\u202e", "zwsp\u200b",
		"sep\u2028", string([]byte{0xff}), strings.Repeat("z", MaxComponentBytes+1),
	}
	for _, raw := range badNames {
		if _, err := ParseRemoteName(raw); !errors.Is(err, ErrInvalidRemoteName) {
			t.Fatalf("ParseRemoteName(%q) = %v, 期望 ErrInvalidRemoteName", raw, err)
		}
	}

	n, err := ParseRemoteName("valid.txt")
	if err != nil {
		t.Fatalf("ParseRemoteName 失败: %v", err)
	}
	if err := n.UnmarshalText([]byte("../escape")); !errors.Is(err, ErrInvalidRemoteName) || n.IsValid() {
		t.Fatalf("UnmarshalText 失败后必须重置零值: n=%v err=%v", n, err)
	}
}

func TestRemotePathAlgebraAndIdempotence(t *testing.T) {
	var zero RemotePath
	if zero.IsValid() || !zero.IsZero() || zero.IsAbs() || zero.IsRoot() || zero.String() != "" ||
		zero.Canonical().IsValid() || zero.Dir().IsValid() || zero.Equal(zero) || zero.HasPrefix(zero) {
		t.Fatal("零值 RemotePath 必须全面失败关闭")
	}
	if _, ok := zero.Base(); ok {
		t.Fatal("零值 RemotePath.Base 应返回 false")
	}
	if _, err := zero.AppendText(nil); !errors.Is(err, ErrInvalidRemotePath) {
		t.Fatalf("零值 AppendText = %v, 期望 ErrInvalidRemotePath", err)
	}

	cases := []struct {
		raw      string
		want     string
		wantAbs  bool
		wantDir  string
		wantBase string
		hasBase  bool
	}{
		{"/", "/", true, "/", "", false},
		{"///", "/", true, "/", "", false},
		{"/etc//ssh/./sshd_config", "/etc/ssh/sshd_config", true, "/etc/ssh", "sshd_config", true},
		{"/a/b/../c/", "/a/c", true, "/a", "c", true},
		{"/../etc/passwd", "/etc/passwd", true, "/etc", "passwd", true},
		{".", ".", false, ".", "", false},
		{"..", "..", false, ".", "", false},
		{"../..", "../..", false, "..", "", false},
		{"a/b/../c", "a/c", false, "a", "c", true},
		{"/tmp/cafe\u0301", "/tmp/cafe\u0301", true, "/tmp", "cafe\u0301", true},
	}
	for _, tc := range cases {
		assertRemotePathCase(t, tc.raw, tc.want, tc.wantAbs, tc.wantDir, tc.wantBase, tc.hasBase)
	}

	if _, err := ParseAbsRemotePath("relative/file"); !errors.Is(err, ErrInvalidRemotePath) {
		t.Fatalf("ParseAbsRemotePath(relative) = %v, 期望 ErrInvalidRemotePath", err)
	}
	assertRemotePathRejections(t)
}

func assertRemotePathCase(t *testing.T, raw, want string, wantAbs bool, wantDir, wantBase string, hasBase bool) {
	t.Helper()
	p, err := ParseRemotePath(raw)
	if err != nil {
		t.Fatalf("ParseRemotePath(%q) 失败: %v", raw, err)
	}
	if p.String() != want || p.IsAbs() != wantAbs || p.Dir().String() != wantDir || !p.Canonical().Equal(p) {
		t.Fatalf("ParseRemotePath(%q) = (str=%q abs=%v dir=%q)", raw, p.String(), p.IsAbs(), p.Dir().String())
	}
	p2, err := ParseRemotePath(p.String())
	if err != nil || !p.Equal(p2) || p.Compare(p2) != 0 {
		t.Fatalf("RemotePath 幂等律失败: raw=%q canon=%q err=%v", raw, p.String(), err)
	}
	base, ok := p.Base()
	if ok != hasBase || (ok && base.String() != wantBase) {
		t.Fatalf("RemotePath(%q).Base() = (%q, %v), 期望 (%q, %v)", want, base.String(), ok, wantBase, hasBase)
	}
	assertTextAndJSONRoundTrip(t, p, want)
}

func assertRemotePathRejections(t *testing.T) {
	t.Helper()
	badPaths := []string{
		"", "a\x00b", "/etc/pass\nwd", "/etc/\u202epasswd", "/etc/\u200bhosts",
		"/etc/a\u2028b", string([]byte{'/', 0xff}),
		"/" + strings.Repeat("a", MaxComponentBytes+1),
		"/" + strings.Repeat("a/", MaxRemotePathBytes/2+2),
	}
	for _, raw := range badPaths {
		if _, err := ParseRemotePath(raw); !errors.Is(err, ErrInvalidRemotePath) {
			t.Fatalf("ParseRemotePath(%q) = %v, 期望 ErrInvalidRemotePath", raw, err)
		}
	}
}

func TestRemotePathJoinResolveRelAndPrefix(t *testing.T) {
	etc := mustRemotePath(t, "/etc")
	sshName := mustRemoteName(t, "ssh")
	cfgName := mustRemoteName(t, "sshd_config")
	joined, err := etc.Join(sshName, cfgName)
	if err != nil || joined.String() != "/etc/ssh/sshd_config" {
		t.Fatalf("Join = (%q, %v)", joined.String(), err)
	}
	if _, err := etc.Join(RemoteName{}); !errors.Is(err, ErrInvalidRemotePath) {
		t.Fatalf("Join(零值 RemoteName) = %v, 期望 ErrInvalidRemotePath", err)
	}

	relCases := [][3]string{
		{"/etc/ssh", "/etc/ssh/sshd_config", "sshd_config"},
		{"/etc/ssh", "/var/log/auth.log", "../../var/log/auth.log"},
		{"/", "/etc/passwd", "etc/passwd"},
		{"/etc", "/etc", "."},
		{"a/b", "a/c/d", "../c/d"},
		{".", "a/b", "a/b"},
	}
	for _, tc := range relCases {
		base := mustRemotePath(t, tc[0])
		target := mustRemotePath(t, tc[1])
		rel, err := base.Rel(target)
		if err != nil || rel.String() != tc[2] {
			t.Fatalf("Rel(%q, %q) = (%q, %v), 期望 %q", tc[0], tc[1], rel.String(), err, tc[2])
		}
		roundTrip, err := base.Resolve(rel)
		if err != nil || !roundTrip.Equal(target) {
			t.Fatalf("base.Resolve(rel) 往返失败: base=%q rel=%q got=%q want=%q err=%v", tc[0], rel.String(), roundTrip.String(), tc[1], err)
		}
	}

	if _, err := mustRemotePath(t, "/etc").Rel(mustRemotePath(t, "etc")); !errors.Is(err, ErrInvalidRemotePath) {
		t.Fatalf("绝对/相对混算 Rel 应失败关闭: %v", err)
	}
	if _, err := mustRemotePath(t, "../a").Rel(mustRemotePath(t, "b")); !errors.Is(err, ErrInvalidRemotePath) {
		t.Fatalf("含 '..' 相对基准 Rel 应失败关闭: %v", err)
	}
}

func TestRemotePathHasPrefixBoundaries(t *testing.T) {
	etc := mustRemotePath(t, "/etc")
	cfg := mustRemotePath(t, "/etc/ssh/sshd_config")
	root := mustRemotePath(t, "/")
	etc2 := mustRemotePath(t, "/etc2/foo")
	if !cfg.HasPrefix(etc) || !cfg.HasPrefix(root) || !etc.HasPrefix(etc) || etc2.HasPrefix(etc) {
		t.Fatal("绝对路径 HasPrefix 段边界语义错误")
	}

	// 相对路径 ".." 子树边界回归：父目录上行 "../.." 不得落入 ".." 子树，而 "../a" 应落入 ".." 子树。
	parentRel := mustRemotePath(t, "..")
	grandParentRel := mustRemotePath(t, "../..")
	grandChildRel := mustRemotePath(t, "../../a")
	parentChildRel := mustRemotePath(t, "../a")
	dotRel := mustRemotePath(t, ".")
	subRel := mustRemotePath(t, "sub/file")
	if grandParentRel.HasPrefix(parentRel) || grandChildRel.HasPrefix(parentRel) ||
		!parentChildRel.HasPrefix(parentRel) || !parentRel.HasPrefix(parentRel) {
		t.Fatal("相对 '..' 路径 HasPrefix 子树边界语义错误")
	}
	if !subRel.HasPrefix(dotRel) || parentRel.HasPrefix(dotRel) || parentChildRel.HasPrefix(dotRel) {
		t.Fatal("相对 '.' 路径 HasPrefix 子树边界语义错误")
	}
}

func assertTextAndJSONRoundTrip[T interface {
	AppendText([]byte) ([]byte, error)
	MarshalText() ([]byte, error)
	String() string
}](t *testing.T, val T, want string) {
	t.Helper()
	appended, err := val.AppendText([]byte("pre:"))
	if err != nil || string(appended) != "pre:"+want {
		t.Fatalf("AppendText = (%q, %v), 期望 %q", appended, err, "pre:"+want)
	}
	raw, err := val.MarshalText()
	if err != nil || string(raw) != want {
		t.Fatalf("MarshalText = (%q, %v), 期望 %q", raw, err, want)
	}
	j1, err := jsonv2.Marshal(val, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("jsonv2.Marshal(%q) 失败: %v", want, err)
	}
	var decoded T
	if err := jsonv2.Unmarshal(j1, &decoded); err != nil {
		t.Fatalf("jsonv2.Unmarshal(%s) 失败: %v", j1, err)
	}
	j2, err := jsonv2.Marshal(decoded, jsonv2.Deterministic(true))
	if err != nil || !bytes.Equal(j1, j2) || decoded.String() != want {
		t.Fatalf("jsonv2 往返不一致: j1=%s j2=%s str=%q", j1, j2, decoded.String())
	}
}

func mustRemotePath(t *testing.T, raw string) RemotePath {
	t.Helper()
	p, err := ParseRemotePath(raw)
	if err != nil {
		t.Fatalf("ParseRemotePath(%q) 失败: %v", raw, err)
	}
	return p
}

func mustRemoteName(t *testing.T, raw string) RemoteName {
	t.Helper()
	n, err := ParseRemoteName(raw)
	if err != nil {
		t.Fatalf("ParseRemoteName(%q) 失败: %v", raw, err)
	}
	return n
}
