package pathalg

import (
	"errors"
	"strings"
	"testing"
)

func TestLocalRootedDestValidationAndAlgebra(t *testing.T) {
	assertLocalRootedDestZero(t)

	d, err := ParseLocalRootedDest("dir/sub/file.txt")
	if err != nil || !d.IsValid() || d.Depth() != 3 || d.Base() != "file.txt" {
		t.Fatalf("ParseLocalRootedDest 失败: d=%v err=%v", d, err)
	}
	parent, ok := d.Parent()
	if !ok || parent.String() != "dir/sub" {
		t.Fatalf("Parent = (%q, %v)", parent.String(), ok)
	}
	joined, err := parent.JoinRemoteName(mustRemoteName(t, "other.txt"))
	if err != nil || joined.String() != "dir/sub/other.txt" {
		t.Fatalf("JoinRemoteName = (%q, %v)", joined.String(), err)
	}
	fromComps, err := LocalRootedDestFromComponents("dir", "sub", "file.txt")
	if err != nil || !fromComps.Equal(d) {
		t.Fatalf("LocalRootedDestFromComponents = (%q, %v)", fromComps.String(), err)
	}
	assertTextAndJSONRoundTrip(t, d, "dir/sub/file.txt")
	assertLocalRootedDestRejections(t, parent)
}

func assertLocalRootedDestZero(t *testing.T) {
	t.Helper()
	var zero LocalRootedDest
	if zero.IsValid() || !zero.IsZero() || zero.Depth() != 0 || zero.Base() != "" || zero.Segments() != nil || zero.Equal(zero) {
		t.Fatal("零值 LocalRootedDest 必须失败关闭")
	}
	if _, ok := zero.Parent(); ok {
		t.Fatal("零值 Parent 应返回 false")
	}
	if _, err := zero.MarshalText(); !errors.Is(err, ErrInvalidLocalDest) {
		t.Fatalf("零值 MarshalText = %v, 期望 ErrInvalidLocalDest", err)
	}
}

func assertLocalRootedDestRejections(t *testing.T, parent LocalRootedDest) {
	t.Helper()
	// 远端合法但本地危险的文件名（含 ':' 或保留设备名）在桥接至 LocalRootedDest 时必须拒绝。
	if _, err := parent.JoinRemoteName(mustRemoteName(t, "file:ads")); !errors.Is(err, ErrInvalidLocalDest) {
		t.Fatalf("含 ':' 远端名应被 JoinRemoteName 拒绝: %v", err)
	}
	if _, err := parent.JoinRemoteName(mustRemoteName(t, "CON.txt")); !errors.Is(err, ErrInvalidLocalDest) {
		t.Fatalf("保留设备名应被 JoinRemoteName 拒绝: %v", err)
	}
	badDests := []string{
		"", ".", "..", "/", "/etc/passwd", "a/", "a//b", "a/./b", "a/../b",
		`a\b`, `C:\Temp\a.txt`, "C:/Temp/a.txt", `\\server\share\a`,
		"dir/CON.txt", "dir/file:$DATA", "dir/trail.", "dir/bad\u202ename",
	}
	for _, raw := range badDests {
		if _, err := ParseLocalRootedDest(raw); !errors.Is(err, ErrInvalidLocalDest) {
			t.Fatalf("ParseLocalRootedDest(%q) = %v, 期望 ErrInvalidLocalDest", raw, err)
		}
	}
}

func TestLocalDirAndLocalSourcePathCrossOS(t *testing.T) {
	var zeroDir LocalDir
	var zeroSrc LocalSourcePath
	if zeroDir.IsValid() || !zeroDir.IsZero() || zeroDir.Kind() != LocalPathInvalid || zeroDir.Kind().String() != "invalid" {
		t.Fatal("零值 LocalDir 必须失败关闭")
	}
	if zeroSrc.IsValid() || !zeroSrc.IsZero() || zeroSrc.Dir().IsValid() || zeroSrc.Base() != "" {
		t.Fatal("零值 LocalSourcePath 必须失败关闭")
	}
	assertValidLocalDirCases(t)
	assertValidLocalSourceCases(t)
	assertLocalPathRejections(t)
}

func assertValidLocalDirCases(t *testing.T) {
	t.Helper()
	dirCases := []struct {
		raw       string
		want      string
		wantKind  LocalPathKind
		wantDrive byte
	}{
		{"/", "/", LocalPathPOSIXAbs, 0},
		{"/home/alice/.xops/", "/home/alice/.xops", LocalPathPOSIXAbs, 0},
		{"/var//lib/./xops", "/var/lib/xops", LocalPathPOSIXAbs, 0},
		{`C:\`, "C:/", LocalPathWindowsDrive, 'C'},
		{`c:\Users\alice\.xops\`, "C:/Users/alice/.xops", LocalPathWindowsDrive, 'C'},
		{"D:/Temp/out", "D:/Temp/out", LocalPathWindowsDrive, 'D'},
		{".", ".", LocalPathRelative, 0},
		{`.\downloads\sub`, "downloads/sub", LocalPathRelative, 0},
	}
	for _, tc := range dirCases {
		d, err := ParseLocalDir(tc.raw)
		if err != nil {
			t.Fatalf("ParseLocalDir(%q) 失败: %v", tc.raw, err)
		}
		drv, _ := d.Drive()
		if d.String() != tc.want || d.Kind() != tc.wantKind || drv != tc.wantDrive {
			t.Fatalf("ParseLocalDir(%q) = (%q, %v, %q)", tc.raw, d.String(), d.Kind(), drv)
		}
		assertTextAndJSONRoundTrip(t, d, tc.want)
	}
}

func assertValidLocalSourceCases(t *testing.T) {
	t.Helper()
	srcCases := []struct {
		raw      string
		want     string
		wantDir  string
		wantBase string
	}{
		{"/home/alice/.ssh/id_ed25519", "/home/alice/.ssh/id_ed25519", "/home/alice/.ssh", "id_ed25519"},
		{"/hosts", "/hosts", "/", "hosts"},
		{`c:\Temp\a.tgz`, "C:/Temp/a.tgz", "C:/Temp", "a.tgz"},
		{`D:\archive.zip`, "D:/archive.zip", "D:/", "archive.zip"},
		{`.\dist\app.bin`, "dist/app.bin", "dist", "app.bin"},
		{"local.key", "local.key", ".", "local.key"},
		{"/tmp/a:b", "/tmp/a:b", "/tmp", "a:b"},
		{"./a:b", "./a:b", ".", "a:b"},
		{"./a:b/file.txt", "./a:b/file.txt", "./a:b", "file.txt"},
		{"sub/a:b", "sub/a:b", "sub", "a:b"},
		{"foo:bar", "foo:bar", ".", "foo:bar"},
	}
	for _, tc := range srcCases {
		s, err := ParseLocalSourcePath(tc.raw)
		if err != nil {
			t.Fatalf("ParseLocalSourcePath(%q) 失败: %v", tc.raw, err)
		}
		if s.String() != tc.want || s.Dir().String() != tc.wantDir || s.Base() != tc.wantBase {
			t.Fatalf("ParseLocalSourcePath(%q) = (str=%q dir=%q base=%q)", tc.raw, s.String(), s.Dir().String(), s.Base())
		}
		assertTextAndJSONRoundTrip(t, s, tc.want)
		assertTextAndJSONRoundTrip(t, s.Dir(), tc.wantDir)
	}
}

func TestLocalDirJoinComponentAndJoinDest(t *testing.T) {
	var zeroDir LocalDir
	if _, err := zeroDir.JoinComponent("sub"); !errors.Is(err, ErrInvalidLocalDir) {
		t.Fatalf("零值 JoinComponent = %v, 期望 ErrInvalidLocalDir", err)
	}
	if _, err := zeroDir.JoinDest(LocalRootedDest{}); !errors.Is(err, ErrInvalidLocalDir) {
		t.Fatalf("零值 JoinDest = %v, 期望 ErrInvalidLocalDir", err)
	}
	rootPOSIX, _ := ParseLocalDir("/")
	if _, err := rootPOSIX.JoinDest(LocalRootedDest{}); !errors.Is(err, ErrInvalidLocalDest) {
		t.Fatalf("无效 dest JoinDest = %v, 期望包装 ErrInvalidLocalDest", err)
	}
	if _, err := rootPOSIX.JoinComponent("bad:ads"); !errors.Is(err, ErrInvalidComponent) {
		t.Fatalf("非法分量 JoinComponent = %v, 期望包装 ErrInvalidComponent", err)
	}

	dest, err := ParseLocalRootedDest("run/transfers")
	if err != nil {
		t.Fatalf("ParseLocalRootedDest: %v", err)
	}
	cases := []struct {
		base     string
		compWant string
		destWant string
	}{
		{"/", "/sub", "/run/transfers"},
		{"/home/alice/.xops", "/home/alice/.xops/sub", "/home/alice/.xops/run/transfers"},
		{`C:\`, "C:/sub", "C:/run/transfers"},
		{`C:\Users\alice\.xops`, "C:/Users/alice/.xops/sub", "C:/Users/alice/.xops/run/transfers"},
		{".", "sub", "run/transfers"},
		{"workspace", "workspace/sub", "workspace/run/transfers"},
	}
	for _, tc := range cases {
		base, err := ParseLocalDir(tc.base)
		if err != nil {
			t.Fatalf("ParseLocalDir(%q): %v", tc.base, err)
		}
		jc, err := base.JoinComponent("sub")
		if err != nil || jc.String() != tc.compWant || strings.HasPrefix(jc.String(), "//") {
			t.Fatalf("%q.JoinComponent(sub) = (%q, %v), want %q", tc.base, jc.String(), err, tc.compWant)
		}
		assertTextAndJSONRoundTrip(t, jc, tc.compWant)

		jd, err := base.JoinDest(dest)
		if err != nil || jd.String() != tc.destWant || strings.HasPrefix(jd.String(), "//") {
			t.Fatalf("%q.JoinDest = (%q, %v), want %q", tc.base, jd.String(), err, tc.destWant)
		}
		assertTextAndJSONRoundTrip(t, jd, tc.destWant)
	}
}

func assertLocalPathRejections(t *testing.T) {
	t.Helper()
	badDirs := []string{
		"", "..", "../outside", "/var/../etc", `C:\Temp\..\Windows`,
		"C:relative", `\rootrel`, `\\server\share\dir`, `//server/share/dir`,
		`\\?\C:\Windows`, `\\.\PhysicalDrive0`, `\??\C:\Windows`, `/??/C:/Windows`,
		`/mixed\slash`, `C:\Temp\CON`, `C:\Temp\file:$DATA`,
		"/bad\x00dir", "/bidi\u202edir",
	}
	for _, raw := range badDirs {
		if _, err := ParseLocalDir(raw); !errors.Is(err, ErrInvalidLocalDir) {
			t.Fatalf("ParseLocalDir(%q) = %v, 期望 ErrInvalidLocalDir", raw, err)
		}
	}

	// LocalSourcePath 额外拒绝裸根目录与当前目录 '.'。
	for _, raw := range append(badDirs, "/", "C:/", `C:\`, ".", "./.") {
		if _, err := ParseLocalSourcePath(raw); !errors.Is(err, ErrInvalidLocalSource) {
			t.Fatalf("ParseLocalSourcePath(%q) = %v, 期望 ErrInvalidLocalSource", raw, err)
		}
	}
}

func TestUnicodeNormalizationAndCollisionDetection(t *testing.T) {
	nfc, err := NormalizeNFC("cafe\u0301")
	if err != nil || nfc != "caf\u00e9" {
		t.Fatalf("NormalizeNFC = (%q, %v)", nfc, err)
	}
	nfd, err := NormalizeNFD("caf\u00e9")
	if err != nil || nfd != "cafe\u0301" {
		t.Fatalf("NormalizeNFD = (%q, %v)", nfd, err)
	}

	collidingPairs := [][2]string{
		{"caf\u00e9.txt", "cafe\u0301.txt"},
		{"CAF\u00c9.txt", "cafe\u0301.txt"},
		{"Readme.md", "README.MD"},
		{"stra\u00dfe", "STRASSE"},
		{"stra\u00dfe", "stra\u1e9ee"},
		{"\u212aelvin", "kelvin"}, // Kelvin 符号 U+212A <-> k
		{"\u017fhell", "shell"},   // Long S U+017F <-> s
		{"\u03c2igma", "\u03a3IGMA"},
		{"\u0130stanbul", "i\u0307stanbul"},
		{"\ufb01le.txt", "FILE.TXT"},
		{"\u0149ame", "\u02bcname"}, // ŉ
		{"\u0587", "\u0565\u0582"},  // և
		{"\u1e9a", "a\u02be"},       // ẚ
		{"\ufb00\ufb02\ufb03\ufb04\ufb05\ufb06", "FFFLFFIFFLSTST"},
		{"\u01f0", "j\u030c"},            // ǰ (经 NFD 分解)
		{"\u0390", "\u03b9\u0308\u0301"}, // ΐ (经 NFD 分解)
		{"\u1f80", "\u1f00\u03b9"},       // ᾀ == ἀι (U+0345 -> ι)
		{"\u1fb2", "\u1f70\u03b9"},       // ᾲ == ὰι
		{"\u1fbc", "\u03b1\u03b9"},       // ᾼ == αι
	}
	for _, pair := range collidingPairs {
		assertCollidingNamePair(t, pair[0], pair[1])
	}
	assertNonCollidingGreekIota(t)

	if err := CheckComponentCollisions([]string{"alpha.txt", "beta.txt", "gamma.log"}); err != nil {
		t.Fatalf("无碰撞名称集意外报错: %v", err)
	}
	d1, _ := ParseLocalRootedDest("Sub/caf\u00e9.txt")
	d2, _ := ParseLocalRootedDest("sub/cafe\u0301.txt")
	if err := CheckPathCollisions([]LocalRootedDest{d1, d2}); !errors.Is(err, ErrNameCollision) {
		t.Fatalf("CheckPathCollisions 未捕获 NFC/NFD + 大小写组合碰撞: %v", err)
	}
	if _, err := FoldCollisionKey(string([]byte{0xff})); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("非法 UTF-8 应返回 ErrInvalidUTF8: %v", err)
	}
}

func assertCollidingNamePair(t *testing.T, a, b string) {
	t.Helper()
	same, err := SameFoldedKey(a, b)
	if err != nil || !same {
		t.Fatalf("SameFoldedKey(%q, %q) = (%v, %v), 期望碰撞等价", a, b, same, err)
	}
	k1, _ := FoldCollisionKey(a)
	k2, err := FoldCollisionKey(k1)
	if err != nil || k1 != k2 {
		t.Fatalf("FoldCollisionKey 幂等律失败: %q -> %q -> %q", a, k1, k2)
	}
	if err := CheckComponentCollisions([]string{a, b}); !errors.Is(err, ErrNameCollision) {
		t.Fatalf("CheckComponentCollisions([%q, %q]) = %v, 期望 ErrNameCollision", a, b, err)
	}
}

// assertNonCollidingGreekIota 验证希腊语 iota 轨道映射到 CCC=0 基字母 'ι'（U+03B9），
// 绝不因 U+0345（CCC=240）触发二次 NFD 跨重音重排导致不同文件名误碰撞。
func assertNonCollidingGreekIota(t *testing.T) {
	t.Helper()
	distinctPairs := [][2]string{
		{"\u03ac\u03b9", "\u03b1\u03af"}, // άι vs αί
		{"\u03b9\u0301", "\u0301\u03b9"}, // ί vs ́ι
	}
	for _, pair := range distinctPairs {
		same, err := SameFoldedKey(pair[0], pair[1])
		if err != nil || same {
			t.Fatalf("不同希腊语文件名不应碰撞: SameFoldedKey(%q, %q) = (%v, %v)", pair[0], pair[1], same, err)
		}
	}
}

func TestSymlinkPolicyAndContainedChain(t *testing.T) {
	var zero SymlinkPolicy
	if zero != SymlinkReject || !zero.IsValid() || zero.AllowsContainedRelative() || zero.AllowsOperatorFollow() || zero.String() != "reject" {
		t.Fatalf("零值 SymlinkPolicy 必须是最严 SymlinkReject: %v", zero)
	}
	if err := ValidateSymlinkTarget(zero, "safe.txt", 1); !errors.Is(err, ErrUnsafeSymlink) {
		t.Fatalf("零值 SymlinkReject 必须拒绝所有软链: %v", err)
	}
	invalidPol := SymlinkPolicy(99)
	if invalidPol.IsValid() {
		t.Fatal("未知枚举值 SymlinkPolicy(99) 不应有效")
	}
	if err := ValidateSymlinkTarget(invalidPol, "safe.txt", 1); !errors.Is(err, ErrInvalidSymlinkPolicy) {
		t.Fatalf("非法 SymlinkPolicy 应失败关闭: %v", err)
	}

	for _, pol := range []SymlinkPolicy{SymlinkReject, SymlinkContainedRelative, SymlinkFollowOperatorSource} {
		assertTextAndJSONRoundTrip(t, pol, pol.String())
	}
	if _, err := ParseSymlinkPolicy(""); !errors.Is(err, ErrInvalidSymlinkPolicy) {
		t.Fatalf("空策略应拒绝: %v", err)
	}

	assertSymlinkPolicyBValidation(t)
	assertSymlinkChainValidation(t)
}

func assertSymlinkPolicyBValidation(t *testing.T) {
	t.Helper()
	if err := ValidateSymlinkTarget(SymlinkContainedRelative, "sub/file.txt", 0); err != nil {
		t.Fatalf("根内相对软链应放行: %v", err)
	}
	if err := ValidateSymlinkTarget(SymlinkContainedRelative, "../sibling/file.txt", 1); err != nil {
		t.Fatalf("深度 1 上溯一层仍留根内应放行: %v", err)
	}
	if err := ValidateSymlinkTarget(SymlinkFollowOperatorSource, "/etc/ssl/certs/ca.pem", 0); err != nil {
		t.Fatalf("OperatorReadFS 策略应允许合法绝对目标: %v", err)
	}

	unsafeTargets := []struct {
		target string
		depth  int
	}{
		{"", 1},
		{"/etc/passwd", 3},
		{`..\secret`, 2},
		{"C:/Windows/win.ini", 2},
		{"file:$DATA", 1},
		{"CON.txt", 1},
		{"../escape", 0},
		{"a/../../escape", 0},
		{"../../escape", 1},
		{"a/b/../../../../escape", 1},
		{"bad\u202ename", 1},
		{"safe", -1},
	}
	for _, tc := range unsafeTargets {
		if err := ValidateContainedSymlink(tc.target, tc.depth); !errors.Is(err, ErrUnsafeSymlink) {
			t.Fatalf("ValidateContainedSymlink(%q, %d) = %v, 期望 ErrUnsafeSymlink", tc.target, tc.depth, err)
		}
	}
}

func assertSymlinkChainValidation(t *testing.T) {
	t.Helper()
	mustDest := func(s string) LocalRootedDest {
		d, err := ParseLocalRootedDest(s)
		if err != nil {
			t.Fatalf("ParseLocalRootedDest(%q): %v", s, err)
		}
		return d
	}
	mustBind := func(link, target string) SymlinkBinding {
		b, err := NewSymlinkBinding(mustDest(link), target)
		if err != nil {
			t.Fatalf("NewSymlinkBinding(%q -> %q): %v", link, target, err)
		}
		return b
	}

	// 合法双跳链：a/b/l1 -> ../l2 -> file.txt（始终留在根内）
	stagedOK := []SymlinkBinding{mustBind("a/l2", "file.txt")}
	if err := ValidateContainedSymlinkChain(mustDest("a/b/l1"), "../l2", stagedOK); err != nil {
		t.Fatalf("合法根内双跳软链应通过: %v", err)
	}

	// 链式逃逸：a/l1 -> Sub（通过折叠命中 staged "sub" -> ".."，再接 "../escape" 逃出根目录）
	stagedEscape := []SymlinkBinding{mustBind("a/sub", "..")}
	if err := ValidateContainedSymlinkChain(mustDest("a/l1"), "Sub/../escape", stagedEscape); !errors.Is(err, ErrUnsafeSymlink) {
		t.Fatalf("大小写折叠链式逃逸必须被拒绝: %v", err)
	}

	// NFC/NFD 折叠碰撞的 staged 软链必须被拒绝
	stagedCollide := []SymlinkBinding{
		mustBind("caf\u00e9", "target1"),
		mustBind("cafe\u0301", "target2"),
	}
	err := ValidateContainedSymlinkChain(mustDest("other"), "safe", stagedCollide)
	if !errors.Is(err, ErrUnsafeSymlink) || !errors.Is(err, ErrNameCollision) {
		t.Fatalf("NFC/NFD 软链碰撞应同时包装 ErrUnsafeSymlink 与 ErrNameCollision: %v", err)
	}

	// 环路必须命中跳数上限
	stagedLoop := []SymlinkBinding{
		mustBind("a", "b"),
		mustBind("b", "a"),
	}
	if err := ValidateContainedSymlinkChain(mustDest("c"), "a", stagedLoop); !errors.Is(err, ErrUnsafeSymlink) {
		t.Fatalf("软链环路应触发跳数上限拒绝: %v", err)
	}

	// 父目录本身为软链必须拒绝
	stagedParent := []SymlinkBinding{mustBind("dir", "real")}
	if err := ValidateContainedSymlinkChain(mustDest("DIR/link"), "target", stagedParent); !errors.Is(err, ErrUnsafeSymlink) {
		t.Fatalf("祖先目录命中软链（含大小写折叠）必须拒绝: %v", err)
	}

	// 超大步数拒绝防放大
	deepTarget := strings.Repeat("a/", 50) + "file"
	if err := ValidateContainedSymlink(deepTarget, 0); err != nil {
		t.Fatalf("合法深相对软链应通过: %v", err)
	}
}

// TestSymlinkWholeGraphPermutationInvariants 回归验证策略 (b) 全图置换不变性：
// 覆盖自环、增量双环、逆序多跳逃逸、逆序祖先软链接管以及精确重复链接冲突。
func TestSymlinkWholeGraphPermutationInvariants(t *testing.T) {
	mustDest := func(s string) LocalRootedDest {
		d, err := ParseLocalRootedDest(s)
		if err != nil {
			t.Fatalf("ParseLocalRootedDest(%q): %v", s, err)
		}
		return d
	}
	mustBind := func(link, target string) SymlinkBinding {
		b, err := NewSymlinkBinding(mustDest(link), target)
		if err != nil {
			t.Fatalf("NewSymlinkBinding(%q -> %q): %v", link, target, err)
		}
		return b
	}

	// 1. 自环与带逃逸自环（staged 为空）
	if err := ValidateContainedSymlinkChain(mustDest("a/self"), "self", nil); !errors.Is(err, ErrUnsafeSymlink) {
		t.Fatalf("自环必须被拒绝: %v", err)
	}
	if err := ValidateContainedSymlinkChain(mustDest("a/b/s"), "s/../../..", nil); !errors.Is(err, ErrUnsafeSymlink) {
		t.Fatalf("逃逸自环必须被拒绝: %v", err)
	}

	// 2. 增量双环（先加 a -> b，再加 b -> a）
	if err := ValidateContainedSymlinkChain(mustDest("b"), "a", []SymlinkBinding{mustBind("a", "b")}); !errors.Is(err, ErrUnsafeSymlink) {
		t.Fatalf("增量双环必须被拒绝: %v", err)
	}

	// 3. 逆序多跳逃逸：先 staged x/l1 -> ../y/sub/../../outside，再加入 y/sub -> ..
	stagedL1 := []SymlinkBinding{mustBind("x/l1", "../y/sub/../../outside")}
	if err := ValidateContainedSymlinkChain(mustDest("y/sub"), "..", stagedL1); !errors.Is(err, ErrUnsafeSymlink) {
		t.Fatalf("逆序多跳逃逸必须被全图校验拒绝: %v", err)
	}
	// 同理：先 staged a/b/l1 -> l2/../../escape，再加入 a/b/l2 -> ../..
	stagedL1b := []SymlinkBinding{mustBind("a/b/l1", "l2/../../escape")}
	if err := ValidateContainedSymlinkChain(mustDest("a/b/l2"), "../..", stagedL1b); !errors.Is(err, ErrUnsafeSymlink) {
		t.Fatalf("逆序同目录多跳逃逸必须被全图校验拒绝: %v", err)
	}

	// 4. 逆序祖先软链接管：先 staged DIR/link -> safe，再加入 dir -> real
	if err := ValidateContainedSymlinkChain(mustDest("dir"), "real", []SymlinkBinding{mustBind("DIR/link", "safe")}); !errors.Is(err, ErrUnsafeSymlink) {
		t.Fatalf("逆序折叠祖先接管必须被拒绝: %v", err)
	}

	// 5. 精确重复链接冲突（不得静默覆写）
	err := ValidateContainedSymlinkChain(mustDest("a"), "other", []SymlinkBinding{mustBind("a", "safe")})
	if !errors.Is(err, ErrUnsafeSymlink) || !errors.Is(err, ErrNameCollision) {
		t.Fatalf("精确重复链接必须失败关闭: %v", err)
	}
	err = ValidateContainedSymlinkSet([]SymlinkBinding{mustBind("a", "one"), mustBind("a", "two")})
	if !errors.Is(err, ErrUnsafeSymlink) || !errors.Is(err, ErrNameCollision) {
		t.Fatalf("集合内重复链接必须失败关闭: %v", err)
	}
}

func TestSymlinkBindingAndCollisionLookup(t *testing.T) {
	dest, err := ParseLocalRootedDest("sub/link")
	if err != nil {
		t.Fatalf("ParseLocalRootedDest: %v", err)
	}
	b, err := NewSymlinkBinding(dest, "target")
	if err != nil || b.Link().String() != "sub/link" || b.Target() != "target" {
		t.Fatalf("SymlinkBinding 访问器异常: %+v %v", b, err)
	}
	cs := NewCollisionSet()
	if err := cs.Add("Sub/Caf\u00e9"); err != nil {
		t.Fatalf("CollisionSet.Add 失败: %v", err)
	}
	prev, ok, err := cs.LookupFolded("sub/cafe\u0301")
	if err != nil || !ok || prev != "Sub/Caf\u00e9" {
		t.Fatalf("LookupFolded = (%q, %v, %v)", prev, ok, err)
	}
	cafeDest, err := ParseLocalRootedDest("Sub/Caf\u00e9")
	if err != nil {
		t.Fatalf("ParseLocalRootedDest: %v", err)
	}
	kDest, err := FoldLocalDestKey(cafeDest)
	if err != nil || kDest != "sub/cafe\u0301" {
		t.Fatalf("FoldLocalDestKey = (%q, %v)", kDest, err)
	}
}

func TestLocalPathPredicatesAndOrdering(t *testing.T) {
	if LocalPathPOSIXAbs.String() != "posix_abs" || LocalPathWindowsDrive.String() != "windows_drive" || LocalPathRelative.String() != "relative" {
		t.Fatal("LocalPathKind.String() 异常")
	}
	dPosix, _ := ParseLocalDir("/tmp")
	dWin, _ := ParseLocalDir(`C:\Temp`)
	dRel, _ := ParseLocalDir("out")
	if !dPosix.IsAbs() || !dWin.IsAbs() || dRel.IsAbs() || dPosix.Compare(dWin) >= 0 || dWin.Compare(dRel) >= 0 {
		t.Fatal("LocalDir IsAbs 或 Compare 序异常")
	}

	sPosix, _ := ParseLocalSourcePath("/tmp/a.tgz")
	sWin, _ := ParseLocalSourcePath(`C:\Temp\a.tgz`)
	sRel, _ := ParseLocalSourcePath("a.tgz")
	drv, hasDrv := sWin.Drive()
	if !sPosix.IsAbs() || !sWin.IsAbs() || sRel.IsAbs() || sWin.Kind() != LocalPathWindowsDrive || !hasDrv || drv != 'C' {
		t.Fatal("LocalSourcePath 谓词或 Drive 异常")
	}
	if sPosix.Compare(sWin) >= 0 || sWin.Compare(sRel) >= 0 {
		t.Fatal("LocalSourcePath Compare 序异常")
	}
}
