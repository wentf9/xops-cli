package pathalg

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"golang.org/x/text/unicode/norm"
)

// NormalizeNFC 将合法 UTF-8 字符串规范化为 Unicode 规范组合形式（NFC）；非法 UTF-8 失败关闭。
func NormalizeNFC(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", domi18n.EF(ErrInvalidUTF8, domi18n.KeyCommonInvalidUTF8)
	}
	return norm.NFC.String(s), nil
}

// NormalizeNFD 将合法 UTF-8 字符串规范化为 Unicode 规范分解形式（NFD）；非法 UTF-8 失败关闭。
func NormalizeNFD(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", domi18n.EF(ErrInvalidUTF8, domi18n.KeyCommonInvalidUTF8)
	}
	return norm.NFD.String(s), nil
}

// FoldCollisionKey 计算用于跨 OS（macOS APFS/HFS+、Windows NTFS、Linux）文件名碰撞检测的规范折叠键。
//
// 算法仅依赖标准库 unicode 与白名单数学包 golang.org/x/text/unicode/norm：
//  1. 校验输入为合法 UTF-8 并先规范分解为 NFD（消除 NFC/NFD 编码差异，如 "é" 与 "e\u0301"、
//     以及带规范分解的字符如 "İ" -> "I\u0307"、"ᾀ" -> "α\u0313\u0345"）；
//  2. 对 NFD 惰性的 Unicode CaseFolding Status F 字符执行多码点全折叠展开（如 "ß"/"ẞ" -> "ss"、
//     "ŉ"、"և"、"ẚ" 与连字 "ﬀ"–"ﬆ"/"ﬓ"–"ﬗ"），并对每个码点取 unicode.SimpleFold 轨道内
//     优先满足 IsLower 且 CCC == 0 的规范基字符代表（使希腊语 iota 轨道 {U+0345, Ι, ι, ι} 稳定映射为
//     CCC=0 的基字母 'ι'，杜绝 U+0345 CCC=240 引发的跨重音重排误碰撞）；
//  3. 再次执行 NFD 规范重排与轨道折叠，保证满足幂等律 Fold(Fold(x)) == Fold(x) 与
//     规范化不变律 Fold(NFC(x)) == Fold(NFD(x))。
func FoldCollisionKey(name string) (string, error) {
	if !utf8.ValidString(name) {
		return "", domi18n.EF(ErrInvalidUTF8, domi18n.KeyCommonInvalidUTF8)
	}
	nfd := norm.NFD.String(name)
	expanded := expandFullAndSimpleFold(nfd)
	renorm := norm.NFD.String(expanded)
	return strings.Map(canonicalSimpleFoldRune, renorm), nil
}

// FoldLocalDestKey 计算沙箱相对路径 LocalRootedDest 的逐段跨 OS 规范折叠键（以 '/' 连接）。
func FoldLocalDestKey(dest LocalRootedDest) (string, error) {
	if !dest.IsValid() {
		return "", domi18n.EF(ErrInvalidLocalDest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "local_dest"))
	}
	return foldSlashPath(dest.rel)
}

func foldSlashPath(rel string) (string, error) {
	if !strings.ContainsRune(rel, '/') {
		return FoldCollisionKey(rel)
	}
	parts := strings.Split(rel, "/")
	for i, seg := range parts {
		folded, err := FoldCollisionKey(seg)
		if err != nil {
			return "", err
		}
		parts[i] = folded
	}
	return strings.Join(parts, "/"), nil
}

// SameFoldedKey 报告两个字符串在跨 OS Unicode NFC/NFD + 大小写折叠下是否等价。
// 输入含非法 UTF-8 时失败关闭返回错误。
func SameFoldedKey(a, b string) (bool, error) {
	ka, err := FoldCollisionKey(a)
	if err != nil {
		return false, err
	}
	kb, err := FoldCollisionKey(b)
	if err != nil {
		return false, err
	}
	return ka == kb, nil
}

// CollisionSet 在纯内存中检测一组同级文件名或沙箱路径是否存在重复、NFC/NFD 等价或跨 OS 大小写折叠碰撞。
//
// 本类型仅用于单协程纯数学校验（零 sync），零值经首次 Add 自动懒初始化并始终保持确定性语义。
type CollisionSet struct {
	seen map[string]string
}

// NewCollisionSet 构造空的纯内存名称碰撞检测集合。
func NewCollisionSet() *CollisionSet {
	return &CollisionSet{seen: make(map[string]string)}
}

// Add 将单个名称或 '/' 分隔相对路径加入集合；若与已有条目重复或折叠等价，则失败关闭返回 ErrNameCollision。
func (s *CollisionSet) Add(raw string) error {
	if s == nil {
		return ErrNilReceiver
	}
	key, err := foldSlashPath(raw)
	if err != nil {
		return err
	}
	if s.seen == nil {
		s.seen = make(map[string]string)
	}
	if _, exists := s.seen[key]; exists {
		return domi18n.EF(ErrNameCollision, domi18n.KeyCommonDuplicateItem, domi18n.Str("kind", "name"), domi18n.BoundStr("value", raw))
	}
	s.seen[key] = raw
	return nil
}

// LookupFolded 查询与 raw 在跨 OS 折叠意义下等价的已登记原始条目。
func (s *CollisionSet) LookupFolded(raw string) (string, bool, error) {
	if s == nil {
		return "", false, ErrNilReceiver
	}
	key, err := foldSlashPath(raw)
	if err != nil {
		return "", false, err
	}
	if s.seen == nil {
		return "", false, nil
	}
	prev, ok := s.seen[key]
	return prev, ok, nil
}

// CheckComponentCollisions 确定性地检验一组同级名称是否存在重复、NFC/NFD 或大小写折叠碰撞。
func CheckComponentCollisions(names []string) error {
	ordered := slices.Clone(names)
	slices.Sort(ordered)
	set := NewCollisionSet()
	for _, name := range ordered {
		if err := set.Add(name); err != nil {
			return err
		}
	}
	return nil
}

// CheckPathCollisions 确定性地检验一组 LocalRootedDest 是否存在路径级（含 NFC/NFD 与大小写折叠）碰撞。
func CheckPathCollisions(paths []LocalRootedDest) error {
	strs := make([]string, 0, len(paths))
	for _, p := range paths {
		if !p.IsValid() {
			return domi18n.EF(ErrInvalidLocalDest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "local_dest"))
		}
		strs = append(strs, p.rel)
	}
	return CheckComponentCollisions(strs)
}

func expandFullAndSimpleFold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if repl, ok := fullCaseFoldExpansion(r); ok {
			for _, rr := range repl {
				b.WriteRune(canonicalSimpleFoldRune(rr))
			}
			continue
		}
		b.WriteRune(canonicalSimpleFoldRune(r))
	}
	return b.String()
}

// canonicalSimpleFoldRune 遍历 unicode.SimpleFold 完整等价轨道，选取唯一确定性规范代表：
//  1. 优先取轨道内最小的“小写且 CCC == 0 基字符”（例如 {U+0345, Ι, ι, ι} -> U+03B9 'ι'，
//     避免将基字母映射为 CCC=240 组合记号导致二次 NFD 跨重音重排误碰撞）；
//  2. 若轨道内无 CCC == 0 小写码点，则退回轨道内最小小写码点；
//  3. 否则退回轨道内最小码点。
//
// 该选择仅依赖于等价轨道集合自身，对所有 Unicode 码点严格满足轨道不变性与幂等性。
func canonicalSimpleFoldRune(r rune) rune {
	bestBaseLower, bestLower, minR := rune(-1), rune(-1), r
	for cur := r; ; {
		minR = min(minR, cur)
		bestBaseLower, bestLower = considerLowerOrbitRune(cur, bestBaseLower, bestLower)
		if cur = unicode.SimpleFold(cur); cur == r {
			break
		}
	}
	if bestBaseLower >= 0 {
		return bestBaseLower
	}
	if bestLower >= 0 {
		return bestLower
	}
	return minR
}

func considerLowerOrbitRune(cur, bestBaseLower, bestLower rune) (rune, rune) {
	if !unicode.IsLower(cur) {
		return bestBaseLower, bestLower
	}
	if bestLower < 0 || cur < bestLower {
		bestLower = cur
	}
	if norm.NFC.PropertiesString(string(cur)).CCC() == 0 && (bestBaseLower < 0 || cur < bestBaseLower) {
		bestBaseLower = cur
	}
	return bestBaseLower, bestLower
}

// fullCaseFoldExpansion 返回 NFD 规范分解之后仍不可再分解（NFD-inert）的 Unicode CaseFolding Status F 多码点映射。
// 其余带规范分解的 Status F 字符（如 İ、ǰ、ΐ、ΰ、ᾀ..ῼ 等）均已由前置 norm.NFD 拆解，
// 其希腊语下标 iota（U+0345）由 canonicalSimpleFoldRune 统一折叠为基字母 'ι'（U+03B9）。
// 使用纯 switch 而非包级可变 map，严格满足 xopsvet/noimplicit 零可变全局状态约束。
func fullCaseFoldExpansion(r rune) (string, bool) {
	switch r {
	case '\u00df', '\u1e9e': // ß, ẞ
		return "ss", true
	case '\u0149': // ŉ
		return "\u02bcn", true
	case '\u0587': // և
		return "\u0565\u0582", true
	case '\u1e9a': // ẚ
		return "a\u02be", true
	case '\ufb00': // ﬀ
		return "ff", true
	case '\ufb01': // ﬁ
		return "fi", true
	case '\ufb02': // ﬂ
		return "fl", true
	case '\ufb03': // ﬃ
		return "ffi", true
	case '\ufb04': // ﬄ
		return "ffl", true
	case '\ufb05', '\ufb06': // ﬅ, ﬆ
		return "st", true
	case '\ufb13': // ﬓ
		return "\u0574\u0576", true
	case '\ufb14': // ﬔ
		return "\u0574\u0565", true
	case '\ufb15': // ﬕ
		return "\u0574\u056b", true
	case '\ufb16': // ﬖ
		return "\u057e\u0576", true
	case '\ufb17': // ﬗ
		return "\u0574\u056d", true
	default:
		return "", false
	}
}
