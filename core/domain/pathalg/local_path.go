package pathalg

import (
	"cmp"
	"encoding"
	"fmt"
	"slices"
	"strings"
)

var (
	_ encoding.TextAppender    = LocalDir{}
	_ encoding.TextMarshaler   = LocalDir{}
	_ encoding.TextUnmarshaler = (*LocalDir)(nil)
	_ encoding.TextAppender    = LocalSourcePath{}
	_ encoding.TextMarshaler   = LocalSourcePath{}
	_ encoding.TextUnmarshaler = (*LocalSourcePath)(nil)
)

// LocalPathKind 标识本地路径（LocalDir / LocalSourcePath）的命名空间类别；零值 LocalPathInvalid 严格代表无效态。
//
//xops:failclosed
type LocalPathKind uint8

const (
	// LocalPathInvalid 表示未初始化或校验失败的无效本地路径类别（失败关闭零值）。
	LocalPathInvalid LocalPathKind = iota
	// LocalPathPOSIXAbs 表示以 '/' 开头的 POSIX 绝对路径（如 "/var/lib/xops"）。
	LocalPathPOSIXAbs
	// LocalPathWindowsDrive 表示以大写盘符开头的 Windows 绝对路径（规范表示为 "C:/..."）。
	LocalPathWindowsDrive
	// LocalPathRelative 表示不含 ".." 穿越段的安全相对本地路径（如 "." 或 "out/app.tgz"）。
	LocalPathRelative
)

// String 返回 LocalPathKind 的可读标识。
func (k LocalPathKind) String() string {
	switch k {
	case LocalPathPOSIXAbs:
		return "posix_abs"
	case LocalPathWindowsDrive:
		return "windows_drive"
	case LocalPathRelative:
		return "relative"
	default:
		return "invalid"
	}
}

// LocalDir 表示面向 ScopedRootFS.WithRoot 的已校验本地目录根标识。
//
// 纯字符串数学同时支持 POSIX 绝对目录（如 "/"、"/var/lib/xops"）、Windows 盘符绝对目录
// （如 "C:/"、"C:\Users\alice\.xops" 规范化为 "C:/Users/alice/.xops"）及无 ".." 穿越的安全相对目录
// （如 "."、"downloads/sub"）；严格拒绝 ".." 遍历段、盘符相对路径（"C:foo"）、单反斜杠根相对（"\foo"）、
// UNC（"\\server\share"）、Win32 设备命名空间（"\\?\"、"\\.\"、"\??\"）及控制/Bidi 字符。
//
//xops:opaque
//xops:failclosed
type LocalDir struct {
	canon string
	kind  LocalPathKind
	drive byte
}

// ParseLocalDir 校验并规范化本地根目录路径。
func ParseLocalDir(raw string) (LocalDir, error) {
	canon, kind, drive, err := parseLocalPath(raw, true)
	if err != nil {
		return LocalDir{}, fmt.Errorf("%w: %w", ErrInvalidLocalDir, err)
	}
	return LocalDir{canon: canon, kind: kind, drive: drive}, nil
}

// IsValid 报告 LocalDir 是否有效。
func (d LocalDir) IsValid() bool { return d.kind != LocalPathInvalid }

// IsZero 报告 LocalDir 是否为无效零值。
func (d LocalDir) IsZero() bool { return d.kind == LocalPathInvalid }

// Kind 返回本地路径命名空间类别。
func (d LocalDir) Kind() LocalPathKind { return d.kind }

// IsAbs 报告目录是否为绝对路径（POSIX 绝对或 Windows 盘符绝对）。
func (d LocalDir) IsAbs() bool {
	return d.kind == LocalPathPOSIXAbs || d.kind == LocalPathWindowsDrive
}

// Drive 在目录为 Windows 盘符路径时返回大写盘符字母（'A'..'Z'）与 true，否则返回 (0, false)。
func (d LocalDir) Drive() (byte, bool) {
	if d.kind != LocalPathWindowsDrive {
		return 0, false
	}
	return d.drive, true
}

// String 返回规范化目录文本（以 '/' 分隔）；无效零值返回空串。
func (d LocalDir) String() string { return d.canon }

// JoinComponent 在当前本地目录根下安全追加单个经 ValidateLocalComponent 校验的子目录分量，
// 正确处理 POSIX 根目录 "/"、Windows 盘符根目录 "C:/" 与当前目录 "."（绝不产生 "//sub"）。
func (d LocalDir) JoinComponent(name string) (LocalDir, error) {
	if !d.IsValid() {
		return LocalDir{}, fmt.Errorf("%w: 无法在无效 LocalDir 上追加分量", ErrInvalidLocalDir)
	}
	if err := ValidateLocalComponent(name); err != nil {
		return LocalDir{}, fmt.Errorf("%w: %w", ErrInvalidLocalDir, err)
	}
	return joinLocalDirRel(d, name)
}

// JoinDest 在当前本地目录根下安全拼接已校验的沙箱相对路径 LocalRootedDest，
// 正确处理 POSIX 根目录 "/"、Windows 盘符根目录 "C:/" 与当前目录 "."（绝不产生 "//sub"）。
func (d LocalDir) JoinDest(dest LocalRootedDest) (LocalDir, error) {
	if !d.IsValid() {
		return LocalDir{}, fmt.Errorf("%w: 无法在无效 LocalDir 上拼接沙箱路径", ErrInvalidLocalDir)
	}
	if !dest.IsValid() {
		return LocalDir{}, fmt.Errorf("%w: %w", ErrInvalidLocalDir, ErrInvalidLocalDest)
	}
	return joinLocalDirRel(d, dest.rel)
}

func joinLocalDirRel(d LocalDir, rel string) (LocalDir, error) {
	var joined string
	switch {
	case d.canon == ".":
		joined = rel
	case strings.HasSuffix(d.canon, "/"):
		joined = d.canon + rel
	default:
		joined = d.canon + "/" + rel
	}
	if len(joined) > MaxLocalPathBytes {
		return LocalDir{}, fmt.Errorf("%w: 拼接后路径长度 %d 超过上限 %d", ErrInvalidLocalDir, len(joined), MaxLocalPathBytes)
	}
	return LocalDir{canon: joined, kind: d.kind, drive: d.drive}, nil
}

// Equal 判断两个 LocalDir 是否均有效且完全相等；无效零值永不相等。
func (d LocalDir) Equal(other LocalDir) bool {
	return d.IsValid() && other.IsValid() && d.kind == other.kind && d.drive == other.drive && d.canon == other.canon
}

// Compare 定义 LocalDir 上的确定性全序关系。
func (d LocalDir) Compare(other LocalDir) int {
	if c := cmp.Compare(d.kind, other.kind); c != 0 {
		return c
	}
	return cmp.Compare(d.canon, other.canon)
}

// AppendText 实现 encoding.TextAppender（值接收者）；无效零值返回 ErrInvalidLocalDir。
func (d LocalDir) AppendText(b []byte) ([]byte, error) {
	if !d.IsValid() {
		return nil, ErrInvalidLocalDir
	}
	return append(b, d.canon...), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (d LocalDir) MarshalText() ([]byte, error) { return d.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为零值。
func (d *LocalDir) UnmarshalText(text []byte) error {
	if d == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseLocalDir(string(text))
	if err != nil {
		*d = LocalDir{}
		return err
	}
	*d = parsed
	return nil
}

// LocalSourcePath 表示面向 OperatorReadFS.WithOperatorRead 的操作员显式本地只读源路径。
//
// 纯字符串数学支持 POSIX 绝对路径（"/home/alice/.ssh/id_ed25519"）、跨盘符 Windows 绝对路径
// （"C:\Temp\a.tgz" -> "C:/Temp/a.tgz"）及无 ".." 穿越的安全相对文件路径（"dist/app.tgz"）；
// 严格拒绝裸根目录（"/"、"C:/"）、"."、".." 穿越段、盘符相对路径、UNC、Win32 设备路径及控制/Bidi 字符。
//
//xops:opaque
//xops:failclosed
type LocalSourcePath struct {
	canon string
	kind  LocalPathKind
	drive byte
}

// ParseLocalSourcePath 校验并规范化操作员提供的本地只读源路径。
func ParseLocalSourcePath(raw string) (LocalSourcePath, error) {
	canon, kind, drive, err := parseLocalPath(raw, false)
	if err != nil {
		return LocalSourcePath{}, fmt.Errorf("%w: %w", ErrInvalidLocalSource, err)
	}
	return LocalSourcePath{canon: canon, kind: kind, drive: drive}, nil
}

// IsValid 报告 LocalSourcePath 是否有效。
func (s LocalSourcePath) IsValid() bool { return s.kind != LocalPathInvalid }

// IsZero 报告 LocalSourcePath 是否为无效零值。
func (s LocalSourcePath) IsZero() bool { return s.kind == LocalPathInvalid }

// Kind 返回本地路径命名空间类别。
func (s LocalSourcePath) Kind() LocalPathKind { return s.kind }

// IsAbs 报告路径是否为绝对路径。
func (s LocalSourcePath) IsAbs() bool {
	return s.kind == LocalPathPOSIXAbs || s.kind == LocalPathWindowsDrive
}

// Drive 在路径为 Windows 盘符路径时返回大写盘符字母（'A'..'Z'）与 true，否则返回 (0, false)。
func (s LocalSourcePath) Drive() (byte, bool) {
	if s.kind != LocalPathWindowsDrive {
		return 0, false
	}
	return s.drive, true
}

// String 返回规范化路径文本（以 '/' 分隔）；无效零值返回空串。
func (s LocalSourcePath) String() string { return s.canon }

// Base 返回源路径末段文件名；无效零值返回空串。
func (s LocalSourcePath) Base() string {
	if !s.IsValid() {
		return ""
	}
	if idx := strings.LastIndexByte(s.canon, '/'); idx >= 0 {
		return s.canon[idx+1:]
	}
	return s.canon
}

// Dir 返回源路径所在的已校验父目录 LocalDir；无效零值返回无效零值。
func (s LocalSourcePath) Dir() LocalDir {
	if !s.IsValid() {
		return LocalDir{}
	}
	idx := strings.LastIndexByte(s.canon, '/')
	switch s.kind {
	case LocalPathPOSIXAbs:
		if idx <= 0 {
			return LocalDir{canon: "/", kind: LocalPathPOSIXAbs}
		}
		return LocalDir{canon: s.canon[:idx], kind: LocalPathPOSIXAbs}
	case LocalPathWindowsDrive:
		if idx <= 2 {
			return LocalDir{canon: s.canon[:3], kind: LocalPathWindowsDrive, drive: s.drive}
		}
		return LocalDir{canon: s.canon[:idx], kind: LocalPathWindowsDrive, drive: s.drive}
	case LocalPathRelative:
		if idx < 0 {
			return LocalDir{canon: ".", kind: LocalPathRelative}
		}
		return LocalDir{canon: s.canon[:idx], kind: LocalPathRelative}
	default:
		return LocalDir{}
	}
}

// Equal 判断两个 LocalSourcePath 是否均有效且完全相等；无效零值永不相等。
func (s LocalSourcePath) Equal(other LocalSourcePath) bool {
	return s.IsValid() && other.IsValid() && s.kind == other.kind && s.drive == other.drive && s.canon == other.canon
}

// Compare 定义 LocalSourcePath 上的确定性全序关系。
func (s LocalSourcePath) Compare(other LocalSourcePath) int {
	if c := cmp.Compare(s.kind, other.kind); c != 0 {
		return c
	}
	return cmp.Compare(s.canon, other.canon)
}

// AppendText 实现 encoding.TextAppender（值接收者）；无效零值返回 ErrInvalidLocalSource。
func (s LocalSourcePath) AppendText(b []byte) ([]byte, error) {
	if !s.IsValid() {
		return nil, ErrInvalidLocalSource
	}
	return append(b, s.canon...), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (s LocalSourcePath) MarshalText() ([]byte, error) { return s.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为零值。
func (s *LocalSourcePath) UnmarshalText(text []byte) error {
	if s == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseLocalSourcePath(string(text))
	if err != nil {
		*s = LocalSourcePath{}
		return err
	}
	*s = parsed
	return nil
}

func parseLocalPath(raw string, allowRootOrDot bool) (canon string, kind LocalPathKind, drive byte, err error) {
	if raw == "" {
		return "", LocalPathInvalid, 0, fmt.Errorf("路径不能为空")
	}
	if len(raw) > MaxLocalPathBytes {
		return "", LocalPathInvalid, 0, fmt.Errorf("路径长度 %d 超过上限 %d", len(raw), MaxLocalPathBytes)
	}
	if hasForbiddenPathText(raw) {
		return "", LocalPathInvalid, 0, fmt.Errorf("路径 %q 包含非法 UTF-8、控制字符或不可见/Bidi 字符", raw)
	}
	if hasDisallowedLocalPrefix(raw) {
		return "", LocalPathInvalid, 0, fmt.Errorf("路径 %q 使用了禁止的 UNC、设备命名空间或根相对反斜杠前缀", raw)
	}
	if hasWindowsDrivePrefix(raw) {
		return parseWindowsDriveLocalPath(raw, allowRootOrDot)
	}
	if strings.HasPrefix(raw, "/") {
		return parsePOSIXAbsLocalPath(raw, allowRootOrDot)
	}
	return parseRelativeLocalPath(raw, allowRootOrDot)
}

func hasWindowsDrivePrefix(raw string) bool {
	return len(raw) >= 2 && isASCIIAlpha(raw[0]) && raw[1] == ':'
}

func hasDisallowedLocalPrefix(raw string) bool {
	if strings.HasPrefix(raw, `\`) || strings.HasPrefix(raw, "//") {
		return true
	}
	// 拦截斜杠写法的 Win32 设备前缀（如 /??/...）。
	return strings.HasPrefix(raw, "/??/") || raw == "/??"
}

func parseWindowsDriveLocalPath(raw string, allowRoot bool) (string, LocalPathKind, byte, error) {
	if len(raw) < 3 || (raw[2] != '\\' && raw[2] != '/') {
		return "", LocalPathInvalid, 0, fmt.Errorf("盘符路径 %q 缺少盘符后分隔符（禁止盘符相对路径）", raw)
	}
	drive := toUpperASCII(raw[0])
	rest := strings.ReplaceAll(raw[3:], "\\", "/")
	segs, err := parseLocalSegments(rest, true)
	if err != nil {
		return "", LocalPathInvalid, 0, err
	}
	if len(segs) == 0 {
		if !allowRoot {
			return "", LocalPathInvalid, 0, fmt.Errorf("本地源路径 %q 不能为裸盘符根目录", raw)
		}
		return string([]byte{drive, ':', '/'}), LocalPathWindowsDrive, drive, nil
	}
	return string([]byte{drive, ':', '/'}) + strings.Join(segs, "/"), LocalPathWindowsDrive, drive, nil
}

func parsePOSIXAbsLocalPath(raw string, allowRoot bool) (string, LocalPathKind, byte, error) {
	if strings.ContainsRune(raw, '\\') {
		return "", LocalPathInvalid, 0, fmt.Errorf("POSIX 绝对路径 %q 禁止混用反斜杠 '\\'", raw)
	}
	segs, err := parseLocalSegments(raw[1:], false)
	if err != nil {
		return "", LocalPathInvalid, 0, err
	}
	if len(segs) == 0 {
		if !allowRoot {
			return "", LocalPathInvalid, 0, fmt.Errorf("本地源路径 %q 不能为裸根目录 '/'", raw)
		}
		return "/", LocalPathPOSIXAbs, 0, nil
	}
	return "/" + strings.Join(segs, "/"), LocalPathPOSIXAbs, 0, nil
}

func parseRelativeLocalPath(raw string, allowDot bool) (string, LocalPathKind, byte, error) {
	hasBackslash := strings.ContainsRune(raw, '\\')
	normalized := strings.ReplaceAll(raw, "\\", "/")
	// 含反斜杠的 Windows 相对路径执行跨平台严格单分量校验；
	// 不含反斜杠的 POSIX 相对路径与 parsePOSIXAbsLocalPath 对齐，保留合法 POSIX 文件名（如 "./a:b"）。
	segs, err := parseLocalSegments(normalized, hasBackslash)
	if err != nil {
		return "", LocalPathInvalid, 0, err
	}
	if len(segs) == 0 {
		if !allowDot {
			return "", LocalPathInvalid, 0, fmt.Errorf("本地源路径 %q 不能解析为当前目录 '.'", raw)
		}
		return ".", LocalPathRelative, 0, nil
	}
	joined := strings.Join(segs, "/")
	// 首段形如单字母加冒号（如 "./a:b" 去掉 "." 后为 "a:b"）时保留 "./" 前缀，
	// 防止序列化往返时与被禁止的 Windows 盘符相对路径（"C:foo"）发生语法歧义。
	if hasWindowsDrivePrefix(segs[0]) {
		if len(joined)+2 > MaxLocalPathBytes {
			return "", LocalPathInvalid, 0, fmt.Errorf("规范化路径长度超过上限 %d", MaxLocalPathBytes)
		}
		return "./" + joined, LocalPathRelative, 0, nil
	}
	return joined, LocalPathRelative, 0, nil
}

// parseLocalSegments 拆分并校验非根目录分量：一律禁止 ".." 穿越段，忽略冗余空段与 "."。
// 当 strictComponent 为 true（Windows 盘符或含反斜杠的相对路径）时，对每段执行完整 ValidateLocalComponent；
// 否则（POSIX 绝对或 POSIX 相对路径）校验单段长度上限并保留 POSIX 合法字符。
func parseLocalSegments(rest string, strictComponent bool) ([]string, error) {
	var out []string
	for seg := range strings.SplitSeq(rest, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			return nil, fmt.Errorf("本地路径禁止包含相对穿越段 '..'")
		}
		if strictComponent {
			if err := ValidateLocalComponent(seg); err != nil {
				return nil, err
			}
		} else if len(seg) > MaxComponentBytes {
			return nil, fmt.Errorf("路径分量 %q 长度 %d 超过上限 %d", seg, len(seg), MaxComponentBytes)
		}
		out = append(out, seg)
	}
	return slices.Clip(out), nil
}
