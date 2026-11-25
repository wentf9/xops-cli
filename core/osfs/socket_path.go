package osfs

import (
	"fmt"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"strings"
	"unicode"
	"unicode/utf8"
)

const percentCHexLen = 40

// ControlSocketPath 表示经平台安全规则与 sun_path 上限校验的本地 AF_UNIX 套接字路径。
// Unix 允许 OpenSSH ControlPath 含 ':'（如 cm-alice@host:22），Windows 除盘符前缀外严禁 ':'。
//
//xops:opaque
//xops:failclosed
type ControlSocketPath struct {
	dir, name, native string
	valid             bool
}

// MaxUnixSocketPathBytes 返回当前平台 sockaddr_un.sun_path 最大路径字节数（不含结尾 NUL）。
func MaxUnixSocketPathBytes() int { return maxUnixSocketPathBytesOS() }

// ValidateControlSocketPath 按当前运行平台规则校验并构造不可变 ControlSocketPath。
func ValidateControlSocketPath(raw string) (ControlSocketPath, error) {
	return validateControlSocketPathOS(raw)
}
func nativeControlBase(kind pathalg.LocalPathKind, raw string) (string, error) {
	native, err := localPathToNativeOS(kind, raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidControlPath, err)
	}
	return stripWin32LongPathPrefix(native), nil
}

// ControlSocketPathFromSource 将经 pathalg 校验的本地源路径转换为当前平台安全控制套接字路径；
// 兼容 Unix 下 OpenSSH %r@%h:%p 含 ':' 文件名，并在 Windows 上剥离 \\?\ 前缀后执行 sun_path 校验。
func ControlSocketPathFromSource(src pathalg.LocalSourcePath) (ControlSocketPath, error) {
	if !src.IsValid() {
		return ControlSocketPath{}, fmt.Errorf("%w: 控制套接字源路径无效", ErrInvalidControlPath)
	}
	native, err := nativeControlBase(src.Kind(), src.String())
	if err != nil {
		return ControlSocketPath{}, err
	}
	return ValidateControlSocketPath(native)
}

// BuildManagedMuxSocketPath 基于经校验的沙箱目录与 OpenSSH %C 40 位小写十六进制摘要构造自管套接字路径。
func BuildManagedMuxSocketPath(dir pathalg.LocalDir, percentC string) (ControlSocketPath, error) {
	if !dir.IsValid() || !isLowerHex40(percentC) {
		return ControlSocketPath{}, fmt.Errorf("%w: 控制套接字目录或 %%C 摘要 %q 无效", ErrInvalidControlPath, percentC)
	}
	nativeDir, err := nativeControlBase(dir.Kind(), dir.String())
	if err != nil {
		return ControlSocketPath{}, err
	}
	sep := pickIf(strings.ContainsRune(nativeDir, '\\'), `\`, "/")
	return ValidateControlSocketPath(strings.TrimRight(nativeDir, `/\`) + sep + "cm-" + percentC + ".sock")
}
func (p ControlSocketPath) IsValid() bool {
	return p.valid && p.native != "" && p.dir != "" && p.name != ""
}
func (p ControlSocketPath) IsZero() bool       { return !p.IsValid() }
func (p ControlSocketPath) Dir() string        { return orZero(p.IsValid(), p.dir) }
func (p ControlSocketPath) Name() string       { return orZero(p.IsValid(), p.name) }
func (p ControlSocketPath) NativePath() string { return orZero(p.IsValid(), p.native) }
func (p ControlSocketPath) String() string     { return orZero(p.IsValid(), p.native) }
func (p ControlSocketPath) Equal(o ControlSocketPath) bool {
	return p.IsValid() && o.IsValid() && p.native == o.native
}
func isLowerHex40(s string) bool {
	return len(s) == percentCHexLen && !strings.ContainsFunc(s, func(r rune) bool { return (r < '0' || r > '9') && (r < 'a' || r > 'f') })
}
func hasForbiddenControlPathRune(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Cf, r)
	})
}
func hasInvalidSocketTail(p string) bool {
	return p == "" || p == "." || p == ".." || strings.HasSuffix(p, "/") || strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..")
}

// ValidateUnixControlSocketPath 按 Unix 规则校验套接字路径：允许文件名含 ':'，拒绝 '..'、尾随分隔符/'.' 与超长 sun_path。
func ValidateUnixControlSocketPath(raw string, maxBytes int) (ControlSocketPath, error) {
	if maxBytes <= 0 || hasInvalidSocketTail(raw) || hasForbiddenControlPathRune(raw) {
		return ControlSocketPath{}, fmt.Errorf("%w: Unix 套接字路径 %q 非法", ErrInvalidControlPath, raw)
	}
	prefix := pickIf(strings.HasPrefix(raw, "/"), "/", "")
	segs, err := splitCheckedSegments(strings.TrimPrefix(raw, "/"), false)
	if err != nil {
		return ControlSocketPath{}, err
	}
	return buildControlSocketPath(prefix, "/", segs, maxBytes)
}

// ValidateWindowsControlSocketPath 按 Windows/NTFS 规则严格校验套接字路径：除盘符前缀外严禁 ':'、前导分隔符与尾随分隔符/'.'。
func ValidateWindowsControlSocketPath(raw string, maxBytes int) (ControlSocketPath, error) {
	if maxBytes <= 0 || raw == "" || hasForbiddenControlPathRune(raw) || strings.HasPrefix(raw, `\`) || strings.HasPrefix(raw, "/") {
		return ControlSocketPath{}, fmt.Errorf("%w: Windows 套接字路径 %q 非法", ErrInvalidControlPath, raw)
	}
	prefix, rest, err := splitWindowsSocketPrefix(raw)
	if err != nil {
		return ControlSocketPath{}, err
	}
	if strings.ContainsRune(rest, ':') {
		return ControlSocketPath{}, fmt.Errorf("%w: Windows/NTFS 套接字路径 %q 禁止文件名包含 ':'", ErrInvalidControlPath, raw)
	}
	slashRest := strings.ReplaceAll(rest, `\`, "/")
	if hasInvalidSocketTail(slashRest) {
		return ControlSocketPath{}, fmt.Errorf("%w: Windows 套接字路径 %q 缺少合法文件名", ErrInvalidControlPath, raw)
	}
	segs, err := splitCheckedSegments(slashRest, true)
	if err != nil {
		return ControlSocketPath{}, err
	}
	return buildControlSocketPath(prefix, `\`, segs, maxBytes)
}
func splitWindowsSocketPrefix(raw string) (string, string, error) {
	if len(raw) >= 2 && isASCIIAlphaByte(raw[0]) && raw[1] == ':' {
		if len(raw) < 3 || !isWin32Sep(raw[2]) {
			return "", "", fmt.Errorf("%w: Windows 路径 %q 禁止盘符相对写法", ErrInvalidControlPath, raw)
		}
		return strings.ToUpper(raw[:1]) + `:\`, raw[3:], nil
	}
	return "", raw, nil
}
func splitCheckedSegments(slashRest string, strictWin bool) ([]string, error) {
	var segs []string
	for seg := range strings.SplitSeq(slashRest, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if strictWin {
			if err := pathalg.ValidateLocalComponent(seg); err != nil {
				return nil, fmt.Errorf("%w: Windows 套接字分量 %q 非法: %w", ErrInvalidControlPath, seg, err)
			}
		} else if seg == ".." || len(seg) > pathalg.MaxComponentBytes {
			return nil, fmt.Errorf("%w: Unix 套接字分量 %q 非法或超长", ErrInvalidControlPath, seg)
		}
		segs = append(segs, seg)
	}
	if len(segs) == 0 {
		return nil, fmt.Errorf("%w: 套接字路径缺少文件名", ErrInvalidControlPath)
	}
	return segs, nil
}
func buildControlSocketPath(prefix, sep string, segs []string, maxBytes int) (ControlSocketPath, error) {
	native := prefix + strings.Join(segs, sep)
	if len(native) > maxBytes {
		return ControlSocketPath{}, fmt.Errorf("%w: 套接字路径长度 %d 超过上限 %d", ErrControlPathTooLong, len(native), maxBytes)
	}
	dir := pickIf(prefix != "", prefix, ".")
	if len(segs) > 1 {
		dir = prefix + strings.Join(segs[:len(segs)-1], sep)
	}
	return ControlSocketPath{dir: dir, name: segs[len(segs)-1], native: native, valid: true}, nil
}
