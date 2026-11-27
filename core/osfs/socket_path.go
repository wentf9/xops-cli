package osfs

import (
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
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
		return "", wrapS(ErrInvalidControlPath, err)
	}
	return stripWin32LongPathPrefix(native), nil
}

// ControlSocketPathFromSource 将经 pathalg 校验的本地源路径转换为当前平台安全控制套接字路径；
// 兼容 Unix 下 OpenSSH %r@%h:%p 含 ':' 文件名，并在 Windows 上剥离 \\?\ 前缀后执行 sun_path 校验。
func ControlSocketPathFromSource(src pathalg.LocalSourcePath) (ControlSocketPath, error) {
	if !src.IsValid() {
		return ControlSocketPath{}, errField(ErrInvalidControlPath, "socket_source")
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
		return ControlSocketPath{}, domi18n.EF(ErrInvalidControlPath, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "percent_c"), domi18n.BoundStr("value", percentC))
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
		return ControlSocketPath{}, domi18n.EF(ErrInvalidControlPath, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "unix_socket_path"), domi18n.BoundStr("value", raw))
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
		return ControlSocketPath{}, domi18n.EF(ErrInvalidControlPath, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "windows_socket_path"), domi18n.BoundStr("value", raw))
	}
	prefix, rest, err := splitWindowsSocketPrefix(raw)
	if err != nil {
		return ControlSocketPath{}, err
	}
	if strings.ContainsRune(rest, ':') {
		return ControlSocketPath{}, domi18n.EF(ErrInvalidControlPath, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "windows_socket_path"), domi18n.BoundStr("value", raw))
	}
	slashRest := strings.ReplaceAll(rest, `\`, "/")
	if hasInvalidSocketTail(slashRest) {
		return ControlSocketPath{}, domi18n.EF(ErrInvalidControlPath, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "windows_socket_path"), domi18n.BoundStr("value", raw))
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
			return "", "", domi18n.EF(ErrInvalidControlPath, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "windows_socket_path"), domi18n.BoundStr("value", raw))
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
				return nil, domi18n.WrapS(ErrInvalidControlPath, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "socket_segment"), domi18n.BoundStr("value", seg))
			}
		} else if seg == ".." || len(seg) > pathalg.MaxComponentBytes {
			return nil, domi18n.EF(ErrInvalidControlPath, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "socket_segment"), domi18n.BoundStr("value", seg))
		}
		segs = append(segs, seg)
	}
	if len(segs) == 0 {
		return nil, domi18n.EF(ErrInvalidControlPath, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "socket_name"))
	}
	return segs, nil
}
func buildControlSocketPath(prefix, sep string, segs []string, maxBytes int) (ControlSocketPath, error) {
	native := prefix + strings.Join(segs, sep)
	if len(native) > maxBytes {
		return ControlSocketPath{}, domi18n.EF(ErrControlPathTooLong, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "socket_path"), domi18n.Int("size", len(native)), domi18n.Int("limit", maxBytes))
	}
	dir := pickIf(prefix != "", prefix, ".")
	if len(segs) > 1 {
		dir = prefix + strings.Join(segs[:len(segs)-1], sep)
	}
	return ControlSocketPath{dir: dir, name: segs[len(segs)-1], native: native, valid: true}, nil
}
