package osfs

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

const percentCHexLen = 40

// ControlSocketPath 表示经平台安全规则与 sun_path 上限校验的本地 AF_UNIX 套接字路径。
//
// 跨平台不变量：
//   - XOps 自管多路复用路径经 BuildManagedMuxSocketPath 使用 40 位小写十六进制 %C 命名（零 ':'）；
//   - Unix 允许用户指定 OpenSSH ControlPath 文件名含 ':'（如 cm-alice@host:22）；
//   - Windows/NTFS 严禁除盘符前缀（C:\）外任意位置出现 ':'，阻断 NTFS ADS 与非法文件名。
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

// BuildManagedMuxSocketPath 基于经校验的沙箱目录与 OpenSSH %C 40 位小写十六进制摘要构造自管套接字路径。
func BuildManagedMuxSocketPath(dir pathalg.LocalDir, percentC string) (ControlSocketPath, error) {
	if !dir.IsValid() || !isLowerHex40(percentC) {
		return ControlSocketPath{}, fmt.Errorf("%w: 控制套接字目录或 %%C 摘要 %q 无效", ErrInvalidControlPath, percentC)
	}
	nativeDir, err := localDirToNativePath(dir)
	if err != nil {
		return ControlSocketPath{}, fmt.Errorf("%w: %w", ErrInvalidControlPath, err)
	}
	// 剥离 \\?\ 扩展前缀，确保超长 Windows 目录落入 sun_path 长度校验并返回 ErrControlPathTooLong。
	nativeDir = stripWin32LongPathPrefix(nativeDir)
	sep := "/"
	if strings.ContainsRune(nativeDir, '\\') {
		sep = `\`
	}
	trimmed := strings.TrimRight(nativeDir, `/\`)
	return ValidateControlSocketPath(trimmed + sep + "cm-" + percentC + ".sock")
}

// ControlSocketPath 只读访问器与等价比对（无效值统一返回空字符串，严格失败关闭）。
func (p ControlSocketPath) IsValid() bool {
	return p.valid && p.native != "" && p.dir != "" && p.name != ""
}
func (p ControlSocketPath) IsZero() bool { return !p.IsValid() }
func (p ControlSocketPath) validStr(s string) string {
	if !p.IsValid() {
		return ""
	}
	return s
}
func (p ControlSocketPath) Dir() string        { return p.validStr(p.dir) }
func (p ControlSocketPath) Name() string       { return p.validStr(p.name) }
func (p ControlSocketPath) NativePath() string { return p.validStr(p.native) }
func (p ControlSocketPath) String() string     { return p.validStr(p.native) }
func (p ControlSocketPath) Equal(o ControlSocketPath) bool {
	return p.IsValid() && o.IsValid() && p.native == o.native
}

func isLowerHex40(s string) bool {
	if len(s) != percentCHexLen {
		return false
	}
	for i := range len(s) {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

func hasForbiddenControlPathRune(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

func hasInvalidSocketTail(slashPath string) bool {
	return slashPath == "" || slashPath == "." || slashPath == ".." ||
		strings.HasSuffix(slashPath, "/") || strings.HasSuffix(slashPath, "/.") || strings.HasSuffix(slashPath, "/..")
}

// ValidateUnixControlSocketPath 按 Unix 规则校验套接字路径：允许文件名含 ':'，拒绝 '..'、尾随分隔符/'.' 与超长 sun_path。
func ValidateUnixControlSocketPath(raw string, maxBytes int) (ControlSocketPath, error) {
	if maxBytes <= 0 || hasInvalidSocketTail(raw) || hasForbiddenControlPathRune(raw) {
		return ControlSocketPath{}, fmt.Errorf("%w: Unix 套接字路径 %q 非法", ErrInvalidControlPath, raw)
	}
	prefix := ""
	if strings.HasPrefix(raw, "/") {
		prefix = "/"
	}
	segs, err := splitCheckedSegments(strings.TrimPrefix(raw, "/"), false)
	if err != nil {
		return ControlSocketPath{}, err
	}
	return buildControlSocketPath(prefix, "/", segs, maxBytes)
}

// ValidateWindowsControlSocketPath 按 Windows/NTFS 规则严格校验套接字路径：除盘符前缀外严禁 ':'、前导 '/' 或 '\\'、尾随分隔符/'.'。
func ValidateWindowsControlSocketPath(raw string, maxBytes int) (ControlSocketPath, error) {
	if maxBytes <= 0 || raw == "" || hasForbiddenControlPathRune(raw) ||
		strings.HasPrefix(raw, `\`) || strings.HasPrefix(raw, "/") {
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
	dir := "."
	if len(segs) > 1 {
		dir = prefix + strings.Join(segs[:len(segs)-1], sep)
	} else if prefix != "" {
		dir = prefix
	}
	return ControlSocketPath{dir: dir, name: segs[len(segs)-1], native: native, valid: true}, nil
}
