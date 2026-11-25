package osfs

import (
	"github.com/wentf9/xops-cli/core/domain/security"
	"os"
	"path/filepath"
	"strings"
)

// Win32LongPathThreshold 是触发 Win32 扩展长路径前缀（\\?\ 与 \\?\UNC\）的 UTF-16 码元阈值（INV-A4）。
const Win32LongPathThreshold = 248

// Win32 DACL 与文件属性位常量（跨平台纯数学副本）。
const (
	WinAttrDirectory, WinAttrDevice, WinAttrReparsePoint                         uint32 = 0x10, 0x40, 0x400
	WinACEFlagInheritOnly, WinACETypeAllow, WinACETypeDeny                       uint8  = 0x08, 0x00, 0x01
	WinAccessWriteData, WinAccessAppendData, WinAccessWriteEA                    uint32 = 0x02, 0x04, 0x10
	WinAccessDeleteChild                                                         uint32 = 0x40 // WinSDK winnt.h FILE_DELETE_CHILD（目录删除子项权限）
	WinAccessWriteAttrs, WinAccessDelete, WinAccessWriteDAC, WinAccessWriteOwner uint32 = 0x100, 0x10000, 0x40000, 0x80000
	WinAccessGenericAll, WinAccessGenericWrite                                   uint32 = 0x10000000, 0x40000000
	winMutatingMask                                                              uint32 = WinAccessWriteData | WinAccessAppendData | WinAccessWriteEA | WinAccessDeleteChild |
		WinAccessWriteAttrs | WinAccessDelete | WinAccessWriteDAC | WinAccessWriteOwner | WinAccessGenericAll | WinAccessGenericWrite
)

// WindowsACLMode 区分 Windows DACL 安全评估策略；零值 WindowsACLInvalid 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type WindowsACLMode uint8

const (
	WindowsACLInvalid         WindowsACLMode = iota // 无效评估模式（零值失败关闭）
	WindowsACLOwnerOnly                             // 仅受信任所有者/系统主体可访问
	WindowsACLWriteRestricted                       // 严禁非受信任主体具备写/删/改权位
)

// ParsedWindowsACE 表示从 Windows DACL 解码出的单条 ACE 纯数学视图。
type ParsedWindowsACE struct {
	ACEType, ACEFlags    uint8
	Mask                 uint32
	SIDValid, SIDTrusted bool
}

// WindowsACLInput 封装待评估 Windows 对象的属性与解析后 DACL 信息。
type WindowsACLInput struct {
	Mode                                           WindowsACLMode
	Attrs                                          uint32
	ExpectDir, AllowReparse, OwnerTrusted, HasDACL bool
	ACEs                                           []ParsedWindowsACE
}

// EvaluateWindowsObjectACL 以失败关闭交半格语义评估 Windows 对象属性与 DACL 安全性（INV-A4 / INV-E1）。
func EvaluateWindowsObjectACL(in WindowsACLInput) security.Verdict {
	if (in.Mode != WindowsACLOwnerOnly && in.Mode != WindowsACLWriteRestricted) ||
		!in.OwnerTrusted || !in.HasDACL || !isSafeWin32ObjectAttrs(in.Attrs, in.ExpectDir, in.AllowReparse) {
		return security.VerdictDeny
	}
	for _, ace := range in.ACEs {
		if evaluateSingleWindowsACE(in.Mode, in.ExpectDir, ace) != security.VerdictAllow {
			return security.VerdictDeny
		}
	}
	return security.VerdictAllow
}
func isSafeWin32ObjectAttrs(attrs uint32, expectDir, allowReparse bool) bool {
	return attrs&WinAttrDevice == 0 && (allowReparse || attrs&WinAttrReparsePoint == 0) && (attrs&WinAttrDirectory != 0) == expectDir
}
func evaluateSingleWindowsACE(mode WindowsACLMode, expectDir bool, ace ParsedWindowsACE) security.Verdict {
	// 非目录对象上 INHERIT_ONLY_ACE 不生效；目录对象上的可继承 ACE 会传染给新建子对象，严禁跳过。
	if (!expectDir && ace.ACEFlags&WinACEFlagInheritOnly != 0) || ace.ACEType == WinACETypeDeny {
		return security.VerdictAllow
	}
	if ace.ACEType != WinACETypeAllow || !ace.SIDValid ||
		(!ace.SIDTrusted && ((mode == WindowsACLOwnerOnly && ace.Mask != 0) || (mode == WindowsACLWriteRestricted && ace.Mask&winMutatingMask != 0))) {
		return security.VerdictDeny
	}
	return security.VerdictAllow
}

// UTF16CodeUnitLen 计算字符串在 UTF-16 编码下的精确码元数量（辅助平面码点计 2 码元）。
func UTF16CodeUnitLen(s string) (n int) {
	for _, r := range s {
		n += pickIf(r >= 0x10000, 2, 1)
	}
	return n
}

// IsExtendedOrDeviceWindowsPath 报告路径是否已携带 \\?\、\\.\ 或 \??\ Win32 设备/扩展前缀。
func IsExtendedOrDeviceWindowsPath(path string) bool {
	return len(path) >= 4 && ((path[0] == '\\' && path[1] == '?' && path[2] == '?' && isWin32Sep(path[3])) ||
		(isWin32Sep(path[0]) && isWin32Sep(path[1]) && (path[2] == '?' || path[2] == '.') && isWin32Sep(path[3])))
}
func stripWin32LongPathPrefix(p string) string {
	if rest, ok := strings.CutPrefix(p, `\\?\UNC\`); ok {
		return `\\` + rest
	}
	return strings.TrimPrefix(p, `\\?\`)
}

// NormalizeWin32LongPath 在有效路径长度 >= 248 UTF-16 码元时补齐 \\?\ 或 \\?\UNC\ 前缀（INV-A4）。
func NormalizeWin32LongPath(p string) string {
	return normalizeWin32LongPathWithResolver(p, filepath.Abs, os.Getwd)
}
func normalizeWin32LongPathWithResolver(path string, fullPath func(string) (string, error), getwd func() (string, error)) string {
	if path == "" || IsExtendedOrDeviceWindowsPath(path) {
		return path
	}
	pre, n, err := measureEffectiveWin32PathLen(path, fullPath, getwd)
	if err != nil || n < Win32LongPathThreshold {
		return path
	}
	if full := resolveWin32LongFullPath(path, pre, fullPath); full != "" {
		return applyWin32LongPathPrefix(full)
	}
	return path
}
func resolveWin32LongFullPath(path, pre string, fullPath func(string) (string, error)) string {
	if pre != "" || fullPath == nil {
		return pickIf(pre != "", pre, path)
	}
	resolved, err := fullPath(path)
	if err != nil || resolved == "" {
		return ""
	}
	// 非 Windows 宿主上 filepath.Abs 会拼 POSIX cwd，保留原 Windows 绝对路径。
	return pickIf(isAbsWinPath(resolved) || IsExtendedOrDeviceWindowsPath(resolved), resolved, pickIf(isAbsWinPath(path), path, ""))
}
func measureEffectiveWin32PathLen(path string, fullPath func(string) (string, error), getwd func() (string, error)) (string, int, error) {
	if isDriveRelativeWinPath(path) {
		if fullPath != nil {
			if full, err := fullPath(path); err == nil && full != "" {
				return full, UTF16CodeUnitLen(full), nil
			}
		}
		return "", 0, os.ErrInvalid
	}
	n := UTF16CodeUnitLen(path)
	if !isAbsWinPath(path) && getwd != nil {
		if wd, err := getwd(); err == nil && wd != "" {
			n += UTF16CodeUnitLen(wd) + 1
		}
	}
	return "", n, nil
}
func applyWin32LongPathPrefix(full string) string {
	if IsExtendedOrDeviceWindowsPath(full) {
		return full
	}
	norm := strings.ReplaceAll(full, "/", `\`)
	if strings.HasPrefix(norm, `\\`) {
		return `\\?\UNC\` + norm[2:]
	}
	if len(norm) >= 3 && isASCIIAlphaByte(norm[0]) && norm[1] == ':' && norm[2] == '\\' {
		return `\\?\` + norm
	}
	return norm
}
func isASCIIAlphaByte(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
func isWin32Sep(b byte) bool       { return b == '\\' || b == '/' }
func isDriveRelativeWinPath(p string) bool {
	return len(p) >= 2 && isASCIIAlphaByte(p[0]) && p[1] == ':' && (len(p) == 2 || !isWin32Sep(p[2]))
}
func isAbsWinPath(p string) bool {
	return (len(p) >= 3 && isASCIIAlphaByte(p[0]) && p[1] == ':' && isWin32Sep(p[2])) || (len(p) >= 2 && isWin32Sep(p[0]) && isWin32Sep(p[1]))
}
