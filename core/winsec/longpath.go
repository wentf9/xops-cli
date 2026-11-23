package winsec

import "strings"

const windowsLongPathThreshold = 248

func utf16CodeUnitLen(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isWin32PathSep(b byte) bool {
	return b == '\\' || b == '/'
}

func isExtendedOrDeviceWindowsPath(path string) bool {
	if len(path) < 4 {
		return false
	}
	p0, p1, p2, p3 := path[0], path[1], path[2], path[3]
	if p0 == '\\' && p1 == '?' && p2 == '?' && isWin32PathSep(p3) {
		return true
	}
	return isWin32PathSep(p0) && isWin32PathSep(p1) && (p2 == '?' || p2 == '.') && isWin32PathSep(p3)
}

func isDriveRelativeWindowsPath(path string) bool {
	if len(path) < 2 || !isASCIIAlpha(path[0]) || path[1] != ':' {
		return false
	}
	return len(path) == 2 || !isWin32PathSep(path[2])
}

func isAbsWindowsPath(path string) bool {
	if len(path) >= 3 && isASCIIAlpha(path[0]) && path[1] == ':' && isWin32PathSep(path[2]) {
		return true
	}
	return len(path) >= 2 && isWin32PathSep(path[0]) && isWin32PathSep(path[1])
}

func applyWin32LongPathPrefix(full string) string {
	if isExtendedOrDeviceWindowsPath(full) {
		return full
	}
	full = strings.ReplaceAll(full, "/", `\`)
	if strings.HasPrefix(full, `\\`) {
		return `\\?\UNC\` + full[2:]
	}
	if len(full) >= 3 && isASCIIAlpha(full[0]) && full[1] == ':' && full[2] == '\\' {
		return `\\?\` + full
	}
	return full
}

// normalizeWin32LongPathWithResolver applies Win32 extended-length prefixing
// (\\?\ for DOS drive paths and \\?\UNC\... for UNC paths) whenever the
// effective path length is at least 248 UTF-16 code units, matching core/fsx's
// fixLongPathWindows semantics while measuring exact UTF-16 code units.
func normalizeWin32LongPathWithResolver(
	path string,
	fullPath func(string) (string, error),
	getwd func() (string, error),
) string {
	if path == "" || isExtendedOrDeviceWindowsPath(path) {
		return path
	}
	precomputedFull, effectiveLen, ok := measureEffectiveWin32PathLen(path, fullPath, getwd)
	if !ok || effectiveLen < windowsLongPathThreshold {
		return path
	}
	full := precomputedFull
	if full == "" {
		if fullPath != nil {
			var err error
			full, err = fullPath(path)
			if err != nil || full == "" {
				return path
			}
		} else {
			full = path
		}
	}
	return applyWin32LongPathPrefix(full)
}

func measureEffectiveWin32PathLen(
	path string,
	fullPath func(string) (string, error),
	getwd func() (string, error),
) (string, int, bool) {
	if isDriveRelativeWindowsPath(path) {
		if fullPath == nil {
			return "", 0, false
		}
		full, err := fullPath(path)
		if err != nil || full == "" {
			return "", 0, false
		}
		return full, utf16CodeUnitLen(full), true
	}
	effectiveLen := utf16CodeUnitLen(path)
	if !isAbsWindowsPath(path) && getwd != nil {
		if wd, err := getwd(); err == nil && wd != "" {
			effectiveLen += utf16CodeUnitLen(wd) + 1
		}
	}
	return "", effectiveLen, true
}
