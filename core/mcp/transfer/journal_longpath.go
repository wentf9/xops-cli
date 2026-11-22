package transfer

import "strings"

func isExtendedOrDeviceWindowsPath(p string) bool {
	if len(p) < 4 {
		return false
	}
	isSlash := func(b byte) bool { return b == '\\' || b == '/' }
	p0, p1, p2, p3 := p[0], p[1], p[2], p[3]
	if p0 == '\\' && p1 == '?' && p2 == '?' && p3 == '\\' {
		return true
	}
	return isSlash(p0) && isSlash(p1) && (p2 == '?' || p2 == '.') && isSlash(p3)
}

func isDriveRelativeWindowsPath(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0]
	isDriveLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	if !isDriveLetter {
		return false
	}
	return len(p) == 2 || (p[2] != '\\' && p[2] != '/')
}

// normalizeWindowsLongPath applies Windows extended-length (\\?\ or \\?\UNC\)
// normalization matching core/fsx/fsx_windows.go:fixLongPathWindows so Win32
// calls such as MoveFileEx succeed on paths exceeding MAX_PATH without
// requiring LongPathsEnabled.
func normalizeWindowsLongPath(
	p string,
	isAbs func(string) bool,
	getwd func() (string, error),
	fullPath func(string) (string, error),
) string {
	if p == "" || isExtendedOrDeviceWindowsPath(p) {
		return p
	}
	var precomputedFull string
	effectiveLen := len(p)
	if isDriveRelativeWindowsPath(p) {
		full, err := fullPath(p)
		if err != nil || full == "" {
			return p
		}
		precomputedFull = full
		effectiveLen = len(full)
	} else if !isAbs(p) {
		if wd, err := getwd(); err == nil {
			effectiveLen += len(wd) + 1
		}
	}
	if effectiveLen < 248 {
		return p
	}
	full := precomputedFull
	if full == "" {
		var err error
		full, err = fullPath(p)
		if err != nil || full == "" {
			return p
		}
	}
	if isExtendedOrDeviceWindowsPath(full) {
		return full
	}
	if strings.HasPrefix(full, `\\`) && !strings.HasPrefix(full, `\\?\`) {
		return `\\?\UNC\` + full[2:]
	}
	return `\\?\` + full
}
