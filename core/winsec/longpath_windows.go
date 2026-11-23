//go:build windows

package winsec

import (
	"os"

	"golang.org/x/sys/windows"
)

func normalizeWin32LongPath(path string) string {
	return normalizeWin32LongPathWithResolver(path, windows.FullPath, os.Getwd)
}
