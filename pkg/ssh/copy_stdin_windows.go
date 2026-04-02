//go:build windows

package ssh

import "io"

// copyStdinTo 在 Windows 上退化为 io.Copy 方案。
// Windows 不支持 unix.Poll，且 sftp shell 的 exec 命令在 Windows 上较少使用，
// 可接受极低概率下首个字符被吞的问题。
func copyStdinTo(dst io.Writer) (cancel func(), done <-chan struct{}) {
	return fallbackCopyStdinTo(dst)
}
