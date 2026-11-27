//go:build !windows

package sys

// detectOSLocaleTag 在非 Windows（Unix/macOS 等）平台返回空串。
// 这些平台完全依赖 POSIX 环境变量链（XOPS_LANG/LC_ALL/LC_MESSAGES/LANG）并在缺失时回退 LocaleEn，
// 从而严守零 os/exec 子进程调用与零磁盘 I/O 的启动期不变量。
func detectOSLocaleTag() string {
	return ""
}
