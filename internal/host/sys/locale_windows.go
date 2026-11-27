//go:build windows

package sys

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsLocaleNameMaxLength 对应 Win32 LOCALE_NAME_MAX_LENGTH（含末尾 UTF-16 NUL 终止符）。
const windowsLocaleNameMaxLength = 85

// detectOSLocaleTag 在 Windows 平台调用 kernel32.dll 的 GetUserDefaultLocaleName 查询当前用户默认区域标签。
//
// 实现约束：
//   - 在函数局部按需构造 LazySystemDLL/LazyProc，严格零包级可变 var；
//   - 调用 proc.Call 前显式检查 proc.Find()，避免目标符号缺失时触发 panic；
//   - 返回值异常（0 或越界）时失败关闭返回空串，由上层安全回退至 LocaleEn。
func detectOSLocaleTag() string {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultLocaleName")
	if err := proc.Find(); err != nil {
		return ""
	}
	var buf [windowsLocaleNameMaxLength]uint16
	r1, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	runtime.KeepAlive(&buf)
	if r1 == 0 || r1 > uintptr(len(buf)) {
		return ""
	}
	return windows.UTF16ToString(buf[:r1])
}
