//go:build windows

package violations

import "syscall"

func bannedWindowsCreateProcess() {
	_ = syscall.CreateProcess(nil, nil, nil, nil, false, 0, nil, nil, nil, nil) // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
}
