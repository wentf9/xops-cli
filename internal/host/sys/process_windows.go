//go:build windows

package sys

import (
	"os"
	"os/exec"
	"sync"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"golang.org/x/sys/windows"
)

func configureCmdPlatform(cmd *exec.Cmd, bindCancel bool) {
	if !bindCancel {
		return
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
}

func attachRunCleanup(cmd *exec.Cmd) func()  { return attachWindowsJobCleanup(cmd) }
func attachDialCleanup(cmd *exec.Cmd) func() { return attachWindowsJobCleanup(cmd) }

// attachWindowsJobCleanup 在 Windows 上为子进程绑定带 KILL_ON_JOB_CLOSE 标志的 Job Object，
// 确保取消、超时或 DialStdio.Close 时由内核同步回收整棵进程树（含持有管道句柄的孙进程），零 PID 复用风险。
func attachWindowsJobCleanup(cmd *exec.Cmd) func() {
	if cmd == nil || cmd.Process == nil {
		return func() {}
	}
	job, err := createKillOnCloseJob()
	if err != nil {
		return func() {}
	}
	procHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = windows.CloseHandle(job)
		return func() {}
	}
	assignErr := windows.AssignProcessToJobObject(job, procHandle)
	_ = windows.CloseHandle(procHandle)
	if assignErr != nil {
		_ = windows.CloseHandle(job)
		return func() {}
	}
	var once sync.Once
	return func() {
		once.Do(func() { _ = windows.CloseHandle(job) })
	}
}

func createKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func exitStatusFromState(ps *os.ProcessState) (execution.ExitStatus, error) {
	if ps == nil {
		return execution.NewExitUnknown("process exit status unavailable"), nil
	}
	return execution.NewExitCode(int32(ps.ExitCode())), nil
}
