//go:build windows

package sshenv

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type platformProc struct {
	job     windows.Handle
	jobOnce sync.Once
}

func startPlatformShellCommand(command string, stdin io.Reader, stdout, stderr io.Writer) (*platformProc, *exec.Cmd, error) {
	job, err := createKillOnCloseJobObject()
	if err != nil {
		return nil, nil, err
	}

	cmdExe := resolveWindowsCmdExe()
	cmd := exec.Command(cmdExe)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: fmt.Sprintf(`"%s" /d /s /c "%s"`, cmdExe, command),
	}
	attachCommandIO(cmd, stdin, stdout, stderr)

	if err := cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, nil, fmt.Errorf("start Windows shell command via %s: %w", cmdExe, err)
	}

	proc := &platformProc{job: job}
	if err := assignPIDToJobObject(job, cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		proc.closeJob()
		return nil, nil, err
	}
	return proc, cmd, nil
}

func createKillOnCloseJobObject() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("create Windows job object: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("configure Windows job object: %w", err)
	}
	return job, nil
}

func assignPIDToJobObject(job windows.Handle, pid int) error {
	procHandle, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE,
		false,
		uint32(pid),
	)
	if err != nil {
		// Short-lived command may have exited before OpenProcess ran.
		return nil
	}
	defer func() {
		_ = windows.CloseHandle(procHandle)
	}()

	if err := windows.AssignProcessToJobObject(job, procHandle); err != nil {
		// AssignProcessToJobObject returns ERROR_ACCESS_DENIED when the child
		// has already terminated before assignment completes.
		waitRes, waitErr := windows.WaitForSingleObject(procHandle, 0)
		if waitErr == nil && waitRes == windows.WAIT_OBJECT_0 {
			return nil
		}
		return fmt.Errorf("assign process %d to Windows job object: %w", pid, err)
	}
	return nil
}

func resolveWindowsCmdExe() string {
	if comspec := strings.TrimSpace(os.Getenv("COMSPEC")); comspec != "" && filepath.IsAbs(comspec) {
		if info, err := os.Stat(comspec); err == nil && !info.IsDir() {
			return comspec
		}
	}
	if sysRoot := strings.TrimSpace(os.Getenv("SystemRoot")); sysRoot != "" && filepath.IsAbs(sysRoot) {
		candidate := filepath.Join(sysRoot, "System32", "cmd.exe")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return "cmd.exe"
}

func (p *platformProc) closeJob() {
	if p == nil {
		return
	}
	p.jobOnce.Do(func() {
		if p.job != 0 {
			_ = windows.CloseHandle(p.job)
			p.job = 0
		}
	})
}

func (p *platformProc) terminateTree(_ time.Duration, _ <-chan struct{}) {
	p.closeJob()
}

func (p *platformProc) reapRemainingGroup(_ time.Duration, _ <-chan struct{}) {
	p.closeJob()
}

func (p *platformProc) cleanupAfterWait() {
	p.closeJob()
}
