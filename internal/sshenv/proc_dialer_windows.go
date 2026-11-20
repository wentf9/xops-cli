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

var procNtResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

type platformProc struct {
	process     *os.Process
	job         windows.Handle
	killOnClose bool
	jobOnce     sync.Once
}

func startPlatformShellCommand(command string, stdin io.Reader, stdout, stderr io.Writer, killTreeOnNormalExit bool) (*platformProc, *exec.Cmd, error) {
	job, err := createShellJobObject(killTreeOnNormalExit)
	if err != nil {
		return nil, nil, err
	}

	cmdExe := resolveWindowsCmdExe()
	cmd := exec.Command(cmdExe)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:       fmt.Sprintf(`"%s" /d /s /c "%s"`, cmdExe, command),
		CreationFlags: windows.CREATE_SUSPENDED,
	}
	attachCommandIO(cmd, stdin, stdout, stderr)

	if err := cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, nil, fmt.Errorf("start Windows shell command via %s: %w", cmdExe, err)
	}

	proc := &platformProc{
		process:     cmd.Process,
		job:         job,
		killOnClose: killTreeOnNormalExit,
	}
	if err := assignAndResumeSuspendedProcess(job, cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		proc.terminateAndCloseJob()
		return nil, nil, err
	}
	return proc, cmd, nil
}

func createShellJobObject(killOnClose bool) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("create Windows job object: %w", err)
	}
	if killOnClose {
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
	}
	return job, nil
}

// assignAndResumeSuspendedProcess attaches the CREATE_SUSPENDED child to job
// before resuming its threads via NtResumeProcess, closing the race window
// where fast grandchildren could escape JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
func assignAndResumeSuspendedProcess(job windows.Handle, pid int) error {
	procHandle, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_SUSPEND_RESUME|windows.SYNCHRONIZE,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("open child process %d for Windows job assignment: %w", pid, err)
	}
	defer func() {
		_ = windows.CloseHandle(procHandle)
	}()

	if err := windows.AssignProcessToJobObject(job, procHandle); err != nil {
		waitRes, waitErr := windows.WaitForSingleObject(procHandle, 0)
		if waitErr == nil && waitRes == windows.WAIT_OBJECT_0 {
			return nil
		}
		return fmt.Errorf("assign process %d to Windows job object: %w", pid, err)
	}

	r1, _, _ := procNtResumeProcess.Call(uintptr(procHandle))
	if status := windows.NTStatus(r1); status != 0 {
		waitRes, waitErr := windows.WaitForSingleObject(procHandle, 0)
		if waitErr == nil && waitRes == windows.WAIT_OBJECT_0 {
			return nil
		}
		return fmt.Errorf("resume process %d after Windows job assignment: %w", pid, status)
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

func (p *platformProc) terminateAndCloseJob() {
	if p == nil {
		return
	}
	p.jobOnce.Do(func() {
		if p.job != 0 {
			_ = windows.TerminateJobObject(p.job, 1)
			_ = windows.CloseHandle(p.job)
			p.job = 0
		}
	})
}

func (p *platformProc) terminateTree(_ time.Duration, _ <-chan struct{}) {
	if p == nil {
		return
	}
	p.terminateAndCloseJob()
	if p.process != nil {
		_ = p.process.Kill()
	}
}

func (p *platformProc) detachSentinelPipe() *os.File { return nil }

func pipeHasOpenWriter(_ *os.File) bool { return false }

func (p *platformProc) reapRemainingGroup(_ time.Duration, _, _ <-chan struct{}, alreadyExited bool) {
	if p == nil {
		return
	}
	p.terminateAndCloseJob()
	if !alreadyExited && p.process != nil {
		_ = p.process.Kill()
	}
}

func (p *platformProc) cleanupAfterWait(canceled bool) {
	if p == nil {
		return
	}
	if canceled || p.killOnClose {
		p.terminateAndCloseJob()
	} else {
		p.closeJob()
	}
}
