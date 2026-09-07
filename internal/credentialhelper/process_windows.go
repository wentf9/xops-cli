//go:build windows

package credentialhelper

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type processSession struct {
	cmd    *exec.Cmd
	job    windows.Handle
	mu     sync.Mutex
	closed bool
}

func startProcessSession(cmd *exec.Cmd) (*processSession, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create job object: %w", err)
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
		return nil, fmt.Errorf("set job object information: %w", err)
	}

	cmd.Cancel = func() error {
		_ = windows.TerminateJobObject(job, 1)
		if cmd.Process != nil {
			return cmd.Process.Kill()
		}
		return nil
	}

	// 在进程启动前将其置为挂起状态，确保在完成 Job Object 绑定前禁止子进程执行任何指令或派生子孙进程
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED

	if err := cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("start suspended process: %w", err)
	}

	cleanupOnError := func() {
		_ = windows.TerminateJobObject(job, 1)
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		_ = windows.CloseHandle(job)
	}

	hProcess, openErr := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if openErr != nil {
		cleanupOnError()
		return nil, fmt.Errorf("open process for job assignment: %w", openErr)
	}

	assignErr := windows.AssignProcessToJobObject(job, hProcess)
	_ = windows.CloseHandle(hProcess)
	if assignErr != nil {
		cleanupOnError()
		return nil, fmt.Errorf("assign process to job object: %w", assignErr)
	}

	// 绑定完成后恢复子进程主线程执行
	if resumeErr := resumeProcessMainThread(cmd.Process.Pid); resumeErr != nil {
		cleanupOnError()
		return nil, fmt.Errorf("resume process main thread: %w", resumeErr)
	}

	return &processSession{
		cmd: cmd,
		job: job,
	}, nil
}

func resumeProcessMainThread(pid int) error {
	deadline := time.Now().Add(1 * time.Second)
	for {
		resumed, err := tryResumeProcessThreads(pid)
		if err != nil {
			return err
		}
		if resumed {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("main thread not found for process %d", pid)
}

func tryResumeProcessThreads(pid int) (bool, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return false, fmt.Errorf("create thread snapshot: %w", err)
	}
	defer func() {
		_ = windows.CloseHandle(snap)
	}()

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if err := windows.Thread32First(snap, &te); err != nil {
		return false, nil
	}
	found := false
	for {
		if te.OwnerProcessID == uint32(pid) {
			hThread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
			if err != nil {
				return false, fmt.Errorf("open thread %d: %w", te.ThreadID, err)
			}
			prevCount, resumeErr := windows.ResumeThread(hThread)
			_ = windows.CloseHandle(hThread)
			if resumeErr != nil && prevCount == 0xFFFFFFFF {
				return false, fmt.Errorf("resume thread %d: %w", te.ThreadID, resumeErr)
			}
			found = true
		}
		if err := windows.Thread32Next(snap, &te); err != nil {
			break
		}
	}
	return found, nil
}

func (s *processSession) KillTree() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.job != 0 {
		_ = windows.TerminateJobObject(s.job, 1)
	}
	if s.cmd != nil && s.cmd.Process != nil {
		return s.cmd.Process.Kill()
	}
	return nil
}

func (s *processSession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	var firstErr error
	if s.job != 0 {
		_ = windows.TerminateJobObject(s.job, 1)
		if err := windows.CloseHandle(s.job); err != nil && firstErr == nil {
			firstErr = err
		}
		s.job = 0
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	return firstErr
}
