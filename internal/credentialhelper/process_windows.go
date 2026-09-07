//go:build windows

package credentialhelper

import (
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

type processSession struct {
	cmd *exec.Cmd
	job windows.Handle
}

func startProcessSession(cmd *exec.Cmd) (*processSession, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err == nil {
		var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		_, _ = windows.SetInformationJobObject(
			job,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
		)
	}

	cmd.Cancel = func() error {
		if job != 0 {
			_ = windows.TerminateJobObject(job, 1)
		}
		if cmd.Process != nil {
			return cmd.Process.Kill()
		}
		return nil
	}

	if err := cmd.Start(); err != nil {
		if job != 0 {
			_ = windows.CloseHandle(job)
		}
		return nil, err
	}

	if job != 0 && cmd.Process != nil {
		hProcess, openErr := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
		if openErr == nil {
			_ = windows.AssignProcessToJobObject(job, hProcess)
			_ = windows.CloseHandle(hProcess)
		}
	}

	return &processSession{
		cmd: cmd,
		job: job,
	}, nil
}

func (s *processSession) KillTree() error {
	if s == nil {
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
	_ = s.KillTree()
	if s.job != 0 {
		err := windows.CloseHandle(s.job)
		s.job = 0
		return err
	}
	return nil
}
