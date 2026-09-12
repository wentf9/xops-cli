//go:build windows && (amd64 || arm64)

package kdfhelper

import (
	"errors"
	"golang.org/x/sys/windows"
	"os/exec"
	"sync"
	"unsafe"
)

var privateJobs sync.Map

func preparePrivateProcess(cmd *exec.Cmd) (func() error, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, errors.Join(err, windows.CloseHandle(job))
	}
	privateJobs.Store(cmd, job)
	return func() error { privateJobs.Delete(cmd); return windows.CloseHandle(job) }, nil
}
func attachPrivateProcess(cmd *exec.Cmd) error {
	value, ok := privateJobs.Load(cmd)
	if !ok {
		return ErrProcess
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}
	return errors.Join(windows.AssignProcessToJobObject(value.(windows.Handle), process), windows.CloseHandle(process))
}
