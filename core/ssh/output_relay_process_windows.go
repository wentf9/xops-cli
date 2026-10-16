//go:build windows

package ssh

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PROC_THREAD_ATTRIBUTE_JOB_LIST is available starting with Windows 10. Using
// creation-time assignment avoids an orphan window between CreateProcess and
// AssignProcessToJobObject, including if the parent is killed during startup.
const windowsRelayJobListAttribute = 0x0002000D

// startWindowsConsoleRelay returns ownership of both handles if a process was
// created, even if closing the initial thread handle failed. On pre-start errors
// it returns no handles. The job handle is non-inheritable and kept only by the
// owning binding; parent exit therefore terminates all processes in the job.
func startWindowsConsoleRelay(config ConsoleOutputRelay, spec string, inherited []windows.Handle) (process, job windows.Handle, retErr error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if process == 0 {
			retErr = errors.Join(retErr, windows.CloseHandle(job))
			job = 0
		}
	}()
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return 0, job, err
	}
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return 0, job, err
	}
	defer attributes.Delete()
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherited[0]), uintptr(len(inherited))*unsafe.Sizeof(inherited[0])); err != nil {
		return 0, job, err
	}
	jobs := []windows.Handle{job}
	if err := attributes.Update(windowsRelayJobListAttribute, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs[0])); err != nil {
		return 0, job, err
	}
	executable, err := windows.UTF16PtrFromString(config.Executable)
	if err != nil {
		return 0, job, err
	}
	args := append([]string{config.Executable}, config.Args...)
	args = append(args, spec)
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return 0, job, err
	}
	environment, err := windowsConsoleRelayEnvironment(config.Env)
	if err != nil {
		return 0, job, err
	}
	var startup windows.StartupInfoEx
	startup.Cb = uint32(unsafe.Sizeof(startup))
	// Standard handles are intentionally null. Only the three protocol/console
	// handles above are inherited; helper startup cannot write into the protocol.
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.ProcThreadAttributeList = attributes.List()
	var info windows.ProcessInformation
	flags := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	err = windows.CreateProcess(executable, commandLine, nil, nil, true, flags, &environment[0], nil, &startup.StartupInfo, &info)
	runtime.KeepAlive(inherited)
	runtime.KeepAlive(jobs)
	if err != nil {
		return 0, job, err
	}
	process = info.Process
	return process, job, windows.CloseHandle(info.Thread)
}

func windowsConsoleRelayEnvironment(entries []string) ([]uint16, error) {
	var block []uint16
	for _, entry := range entries {
		if entry == "" {
			continue
		}
		encoded, err := windows.UTF16FromString(entry)
		if err != nil {
			return nil, err
		}
		block = append(block, encoded...)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0), nil // Windows environment blocks end in two NULs.
}
