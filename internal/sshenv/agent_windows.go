//go:build windows

package sshenv

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
)

const agentDialDefaultTimeout = 2 * time.Second

func defaultAgentSocket() string {
	raw := os.Getenv("SSH_AUTH_SOCK")
	if hasWindowsAgentControlChar(raw) {
		return raw
	}
	if sock := strings.TrimSpace(raw); sock != "" {
		return sock
	}
	return defaultWindowsOpenSSHAgentPipe
}

func platformDialAgent() func(ctx context.Context, socket string) (net.Conn, error) {
	return func(ctx context.Context, socket string) (net.Conn, error) {
		if ctx == nil {
			return nil, errors.New("ssh-agent dial context is nil")
		}
		target := socket
		if strings.TrimSpace(target) == "" && !hasWindowsAgentControlChar(target) {
			target = defaultWindowsOpenSSHAgentPipe
		}
		pipePath, isPipe, pipeErr := parseWindowsAgentPipePath(target)
		if pipeErr != nil {
			if isPipe {
				return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(strings.TrimSpace(target)), Err: pipeErr}
			}
			return nil, &net.OpError{Op: "dial", Net: "unix", Addr: &net.UnixAddr{Name: strings.TrimSpace(target), Net: "unix"}, Err: pipeErr}
		}
		if isPipe {
			return dialWindowsNamedPipe(ctx, pipePath)
		}
		dialer := net.Dialer{Timeout: agentDialDefaultTimeout}
		return dialer.DialContext(ctx, "unix", strings.TrimSpace(target))
	}
}

type windowsPipeAddr string

func (windowsPipeAddr) Network() string  { return "pipe" }
func (a windowsPipeAddr) String() string { return string(a) }

type windowsNamedPipeConn struct {
	file *os.File
	addr windowsPipeAddr
}

func (c *windowsNamedPipeConn) Read(p []byte) (int, error)         { return c.file.Read(p) }
func (c *windowsNamedPipeConn) Write(p []byte) (int, error)        { return c.file.Write(p) }
func (c *windowsNamedPipeConn) Close() error                       { return c.file.Close() }
func (c *windowsNamedPipeConn) LocalAddr() net.Addr                { return c.addr }
func (c *windowsNamedPipeConn) RemoteAddr() net.Addr               { return c.addr }
func (c *windowsNamedPipeConn) SetDeadline(t time.Time) error      { return c.file.SetDeadline(t) }
func (c *windowsNamedPipeConn) SetReadDeadline(t time.Time) error  { return c.file.SetReadDeadline(t) }
func (c *windowsNamedPipeConn) SetWriteDeadline(t time.Time) error { return c.file.SetWriteDeadline(t) }

func dialWindowsNamedPipe(ctx context.Context, pipePath string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, agentDialDefaultTimeout)
	defer cancel()

	if err := dialCtx.Err(); err != nil {
		return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(pipePath), Err: err}
	}

	pathPtr, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(pipePath), Err: err}
	}

	const flags = uint32(windows.FILE_FLAG_OVERLAPPED | windows.SECURITY_SQOS_PRESENT | windows.SECURITY_IDENTIFICATION)
	const desiredAccess = uint32(windows.FILE_GENERIC_READ | windows.FILE_WRITE_DATA)
	// Compile-time lockstep check ensuring the Windows constant matches the
	// cross-platform windowsAgentPipeDesiredAccess invariant (0x0012008b).
	const _ = uint32(windowsAgentPipeDesiredAccess-desiredAccess) + uint32(desiredAccess-windowsAgentPipeDesiredAccess)
	for {
		if err := dialCtx.Err(); err != nil {
			return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(pipePath), Err: err}
		}

		handle, createErr := windows.CreateFile(
			pathPtr,
			desiredAccess,
			0,
			nil,
			windows.OPEN_EXISTING,
			flags,
			0,
		)
		if createErr == nil {
			fileType, typeErr := windows.GetFileType(handle)
			if typeErr != nil {
				_ = windows.CloseHandle(handle)
				return nil, &net.OpError{
					Op:   "dial",
					Net:  "pipe",
					Addr: windowsPipeAddr(pipePath),
					Err:  fmt.Errorf("query windows agent pipe file type: %w", typeErr),
				}
			}
			if fileType != windows.FILE_TYPE_PIPE {
				_ = windows.CloseHandle(handle)
				return nil, &net.OpError{
					Op:   "dial",
					Net:  "pipe",
					Addr: windowsPipeAddr(pipePath),
					Err:  fmt.Errorf("agent socket %q is not a named pipe (file type %#x)", pipePath, fileType),
				}
			}
			if ownerErr := verifyWindowsAgentPipeServerOwner(handle); ownerErr != nil {
				_ = windows.CloseHandle(handle)
				return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(pipePath), Err: ownerErr}
			}
			file := os.NewFile(uintptr(handle), pipePath)
			if file == nil {
				_ = windows.CloseHandle(handle)
				return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(pipePath), Err: errors.New("os.NewFile returned nil for named pipe handle")}
			}
			if ctxErr := dialCtx.Err(); ctxErr != nil {
				_ = file.Close()
				return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(pipePath), Err: ctxErr}
			}
			return &windowsNamedPipeConn{file: file, addr: windowsPipeAddr(pipePath)}, nil
		}

		if !errors.Is(createErr, windows.ERROR_PIPE_BUSY) {
			return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(pipePath), Err: createErr}
		}

		waitDur := 25 * time.Millisecond
		if deadline, ok := dialCtx.Deadline(); ok {
			rem := time.Until(deadline)
			if rem <= 0 {
				err := dialCtx.Err()
				if err == nil {
					err = context.DeadlineExceeded
				}
				return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(pipePath), Err: err}
			}
			if rem < waitDur {
				waitDur = rem
			}
		}

		timer := time.NewTimer(waitDur)
		select {
		case <-dialCtx.Done():
			timer.Stop()
			return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(pipePath), Err: dialCtx.Err()}
		case <-timer.C:
		}
	}
}

// verifyWindowsAgentPipeServerOwner verifies that the named pipe server belongs
// to SYSTEM, Builtin\Administrators, or the current user, AND that the pipe's
// DACL does not grant FILE_CREATE_PIPE_INSTANCE / WRITE_DAC / WRITE_OWNER /
// GENERIC_WRITE / GENERIC_ALL to any untrusted principal.
func verifyWindowsAgentPipeServerOwner(pipeHandle windows.Handle) error {
	currSID, _ := currentWindowsProcessUserSID()

	var (
		serverPID     uint32
		tokenResolved bool
		tokenTrusted  bool
	)
	if err := windows.GetNamedPipeServerProcessId(pipeHandle, &serverPID); err == nil && serverPID != 0 {
		if serverPID == uint32(os.Getpid()) {
			tokenResolved = true
			tokenTrusted = true
		} else if peerSID, sidErr := winsec.ProcessUserSID(serverPID); sidErr == nil && peerSID != nil {
			tokenResolved = true
			tokenTrusted = isTrustedWindowsPrincipalSID(peerSID, currSID)
		}
	}

	sd, sdErr := windows.GetSecurityInfo(
		pipeHandle,
		windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if sdErr == nil && sd == nil {
		sdErr = errors.New("GetSecurityInfo returned nil security descriptor")
	}
	var (
		hasSDOwner     bool
		sdOwnerTrusted bool
		ownerErr       error
		hasDACL        bool
		aces           []windowsParsedACE
		daclErr        error
	)
	if sdErr == nil {
		owner, _, oErr := sd.Owner()
		if oErr != nil {
			ownerErr = oErr
		} else if owner != nil {
			hasSDOwner = true
			sdOwnerTrusted = isTrustedWindowsPrincipalSID(owner, currSID)
		}
		dacl, _, dErr := sd.DACL()
		if dErr != nil {
			daclErr = dErr
		} else if dacl != nil {
			parsed, ok := parseWindowsACL(dacl, currSID)
			if !ok {
				daclErr = errors.New("parse ssh-agent named pipe DACL failed")
			} else {
				hasDACL = true
				aces = parsed
			}
		}
	}
	effectiveSDErr := sdErr
	if effectiveSDErr == nil {
		effectiveSDErr = ownerErr
	}
	return evaluateWindowsAgentPipeSecurity(
		tokenResolved,
		tokenTrusted,
		serverPID,
		effectiveSDErr,
		hasSDOwner,
		sdOwnerTrusted,
		daclErr,
		hasDACL,
		aces,
	)
}
