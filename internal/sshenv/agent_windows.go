//go:build windows

package sshenv

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

const agentDialDefaultTimeout = 2 * time.Second

func defaultAgentSocket() string {
	if sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK")); sock != "" {
		return sock
	}
	return defaultWindowsOpenSSHAgentPipe
}

func platformDialAgent() func(ctx context.Context, socket string) (net.Conn, error) {
	return func(ctx context.Context, socket string) (net.Conn, error) {
		if ctx == nil {
			return nil, errors.New("ssh-agent dial context is nil")
		}
		trimmed := strings.TrimSpace(socket)
		if trimmed == "" {
			trimmed = defaultWindowsOpenSSHAgentPipe
		}
		if pipePath, isPipe := normalizeWindowsAgentPipePath(trimmed); isPipe {
			return dialWindowsNamedPipe(ctx, pipePath)
		}
		dialer := net.Dialer{Timeout: agentDialDefaultTimeout}
		return dialer.DialContext(ctx, "unix", trimmed)
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
	for {
		if err := dialCtx.Err(); err != nil {
			return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(pipePath), Err: err}
		}

		handle, createErr := windows.CreateFile(
			pathPtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			flags,
			0,
		)
		if createErr == nil {
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
				return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: windowsPipeAddr(pipePath), Err: dialCtx.Err()}
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
// to SYSTEM, Builtin\Administrators, or the current user. When querying a
// privileged service token returns ERROR_ACCESS_DENIED, it falls back to the
// pipe kernel object's owner SID (readable via GENERIC_READ) and fails closed
// if neither check can establish a trusted owner.
func verifyWindowsAgentPipeServerOwner(pipeHandle windows.Handle) error {
	currSID, _ := currentWindowsProcessUserSID()

	var serverPID uint32
	if err := windows.GetNamedPipeServerProcessId(pipeHandle, &serverPID); err == nil && serverPID != 0 {
		if serverPID == uint32(os.Getpid()) {
			return nil
		}
		procHandle, openErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, serverPID)
		if openErr == nil {
			var tok windows.Token
			tokErr := windows.OpenProcessToken(procHandle, windows.TOKEN_QUERY, &tok)
			_ = windows.CloseHandle(procHandle)
			if tokErr == nil {
				tu, userErr := tok.GetTokenUser()
				_ = tok.Close()
				if userErr == nil && tu != nil && tu.User.Sid != nil {
					return evaluateWindowsAgentPipeOwner(
						true,
						isTrustedWindowsPrincipalSID(tu.User.Sid, currSID),
						serverPID,
						nil,
						false,
						false,
					)
				}
			}
		}
	}

	sd, err := windows.GetSecurityInfo(pipeHandle, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return evaluateWindowsAgentPipeOwner(false, false, serverPID, err, false, false)
	}
	if sd == nil {
		return evaluateWindowsAgentPipeOwner(false, false, serverPID, nil, false, false)
	}
	owner, _, ownerErr := sd.Owner()
	if ownerErr != nil {
		return evaluateWindowsAgentPipeOwner(false, false, serverPID, ownerErr, false, false)
	}
	if owner == nil {
		return evaluateWindowsAgentPipeOwner(false, false, serverPID, nil, false, false)
	}
	return evaluateWindowsAgentPipeOwner(
		false,
		false,
		serverPID,
		nil,
		true,
		isTrustedWindowsPrincipalSID(owner, currSID),
	)
}
