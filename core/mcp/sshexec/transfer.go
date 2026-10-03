package sshexec

import "github.com/wentf9/xops-cli/core/sftp"

// Transfer permits are enforced by ports.GuardTransfer. The original subsystem
// and plan lease survive the handoff from streaming to commit authority.
type transferFiles struct {
	*sftp.Client
	release func() error
}

func (f *transferFiles) Close() error { return f.release() }
