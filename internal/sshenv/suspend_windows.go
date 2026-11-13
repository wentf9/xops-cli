//go:build windows

package sshenv

func platformSuspendProcess() func() error {
	return nil
}
