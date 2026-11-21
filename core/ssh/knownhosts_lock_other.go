//go:build !unix && !windows

package ssh

import "os"

func openKnownHostsFileNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}

func openKnownHostsReadOnlyFollow(path string) (*os.File, error) {
	return os.Open(path)
}

func lockKnownHostsFile(*os.File, bool) error {
	return nil
}

func unlockKnownHostsFile(*os.File) error {
	return nil
}

func hardenNewKnownHostsFile(string) error {
	return nil
}

func withControlSocketDirLock(_ string, fn func() error) error {
	return fn()
}
