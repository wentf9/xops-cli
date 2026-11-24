//go:build unix

package osfs

import "syscall"

func UseAllowedUnixFlock() {
	_ = syscall.Flock(0, syscall.LOCK_EX)
}
