//go:build unix

package violations

import "syscall"

func bannedUnixFlock() {
	_ = syscall.Flock(0, syscall.LOCK_EX) // want "core/osfs 之外禁止直接调用裸 OS"
}
