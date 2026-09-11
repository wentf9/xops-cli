//go:build linux

// Package vaultsys implements handle-relative operations used by offline vaults.
package vaultsys

import (
	"golang.org/x/sys/unix"
	"os"
)

type Stat_t = unix.Stat_t

const (
	O_RDONLY            = unix.O_RDONLY
	O_WRONLY            = unix.O_WRONLY
	O_RDWR              = unix.O_RDWR
	O_CREAT             = unix.O_CREAT
	O_EXCL              = unix.O_EXCL
	O_CLOEXEC           = unix.O_CLOEXEC
	O_DIRECTORY         = unix.O_DIRECTORY
	O_NOFOLLOW          = unix.O_NOFOLLOW
	O_NONBLOCK          = unix.O_NONBLOCK
	S_IFREG             = unix.S_IFREG
	S_IFDIR             = unix.S_IFDIR
	S_ISVTX             = unix.S_ISVTX
	AT_REMOVEDIR        = unix.AT_REMOVEDIR
	AT_SYMLINK_NOFOLLOW = unix.AT_SYMLINK_NOFOLLOW
	LOCK_EX             = unix.LOCK_EX
	LOCK_SH             = unix.LOCK_SH
	LOCK_NB             = unix.LOCK_NB
	LOCK_UN             = unix.LOCK_UN
	EAGAIN              = unix.EAGAIN
	EEXIST              = unix.EEXIST
	EINVAL              = unix.EINVAL
	ELOOP               = unix.ELOOP
	ENOSYS              = unix.ENOSYS
	ENOTDIR             = unix.ENOTDIR
	EOPNOTSUPP          = unix.EOPNOTSUPP
	EWOULDBLOCK         = unix.EWOULDBLOCK
)

func Openat(fd int, name string, flags int, mode uint32) (int, error) {
	return unix.Openat(fd, name, flags, mode)
}
func Fstat(fd int, st *Stat_t) error { return unix.Fstat(fd, st) }
func Fstatat(fd int, name string, st *Stat_t, flags int) error {
	return unix.Fstatat(fd, name, st, flags)
}
func Mkdirat(fd int, name string, mode uint32) error { return unix.Mkdirat(fd, name, mode) }
func Unlinkat(fd int, name string, flags int) error  { return unix.Unlinkat(fd, name, flags) }
func Flock(fd, flags int) error                      { return unix.Flock(fd, flags) }
func SyncFile(file *os.File) error                   { return file.Sync() }
