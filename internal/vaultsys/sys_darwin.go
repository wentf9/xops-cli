//go:build darwin

// Package vaultsys implements handle-relative operations used by offline vaults.
package vaultsys

import (
	"golang.org/x/sys/unix"
	"os"
)

type Stat_t struct {
	Dev, Ino, Nlink uint64
	Mode, Uid       uint32
	Size            int64
}

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
func Fstat(fd int, st *Stat_t) error {
	var raw unix.Stat_t
	if err := unix.Fstat(fd, &raw); err != nil {
		return err
	}
	*st = normalizeStat(raw)
	bits, err := aclPermissionBits(fd)
	if err != nil {
		return err
	}
	st.Mode |= bits
	return nil
}
func Fstatat(fd int, name string, st *Stat_t, flags int) error {
	var raw unix.Stat_t
	if err := unix.Fstatat(fd, name, &raw, flags); err != nil {
		return err
	}
	*st = normalizeStat(raw)
	return nil
}
func Mkdirat(fd int, name string, mode uint32) error { return unix.Mkdirat(fd, name, mode) }
func Unlinkat(fd int, name string, flags int) error  { return unix.Unlinkat(fd, name, flags) }
func Flock(fd, flags int) error                      { return unix.Flock(fd, flags) }
func SyncFile(file *os.File) error                   { return file.Sync() }

func normalizeStat(st unix.Stat_t) Stat_t {
	return Stat_t{Dev: uint64(st.Dev), Ino: st.Ino, Nlink: uint64(st.Nlink), Mode: uint32(st.Mode), Uid: st.Uid, Size: st.Size}
}
