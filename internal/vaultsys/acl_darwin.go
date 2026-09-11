//go:build darwin

package vaultsys

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"sync"

	"github.com/ebitengine/purego"
)

type darwinACLAPI struct {
	getFD uintptr
	valid func(uintptr) int32
	entry func(uintptr, int32, *uintptr) int32
	tag   func(uintptr, *uint32) int32
	mask  func(uintptr, *uint64) int32
	flags func(uintptr, *uintptr) int32
	flag  func(uintptr, uint32) int32
	free  func(uintptr) int32
}

// libSystem is retained for the process lifetime while these pointers are live.
var loadDarwinACL = sync.OnceValues(func() (*darwinACLAPI, error) {
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	api := &darwinACLAPI{}
	api.getFD, err = purego.Dlsym(lib, "acl_get_fd_np")
	if err != nil {
		return nil, errors.Join(err, purego.Dlclose(lib))
	}
	for _, binding := range []struct {
		name   string
		target any
	}{
		{"acl_valid", &api.valid}, {"acl_get_entry", &api.entry},
		{"acl_get_tag_type", &api.tag}, {"acl_get_permset_mask_np", &api.mask},
		{"acl_get_flagset_np", &api.flags}, {"acl_get_flag_np", &api.flag}, {"acl_free", &api.free},
	} {
		address, e := purego.Dlsym(lib, binding.name)
		if e != nil {
			return nil, errors.Join(e, purego.Dlclose(lib))
		}
		purego.RegisterFunc(binding.target, address)
	}
	return api, nil
})

// POSIX mode bits alone do not account for macOS extended ACL grants. Mark
// additional grants conservatively; inherited data grants also make a parent
// unsafe for private-file creation, before any secret bytes are written.
func aclPermissionBits(fd int) (bits uint32, err error) {
	api, err := loadDarwinACL()
	if err != nil {
		return 0, fmt.Errorf("load macOS ACL API: %w", err)
	}
	acl, status := getDarwinACL(api, fd)
	if acl == 0 {
		if status == unix.ENOENT || status == unix.ENOTSUP {
			return 0, nil
		}
		return 0, fmt.Errorf("read macOS file ACL: %w", status)
	}
	defer func() {
		if api.free(acl) != 0 {
			err = errors.Join(err, fmt.Errorf("free macOS file ACL"))
		}
	}()
	if api.valid(acl) != 0 {
		return 0, fmt.Errorf("invalid macOS file ACL: %w", os.ErrPermission)
	}
	for index := int32(0); index < 170; index++ {
		var entry uintptr
		if api.entry(acl, index, &entry) != 0 {
			return bits, nil
		}
		extra, e := aclEntryBits(api, entry)
		if e != nil {
			return 0, e
		}
		bits |= extra
	}
	return 0, fmt.Errorf("macOS ACL entry limit exceeded: %w", os.ErrPermission)
}

func aclEntryBits(api *darwinACLAPI, entry uintptr) (uint32, error) {
	var tag uint32
	if api.tag(entry, &tag) != 0 {
		return 0, os.ErrPermission
	}
	if tag == 2 {
		return 0, nil
	} // A deny entry grants no additional access.
	if tag != 1 {
		return 0, os.ErrPermission
	}
	var mask uint64
	var flags uintptr
	if api.mask(entry, &mask) != 0 || api.flags(entry, &flags) != 0 {
		return 0, os.ErrPermission
	}
	bits := uint32(0)
	const readData = 1 << 1
	const writeData = (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13)
	if mask&readData != 0 {
		bits |= 0044
	}
	if mask&writeData != 0 {
		bits |= 0022
	}
	if mask&(readData|writeData) != 0 && (api.flag(flags, 1<<5) == 1 || api.flag(flags, 1<<6) == 1) {
		bits |= 0022
	}
	return bits, nil
}

// Capture errno in the same native call. Reading thread-local errno after
// returning through Go can observe an unrelated runtime/library operation.
func getDarwinACL(api *darwinACLAPI, fd int) (uintptr, unix.Errno) {
	for range 8 {
		value, _, status := purego.SyscallN(api.getFD, uintptr(fd), 0x100)
		if value != 0 || unix.Errno(status) != unix.EINTR {
			return value, unix.Errno(status)
		}
	}
	return 0, unix.EINTR
}
