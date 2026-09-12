//go:build linux && (amd64 || arm64)

package credentialfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type statxMountFunc func(int, string, int, int, *unix.Statx_t) error

func mountID(file *os.File) (uint64, error) {
	return mountIDWithStatx(file, unix.Statx)
}

func mountIDWithStatx(file *os.File, statx statxMountFunc) (uint64, error) {
	var st unix.Statx_t
	err := statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st)
	if err == nil && st.Mask&unix.STATX_MNT_ID != 0 {
		return st.Mnt_id, nil
	}
	if err != nil && !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP) {
		return 0, fmt.Errorf("identify vault mount: %w", errors.Join(ErrUnsupported, err))
	}
	// Older kernels can expose the same mount identity via fdinfo without
	// supporting statx or STATX_MNT_ID. Never substitute the device number:
	// distinct bind mounts may share one device.
	id, fallbackErr := mountIDFromFDInfo(file)
	if fallbackErr != nil {
		return 0, fmt.Errorf("identify vault mount via proc fdinfo: %w", errors.Join(ErrUnsupported, err, fallbackErr))
	}
	return id, nil
}

func mountIDFromFDInfo(file *os.File) (id uint64, err error) {
	info, err := os.Open("/proc/self/fdinfo/" + strconv.FormatUint(uint64(file.Fd()), 10))
	if err != nil {
		return 0, err
	}
	defer func() {
		closeFile(&err, info)
		if err != nil {
			id = 0
		}
	}()
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(info.Fd()), &fs); err != nil {
		return 0, fmt.Errorf("verify fdinfo filesystem: %w", err)
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return 0, fmt.Errorf("fdinfo is not on procfs")
	}
	data, err := io.ReadAll(io.LimitReader(info, 4097))
	if err != nil {
		return 0, fmt.Errorf("read mount fdinfo: %w", err)
	}
	if len(data) > 4096 {
		return 0, fmt.Errorf("mount fdinfo exceeds size limit")
	}
	return parseFDInfoMountID(string(data))
}

func parseFDInfoMountID(data string) (uint64, error) {
	var id uint64
	found := false
	for _, line := range strings.Split(data, "\n") {
		value, ok := strings.CutPrefix(line, "mnt_id:")
		if !ok {
			continue
		}
		if found {
			return 0, fmt.Errorf("duplicate mount ID in fdinfo")
		}
		found = true
		value = strings.TrimSpace(value)
		if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return 0, fmt.Errorf("invalid mount ID in fdinfo")
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil || parsed == 0 {
			return 0, fmt.Errorf("invalid mount ID in fdinfo")
		}
		id = parsed
	}
	if !found {
		return 0, fmt.Errorf("mount ID unavailable in fdinfo")
	}
	return id, nil
}
