//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	unix "github.com/wentf9/xops-cli/internal/vaultsys"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func readKeyFile(ctx context.Context, path string) (key []byte, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, credential.ErrCredentialAccessDenied
	}
	f, err := os.Open(filepath.VolumeName(path) + string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if err != nil {
			clear(key)
			key = nil
		}
	}()
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(path, filepath.VolumeName(path)), string(filepath.Separator)), string(filepath.Separator))
	for i, part := range parts {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(int(f.Fd()), part, flags, 0)
		if err != nil {
			return nil, mapAccess(err)
		}
		next := os.NewFile(uintptr(fd), "unlock-material")
		closeErr := f.Close()
		f = next
		if closeErr != nil {
			return nil, closeErr
		}
		st, err := inspect(f)
		if err != nil {
			return nil, err
		}
		if err := validateKeyPathStat(st, i == len(parts)-1); err != nil {
			return nil, err
		}
	}
	key, err = readKeyMaterial(f)
	if err != nil {
		return nil, err
	}
	if err := context.Cause(ctx); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

func readKeyMaterial(r io.Reader) ([]byte, error) {
	key, err := io.ReadAll(io.LimitReader(r, 33))
	if err != nil {
		clear(key)
		return nil, err
	}
	if len(key) != 32 {
		clear(key)
		return nil, credential.ErrCredentialStoreLocked
	}
	return key, nil
}

func validateKeyPathStat(st unix.Stat_t, final bool) error {
	if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
		return credential.ErrCredentialAccessDenied
	}
	if !final {
		if st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0 {
			return credential.ErrCredentialAccessDenied
		}
		return nil
	}
	if st.Nlink != 1 || (st.Mode != unix.S_IFREG|0400 && st.Mode != unix.S_IFREG|0600) {
		return credential.ErrCredentialAccessDenied
	}
	if st.Size != 32 {
		return credential.ErrCredentialStoreLocked
	}
	return nil
}
