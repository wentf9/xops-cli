//go:build linux && amd64

package credentialfile

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
	"golang.org/x/sys/unix"
)

type fileID struct {
	dev uint64
	ino uint64
}

type directory struct {
	file  *os.File
	id    fileID
	mount uint64
}

// Fault injection stays package-private; production callers cannot bypass checks.
type fileOps struct {
	before func(string) error
	after  func(string)
	random io.Reader
}

func (o fileOps) step(ctx context.Context, name string, fn func() error) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if o.before != nil {
		if err := o.before(name); err != nil {
			return err
		}
	}
	if err := fn(); err != nil {
		return err
	}
	if o.after != nil {
		o.after(name)
	}
	return nil
}

func (o fileOps) randomBytes(b []byte) error {
	r := o.random
	if r == nil {
		r = rand.Reader
	}
	if _, err := io.ReadFull(r, b); err != nil {
		return fmt.Errorf("generate vault randomness: %w", err)
	}
	return nil
}

func inspect(file *os.File) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return st, fmt.Errorf("stat vault handle: %w", err)
	}
	return st, nil
}

func validatePrivate(st unix.Stat_t, dir bool) error {
	want := uint32(unix.S_IFREG | 0600)
	if dir {
		want = unix.S_IFDIR | 0700
	}
	if st.Mode != want || st.Uid != uint32(os.Geteuid()) || (!dir && st.Nlink != 1) {
		return credential.ErrCredentialAccessDenied
	}
	return nil
}

func mountID(file *os.File) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st); err != nil {
		return 0, fmt.Errorf("identify vault mount: %w", errors.Join(ErrUnsupported, err))
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, ErrUnsupported
	}
	return st.Mnt_id, nil
}

func checkExt4(file *os.File, st unix.Stat_t) (id uint64, err error) {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &fs); err != nil {
		return 0, fmt.Errorf("identify vault filesystem: %w", err)
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		return 0, ErrUnsupported
	}
	id, err = mountID(file)
	if err != nil {
		return 0, err
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return 0, fmt.Errorf("read mount information: %w", errors.Join(ErrUnsupported, err))
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return id, matchMount(f, id, st.Dev)
}

func matchMount(r io.Reader, id, dev uint64) error {
	scan := bufio.NewScanner(io.LimitReader(r, 4*1024*1024+1))
	scan.Buffer(make([]byte, 4096), 64*1024)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) < 10 {
			continue
		}
		mount, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || mount != id {
			continue
		}
		want := fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev))
		if fields[2] != want {
			return ErrUnsupported
		}
		for i := 6; i+1 < len(fields); i++ {
			if fields[i] == "-" {
				if fields[i+1] == "ext4" {
					return nil
				}
				return ErrUnsupported
			}
		}
		return ErrUnsupported
	}
	if err := scan.Err(); err != nil {
		return fmt.Errorf("parse mount information: %w", errors.Join(ErrUnsupported, err))
	}
	return ErrUnsupported
}

func newDirectory(file *os.File, root *directory) (d *directory, err error) {
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	st, err := inspect(file)
	if err != nil {
		return nil, err
	}
	if err := validatePrivate(st, true); err != nil {
		return nil, err
	}
	var mount uint64
	if root == nil {
		mount, err = checkExt4(file, st)
	} else {
		mount, err = mountID(file)
		if err == nil && (st.Dev != root.id.dev || mount != root.mount) {
			err = ErrUnsupported
		}
	}
	if err != nil {
		return nil, err
	}
	return &directory{file: file, id: fileID{st.Dev, st.Ino}, mount: mount}, nil
}

func openRoot(ctx context.Context, path string) (*directory, error) {
	f, err := walkDirectory(ctx, path)
	if err != nil {
		return nil, err
	}
	return newDirectory(f, nil)
}

func walkDirectory(ctx context.Context, path string) (_ *os.File, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("vault path must be a clean absolute private directory")
	}
	f, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	defer func() {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
	}()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		parts = nil
	}
	for _, part := range parts {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		fd, openErr := unix.Openat(int(f.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, fmt.Errorf("open vault directory component: %w", openErr)
		}
		next := os.NewFile(uintptr(fd), "vault-directory")
		closeErr := f.Close()
		f = next
		if closeErr != nil {
			return nil, fmt.Errorf("close ancestor directory: %w", closeErr)
		}
		{
			st, statErr := inspect(f)
			if statErr != nil {
				return nil, statErr
			}
			trustedOwner := st.Uid == 0 || st.Uid == uint32(os.Geteuid())
			protected := st.Mode&0022 == 0 || st.Mode&unix.S_ISVTX != 0
			if !trustedOwner || !protected {
				return nil, credential.ErrCredentialAccessDenied
			}
		}
	}
	owned := f
	f = nil
	return owned, nil
}

func component(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00")
}

func (d *directory) check() error {
	st, err := inspect(d.file)
	if err != nil {
		return err
	}
	if err := validatePrivate(st, true); err != nil {
		return err
	}
	if (fileID{st.Dev, st.Ino}) != d.id {
		return ErrRevisionChanged
	}
	return nil
}

func (d *directory) child(name string) (*directory, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	if !component(name) {
		return nil, credential.ErrCredentialAccessDenied
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open vault subdirectory: %w", err)
	}
	return newDirectory(os.NewFile(uintptr(fd), "vault-subdirectory"), d)
}

// openHandle transfers ownership immediately after openat, before validation.
// Creation callers must install both handle and pathname cleanup before checking it.
func (d *directory) openHandle(name string, flags int) (*os.File, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	if !component(name) {
		return nil, credential.ErrCredentialAccessDenied
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("open vault file: %w", err)
	}
	return os.NewFile(uintptr(fd), "vault-file"), nil
}

func (d *directory) validateFile(f *os.File) error {
	st, err := inspect(f)
	if err == nil {
		err = validatePrivate(st, false)
	}
	if err == nil && st.Dev != d.id.dev {
		err = ErrUnsupported
	}
	if err == nil {
		var mount uint64
		mount, err = mountID(f)
		if err == nil && mount != d.mount {
			err = ErrUnsupported
		}
	}
	return err
}

func (d *directory) open(name string, flags int) (*os.File, error) {
	if flags&unix.O_CREAT != 0 {
		return nil, fmt.Errorf("vault file creation requires immediate pathname cleanup")
	}
	f, err := d.openHandle(name, flags)
	if err != nil {
		return nil, err
	}
	if err := d.validateFile(f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func (d *directory) read(ctx context.Context, name string, max int) (data []byte, err error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	f, err := d.open(name, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if err != nil {
			data = nil
		}
	}()
	st, err := inspect(f)
	if err != nil {
		return nil, err
	}
	if st.Size < 0 || st.Size > int64(max) {
		return nil, fmt.Errorf("vault file exceeds size limit: %w", format.ErrCorrupt)
	}
	data, err = io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("read vault file: %w", err)
	}
	if len(data) > max {
		return nil, fmt.Errorf("vault file exceeds size limit: %w", format.ErrCorrupt)
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	return data, nil
}

func (d *directory) pending(ctx context.Context, anyEntry bool) (err error) {
	if err := d.check(); err != nil {
		return err
	}
	fd, err := unix.Openat(int(d.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open directory listing: %w", err)
	}
	f := os.NewFile(uintptr(fd), "vault-listing")
	defer func() { err = errors.Join(err, f.Close()) }()
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		entries, readErr := f.ReadDir(64)
		for _, entry := range entries {
			if anyEntry || strings.HasPrefix(entry.Name(), ".tmp-") {
				return ErrMaintenanceRequired
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("list vault directory: %w", readErr)
		}
	}
}

func (d *directory) syncExisting(ctx context.Context, name, scope string, ops fileOps) (durable bool, err error) {
	f, err := d.open(name, unix.O_RDONLY)
	if err != nil {
		return false, err
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if ops.before != nil {
			err = errors.Join(err, ops.before(scope+":close"))
		}
	}()
	if err := ops.step(ctx, scope+":file-sync", f.Sync); err != nil {
		return false, err
	}
	if err := ops.step(ctx, scope+":dir-sync", d.file.Sync); err != nil {
		return false, err
	}
	return true, nil
}

type mutationOutcome struct{ applied, durable bool }

func (d *directory) write(ctx context.Context, name string, data []byte, replace bool, scope string, ops fileOps) (out mutationOutcome, err error) {
	var random [16]byte
	if err := ops.randomBytes(random[:]); err != nil {
		return out, err
	}
	temp := ".tmp-" + hex.EncodeToString(random[:])
	f, err := d.openHandle(temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return out, err
	}
	published := false
	defer func() {
		err = errors.Join(err, f.Close())
		if ops.before != nil {
			err = errors.Join(err, ops.before(scope+":close"))
		}
		if !published {
			err = errors.Join(err, unix.Unlinkat(int(d.file.Fd()), temp, 0), d.file.Sync())
		}
		if err != nil && out.applied {
			err = &DurabilityError{Op: scope, Applied: out.applied, Durable: out.durable, Cause: err}
		}
	}()
	if err := d.validateFile(f); err != nil {
		return out, err
	}
	if err := ops.step(ctx, scope+":write", func() error {
		n, err := f.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	}); err != nil {
		return out, err
	}
	if err := ops.step(ctx, scope+":file-sync", f.Sync); err != nil {
		return out, err
	}
	if err := ops.step(ctx, scope+":publish", func() error {
		flags := uint(unix.RENAME_NOREPLACE)
		if replace {
			flags = 0
		}
		return unix.Renameat2(int(d.file.Fd()), temp, int(d.file.Fd()), name, flags)
	}); err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
			err = errors.Join(ErrUnsupported, err)
		}
		return out, err
	}
	published = true
	out.applied = true
	if err := ops.step(ctx, scope+":dir-sync", d.file.Sync); err != nil {
		return out, err
	}
	out.durable = true
	return out, nil
}
