package remotefile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	pkgsftp "github.com/pkg/sftp"
	sshfx "github.com/pkg/sftp/v2/encoding/ssh/filexfer"
	"github.com/wentf9/xops-cli/core/sftp"
)

type Metadata struct {
	Path    string
	Size    int64
	ModTime int64
}

type StreamResult struct {
	Created           bool
	CreationAttempted bool
	CreationRejected  bool
	Bytes             int64
	SHA256            string
}

type CommitResult struct {
	Attempted bool
	Committed bool
	Rejected  bool
}

// Remote owns a dedicated SFTP subsystem. Readers/writers supplied by
// HTTP must have rolling deadlines and cancellation-driven I/O interruption.
type Remote interface {
	Inspect(context.Context, string, bool, bool) (Metadata, error)
	Upload(context.Context, string, io.Reader, int64, func() error, func(int64) error) (StreamResult, error)
	Download(context.Context, Metadata, io.Writer, func(int64) error) (StreamResult, error)
	Commit(context.Context, string, string, bool) (CommitResult, error)
	Remove(context.Context, string) error
	Close() error
}

// Client is the existing SFTP capability used by the streaming adapter.
type Client interface {
	Do(context.Context, func(*pkgsftp.Client) error) error
	CreatePrivateExclusive(context.Context, string, func(io.Writer) error) (bool, bool, error)
	Close() error
}

type Session struct{ client Client }

func New(client Client) *Session { return &Session{client: client} }

func (r *Session) Close() error { return r.client.Close() }

func (r *Session) Inspect(ctx context.Context, name string, upload, overwrite bool) (metadata Metadata, retErr error) {
	retErr = r.client.Do(ctx, func(client *pkgsftp.Client) error {
		var err error
		metadata, err = inspectTransferFile(client, name, upload, overwrite)
		return err
	})
	return metadata, retErr
}

func validateResolvedRealPath(raw string) (string, error) {
	parsed, err := sftp.ParseRemotePath(raw)
	if err != nil {
		return "", fmt.Errorf("invalid resolved remote path: %w", err)
	}
	if !parsed.IsAbs() {
		return "", fmt.Errorf("%w: resolved remote path %q is not absolute", sftp.ErrInvalidRemotePath, raw)
	}
	return parsed.String(), nil
}

func validateTransferInputPath(name string) (string, error) {
	if _, err := sftp.ParseRemotePath(name); err != nil {
		return "", fmt.Errorf("transfer requires an absolute remote file path: %w", err)
	}
	norm := NormalizeSFTPPath(name)
	parsed, err := sftp.ParseRemotePath(norm)
	if err != nil || !parsed.IsAbs() || IsRootPath(parsed.String()) || len(parsed.String()) > 4096 {
		return "", errors.New("transfer requires an absolute remote file path")
	}
	return parsed.String(), nil
}

func resolveTransferTargetPath(client *pkgsftp.Client, name string) (string, error) {
	rawParent, err := client.RealPath(path.Dir(name))
	if err != nil {
		return "", fmt.Errorf("resolve transfer parent directory: %w", err)
	}
	parent, err := validateResolvedRealPath(rawParent)
	if err != nil {
		return "", fmt.Errorf("resolve transfer parent directory: %w", err)
	}
	parentInfo, err := client.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("inspect transfer parent directory: %w", err)
	}
	if !parentInfo.IsDir() {
		return "", errors.New("transfer parent is not a directory")
	}
	resolved := path.Join(parent, path.Base(name))
	parsed, err := sftp.ParseRemotePath(resolved)
	if err != nil || !parsed.IsAbs() || IsRootPath(parsed.String()) || len(parsed.String()) > 4096 {
		return "", fmt.Errorf("resolve transfer file path: %w", sftp.ErrInvalidRemotePath)
	}
	return parsed.String(), nil
}

func inspectTransferFile(client *pkgsftp.Client, name string, upload, overwrite bool) (Metadata, error) {
	validName, err := validateTransferInputPath(name)
	if err != nil {
		return Metadata{}, err
	}
	resolvedPath, err := resolveTransferTargetPath(client, validName)
	if err != nil {
		return Metadata{}, err
	}
	metadata := Metadata{Path: resolvedPath}
	info, err := client.Lstat(metadata.Path)
	if err != nil && (!upload || !errors.Is(err, os.ErrNotExist)) {
		return metadata, fmt.Errorf("inspect transfer file: %w", err)
	}
	if err == nil {
		if !info.Mode().IsRegular() {
			return metadata, errors.New("transfer accepts ordinary files only, not symbolic links or special files")
		}
		if info.Size() < 0 {
			return Metadata{}, fmt.Errorf("%w: remote file %q has negative size %d", sftp.ErrInvalidRemoteSize, metadata.Path, info.Size())
		}
		if upload && !overwrite {
			return metadata, fmt.Errorf("upload destination already exists: %w", os.ErrExist)
		}
		metadata.Size, metadata.ModTime = info.Size(), info.ModTime().UnixNano()
	}
	if upload && overwrite {
		if _, ok := client.HasExtension("posix-rename@openssh.com"); !ok {
			return metadata, errors.New("target does not support atomic file replacement")
		}
	}
	return metadata, nil
}

func (r *Session) Upload(ctx context.Context, temporary string, source io.Reader, size int64, confirm func() error, progress func(int64) error) (result StreamResult, retErr error) {
	retErr = r.client.Do(ctx, func(client *pkgsftp.Client) (opErr error) {
		if _, err := client.Lstat(temporary); err == nil {
			result.CreationRejected = true
			return fmt.Errorf("temporary upload path already exists: %w", os.ErrExist)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect temporary upload path: %w", err)
		}
		var err error
		result.CreationAttempted, result.Created, err = r.client.CreatePrivateExclusive(ctx, temporary, func(file io.Writer) error {
			if confirm != nil {
				if err := confirm(); err != nil {
					return err
				}
			}
			var err error
			result.Bytes, result.SHA256, err = CopyStream(ctx, file, source, size, progress)
			if err != nil {
				return err
			}
			// Reject excess/chunked bodies before commit, including zero-byte files.
			var extra [1]byte
			if n, err := io.ReadFull(source, extra[:]); n != 0 || !errors.Is(err, io.EOF) {
				return errors.New("upload body exceeds declared length or did not terminate")
			}
			return nil
		})
		if !result.Created {
			result.CreationRejected = ExplicitSFTPRejection(err)
		}
		return err
	})
	return result, retErr
}

func (r *Session) Download(ctx context.Context, expected Metadata, destination io.Writer, progress func(int64) error) (result StreamResult, retErr error) {
	retErr = r.client.Do(ctx, func(client *pkgsftp.Client) (opErr error) {
		metadata, err := inspectTransferFile(client, expected.Path, false, false)
		if err != nil {
			return err
		}
		if metadata != expected {
			return errors.New("download source changed since task preparation")
		}
		file, err := client.Open(metadata.Path)
		if err != nil {
			return fmt.Errorf("open remote download file: %w", err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				opErr = errors.Join(opErr, fmt.Errorf("close remote download file failed: %w", err))
			}
		}()
		if err := verifyDownloadHandle(file, expected); err != nil {
			return err
		}
		result.Bytes, result.SHA256, err = CopyStream(ctx, destination, file, expected.Size, progress)
		if err != nil {
			return err
		}
		return verifyDownloadHandle(file, expected)
	})
	return result, retErr
}

func verifyDownloadHandle(file *pkgsftp.File, expected Metadata) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened download file: %w", err)
	}
	if info.Size() < 0 {
		return fmt.Errorf("%w: remote file %q has negative size %d", sftp.ErrInvalidRemoteSize, expected.Path, info.Size())
	}
	if !info.Mode().IsRegular() || info.Size() != expected.Size || info.ModTime().UnixNano() != expected.ModTime {
		return errors.New("opened download source changed during transfer")
	}
	return nil
}

func CopyStream(ctx context.Context, destination io.Writer, source io.Reader, size int64, progress func(int64) error) (int64, string, error) {
	if size < 0 {
		return 0, "", errors.New("negative transfer size")
	}
	digest := sha256.New()
	writer := io.MultiWriter(destination, digest)
	buffer := make([]byte, 32*1024)
	var copied int64
	emptyReads := 0
	for copied < size {
		if err := ctx.Err(); err != nil {
			return copied, "", fmt.Errorf("transfer interrupted: %w", err)
		}
		chunk := buffer[:min(int64(len(buffer)), size-copied)]
		n, err := source.Read(chunk)
		if n > 0 {
			emptyReads = 0
			written, writeErr := writer.Write(chunk[:n])
			copied += int64(written)
			if writeErr != nil {
				return copied, "", fmt.Errorf("forward file stream: %w", writeErr)
			}
			if progress != nil {
				if progressErr := progress(int64(written)); progressErr != nil {
					return copied, "", progressErr
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if copied == size {
					break
				}
				err = io.ErrUnexpectedEOF
			}
			return copied, "", fmt.Errorf("read complete file stream: %w", err)
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return copied, "", io.ErrNoProgress
			}
		}
	}
	return copied, hex.EncodeToString(digest.Sum(nil)), nil
}

func (r *Session) Commit(ctx context.Context, temporary, destination string, overwrite bool) (result CommitResult, retErr error) {
	retErr = r.client.Do(ctx, func(client *pkgsftp.Client) error {
		metadata, err := inspectTransferFile(client, destination, true, overwrite)
		if err != nil {
			return err
		}
		if metadata.Path != destination || path.Dir(temporary) != path.Dir(destination) {
			return errors.New("upload destination resolution changed before commit")
		}
		info, err := client.Lstat(temporary)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("upload temporary file is unavailable or not regular: %w", errors.Join(err, os.ErrInvalid))
		}
		result.Attempted = true
		if overwrite {
			err = client.PosixRename(temporary, destination)
		} else {
			// SFTP v3 RENAME must reject an existing newpath. Do not substitute
			// POSIX rename here: that would race a preceding existence check.
			err = client.Rename(temporary, destination)
		}
		if err == nil {
			result.Committed = true
			return nil
		}
		result.Rejected = ExplicitSFTPRejection(err)
		return fmt.Errorf("commit remote upload: %w", err)
	})
	return result, retErr
}

// ExplicitSFTPRejection reports whether err is a definitive SFTP server status
// indicating the target operation was rejected without mutating the path.
func ExplicitSFTPRejection(err error) bool {
	if errors.Is(err, os.ErrExist) || errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) {
		return true
	}
	var modern *sshfx.StatusPacket
	if errors.As(err, &modern) {
		return modern.StatusCode == sshfx.StatusNoSuchFile || modern.StatusCode == sshfx.StatusPermissionDenied || modern.StatusCode == sshfx.StatusOpUnsupported || modern.StatusCode == sshfx.StatusV4FileAlreadyExists
	}
	var status *pkgsftp.StatusError
	if errors.As(err, &status) {
		return status.Code == 2 || status.Code == 3 || status.Code == 8 || status.Code == 11
	}
	return false
}

// IsPermissionDenied reports whether err is an OS or SFTP permission-denied status.
func IsPermissionDenied(err error) bool {
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	var modern *sshfx.StatusPacket
	if errors.As(err, &modern) && modern.StatusCode == sshfx.StatusPermissionDenied {
		return true
	}
	var status *pkgsftp.StatusError
	return errors.As(err, &status) && status.Code == 3
}

func (r *Session) Remove(ctx context.Context, name string) error {
	parsedName, err := sftp.ParseRemotePath(name)
	if err != nil || !parsedName.IsAbs() || IsRootPath(parsedName.String()) {
		return fmt.Errorf("%w: cleanup requires an absolute remote file path", sftp.ErrInvalidRemotePath)
	}
	name = parsedName.String()
	return r.client.Do(ctx, func(client *pkgsftp.Client) error {
		rawParent, err := client.RealPath(path.Dir(name))
		if err != nil {
			return fmt.Errorf("resolve cleanup parent: %w", err)
		}
		parent, err := validateResolvedRealPath(rawParent)
		if err != nil {
			return fmt.Errorf("resolve cleanup parent: %w", err)
		}
		if path.Join(parent, path.Base(name)) != name {
			return errors.New("cleanup path resolution changed")
		}
		info, err := client.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect owned remote temporary file: %w", err)
		}
		if !info.Mode().IsRegular() {
			return errors.New("owned temporary path is no longer a regular file")
		}
		if err := client.Remove(name); err != nil {
			return fmt.Errorf("remove owned remote temporary file: %w", err)
		}
		return nil
	})
}

func isAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func formatNormalizedDrivePath(drive, rest string) string {
	rest = strings.ReplaceAll(rest, "\\", "/")
	cleanRest := path.Clean("/" + rest)
	if cleanRest == "/" {
		return "/" + drive + ":"
	}
	return "/" + drive + ":" + cleanRest
}

func normalizeLeadingDrivePath(p string, allowBare bool) (string, bool) {
	if allowBare && len(p) >= 2 && isAlpha(p[0]) && p[1] == ':' && (len(p) == 2 || p[2] == '/' || p[2] == '\\') {
		return formatNormalizedDrivePath(strings.ToUpper(string(p[0])), p[2:]), true
	}
	trimmed := strings.TrimLeft(p, "/")
	if len(trimmed) < len(p) && len(trimmed) >= 2 && isAlpha(trimmed[0]) && trimmed[1] == ':' && (len(trimmed) == 2 || trimmed[2] == '/' || trimmed[2] == '\\') {
		return formatNormalizedDrivePath(strings.ToUpper(string(trimmed[0])), trimmed[2:]), true
	}
	return "", false
}

// NormalizeSFTPPath converts Windows drive paths (C:\..., c:/..., /C:\...,
// //c:\..., /tmp/../C:/...) into OpenSSH SFTP canonical form (/C:/...) with an
// uppercase drive letter and forward slashes. Non-drive POSIX paths are cleaned
// without altering backslashes.
func NormalizeSFTPPath(p string) string {
	if p == "" {
		return ""
	}
	if norm, ok := normalizeLeadingDrivePath(p, true); ok {
		return norm
	}
	cleaned := path.Clean(p)
	if strings.HasPrefix(cleaned, "/") {
		if norm, ok := normalizeLeadingDrivePath(cleaned, false); ok {
			return norm
		}
	}
	return cleaned
}

// IsRootPath reports whether p represents a POSIX or Windows drive root directory.
func IsRootPath(cleaned string) bool {
	norm := NormalizeSFTPPath(cleaned)
	if norm == "/" {
		return true
	}
	return len(norm) == 3 && norm[0] == '/' && isAlpha(norm[1]) && norm[2] == ':'
}
