package mcpserver

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
	"github.com/wentf9/xops-cli/pkg/sftp"
)

type remoteFileMetadata struct {
	Path    string
	Size    int64
	ModTime int64
}

type streamResult struct {
	Created           bool
	CreationAttempted bool
	CreationRejected  bool
	Bytes             int64
	SHA256            string
}

type commitResult struct {
	Attempted bool
	Committed bool
	Rejected  bool
}

// transferRemote owns a dedicated SFTP subsystem. Readers/writers supplied by
// HTTP must have rolling deadlines and cancellation-driven I/O interruption.
type transferRemote interface {
	Inspect(context.Context, string, bool, bool) (remoteFileMetadata, error)
	Upload(context.Context, string, io.Reader, int64, func() error, func(int64) error) (streamResult, error)
	Download(context.Context, remoteFileMetadata, io.Writer, func(int64) error) (streamResult, error)
	Commit(context.Context, string, string, bool) (commitResult, error)
	Remove(context.Context, string) error
	Close() error
}

type sftpTransferRemote struct{ client *sftp.Client }

func (r *Runtime) openTransferRemote(ctx context.Context, nodeID string) (transferRemote, error) {
	if r.transferDial != nil {
		return r.transferDial(ctx, nodeID)
	}
	client, err := r.getMCPSFTPClient(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	return &sftpTransferRemote{client: client}, nil
}

func (r *sftpTransferRemote) Close() error { return r.client.Close() }

func (r *sftpTransferRemote) Inspect(ctx context.Context, name string, upload, overwrite bool) (metadata remoteFileMetadata, retErr error) {
	retErr = r.client.Do(ctx, func(client *pkgsftp.Client) error {
		var err error
		metadata, err = inspectTransferFile(client, name, upload, overwrite)
		return err
	})
	return metadata, retErr
}

func inspectTransferFile(client *pkgsftp.Client, name string, upload, overwrite bool) (remoteFileMetadata, error) {
	if !path.IsAbs(name) || name == "/" || len(name) > 4096 || strings.ContainsRune(name, '\x00') {
		return remoteFileMetadata{}, errors.New("transfer requires an absolute remote file path")
	}
	name = path.Clean(name)
	parent, err := client.RealPath(path.Dir(name))
	if err != nil {
		return remoteFileMetadata{}, fmt.Errorf("resolve transfer parent directory: %w", err)
	}
	parentInfo, err := client.Stat(parent)
	if err != nil {
		return remoteFileMetadata{}, fmt.Errorf("inspect transfer parent directory: %w", err)
	}
	if !parentInfo.IsDir() {
		return remoteFileMetadata{}, errors.New("transfer parent is not a directory")
	}
	metadata := remoteFileMetadata{Path: path.Join(parent, path.Base(name))}
	info, err := client.Lstat(metadata.Path)
	if err != nil && (!upload || !errors.Is(err, os.ErrNotExist)) {
		return metadata, fmt.Errorf("inspect transfer file: %w", err)
	}
	if err == nil {
		if !info.Mode().IsRegular() {
			return metadata, errors.New("transfer accepts ordinary files only, not symbolic links or special files")
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

func (r *sftpTransferRemote) Upload(ctx context.Context, temporary string, source io.Reader, size int64, confirm func() error, progress func(int64) error) (result streamResult, retErr error) {
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
			result.Bytes, result.SHA256, err = copyTransferStream(ctx, file, source, size, progress)
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
			result.CreationRejected = explicitSFTPRejection(err)
		}
		return err
	})
	return result, retErr
}

func (r *sftpTransferRemote) Download(ctx context.Context, expected remoteFileMetadata, destination io.Writer, progress func(int64) error) (result streamResult, retErr error) {
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
		defer joinCloseError(&opErr, file, "remote download file")
		if err := verifyDownloadHandle(file, expected); err != nil {
			return err
		}
		result.Bytes, result.SHA256, err = copyTransferStream(ctx, destination, file, expected.Size, progress)
		if err != nil {
			return err
		}
		return verifyDownloadHandle(file, expected)
	})
	return result, retErr
}

func verifyDownloadHandle(file *pkgsftp.File, expected remoteFileMetadata) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened download file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != expected.Size || info.ModTime().UnixNano() != expected.ModTime {
		return errors.New("opened download source changed during transfer")
	}
	return nil
}

func copyTransferStream(ctx context.Context, destination io.Writer, source io.Reader, size int64, progress func(int64) error) (int64, string, error) {
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

func (r *sftpTransferRemote) Commit(ctx context.Context, temporary, destination string, overwrite bool) (result commitResult, retErr error) {
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
		result.Rejected = explicitSFTPRejection(err)
		return fmt.Errorf("commit remote upload: %w", err)
	})
	return result, retErr
}

func explicitSFTPRejection(err error) bool {
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

func (r *sftpTransferRemote) Remove(ctx context.Context, name string) error {
	return r.client.Do(ctx, func(client *pkgsftp.Client) error {
		parent, err := client.RealPath(path.Dir(name))
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
