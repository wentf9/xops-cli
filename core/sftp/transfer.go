package sftp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/fsx"
	"golang.org/x/sync/errgroup"
	"golang.org/x/text/unicode/norm"
)

// stagingFilePerm is the mandatory owner-only permission mode enforced on all
// local and remote temporary staging files before writing or resuming bytes.
const stagingFilePerm os.FileMode = fsx.OwnerOnlyPerm

// sanitizeTransferFilePerm masks a file mode to standard rwx permission bits
// (0o777), unconditionally stripping special bits (setuid, setgid, sticky) and
// file-type bits.
func sanitizeTransferFilePerm(mode os.FileMode) os.FileMode {
	return mode.Perm()
}

// sanitizeTransferDirPerm masks a directory mode to standard rwx permission
// bits (0o777), unconditionally stripping special bits (setuid, setgid, sticky)
// and file-type bits.
func sanitizeTransferDirPerm(mode os.FileMode) os.FileMode {
	return mode.Perm()
}

// Upload 上传入口：支持文件或目录（顶层路径使用 os.Stat 解引用符号链接，与 OpenSSH scp 单路径行为一致；
// 目录递归遍历内部则通过 UploadLink 保留子项符号链接）。
func (c *Client) Upload(ctx context.Context, localPath, remotePath string, progress ProgressCallback) error {
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		return c.upload(ctx, localPath, remotePath, progress)
	})
}

func (c *Client) upload(ctx context.Context, localPath, remotePath string, progress ProgressCallback) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("stat local path failed: %w", err)
	}

	if info.IsDir() {
		return c.uploadDirectory(ctx, localPath, remotePath, progress)
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	// 检查远程路径是否是目录
	remoteStat, err := c.SFTPClient().Stat(remotePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat remote destination failed: %w", err)
	}
	remoteTarget, parseErr := ParseRemoteUploadTarget(remotePath, localPath, err == nil && remoteStat.IsDir())
	if parseErr != nil {
		return fmt.Errorf("upload %q to %q: %w", localPath, remotePath, parseErr)
	}
	remotePath = remoteTarget.String()

	if err := c.uploadFile(ctx, localPath, remotePath, info.Size(), info.Mode(), progress, fsx.FollowSymlinks()); err != nil {
		return fmt.Errorf("upload %q to %q: %w", localPath, remotePath, err)
	}
	return nil
}

// ================== 单文件多线程分块逻辑 ==================

func (c *Client) UploadFile(ctx context.Context, localPath, remotePath string, size int64, mode os.FileMode, progress ProgressCallback) (retErr error) {
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		if err := c.uploadFile(ctx, localPath, remotePath, size, mode, progress); err != nil {
			return fmt.Errorf("upload %q to %q: %w", localPath, remotePath, err)
		}
		return nil
	})
}

//nolint:gocyclo
func (c *Client) uploadFile(ctx context.Context, localPath, remotePath string, size int64, mode os.FileMode, progress ProgressCallback, openOpts ...fsx.OpenOption) (retErr error) {
	finishDiagnostic := c.observeFileTransfer("upload", localPath, remotePath, size)
	defer func() { finishDiagnostic(retErr) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	srcFile, srcStat, err := fsx.OpenRegularUnbounded(localPath, openOpts...)
	if err != nil {
		return fmt.Errorf("open local source file failed: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, closeTransferResource(srcFile, "local source file"))
	}()

	if srcStat.Size() != size {
		return fmt.Errorf("local source size changed: expected %d bytes, got %d", size, srcStat.Size())
	}

	var fileTransferred atomic.Int64
	var completedEmitted bool
	if c.fileProgress != nil {
		if size > 0 {
			c.fileProgress(FileTransferProgress{
				Path:        localPath,
				Size:        size,
				Transferred: 0,
				Increment:   0,
			})
		}
		defer func() {
			if retErr == nil && !completedEmitted {
				if fileTransferred.Load() < size || size == 0 {
					c.fileProgress(FileTransferProgress{
						Path:        localPath,
						Size:        size,
						Transferred: size,
						Increment:   0,
					})
				}
			}
		}()
	}

	// 只有在非强制模式下才检查跳过
	if !c.config.Force {
		if err := ctx.Err(); err != nil {
			return err
		}
		skip, skipErr := c.shouldSkipUpload(remotePath, srcStat)
		if skipErr != nil {
			return skipErr
		}
		if skip {
			fileTransferred.Store(srcStat.Size())
			if c.fileProgress != nil {
				completedEmitted = true
				c.fileProgress(FileTransferProgress{
					Path:        localPath,
					Size:        srcStat.Size(),
					Transferred: srcStat.Size(),
					Increment:   srcStat.Size(),
				})
			}
			if progress != nil && srcStat.Size() > 0 {
				progress(srcStat.Size())
			}
			return nil
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	tempPath := remotePath + c.config.TempSuffix
	startOffset, dstFile, err := c.prepareUploadFile(ctx, tempPath, size, srcFile)
	if err != nil {
		return c.wrapUploadStorageError(ctx, "prepare remote temporary file", tempPath, size, err)
	}

	if dstFile != nil {
		defer func() {
			if dstFile != nil {
				retErr = errors.Join(retErr, closeTransferResource(dstFile, "remote temporary file"))
			}
		}()
		if err := ctx.Err(); err != nil {
			return err
		}

		fileCb := progress
		if c.fileProgress != nil {
			fileCb = func(n int64) {
				curr := fileTransferred.Add(n)
				c.fileProgress(FileTransferProgress{
					Path:        localPath,
					Size:        size,
					Transferred: curr,
					Increment:   n,
				})
				if progress != nil {
					progress(n)
				}
			}
		}

		if startOffset > 0 {
			if fileCb != nil {
				fileCb(startOffset)
			}
		}

		if err := c.doUpload(ctx, srcFile, dstFile, startOffset, size, fileCb); err != nil {
			remainingNeeded := size - fileTransferred.Load()
			return c.wrapUploadStorageError(ctx, "upload file content", tempPath, remainingNeeded, err)
		}
		if err := dstFile.Close(); err != nil {
			dstFile = nil
			return fmt.Errorf("close remote temporary file failed: %w", err)
		}
		dstFile = nil
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	return c.finalizeRemoteTempFile(ctx, tempPath, remotePath, srcStat.ModTime(), sanitizeTransferFilePerm(mode))
}

func (c *Client) finalizeRemoteTempFile(ctx context.Context, tempPath, remotePath string, modTime time.Time, targetMode os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.verifyRemoteTemporaryFile(tempPath); err != nil {
		return err
	}
	if err := c.SFTPClient().Chtimes(tempPath, modTime, modTime); err != nil {
		return fmt.Errorf("set remote temporary file timestamps failed: %w", err)
	}
	if targetPerm := sanitizeTransferFilePerm(targetMode); targetPerm != 0 {
		if err := c.SFTPClient().Chmod(tempPath, targetPerm); err != nil {
			return fmt.Errorf("set remote temporary file mode failed: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.replaceRemoteFile(tempPath, remotePath)
}

// ReplaceRemoteFile promotes a temporary remote file to its destination while
// preserving an existing destination when the replacement fails. Cancellation
// interrupts this SFTP subsystem, so the client must not be reused afterwards.
func (c *Client) ReplaceRemoteFile(ctx context.Context, tempPath, remotePath string) error {
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		return c.replaceRemoteFile(tempPath, remotePath)
	})
}

func (c *Client) replaceRemoteFile(tempPath, remotePath string) error {
	posixRenameErr := c.SFTPClient().PosixRename(tempPath, remotePath)
	if posixRenameErr == nil {
		return nil
	}
	if !errors.Is(posixRenameErr, sftp.ErrSSHFxOpUnsupported) {
		return fmt.Errorf("atomically replace remote destination failed: %w", posixRenameErr)
	}
	return c.replaceRemoteDestinationFallback(tempPath, remotePath)
}

func (c *Client) replaceRemoteDestinationFallback(tempPath, remotePath string) error {
	if _, err := c.SFTPClient().Lstat(remotePath); errors.Is(err, os.ErrNotExist) {
		if renameErr := c.SFTPClient().Rename(tempPath, remotePath); renameErr != nil {
			return fmt.Errorf("rename remote temporary file failed: %w", renameErr)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("lstat remote destination before replacement failed: %w", err)
	}

	backupPath := remotePath + c.config.TempSuffix + ".backup"
	if _, err := c.SFTPClient().Lstat(backupPath); err == nil {
		return fmt.Errorf("prepare remote destination backup failed: backup %q already exists", backupPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lstat remote destination backup failed: %w", err)
	}

	if err := c.SFTPClient().Rename(remotePath, backupPath); err != nil {
		return fmt.Errorf("backup remote destination failed: %w", err)
	}
	if err := c.SFTPClient().Rename(tempPath, remotePath); err != nil {
		rollbackErr := c.SFTPClient().Rename(backupPath, remotePath)
		if rollbackErr != nil {
			rollbackErr = fmt.Errorf("restore remote destination backup failed: %w", rollbackErr)
		}
		return errors.Join(fmt.Errorf("rename remote temporary file failed: %w", err), rollbackErr)
	}
	if err := c.SFTPClient().Remove(backupPath); err != nil {
		// On Windows or certain SFTP servers, deleting a read-only file fails with SSH_FX_FAILURE/permission denied.
		// Attempt to clear read-only flag and retry deletion.
		_ = c.SFTPClient().Chmod(backupPath, 0o600)
		if retryErr := c.SFTPClient().Remove(backupPath); retryErr != nil {
			return fmt.Errorf("remove remote destination backup failed: %w", err)
		}
	}
	return nil
}

func (c *Client) shouldSkipUpload(remotePath string, srcStat os.FileInfo) (bool, error) {
	rStat, err := c.SFTPClient().Stat(remotePath)
	if err == nil {
		if rStat.Size() == srcStat.Size() && rStat.ModTime().Unix() == srcStat.ModTime().Unix() {
			return true, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat remote destination for skip check failed: %w", err)
	}
	return false, nil
}

func (c *Client) prepareUploadFile(ctx context.Context, tempPath string, size int64, srcFile io.ReaderAt) (int64, *sftp.File, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	tempInfo, exists, err := c.inspectRemoteTemporaryFile(tempPath)
	if err != nil {
		return 0, nil, err
	}

	startOffset := int64(0)
	flags := os.O_RDWR | os.O_TRUNC
	if !exists {
		flags = os.O_RDWR | os.O_CREATE | os.O_EXCL
	} else if c.config.EnableResume && tempInfo.Size() <= size && tempInfo.Size() >= c.config.ResumeMinSize {
		startOffset = tempInfo.Size()
		flags = os.O_RDWR
	}

	dstFile, err := c.SFTPClient().OpenFile(tempPath, flags)
	if err != nil {
		return 0, nil, err
	}
	if err := c.verifyRemoteTemporaryFile(tempPath); err != nil {
		return 0, nil, errors.Join(err, closeTransferResource(dstFile, "remote temporary file after validation failure"))
	}
	if err := dstFile.Chmod(stagingFilePerm); err != nil {
		return 0, nil, errors.Join(fmt.Errorf("set remote temporary file mode failed: %w", err), closeTransferResource(dstFile, "remote temporary file"))
	}
	if exists && startOffset > 0 {
		if err := c.validateResumePrefixUpload(ctx, dstFile, srcFile, startOffset); err != nil {
			if !errors.Is(err, errPrefixMismatch) {
				return 0, nil, errors.Join(fmt.Errorf("validate prefix failed: %w", err), closeTransferResource(dstFile, "remote temporary file"))
			}
			startOffset = 0
			if _, err := dstFile.Seek(0, 0); err != nil {
				return 0, nil, errors.Join(fmt.Errorf("seek failed: %w", err), closeTransferResource(dstFile, "remote temporary file"))
			}
			if err := dstFile.Truncate(0); err != nil {
				return 0, nil, errors.Join(fmt.Errorf("truncate failed: %w", err), closeTransferResource(dstFile, "remote temporary file"))
			}
		}
	}
	return startOffset, dstFile, nil
}

func (c *Client) inspectRemoteTemporaryFile(tempPath string) (os.FileInfo, bool, error) {
	info, err := c.SFTPClient().Lstat(tempPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("lstat remote temporary file failed: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("remote temporary path %q is not a regular file", tempPath)
	}
	return info, true, nil
}

func (c *Client) verifyRemoteTemporaryFile(tempPath string) error {
	_, exists, err := c.inspectRemoteTemporaryFile(tempPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("remote temporary path %q disappeared during open", tempPath)
	}
	return nil
}

func (c *Client) doUpload(ctx context.Context, srcFile *os.File, dstFile *sftp.File, startOffset, size int64, progress ProgressCallback) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if (size - startOffset) <= 0 {
		return nil
	}
	if (size-startOffset) < c.config.ChunkSize || c.config.ThreadsPerFile <= 1 {
		if startOffset > 0 {
			if _, err := srcFile.Seek(startOffset, io.SeekStart); err != nil {
				return err
			}
		}
		return copyExactContext(ctx, dstFile, srcFile, size-startOffset, progress)
	}
	return c.parallelTransfer(ctx, srcFile, dstFile, startOffset, size, progress)
}

func (c *Client) wrapUploadStorageError(ctx context.Context, op string, remotePath string, neededBytes int64, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return fmt.Errorf("%s failed: %w", op, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, sftp.ErrSSHFxPermissionDenied) || errors.Is(err, sftp.ErrSSHFxNoSuchFile) ||
		errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%s failed: %w", op, err)
	}
	if vfs, vfsErr := c.checkRemoteFreeSpace(remotePath); vfsErr == nil && vfs != nil {
		avail := AvailableStorageSpace(vfs)
		total := TotalStorageSpace(vfs)
		if avail == 0 || (neededBytes > 0 && avail < uint64(neededBytes)) {
			return fmt.Errorf("%s failed (insufficient remote storage space: %s free of %s): %w",
				op, FormatByteSize(avail), FormatByteSize(total), err)
		}
	}
	return fmt.Errorf("%s failed: %w", op, err)
}

func isOpUnsupported(err error) bool {
	if errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		return true
	}
	var statusErr *sftp.StatusError
	if errors.As(err, &statusErr) {
		return statusErr.FxCode() == sftp.ErrSSHFxOpUnsupported
	}
	return false
}

func (c *Client) checkRemoteFreeSpace(remotePath string) (*sftp.StatVFS, error) {
	if c == nil || c.state == nil || c.state.sftpClient == nil {
		return nil, errors.New("client not available")
	}
	vfs, err := c.state.sftpClient.StatVFS(remotePath)
	if err == nil && vfs != nil {
		return vfs, nil
	}
	if isOpUnsupported(err) {
		return nil, err
	}
	target := remotePath
	for {
		dir := path.Dir(target)
		if dir == "" || dir == target {
			break
		}
		vfs, err = c.state.sftpClient.StatVFS(dir)
		if err == nil && vfs != nil {
			return vfs, nil
		}
		if isOpUnsupported(err) {
			return nil, err
		}
		target = dir
	}
	return nil, err
}

// AvailableStorageSpace returns the available space in bytes from StatVFS.
func AvailableStorageSpace(vfs *sftp.StatVFS) uint64 {
	if vfs == nil {
		return 0
	}
	frsize := vfs.Frsize
	if frsize == 0 {
		frsize = vfs.Bsize
	}
	if frsize == 0 {
		frsize = 512
	}
	return frsize * vfs.Bavail
}

// TotalStorageSpace returns the total space in bytes from StatVFS.
func TotalStorageSpace(vfs *sftp.StatVFS) uint64 {
	if vfs == nil {
		return 0
	}
	frsize := vfs.Frsize
	if frsize == 0 {
		frsize = vfs.Bsize
	}
	if frsize == 0 {
		frsize = 512
	}
	return frsize * vfs.Blocks
}

// FormatByteSize formats a byte count into a human-readable size string (e.g. "24.5 KB", "40.0 GB").
func FormatByteSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit && exp < 5; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

//nolint:gocyclo
func (c *Client) downloadFile(ctx context.Context, remotePath, localPath string, size int64, mode os.FileMode, progress ProgressCallback) (retErr error) {
	finishDiagnostic := c.observeFileTransfer("download", remotePath, localPath, size)
	defer func() { finishDiagnostic(retErr) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	srcFile, err := c.SFTPClient().Open(remotePath)
	if err != nil {
		return fmt.Errorf("open remote source file failed: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, closeTransferResource(srcFile, "remote source file"))
	}()

	srcStat, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat remote source file failed: %w", err)
	}
	if !srcStat.Mode().IsRegular() {
		return fmt.Errorf("remote source %q is not a regular file (mode %s)", remotePath, srcStat.Mode())
	}
	if srcStat.Size() != size {
		return fmt.Errorf("remote source size changed: expected %d bytes, got %d", size, srcStat.Size())
	}
	targetPerm := sanitizeTransferFilePerm(mode)

	var fileTransferred atomic.Int64
	var completedEmitted bool
	if c.fileProgress != nil {
		if size > 0 {
			c.fileProgress(FileTransferProgress{
				Path:        remotePath,
				Size:        size,
				Transferred: 0,
				Increment:   0,
			})
		}
		defer func() {
			if retErr == nil && !completedEmitted {
				if fileTransferred.Load() < size || size == 0 {
					c.fileProgress(FileTransferProgress{
						Path:        remotePath,
						Size:        size,
						Transferred: size,
						Increment:   0,
					})
				}
			}
		}()
	}

	// 只有在非强制模式下才检查跳过
	if !c.config.Force {
		if err := ctx.Err(); err != nil {
			return err
		}
		skip, skipErr := c.shouldSkipDownload(localPath, srcStat)
		if skipErr != nil {
			return skipErr
		}
		if skip {
			fileTransferred.Store(srcStat.Size())
			if c.fileProgress != nil {
				completedEmitted = true
				c.fileProgress(FileTransferProgress{
					Path:        remotePath,
					Size:        srcStat.Size(),
					Transferred: srcStat.Size(),
					Increment:   srcStat.Size(),
				})
			}
			if progress != nil && srcStat.Size() > 0 {
				progress(srcStat.Size())
			}
			return nil
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	tempPath := localPath + c.config.TempSuffix
	startOffset, dstFile, dstStat, err := c.prepareDownloadFile(ctx, tempPath, size, targetPerm, srcFile)
	if err != nil {
		return fmt.Errorf("prepare local temporary file failed: %w", err)
	}
	if dstFile != nil {
		defer func() {
			if dstFile != nil {
				retErr = errors.Join(retErr, closeTransferResource(dstFile, "local temporary file"))
			}
		}()
	}

	fileCb := progress
	if c.fileProgress != nil {
		fileCb = func(n int64) {
			curr := fileTransferred.Add(n)
			c.fileProgress(FileTransferProgress{
				Path:        remotePath,
				Size:        size,
				Transferred: curr,
				Increment:   n,
			})
			if progress != nil {
				progress(n)
			}
		}
	}

	if dstFile != nil {
		f := dstFile
		dstFile = nil // ownership transferred to writeDownloadTemporaryFile
		if err := c.writeDownloadTemporaryFile(ctx, srcFile, f, startOffset, size, fileCb); err != nil {
			return err
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	rb := make([]byte, 16)
	if _, err := rand.Read(rb); err != nil {
		return fmt.Errorf("generate random bytes failed: %w", err)
	}
	finalTempPath := tempPath + "." + hex.EncodeToString(rb)

	if err := os.Rename(tempPath, finalTempPath); err != nil {
		return fmt.Errorf("rename to final temporary path failed: %w", err)
	}
	defer func() {
		if rmErr := os.Remove(finalTempPath); rmErr != nil && !os.IsNotExist(rmErr) { //nolint:forbidigo // deferred cleanup of randomly-suffixed download temp file created by this transfer
			_ = os.Chmod(finalTempPath, 0o600)
			if retryErr := os.Remove(finalTempPath); retryErr != nil && !os.IsNotExist(retryErr) { //nolint:forbidigo // retry cleanup after chmod on read-only download temp file
				retErr = errors.Join(retErr, fmt.Errorf("remove final temporary path failed: %w", rmErr))
			}
		}
	}()

	if dstStat != nil {
		stat, err := os.Lstat(finalTempPath)
		if err != nil || !stat.Mode().IsRegular() || !os.SameFile(dstStat, stat) {
			return fmt.Errorf("local temporary file was replaced during finalization")
		}
	} else if err := verifyLocalTemporaryFile(finalTempPath); err != nil {
		return err
	}
	if err := os.Chtimes(finalTempPath, srcStat.ModTime(), srcStat.ModTime()); err != nil {
		return fmt.Errorf("set local temporary file timestamps failed: %w", err)
	}
	if targetPerm != 0 {
		if err := os.Chmod(finalTempPath, targetPerm); err != nil {
			return fmt.Errorf("set local temporary file mode failed: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return replaceLocalFile(finalTempPath, localPath, os.Rename)
}

func (c *Client) writeDownloadTemporaryFile(ctx context.Context, srcFile *sftp.File, dstFile *os.File, startOffset, size int64, progress ProgressCallback) (retErr error) {
	defer func() {
		if dstFile != nil {
			retErr = errors.Join(retErr, closeTransferResource(dstFile, "local temporary file"))
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if progress != nil && startOffset > 0 {
		progress(startOffset)
	}
	if err := c.doDownload(ctx, srcFile, dstFile, startOffset, size, progress); err != nil {
		return fmt.Errorf("download file content failed: %w", err)
	}
	if err := dstFile.Close(); err != nil {
		dstFile = nil
		return fmt.Errorf("close local temporary file failed: %w", err)
	}
	dstFile = nil
	return nil
}

func (c *Client) shouldSkipDownload(localPath string, srcStat os.FileInfo) (bool, error) {
	lStat, err := os.Stat(localPath)
	if err == nil {
		if lStat.Size() == srcStat.Size() && lStat.ModTime().Unix() == srcStat.ModTime().Unix() {
			return true, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat local destination for skip check failed: %w", err)
	}
	return false, nil
}

func (c *Client) prepareDownloadFile(ctx context.Context, tempPath string, size int64, _ os.FileMode, srcFile *sftp.File) (int64, *os.File, os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, nil, err
	}
	dstFile, openedInfo, created, err := fsx.OpenStagingFile(tempPath, stagingFilePerm)
	if err != nil {
		return 0, nil, nil, err
	}
	if err := dstFile.Chmod(stagingFilePerm); err != nil {
		return 0, nil, nil, errors.Join(fmt.Errorf("set local temporary file mode failed: %w", err), closeTransferResource(dstFile, "local temporary file"))
	}

	startOffset := int64(0)
	resuming := !created && c.config.EnableResume && openedInfo.Size() <= size && openedInfo.Size() >= c.config.ResumeMinSize
	if resuming {
		startOffset = openedInfo.Size()
		if err := c.validateResumePrefixDownload(ctx, dstFile, srcFile, startOffset); err != nil {
			if !errors.Is(err, errPrefixMismatch) {
				return 0, nil, nil, errors.Join(fmt.Errorf("validate prefix failed: %w", err), closeTransferResource(dstFile, "local temporary file"))
			}
			startOffset = 0
			resuming = false
		}
	}
	if !created && !resuming {
		if _, err := dstFile.Seek(0, io.SeekStart); err != nil {
			return 0, nil, nil, errors.Join(fmt.Errorf("seek failed: %w", err), closeTransferResource(dstFile, "local temporary file"))
		}
		if err := dstFile.Truncate(0); err != nil {
			return 0, nil, nil, errors.Join(fmt.Errorf("truncate failed: %w", err), closeTransferResource(dstFile, "local temporary file"))
		}
	}
	return startOffset, dstFile, openedInfo, nil
}

func inspectLocalTemporaryFile(tempPath string) (os.FileInfo, bool, error) {
	info, err := os.Lstat(tempPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("lstat local temporary file failed: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("local temporary path %q is not a regular file", tempPath)
	}
	return info, true, nil
}

func verifyLocalTemporaryFile(tempPath string) error {
	_, exists, err := inspectLocalTemporaryFile(tempPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("local temporary path %q disappeared before promotion", tempPath)
	}
	return nil
}

func (c *Client) doDownload(ctx context.Context, srcFile *sftp.File, dstFile *os.File, startOffset, size int64, progress ProgressCallback) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if (size - startOffset) <= 0 {
		return nil
	}
	if (size-startOffset) < c.config.ChunkSize || c.config.ThreadsPerFile <= 1 {
		if startOffset > 0 {
			if _, err := dstFile.Seek(startOffset, io.SeekStart); err != nil {
				return err
			}
			if _, err := srcFile.Seek(startOffset, io.SeekStart); err != nil {
				return err
			}
		}
		return copyExactContext(ctx, dstFile, srcFile, size-startOffset, progress)
	}
	return c.parallelTransfer(ctx, srcFile, dstFile, startOffset, size, progress)
}

type readAtSeeker interface {
	io.ReaderAt
	io.Seeker
}

type writeAtSeeker interface {
	io.WriterAt
	io.Seeker
}

func (c *Client) parallelTransfer(ctx context.Context, src readAtSeeker, dst writeAtSeeker, startOffset, totalSize int64, progress ProgressCallback) error {
	g, gCtx := errgroup.WithContext(ctx)
	chunkSize := c.config.ChunkSize
	sem := make(chan struct{}, c.config.ThreadsPerFile)

Loop:
	for offset := startOffset; offset < totalSize; offset += chunkSize {
		currOffset := offset
		currSize := chunkSize
		if currOffset+currSize > totalSize {
			currSize = totalSize - currOffset
		}

		select {
		case sem <- struct{}{}:
		case <-gCtx.Done():
			break Loop
		}

		if gCtx.Err() != nil {
			break Loop
		}

		g.Go(func() error {
			defer func() { <-sem }()
			if gCtx.Err() != nil {
				return gCtx.Err()
			}
			buf := make([]byte, currSize)
			n, err := src.ReadAt(buf, currOffset)
			if n != len(buf) {
				if err == nil || errors.Is(err, io.EOF) {
					return io.ErrUnexpectedEOF
				}
				return err
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			nw, err := dst.WriteAt(buf[:n], currOffset)
			if err != nil {
				return err
			}
			if nw != n {
				return io.ErrShortWrite
			}
			if progress != nil {
				progress(int64(n))
			}
			return nil
		})
	}
	return g.Wait()
}

// StreamTransfer copies exactly size bytes between two SFTP clients. The
// caller retains ownership of r and w. Cancellation interrupts both clients'
// SFTP subsystems, so both SFTP clients become unusable afterwards. Shared SSH
// transports remain open unless a subsystem close itself blocks and requires
// the bounded transport fallback documented on Client.
func (c *Client) StreamTransfer(ctx context.Context, source *Client, r io.Reader, w io.Writer, size int64, progress ProgressCallback) error {
	interrupt := func() error {
		return errors.Join(source.interruptTransfers(), c.interruptTransfers())
	}
	if err := runInterruptibleOperation(ctx, interrupt, func() error {
		return copyExactContext(ctx, w, r, size, progress)
	}); err != nil {
		return fmt.Errorf("stream transfer failed: %w", err)
	}
	return nil
}

// RelayFileFrom relays one regular remote file from srcClient:srcPath to
// c:dstPath using c's Lstat-verified staging flow: exclusive creation
// (O_CREATE|O_EXCL) for new temporary files, fail-closed rejection of
// non-regular or symbolic-link temporary paths, owner-only 0600 permissions
// while staging, resume prefix verification, and restoration of source file
// permissions and timestamps prior to atomic replacement.
//
// srcInfo is optional; when provided, RelayFileFrom verifies the opened source
// handle is a regular file matching srcInfo.Size(). Cancellation interrupts
// both srcClient and c's SFTP subsystems, so neither client should be reused
// afterwards.
func (c *Client) RelayFileFrom(
	ctx context.Context,
	srcClient *Client,
	srcPath RemotePath,
	dstPath RemotePath,
	srcInfo os.FileInfo,
	progress ProgressCallback,
) error {
	if c == nil || c.SFTPClient() == nil {
		return fmt.Errorf("destination sftp client is nil")
	}
	if srcClient == nil || srcClient.SFTPClient() == nil {
		return fmt.Errorf("source sftp client is nil")
	}
	if !srcPath.IsValid() {
		return fmt.Errorf("%w: remote source path is invalid", ErrInvalidRemotePath)
	}
	if !dstPath.IsValid() {
		return fmt.Errorf("%w: remote destination path is invalid", ErrInvalidRemotePath)
	}
	if srcInfo != nil {
		if srcInfo.IsDir() {
			return fmt.Errorf("remote-to-remote directory transfer is not supported for %q: download locally and upload instead", srcPath.String())
		}
		if !srcInfo.Mode().IsRegular() {
			return fmt.Errorf("remote source %q is not a regular file (mode %s)", srcPath.String(), srcInfo.Mode())
		}
	}
	interrupt := func() error {
		return errors.Join(srcClient.interruptTransfers(), c.interruptTransfers())
	}
	return runInterruptibleOperation(ctx, interrupt, func() error {
		return c.relayFileFrom(ctx, srcClient, srcPath, dstPath, srcInfo, progress)
	})
}

func (c *Client) relayFileFrom(
	ctx context.Context,
	srcClient *Client,
	srcPath RemotePath,
	dstPath RemotePath,
	srcInfo os.FileInfo,
	progress ProgressCallback,
) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if srcInfo == nil {
		preStat, statErr := srcClient.SFTPClient().Stat(srcPath.String())
		if statErr != nil {
			return fmt.Errorf("stat remote source %q failed: %w", srcPath.String(), statErr)
		}
		if preStat.IsDir() {
			return fmt.Errorf("remote-to-remote directory transfer is not supported for %q: download locally and upload instead", srcPath.String())
		}
		if !preStat.Mode().IsRegular() {
			return fmt.Errorf("remote source %q is not a regular file (mode %s)", srcPath.String(), preStat.Mode())
		}
	}
	srcFile, err := srcClient.SFTPClient().Open(srcPath.String())
	if err != nil {
		return fmt.Errorf("open remote source %q failed: %w", srcPath.String(), err)
	}
	defer func() {
		retErr = errors.Join(retErr, closeTransferResource(srcFile, "remote source file"))
	}()

	srcStat, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat remote source %q failed: %w", srcPath.String(), err)
	}
	if srcStat.IsDir() {
		return fmt.Errorf("remote-to-remote directory transfer is not supported for %q: download locally and upload instead", srcPath.String())
	}
	if !srcStat.Mode().IsRegular() {
		return fmt.Errorf("remote source %q is not a regular file", srcPath.String())
	}
	if srcInfo != nil && srcStat.Size() != srcInfo.Size() {
		return fmt.Errorf("remote source size changed: expected %d bytes, got %d", srcInfo.Size(), srcStat.Size())
	}

	size := srcStat.Size()
	finishDiagnostic := c.observeFileTransfer("relay", srcPath.String(), dstPath.String(), size)
	defer func() { finishDiagnostic(retErr) }()

	targetPerm := sanitizeTransferFilePerm(srcStat.Mode())
	if targetPerm == 0 && srcInfo != nil {
		targetPerm = sanitizeTransferFilePerm(srcInfo.Mode())
	}

	tempPath := dstPath.String() + c.config.TempSuffix
	if srcClient.state == c.state && tempPath == srcPath.String() {
		return fmt.Errorf("remote relay temporary path conflicts with source: %q", tempPath)
	}

	if err := c.stageRelayFile(ctx, srcPath.String(), tempPath, srcFile, size, progress); err != nil {
		return err
	}
	return c.finalizeRemoteTempFile(ctx, tempPath, dstPath.String(), srcStat.ModTime(), targetPerm)
}

func (c *Client) stageRelayFile(
	ctx context.Context,
	srcLabel, tempPath string,
	srcFile *sftp.File,
	size int64,
	progress ProgressCallback,
) (retErr error) {
	var fileTransferred atomic.Int64
	if c.fileProgress != nil {
		if size > 0 {
			c.fileProgress(FileTransferProgress{Path: srcLabel, Size: size})
		}
		defer func() {
			if retErr == nil && (fileTransferred.Load() < size || size == 0) {
				c.fileProgress(FileTransferProgress{Path: srcLabel, Size: size, Transferred: size})
			}
		}()
	}

	startOffset, dstFile, err := c.prepareUploadFile(ctx, tempPath, size, srcFile)
	if err != nil {
		return c.wrapUploadStorageError(ctx, "prepare remote temporary file", tempPath, size, err)
	}
	if dstFile == nil {
		return nil
	}
	defer func() {
		if dstFile != nil {
			retErr = errors.Join(retErr, closeTransferResource(dstFile, "remote temporary file"))
		}
	}()

	if err := ctx.Err(); err != nil {
		return err
	}

	fileCb := c.wrapRelayProgress(srcLabel, size, &fileTransferred, progress)
	if startOffset > 0 && fileCb != nil {
		fileCb(startOffset)
	}
	if err := c.copyRelayContent(ctx, tempPath, srcFile, dstFile, startOffset, size, &fileTransferred, fileCb); err != nil {
		return err
	}
	if err := dstFile.Close(); err != nil {
		dstFile = nil
		return fmt.Errorf("close remote temporary file failed: %w", err)
	}
	dstFile = nil
	return nil
}

func (c *Client) wrapRelayProgress(srcLabel string, size int64, transferred *atomic.Int64, progress ProgressCallback) ProgressCallback {
	if c.fileProgress == nil {
		return progress
	}
	return func(n int64) {
		curr := transferred.Add(n)
		c.fileProgress(FileTransferProgress{
			Path:        srcLabel,
			Size:        size,
			Transferred: curr,
			Increment:   n,
		})
		if progress != nil {
			progress(n)
		}
	}
}

func (c *Client) copyRelayContent(
	ctx context.Context,
	tempPath string,
	srcFile, dstFile *sftp.File,
	startOffset, size int64,
	transferred *atomic.Int64,
	progress ProgressCallback,
) error {
	if startOffset >= size {
		return nil
	}
	if startOffset > 0 {
		if _, seekErr := srcFile.Seek(startOffset, io.SeekStart); seekErr != nil {
			return fmt.Errorf("seek remote source failed: %w", seekErr)
		}
		if _, seekErr := dstFile.Seek(startOffset, io.SeekStart); seekErr != nil {
			return fmt.Errorf("seek remote temporary file failed: %w", seekErr)
		}
	}
	if err := copyExactContext(ctx, dstFile, srcFile, size-startOffset, progress); err != nil {
		remainingNeeded := size - transferred.Load()
		return c.wrapUploadStorageError(ctx, "relay file content", tempPath, remainingNeeded, err)
	}
	return nil
}

// RemoteCopy copies a remote file, directory, or symbolic link through SFTP.
// Symbolic links are copied as links and are never followed during traversal.
func (c *Client) RemoteCopy(ctx context.Context, src, dst string) (retErr error) {
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		sourcePath, err := c.canonicalRemoteEntryPath(src)
		if err != nil {
			return fmt.Errorf("resolve remote source path failed: %w", err)
		}
		destinationPath, err := c.canonicalRemoteEntryPath(dst)
		if err != nil {
			return fmt.Errorf("resolve remote destination path failed: %w", err)
		}
		if sourcePath == destinationPath {
			return fmt.Errorf("remote source and destination are the same path: %q", sourcePath)
		}

		sourceInfo, err := c.SFTPClient().Lstat(sourcePath)
		if err != nil {
			return fmt.Errorf("lstat remote source path failed: %w", err)
		}
		if sourceInfo.IsDir() {
			canonicalSourcePath, resolveErr := c.canonicalRemotePath(sourcePath)
			if resolveErr != nil {
				return fmt.Errorf("resolve remote source directory failed: %w", resolveErr)
			}
			if remotePathContains(canonicalSourcePath, destinationPath) {
				return fmt.Errorf("remote destination %q is inside source directory %q", destinationPath, canonicalSourcePath)
			}
			sourcePath = canonicalSourcePath
		}
		return c.remoteCopy(ctx, sourcePath, destinationPath, sourceInfo)
	})
}

// RemoveAll removes a remote file, directory tree, or symbolic link through
// SFTP. Symbolic links are removed as links and are never followed.
func (c *Client) RemoveAll(ctx context.Context, remotePath string) error {
	cleanPath := cleanRemotePathForRemoval(remotePath)
	root, err := ParseRemotePath(cleanPath)
	if err != nil {
		return fmt.Errorf("remove remote entry %q failed: %w", remotePath, err)
	}
	return c.Do(ctx, func(client *sftp.Client) error {
		return removeRemoteEntry(ctx, client, root, root)
	})
}

func cleanRemotePathForRemoval(remotePath string) string {
	if remotePath == "" || remotePath == "/" {
		return remotePath
	}
	trimmed := strings.TrimRight(remotePath, "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

func removeRemoteEntry(ctx context.Context, client *sftp.Client, root, current RemotePath) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, relErr := current.RelativeTo(root); relErr != nil {
		return fmt.Errorf("remove remote entry %q escapes root %q: %w", current.String(), root.String(), relErr)
	}
	curPath := current.String()
	info, err := client.Lstat(curPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lstat remote entry %q failed: %w", curPath, err)
	}
	if info.Mode()&os.ModeType != os.ModeDir {
		if err := client.Remove(curPath); err != nil {
			return fmt.Errorf("remove remote entry %q failed: %w", curPath, err)
		}
		return nil
	}

	entries, err := readValidatedRemoteDir(ctx, client, current, "remove")
	if err != nil {
		return err
	}
	for _, item := range entries {
		if _, relErr := item.child.RelativeTo(root); relErr != nil {
			return fmt.Errorf("remove %q: entry %q escapes root %q: %w", curPath, item.child.String(), root.String(), relErr)
		}
		if err := removeRemoteEntry(ctx, client, root, item.child); err != nil {
			return err
		}
	}
	if err := client.RemoveDirectory(curPath); err != nil {
		return fmt.Errorf("remove remote directory %q failed: %w", curPath, err)
	}
	return nil
}

// Rename renames one remote entry through SFTP.
func (c *Client) Rename(ctx context.Context, src, dst string) error {
	return c.Do(ctx, func(client *sftp.Client) error {
		if err := client.Rename(src, dst); err != nil {
			return fmt.Errorf("rename remote entry %q to %q failed: %w", src, dst, err)
		}
		return nil
	})
}

func (c *Client) remoteCopy(ctx context.Context, src, dst string, srcStat os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if srcStat == nil {
		var err error
		srcStat, err = c.SFTPClient().Lstat(src)
		if err != nil {
			return fmt.Errorf("lstat remote source entry failed: %w", err)
		}
	}
	if srcStat.Mode()&os.ModeSymlink != 0 {
		return c.remoteCopyLink(ctx, src, dst)
	}
	if srcStat.Mode()&os.ModeType == os.ModeDir {
		return c.remoteCopyDirectory(ctx, src, dst, srcStat)
	}
	return c.remoteCopyFile(ctx, src, dst, srcStat)
}

func (c *Client) prepareRemoteDestinationDirectory(src, dst string, srcStat os.FileInfo) (bool, error) {
	dstLstat, dstLstatErr := c.SFTPClient().Lstat(dst)
	if dstLstatErr == nil {
		if dstLstat.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("cannot overwrite remote symbolic link %q with directory %q", dst, src)
		}
		if !dstLstat.IsDir() {
			return false, fmt.Errorf("cannot overwrite non-directory remote destination %q with directory %q", dst, src)
		}
	} else if !errors.Is(dstLstatErr, os.ErrNotExist) && !os.IsNotExist(dstLstatErr) {
		return false, fmt.Errorf("lstat remote destination failed: %w", dstLstatErr)
	}

	dstStat, dstErr := c.SFTPClient().Stat(dst)
	if dstErr != nil && !errors.Is(dstErr, os.ErrNotExist) && !os.IsNotExist(dstErr) {
		return false, fmt.Errorf("stat remote destination failed: %w", dstErr)
	}
	dstExisted := dstErr == nil && dstStat.IsDir()

	if err := c.SFTPClient().MkdirAll(dst); err != nil {
		return false, fmt.Errorf("mkdir remote directory failed: %w", err)
	}
	if !dstExisted && srcStat != nil {
		initialMode := sanitizeTransferDirPerm(srcStat.Mode()) | 0o700
		if err := c.SFTPClient().Chmod(dst, initialMode); err != nil {
			return false, fmt.Errorf("set remote directory initial mode failed: %w", err)
		}
	}
	return dstExisted, nil
}

func (c *Client) remoteCopyDirectory(ctx context.Context, src, dst string, srcStat os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	srcRoot, err := ParseRemotePath(src)
	if err != nil {
		return fmt.Errorf("invalid remote copy source directory %q: %w", src, err)
	}
	dstRoot, err := ParseRemotePath(dst)
	if err != nil {
		return fmt.Errorf("invalid remote copy destination directory %q: %w", dst, err)
	}
	entries, err := readValidatedRemoteDir(ctx, c.SFTPClient(), srcRoot, "copy")
	if err != nil {
		return err
	}
	dstExisted, err := c.prepareRemoteDestinationDirectory(srcRoot.String(), dstRoot.String(), srcStat)
	if err != nil {
		return err
	}
	for _, item := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		subDst := dstRoot.Join(item.name)
		rels, relErr := subDst.RelativeTo(dstRoot)
		if relErr != nil || len(rels) != 1 || !rels[0].Equal(item.name) {
			return fmt.Errorf("copy %q: destination %q escapes parent directory %q", srcRoot.String(), subDst.String(), dstRoot.String())
		}
		// Lstat in remoteCopy preserves symbolic links instead of traversing
		// their targets.
		if err := c.remoteCopy(ctx, item.child.String(), subDst.String(), nil); err != nil {
			return fmt.Errorf("copy remote entry %q to %q failed: %w", item.child.String(), subDst.String(), err)
		}
	}
	if !dstExisted && srcStat != nil {
		if err := c.SFTPClient().Chtimes(dstRoot.String(), srcStat.ModTime(), srcStat.ModTime()); err != nil {
			return fmt.Errorf("set remote directory timestamps failed: %w", err)
		}
		if finalDirMode := sanitizeTransferDirPerm(srcStat.Mode()); finalDirMode != 0 {
			if err := c.SFTPClient().Chmod(dstRoot.String(), finalDirMode); err != nil {
				return fmt.Errorf("set remote directory final mode failed: %w", err)
			}
		}
	}
	return nil
}

func (c *Client) remoteCopyLink(ctx context.Context, src, dst string) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	target, err := c.SFTPClient().ReadLink(src)
	if err != nil {
		return fmt.Errorf("read remote symbolic link failed: %w", err)
	}

	tempPath := dst + c.config.TempSuffix
	if tempPath == src {
		return fmt.Errorf("remote copy temporary path conflicts with source: %q", tempPath)
	}
	if _, err := c.SFTPClient().Lstat(tempPath); err == nil {
		return fmt.Errorf("create remote temporary symbolic link failed: path %q already exists", tempPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lstat remote temporary symbolic link failed: %w", err)
	}
	if err := c.SFTPClient().Symlink(target, tempPath); err != nil {
		return fmt.Errorf("create remote temporary symbolic link failed: %w", err)
	}
	promoted := false
	defer func() {
		if promoted {
			return
		}
		if removeErr := c.SFTPClient().Remove(tempPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			retErr = errors.Join(retErr, fmt.Errorf("remove remote temporary symbolic link failed: %w", removeErr))
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.replaceRemoteLink(tempPath, dst); err != nil {
		return err
	}
	promoted = true
	return nil
}

func (c *Client) replaceRemoteLink(tempPath, remotePath string) error {
	if err := c.SFTPClient().PosixRename(tempPath, remotePath); err == nil {
		return nil
	} else if fallbackErr := c.replaceRemoteDestinationFallback(tempPath, remotePath); fallbackErr != nil {
		return errors.Join(
			fmt.Errorf("atomically replace remote symbolic link failed: %w", err),
			fmt.Errorf("replace remote symbolic link with backup failed: %w", fallbackErr),
		)
	}
	return nil
}

// resolveRemoteCopyFileDestination follows a destination symbolic link so that
// copying a regular file onto it updates the link target and leaves the link in
// place, like cp -r. It also reports the mode of an existing regular
// destination so that overwriting keeps its permissions.
func (c *Client) resolveRemoteCopyFileDestination(src, dst string) (string, os.FileMode, bool, error) {
	info, err := c.SFTPClient().Lstat(dst)
	if errors.Is(err, os.ErrNotExist) {
		return dst, 0, false, nil
	}
	if err != nil {
		return "", 0, false, fmt.Errorf("lstat remote destination failed: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, resolveErr := c.canonicalRemotePath(dst)
		if resolveErr != nil {
			return "", 0, false, fmt.Errorf("resolve remote destination symbolic link failed: %w", resolveErr)
		}
		if resolved == src {
			return "", 0, false, fmt.Errorf("remote source and destination are the same file: %q", src)
		}
		dst = resolved
		info, err = c.SFTPClient().Stat(dst)
		if errors.Is(err, os.ErrNotExist) {
			return dst, 0, false, nil
		}
		if err != nil {
			return "", 0, false, fmt.Errorf("stat remote destination symbolic link target failed: %w", err)
		}
	}
	if info.IsDir() {
		return "", 0, false, fmt.Errorf("cannot overwrite remote destination directory %q with a file", dst)
	}
	if !info.Mode().IsRegular() {
		return "", 0, false, fmt.Errorf("cannot overwrite non-regular remote destination %q", dst)
	}
	return dst, info.Mode(), true, nil
}

func (c *Client) openVerifiedRemoteCopySource(src string, srcStat os.FileInfo) (*sftp.File, os.FileInfo, error) {
	srcFile, err := c.SFTPClient().Open(src)
	if err != nil {
		return nil, nil, fmt.Errorf("open remote source file failed: %w", err)
	}
	openedStat, err := srcFile.Stat()
	if err != nil {
		return nil, nil, errors.Join(
			fmt.Errorf("stat remote source file failed: %w", err),
			closeTransferResource(srcFile, "remote source file"),
		)
	}
	if !openedStat.Mode().IsRegular() {
		return nil, nil, errors.Join(
			fmt.Errorf("remote source %q is not a regular file (mode %s)", src, openedStat.Mode()),
			closeTransferResource(srcFile, "remote source file"),
		)
	}
	if openedStat.Size() != srcStat.Size() {
		return nil, nil, errors.Join(
			fmt.Errorf("remote source size changed: expected %d bytes, got %d", srcStat.Size(), openedStat.Size()),
			closeTransferResource(srcFile, "remote source file"),
		)
	}
	return srcFile, openedStat, nil
}

func (c *Client) remoteCopyFile(ctx context.Context, src, dst string, srcStat os.FileInfo) (retErr error) {
	if !srcStat.Mode().IsRegular() {
		return fmt.Errorf("remote source %q is not a regular file (mode %s)", src, srcStat.Mode())
	}
	dst, existingMode, dstExisted, err := c.resolveRemoteCopyFileDestination(src, dst)
	if err != nil {
		return err
	}
	srcFile, openedStat, err := c.openVerifiedRemoteCopySource(src, srcStat)
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, closeTransferResource(srcFile, "remote source file"))
	}()

	finalMode := sanitizeTransferFilePerm(openedStat.Mode())
	if finalMode == 0 {
		finalMode = sanitizeTransferFilePerm(srcStat.Mode())
	}
	if dstExisted {
		finalMode = sanitizeTransferFilePerm(existingMode)
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	tempPath := dst + c.config.TempSuffix
	if tempPath == src {
		return fmt.Errorf("remote copy temporary path conflicts with source: %q", tempPath)
	}
	_, exists, err := c.inspectRemoteTemporaryFile(tempPath)
	if err != nil {
		return err
	}
	flags := os.O_RDWR | os.O_CREATE | os.O_EXCL
	if exists {
		flags = os.O_RDWR | os.O_TRUNC
	}
	dstFile, err := c.SFTPClient().OpenFile(tempPath, flags)
	if err != nil {
		return fmt.Errorf("create remote temporary destination file failed: %w", err)
	}
	if err := c.verifyRemoteTemporaryFile(tempPath); err != nil {
		return errors.Join(err, closeTransferResource(dstFile, "remote temporary destination file after validation failure"))
	}
	defer func() {
		if dstFile != nil {
			retErr = errors.Join(retErr, closeTransferResource(dstFile, "remote temporary destination file"))
		}
	}()
	if err := dstFile.Chmod(stagingFilePerm); err != nil {
		return fmt.Errorf("set remote temporary destination mode failed: %w", err)
	}

	if err := copyExactContext(ctx, dstFile, srcFile, openedStat.Size(), nil); err != nil {
		return fmt.Errorf("copy remote source %q to %q failed: %w", src, dst, err)
	}
	if err := dstFile.Close(); err != nil {
		dstFile = nil
		return fmt.Errorf("close remote temporary destination file failed: %w", err)
	}
	dstFile = nil
	return c.finalizeRemoteTempFile(ctx, tempPath, dst, openedStat.ModTime(), finalMode)
}

func (c *Client) canonicalRemotePath(remotePath string) (string, error) {
	cleanPath, err := c.absoluteRemotePath(remotePath)
	if err != nil {
		return "", err
	}

	pending := remotePathComponents(cleanPath)
	resolved := "/"
	const maxSymbolicLinkDepth = 40
	linkDepth := 0
	for len(pending) > 0 {
		component := pending[0]
		pending = pending[1:]
		candidate := path.Join(resolved, component)
		info, lstatErr := c.SFTPClient().Lstat(candidate)
		if errors.Is(lstatErr, os.ErrNotExist) {
			return path.Join(append([]string{candidate}, pending...)...), nil
		}
		if lstatErr != nil {
			return "", fmt.Errorf("resolve remote path %q failed: %w", candidate, lstatErr)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			resolved = candidate
			continue
		}

		linkDepth++
		if linkDepth > maxSymbolicLinkDepth {
			return "", fmt.Errorf("resolve remote path %q failed: too many symbolic links", cleanPath)
		}
		target, readErr := c.SFTPClient().ReadLink(candidate)
		if readErr != nil {
			return "", fmt.Errorf("read remote symbolic link %q failed: %w", candidate, readErr)
		}
		if !path.IsAbs(target) {
			target = path.Join(resolved, target)
		}
		pending = append(remotePathComponents(path.Clean(target)), pending...)
		resolved = "/"
	}
	return path.Clean(resolved), nil
}

func remotePathComponents(remotePath string) []string {
	cleanPath := strings.TrimPrefix(path.Clean(remotePath), "/")
	if cleanPath == "" || cleanPath == "." {
		return nil
	}
	return strings.Split(cleanPath, "/")
}

func (c *Client) absoluteRemotePath(remotePath string) (string, error) {
	cleanPath := path.Clean(remotePath)
	if path.IsAbs(cleanPath) {
		return cleanPath, nil
	}
	cwd, err := c.SFTPClient().Getwd()
	if err != nil {
		return "", fmt.Errorf("get remote working directory failed: %w", err)
	}
	return path.Join(cwd, cleanPath), nil
}

// canonicalRemoteEntryPath resolves the parent directory while preserving the
// final entry. This compares aliases without dereferencing a source symlink.
func (c *Client) canonicalRemoteEntryPath(remotePath string) (string, error) {
	absolutePath, err := c.absoluteRemotePath(remotePath)
	if err != nil {
		return "", err
	}
	canonicalParent, err := c.canonicalRemotePath(path.Dir(absolutePath))
	if err != nil {
		return "", fmt.Errorf("resolve remote entry parent failed: %w", err)
	}
	return path.Join(canonicalParent, path.Base(absolutePath)), nil
}

func remotePathContains(parent, candidate string) bool {
	parent = path.Clean(parent)
	candidate = path.Clean(candidate)
	if parent == candidate {
		return true
	}
	if parent == "/" {
		return path.IsAbs(candidate)
	}
	return strings.HasPrefix(candidate, parent+"/")
}

func copyExactContext(ctx context.Context, dst io.Writer, src io.Reader, size int64, progress ProgressCallback) error {
	if size < 0 {
		return fmt.Errorf("copy size must not be negative: %d", size)
	}
	buf := make([]byte, 32*1024)
	remaining := size
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		readBuffer := buf
		if remaining < int64(len(readBuffer)) {
			readBuffer = readBuffer[:remaining]
		}
		n, err := src.Read(readBuffer)
		if n < 0 || n > len(readBuffer) {
			return fmt.Errorf("invalid read result: %d", n)
		}
		if n > 0 {
			nw, wErr := dst.Write(buf[:n])
			if nw < 0 || n < nw {
				nw = 0
				if wErr == nil {
					wErr = errors.New("invalid write result")
				}
			}
			if wErr != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return ctxErr
				}
				return wErr
			}
			if nw != n {
				return io.ErrShortWrite
			}
			if progress != nil {
				progress(int64(n))
			}
			remaining -= int64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if remaining == 0 {
					return nil
				}
				return io.ErrUnexpectedEOF
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func runInterruptibleOperation(
	ctx context.Context,
	interrupt func() error,
	operation func() error,
) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}

	closeDone := make(chan error, 1)
	stopClose := context.AfterFunc(ctx, func() {
		closeDone <- interrupt()
	})
	defer func() {
		if !stopClose() {
			retErr = errors.Join(retErr, <-closeDone)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			retErr = errors.Join(ctxErr, retErr)
		}
	}()

	return operation()
}

func closeTransferResource(closer io.Closer, resource string) error {
	if closer == nil {
		return nil
	}
	if err := closer.Close(); err != nil && !errors.Is(err, os.ErrClosed) &&
		!errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		return fmt.Errorf("close %s failed: %w", resource, err)
	}
	return nil
}

// ================== 目录并发逻辑 ==================

func (c *Client) UploadDirectory(ctx context.Context, localDir, remoteDir string, progress ProgressCallback) error {
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		return c.uploadDirectory(ctx, localDir, remoteDir, progress)
	})
}

func (c *Client) ensureRemoteUploadDirectory(src, dst string) error {
	dst = cleanRemotePathForRemoval(dst)
	dstLstat, err := c.SFTPClient().Lstat(dst)
	if err == nil {
		if dstLstat.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("cannot overwrite remote symbolic link %q with directory %q", dst, src)
		}
		if !dstLstat.IsDir() {
			return fmt.Errorf("cannot overwrite non-directory remote destination %q with directory %q", dst, src)
		}
	} else if !errors.Is(err, os.ErrNotExist) && !os.IsNotExist(err) {
		return fmt.Errorf("lstat remote destination %q failed: %w", dst, err)
	}
	return c.SFTPClient().MkdirAll(dst)
}

func ensureLocalDownloadDirectory(src, dst string, perm os.FileMode) (bool, error) {
	dst = filepath.Clean(dst)
	dstLstat, err := os.Lstat(dst)
	if err == nil {
		if dstLstat.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("cannot overwrite local symbolic link %q with directory %q", dst, src)
		}
		if dstLstat.Mode()&os.ModeType != os.ModeDir {
			return false, fmt.Errorf("cannot overwrite non-directory local destination %q with directory %q", dst, src)
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) && !os.IsNotExist(err) {
		return false, fmt.Errorf("lstat local destination %q failed: %w", dst, err)
	}
	dirPerm := sanitizeTransferDirPerm(perm)
	if dirPerm == 0 {
		dirPerm = 0o700
	}
	if mkErr := os.MkdirAll(dst, dirPerm); mkErr != nil {
		return false, mkErr
	}
	return true, nil
}

// ResolveLocalUploadRootDir resolves a top-level local upload directory
// (dereferencing top-level symlinks or irregular reparse points) and verifies
// via os.Lstat that the resolved walk root itself is a real directory
// (os.ModeDir) before any remote directory is created.
func ResolveLocalUploadRootDir(localDir string) (string, error) {
	return resolveLocalUploadRootDirWith(localDir, os.Lstat, filepath.EvalSymlinks, os.Stat)
}

func resolveLocalUploadRootDirWith(
	localDir string,
	lstatFn func(string) (os.FileInfo, error),
	evalSymlinksFn func(string) (string, error),
	statFn func(string) (os.FileInfo, error),
) (string, error) {
	if localDir == "" {
		return "", fmt.Errorf("stat local directory %q failed: %w", localDir, os.ErrNotExist)
	}
	cleanLocal := filepath.Clean(localDir)
	linfo, err := lstatFn(cleanLocal)
	if err != nil {
		return "", fmt.Errorf("lstat local directory %q failed: %w", localDir, err)
	}
	walkRoot := cleanLocal
	lstatWalk := linfo
	if linfo.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		resolved, evalErr := evalSymlinksFn(cleanLocal)
		if evalErr != nil {
			return "", fmt.Errorf("resolve local directory symlink %q failed: %w", localDir, evalErr)
		}
		walkRoot = resolved
		lstatWalk, err = lstatFn(walkRoot)
		if err != nil {
			return "", fmt.Errorf("lstat resolved local directory %q failed: %w", localDir, err)
		}
	}
	if lstatWalk.Mode()&os.ModeType != os.ModeDir {
		return "", fmt.Errorf("resolved local upload root %q is not a directory (mode %s)", walkRoot, lstatWalk.Mode())
	}
	info, err := statFn(walkRoot)
	if err != nil {
		return "", fmt.Errorf("stat local directory %q failed: %w", localDir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("local upload path %q is not a directory", localDir)
	}
	return walkRoot, nil
}

func (c *Client) resolveLocalUploadRoot(localDir string) (string, error) {
	if c != nil && c.resolveUploadRoot != nil {
		return c.resolveUploadRoot(localDir)
	}
	return ResolveLocalUploadRootDir(localDir)
}

func (c *Client) emitLinkProgress(path string, linkSize int64, progress ProgressCallback) {
	if c.fileProgress != nil {
		c.fileProgress(FileTransferProgress{
			Path:        path,
			Size:        linkSize,
			Transferred: linkSize,
			Increment:   linkSize,
		})
	}
	if progress != nil && linkSize > 0 {
		progress(linkSize)
	}
}

func (c *Client) uploadDirectory(ctx context.Context, localDir, remoteDir string, progress ProgressCallback) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	remoteRoot, err := ParseRemotePath(remoteDir)
	if err != nil {
		return fmt.Errorf("invalid remote upload directory %q: %w", remoteDir, err)
	}
	walkRoot, err := c.resolveLocalUploadRoot(localDir)
	if err != nil {
		return err
	}
	// 1. 确保远程根目录存在且不是符号链接/非目录条目
	if err := c.ensureRemoteUploadDirectory(walkRoot, remoteRoot.String()); err != nil {
		return fmt.Errorf("create remote destination directory failed: %w", err)
	}

	// 2. 遍历本地目录收集文件
	transferCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, groupCtx := errgroup.WithContext(transferCtx)
	sem := make(chan struct{}, c.config.ConcurrentFiles)

	err = filepath.Walk(walkRoot, func(localPath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if groupCtx.Err() != nil {
			return groupCtx.Err()
		}

		relPath, relErr := filepath.Rel(walkRoot, localPath)
		if relErr != nil {
			return relErr
		}
		if relPath == "." {
			if info.Mode()&os.ModeType != os.ModeDir {
				return fmt.Errorf("local upload root %q is no longer a directory", localDir)
			}
			return nil
		}

		remoteDest, destErr := joinUploadRemoteRel(remoteRoot, relPath)
		if destErr != nil {
			return fmt.Errorf("resolve remote destination for %q: %w", localPath, destErr)
		}

		if info.IsDir() {
			if mkdirErr := c.ensureRemoteUploadDirectory(localPath, remoteDest.String()); mkdirErr != nil {
				return fmt.Errorf("create remote directory %q: %w", remoteDest.String(), mkdirErr)
			}
			return nil
		}

		loopPath := localPath
		loopDest := remoteDest.String()
		loopInfo := info

		select {
		case sem <- struct{}{}:
		case <-groupCtx.Done():
			return groupCtx.Err()
		}
		g.Go(func() error {
			defer func() { <-sem }()
			if loopInfo.Mode()&os.ModeSymlink != 0 {
				if err := c.uploadLink(groupCtx, loopPath, loopDest, progress); err != nil {
					return fmt.Errorf("upload %q to %q: %w", loopPath, loopDest, err)
				}
				return nil
			}
			if err := c.uploadFile(groupCtx, loopPath, loopDest, loopInfo.Size(), loopInfo.Mode(), progress); err != nil {
				return fmt.Errorf("upload %q to %q: %w", loopPath, loopDest, err)
			}
			return nil
		})

		return nil
	})

	return finishTransferGroup(ctx, cancel, g, err)
}

func joinUploadRemoteRel(remoteRoot RemotePath, localRel string) (RemotePath, error) {
	if localRel == "." {
		return remoteRoot, nil
	}
	parts := strings.Split(filepath.ToSlash(localRel), "/")
	names := make([]RemoteName, 0, len(parts))
	for _, seg := range parts {
		name, err := ParseRemoteName(seg)
		if err != nil {
			return RemotePath{}, err
		}
		names = append(names, name)
	}
	return remoteRoot.JoinNames(names...)
}

func (c *Client) UploadLink(ctx context.Context, localPath, remotePath string, progress ProgressCallback) error {
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		return c.uploadLink(ctx, localPath, remotePath, progress)
	})
}

func (c *Client) shouldSkipUploadLink(remotePath, target string) (bool, error) {
	dstLstat, err := c.SFTPClient().Lstat(remotePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("lstat remote destination failed: %w", err)
	}
	if dstLstat.IsDir() {
		return false, fmt.Errorf("cannot overwrite remote destination directory %q with symbolic link", remotePath)
	}
	if !c.config.Force && dstLstat.Mode()&os.ModeSymlink != 0 {
		if existingTarget, readErr := c.SFTPClient().ReadLink(remotePath); readErr == nil && existingTarget == target {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) createRemoteTempLink(tempPath, target string) error {
	if tempInfo, err := c.SFTPClient().Lstat(tempPath); err == nil {
		if tempInfo.IsDir() {
			return fmt.Errorf("create remote temporary symbolic link failed: temporary path %q is a directory", tempPath)
		}
		if !c.config.Force {
			return fmt.Errorf("create remote temporary symbolic link failed: path %q already exists", tempPath)
		}
		if rmErr := c.SFTPClient().Remove(tempPath); rmErr != nil {
			return fmt.Errorf("remove existing remote temporary path %q failed: %w", tempPath, rmErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lstat remote temporary symbolic link failed: %w", err)
	}
	if err := c.SFTPClient().Symlink(target, tempPath); err != nil {
		return fmt.Errorf("create remote temporary symbolic link failed: %w", err)
	}
	return nil
}

func (c *Client) uploadLink(ctx context.Context, localPath, remotePath string, progress ProgressCallback) (retErr error) {
	finishDiagnostic := c.observeFileTransfer("upload", localPath, remotePath, 0)
	defer func() { finishDiagnostic(retErr) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	target, err := os.Readlink(localPath)
	if err != nil {
		return fmt.Errorf("read local symbolic link %q failed: %w", localPath, err)
	}
	if runtime.GOOS == "windows" {
		target = filepath.ToSlash(target)
	}
	linkSize := int64(len(target))

	skip, skipErr := c.shouldSkipUploadLink(remotePath, target)
	if skipErr != nil {
		return skipErr
	}
	if skip {
		c.emitLinkProgress(localPath, linkSize, progress)
		return nil
	}

	tempPath := remotePath + c.config.TempSuffix
	if tempPath == remotePath {
		return fmt.Errorf("upload temporary link conflicts with destination: %q", tempPath)
	}
	if err := c.createRemoteTempLink(tempPath, target); err != nil {
		return err
	}
	promoted := false
	defer func() {
		if promoted {
			return
		}
		if removeErr := c.SFTPClient().Remove(tempPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			retErr = errors.Join(retErr, fmt.Errorf("remove remote temporary symbolic link failed: %w", removeErr))
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.replaceRemoteLink(tempPath, remotePath); err != nil {
		return err
	}
	promoted = true
	c.emitLinkProgress(localPath, linkSize, progress)
	return nil
}

type stagedDownloadSymlink struct {
	remotePath string
	localPath  string
	relPath    string
	target     string
}

type downloadDirWalkState struct {
	client          *Client
	remoteRoot      RemotePath
	groupCtx        context.Context
	group           *errgroup.Group
	sem             chan struct{}
	progress        ProgressCallback
	caseInsensitive bool

	symlinks   []stagedDownloadSymlink
	symlinkMap map[string]string
}

func (c *Client) isCaseInsensitiveDir(dir string) bool {
	if c != nil && c.caseInsensitiveDirProbe != nil {
		return c.caseInsensitiveDirProbe(dir)
	}
	return probeCaseInsensitiveDir(dir)
}

func (c *Client) downloadDirectory(ctx context.Context, remoteRoot RemotePath, localRoot LocalTarget, progress ProgressCallback) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !remoteRoot.IsValid() {
		return fmt.Errorf("%w: remote directory root is invalid", ErrInvalidRemotePath)
	}
	if !localRoot.IsValid() {
		return fmt.Errorf("%w: local download root is invalid", ErrInvalidLocalTarget)
	}
	rootInfo, statErr := c.SFTPClient().Stat(remoteRoot.String())
	if statErr != nil {
		return fmt.Errorf("stat remote directory %q failed: %w", remoteRoot.String(), statErr)
	}
	if rootInfo.Mode()&os.ModeType != os.ModeDir {
		return fmt.Errorf("download %q: unsafe remote filename %q: root is not a directory", remoteRoot.String(), rootInfo.Name())
	}
	rootFinalPerm := sanitizeTransferDirPerm(rootInfo.Mode())
	rootCreatePerm := rootFinalPerm | 0o700
	rootCreated, mkdirErr := ensureLocalDownloadDirectory(remoteRoot.String(), localRoot.Path(), rootCreatePerm)
	if mkdirErr != nil {
		return fmt.Errorf("create local download directory failed: %w", mkdirErr)
	}
	caseInsensitive := c.isCaseInsensitiveDir(localRoot.Path())

	transferCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, groupCtx := errgroup.WithContext(transferCtx)
	walker := &downloadDirWalkState{
		client:          c,
		remoteRoot:      remoteRoot,
		groupCtx:        groupCtx,
		group:           g,
		sem:             make(chan struct{}, c.config.ConcurrentFiles),
		progress:        progress,
		caseInsensitive: caseInsensitive,
		symlinkMap:      make(map[string]string),
	}

	// Phase 1: walk directories, create local directories, download regular
	// files, and stage all symlinks with their ReadLink targets without
	// creating any local symlinks yet.
	traversalErr := walker.walkDir(remoteRoot, localRoot)
	if err := finishTransferGroup(ctx, cancel, g, traversalErr); err != nil {
		return err
	}

	// Phase 2: validate EVERY staged symlink against the complete in-tree
	// symlink map and local disk state before creating any symlink on disk.
	if err := c.applyStagedDownloadSymlinks(ctx, localRoot.Path(), walker.symlinks, walker.symlinkMap, progress); err != nil {
		return err
	}
	if rootCreated && rootFinalPerm != 0 && rootFinalPerm != rootCreatePerm {
		linfo, lstatErr := os.Lstat(localRoot.Path())
		if lstatErr != nil {
			return fmt.Errorf("lstat local download directory %q failed: %w", localRoot.Path(), lstatErr)
		}
		if linfo.Mode()&os.ModeType != os.ModeDir {
			return fmt.Errorf("local download directory %q is no longer a directory", localRoot.Path())
		}
		if chmodErr := os.Chmod(localRoot.Path(), rootFinalPerm); chmodErr != nil {
			return fmt.Errorf("set local download directory mode failed: %w", chmodErr)
		}
	}
	return nil
}

type validatedWalkEntry struct {
	entry       os.FileInfo
	childRemote RemotePath
	childLocal  LocalTarget
}

func (w *downloadDirWalkState) walkDir(curRemote RemotePath, curLocal LocalTarget) error {
	if err := w.groupCtx.Err(); err != nil {
		return err
	}
	validatedDir, readErr := readValidatedRemoteDir(w.groupCtx, w.client.SFTPClient(), curRemote, "download")
	if readErr != nil {
		return readErr
	}
	validated, err := w.validateValidatedDirEntries(curRemote, curLocal, validatedDir)
	if err != nil {
		return err
	}
	for _, item := range validated {
		if err := w.applyValidatedEntry(curRemote, item); err != nil {
			return err
		}
	}
	return nil
}

// validateDirEntries pre-validates every sibling entry in curRemote (non-nil
// metadata, safe remote name, exact duplicate, Unicode NFD/case-folded
// collision, local target containment, and supported entry type) BEFORE
// creating any child directories, reading symlinks, or enqueueing download
// workers.
func (w *downloadDirWalkState) validateDirEntries(curRemote RemotePath, curLocal LocalTarget, entries []os.FileInfo) ([]validatedWalkEntry, error) {
	validatedDir, err := validateRemoteDirEntries(w.groupCtx, curRemote, entries, "download")
	if err != nil {
		return nil, err
	}
	return w.validateValidatedDirEntries(curRemote, curLocal, validatedDir)
}

func (w *downloadDirWalkState) validateValidatedDirEntries(curRemote RemotePath, curLocal LocalTarget, entries []validatedRemoteDirEntry) ([]validatedWalkEntry, error) {
	var seenFold map[string]string
	var seenNorm map[string]string
	if w.caseInsensitive {
		seenFold = make(map[string]string, len(entries))
	} else {
		seenNorm = make(map[string]string, len(entries))
	}
	validated := make([]validatedWalkEntry, 0, len(entries))
	for _, item := range entries {
		if err := w.groupCtx.Err(); err != nil {
			return nil, err
		}
		entry := item.info
		entryName := item.name
		rawName := entryName.String()
		if seenFold != nil {
			folded := foldDownloadSegment(rawName)
			if prev, dup := seenFold[folded]; dup {
				return nil, fmt.Errorf("download %q: case-colliding remote directory entries %q and %q on case-insensitive filesystem", curRemote.String(), prev, rawName)
			}
			seenFold[folded] = rawName
		} else {
			decomposed := norm.NFD.String(rawName)
			if prev, dup := seenNorm[decomposed]; dup {
				return nil, fmt.Errorf("download %q: canonically-equivalent remote directory entries %q and %q", curRemote.String(), prev, rawName)
			}
			seenNorm[decomposed] = rawName
		}

		childRemote := item.child
		if _, relErr := childRemote.RelativeTo(w.remoteRoot); relErr != nil {
			return nil, fmt.Errorf("download %q: %w", childRemote.String(), relErr)
		}
		childLocal, targetErr := curLocal.Join(entryName)
		if targetErr != nil {
			return nil, fmt.Errorf("download %q: unsafe remote filename %q: %w", childRemote.String(), rawName, targetErr)
		}
		if modeErr := validateRemoteDownloadMode(childRemote.String(), entry.Mode(), true); modeErr != nil {
			return nil, modeErr
		}
		validated = append(validated, validatedWalkEntry{
			entry:       entry,
			childRemote: childRemote,
			childLocal:  childLocal,
		})
	}
	return validated, nil
}

func (w *downloadDirWalkState) applyValidatedEntry(curRemote RemotePath, item validatedWalkEntry) error {
	if err := w.groupCtx.Err(); err != nil {
		return err
	}
	entry := item.entry
	childRemote := item.childRemote
	childLocal := item.childLocal

	if entry.Mode()&os.ModeSymlink != 0 {
		target, readErr := w.client.SFTPClient().ReadLink(childRemote.String())
		if readErr != nil {
			return fmt.Errorf("download %q to %q: read remote symbolic link %q failed: %w", childRemote.String(), childLocal.Path(), childRemote.String(), readErr)
		}
		relPath := childLocal.RelSlash()
		if _, dup := w.symlinkMap[relPath]; dup {
			return fmt.Errorf("download %q: duplicate remote symbolic link %q", curRemote.String(), relPath)
		}
		w.symlinkMap[relPath] = target
		w.symlinks = append(w.symlinks, stagedDownloadSymlink{
			remotePath: childRemote.String(),
			localPath:  childLocal.Path(),
			relPath:    relPath,
			target:     target,
		})
		return nil
	}
	if entry.IsDir() {
		if _, err := ensureLocalDownloadDirectory(childRemote.String(), childLocal.Path(), sanitizeTransferDirPerm(entry.Mode())|0o700); err != nil {
			return fmt.Errorf("create local directory %q failed: %w", childLocal.Path(), err)
		}
		return w.walkDir(childRemote, childLocal)
	}
	return w.enqueueTask(func() error {
		if err := w.client.downloadFile(w.groupCtx, childRemote.String(), childLocal.Path(), entry.Size(), sanitizeTransferFilePerm(entry.Mode()), w.progress); err != nil {
			return fmt.Errorf("download %q to %q: %w", childRemote.String(), childLocal.Path(), err)
		}
		return nil
	})
}

func (c *Client) applyStagedDownloadSymlinks(
	ctx context.Context,
	localRoot string,
	symlinks []stagedDownloadSymlink,
	symlinkMap map[string]string,
	progress ProgressCallback,
) error {
	if len(symlinks) == 0 {
		return nil
	}
	idx, idxErr := buildDownloadSymlinkIndex(symlinkMap)
	if idxErr != nil {
		return fmt.Errorf("download to %q: %w", localRoot, idxErr)
	}
	inspector := defaultDownloadDiskInspector()
	for _, sym := range symlinks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateDownloadSymlinkInTreeWithIndex(localRoot, sym.relPath, sym.target, idx, inspector); err != nil {
			return fmt.Errorf("download %q to %q: reject remote symbolic link %q -> %q: %w", sym.remotePath, sym.localPath, sym.remotePath, sym.target, err)
		}
	}
	ordered, orderErr := orderStagedDownloadSymlinks(symlinks)
	if orderErr != nil {
		return orderErr
	}
	for _, sym := range ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.createDownloadLink(ctx, sym.remotePath, sym.localPath, sym.target, progress); err != nil {
			return fmt.Errorf("download %q to %q: %w", sym.remotePath, sym.localPath, err)
		}
	}
	return nil
}

// orderStagedDownloadSymlinks places symlinks that overwrite pre-existing local
// entries ahead of newly-created symlinks so a partial failure during
// replacement cannot leave a newly created symlink pointing through an
// unreplaced on-disk symlink.
func orderStagedDownloadSymlinks(symlinks []stagedDownloadSymlink) ([]stagedDownloadSymlink, error) {
	replaceExisting := make([]stagedDownloadSymlink, 0, len(symlinks))
	createNew := make([]stagedDownloadSymlink, 0, len(symlinks))
	for _, sym := range symlinks {
		_, err := os.Lstat(sym.localPath)
		switch {
		case err == nil:
			replaceExisting = append(replaceExisting, sym)
		case errors.Is(err, os.ErrNotExist):
			createNew = append(createNew, sym)
		default:
			return nil, fmt.Errorf("download %q to %q: lstat local symbolic link destination failed: %w", sym.remotePath, sym.localPath, err)
		}
	}
	return append(replaceExisting, createNew...), nil
}

func (w *downloadDirWalkState) enqueueTask(fn func() error) error {
	select {
	case w.sem <- struct{}{}:
	case <-w.groupCtx.Done():
		return w.groupCtx.Err()
	}
	w.group.Go(func() error {
		defer func() { <-w.sem }()
		return fn()
	})
	return nil
}

func (c *Client) shouldSkipDownloadLink(localPath, target string) (bool, error) {
	dstLstat, err := os.Lstat(localPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("lstat local destination failed: %w", err)
	}
	if dstLstat.IsDir() {
		return false, fmt.Errorf("cannot overwrite local destination directory %q with symbolic link", localPath)
	}
	if !c.config.Force && dstLstat.Mode()&os.ModeSymlink != 0 {
		if existingTarget, readErr := os.Readlink(localPath); readErr == nil && (existingTarget == target || (runtime.GOOS == "windows" && filepath.ToSlash(existingTarget) == target)) {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) createDownloadLink(ctx context.Context, remotePath, localPath, target string, progress ProgressCallback) (retErr error) {
	finishDiagnostic := c.observeFileTransfer("download", remotePath, localPath, 0)
	defer func() { finishDiagnostic(retErr) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	linkSize := int64(len(target))

	skip, err := c.shouldSkipDownloadLink(localPath, target)
	if err != nil {
		return err
	}
	if skip {
		c.emitLinkProgress(remotePath, linkSize, progress)
		return nil
	}

	rb := make([]byte, 16)
	if _, err := rand.Read(rb); err != nil {
		return fmt.Errorf("generate random bytes failed: %w", err)
	}
	tempPath := localPath + c.config.TempSuffix + "." + hex.EncodeToString(rb)
	if err := os.Symlink(target, tempPath); err != nil {
		return fmt.Errorf("create local temporary symbolic link failed: %w", err)
	}
	promoted := false
	defer func() {
		if promoted {
			return
		}
		if rmErr := os.Remove(tempPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) { //nolint:forbidigo // deferred cleanup of randomly-suffixed temporary symlink created by this call
			retErr = errors.Join(retErr, fmt.Errorf("remove local temporary symbolic link failed: %w", rmErr))
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := replaceLocalLink(tempPath, localPath, os.Rename); err != nil {
		return err
	}
	promoted = true
	c.emitLinkProgress(remotePath, linkSize, progress)
	return nil
}

func ensureLocalDestWithinDir(baseDir, destPath string, allowEqual bool) error {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("resolve local download root %q failed: %w", baseDir, err)
	}
	absDest, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("resolve local download destination %q failed: %w", destPath, err)
	}
	rel, err := filepath.Rel(absBase, absDest)
	if err != nil {
		return fmt.Errorf("local destination %q escapes download root %q: %w", destPath, baseDir, err)
	}
	if rel == "." {
		if !allowEqual {
			return fmt.Errorf("local destination %q must be inside download root %q", destPath, baseDir)
		}
		return nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("local destination %q escapes download root %q", destPath, baseDir)
	}
	return nil
}

func finishTransferGroup(ctx context.Context, cancel context.CancelFunc, group *errgroup.Group, operationErr error) error {
	if operationErr != nil {
		cancel()
	}
	groupErr := group.Wait()
	cancel()
	if groupErr != nil && ctx.Err() == nil && errors.Is(operationErr, context.Canceled) {
		return groupErr
	}
	if operationErr != nil && ctx.Err() == nil && errors.Is(groupErr, context.Canceled) {
		return operationErr
	}
	return errors.Join(operationErr, groupErr)
}

func (c *Client) validateResumePrefixUpload(ctx context.Context, dstFile io.ReaderAt, srcFile io.ReaderAt, startOffset int64) error {
	return validatePrefix(ctx, dstFile, srcFile, startOffset)
}

func (c *Client) validateResumePrefixDownload(ctx context.Context, dstFile io.ReaderAt, srcFile io.ReaderAt, startOffset int64) error {
	return validatePrefix(ctx, dstFile, srcFile, startOffset)
}

func validatePrefix(ctx context.Context, dstFile io.ReaderAt, srcFile io.ReaderAt, startOffset int64) error {
	const chunkSize = 32 * 1024
	buf1 := make([]byte, chunkSize)
	buf2 := make([]byte, chunkSize)

	var offset int64
	for offset < startOffset {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		readSize := int64(chunkSize)
		if startOffset-offset < readSize {
			readSize = startOffset - offset
		}

		n1, err1 := dstFile.ReadAt(buf1[:readSize], offset)
		if err1 != nil && !errors.Is(err1, io.EOF) {
			return fmt.Errorf("read destination failed at offset %d: %w", offset, err1)
		}

		n2, err2 := srcFile.ReadAt(buf2[:readSize], offset)
		if err2 != nil && !errors.Is(err2, io.EOF) {
			return fmt.Errorf("read source failed at offset %d: %w", offset, err2)
		}

		if n1 != n2 || string(buf1[:n1]) != string(buf2[:n2]) {
			return errPrefixMismatch
		}
		if n1 == 0 {
			break
		}
		offset += int64(n1)
	}
	if offset != startOffset {
		return errPrefixMismatch
	}
	return nil
}

var errPrefixMismatch = errors.New("resume prefix mismatch")
