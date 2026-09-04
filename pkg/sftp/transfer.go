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
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/sync/errgroup"
)

// Upload 上传入口：支持文件或目录
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
	if err == nil && remoteStat.IsDir() {
		// 如果是目录，拼接文件名
		remotePath = c.JoinPath(remotePath, filepath.Base(localPath))
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat remote destination failed: %w", err)
	}

	return c.uploadFile(ctx, localPath, remotePath, info.Size(), info.Mode(), progress)
}

// Download 下载入口：支持文件或目录
func (c *Client) Download(ctx context.Context, remotePath, localPath string, progress ProgressCallback) error {
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		return c.download(ctx, remotePath, localPath, progress)
	})
}

func (c *Client) download(ctx context.Context, remotePath, localPath string, progress ProgressCallback) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := c.SFTPClient().Stat(remotePath)
	if err != nil {
		return fmt.Errorf("stat remote path failed: %w", err)
	}

	if info.IsDir() {
		return c.downloadDirectory(ctx, remotePath, localPath, progress)
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	stat, err := os.Stat(localPath)
	if err == nil && stat.IsDir() {
		localPath = filepath.Join(localPath, info.Name())
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat local destination failed: %w", err)
	}

	return c.downloadFile(ctx, remotePath, localPath, info.Size(), info.Mode(), progress)
}

// ================== 单文件多线程分块逻辑 ==================

func (c *Client) UploadFile(ctx context.Context, localPath, remotePath string, size int64, mode os.FileMode, progress ProgressCallback) (retErr error) {
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		return c.uploadFile(ctx, localPath, remotePath, size, mode, progress)
	})
}

func (c *Client) uploadFile(ctx context.Context, localPath, remotePath string, size int64, mode os.FileMode, progress ProgressCallback) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	srcFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local source file failed: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, closeTransferResource(srcFile, "local source file"))
	}()

	srcStat, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat local source file failed: %w", err)
	}
	if srcStat.Size() != size {
		return fmt.Errorf("local source size changed: expected %d bytes, got %d", size, srcStat.Size())
	}

	// 只有在非强制模式下才检查跳过
	if !c.config.Force {
		if err := ctx.Err(); err != nil {
			return err
		}
		skip, skipErr := c.shouldSkipUpload(remotePath, srcStat, progress)
		if skipErr != nil {
			return skipErr
		}
		if skip {
			return nil
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	tempPath := remotePath + c.config.TempSuffix
	startOffset, dstFile, err := c.prepareUploadFile(tempPath, size, srcFile)
	if err != nil {
		return fmt.Errorf("prepare remote temporary file failed: %w", err)
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
		if err := dstFile.Chmod(mode); err != nil {
			return fmt.Errorf("set remote temporary file mode failed: %w", err)
		}

		if progress != nil && startOffset > 0 {
			progress(startOffset)
		}

		if err := c.doUpload(ctx, srcFile, dstFile, startOffset, size, progress); err != nil {
			return fmt.Errorf("upload file content failed: %w", err)
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
	return c.finalizeUpload(ctx, tempPath, remotePath, srcStat)
}

func (c *Client) finalizeUpload(ctx context.Context, tempPath, remotePath string, srcStat os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.verifyRemoteTemporaryFile(tempPath); err != nil {
		return err
	}
	if err := c.SFTPClient().Chtimes(tempPath, srcStat.ModTime(), srcStat.ModTime()); err != nil {
		return fmt.Errorf("set remote temporary file timestamps failed: %w", err)
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
		return fmt.Errorf("remove remote destination backup failed: %w", err)
	}
	return nil
}

func (c *Client) shouldSkipUpload(remotePath string, srcStat os.FileInfo, progress ProgressCallback) (bool, error) {
	rStat, err := c.SFTPClient().Stat(remotePath)
	if err == nil {
		if rStat.Size() == srcStat.Size() && rStat.ModTime().Unix() == srcStat.ModTime().Unix() {
			if progress != nil {
				progress(srcStat.Size())
			}
			return true, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat remote destination for skip check failed: %w", err)
	}
	return false, nil
}

func (c *Client) prepareUploadFile(tempPath string, size int64, srcFile *os.File) (int64, *sftp.File, error) {
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
	if exists && startOffset > 0 {
		if err := c.validateResumePrefixUpload(dstFile, srcFile, startOffset); err != nil {
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

func (c *Client) DownloadFile(ctx context.Context, remotePath, localPath string, size int64, mode os.FileMode, progress ProgressCallback) (retErr error) {
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		return c.downloadFile(ctx, remotePath, localPath, size, mode, progress)
	})
}

//nolint:gocyclo
func (c *Client) downloadFile(ctx context.Context, remotePath, localPath string, size int64, mode os.FileMode, progress ProgressCallback) (retErr error) {
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
	if srcStat.Size() != size {
		return fmt.Errorf("remote source size changed: expected %d bytes, got %d", size, srcStat.Size())
	}

	// 只有在非强制模式下才检查跳过
	if !c.config.Force {
		if err := ctx.Err(); err != nil {
			return err
		}
		skip, skipErr := c.shouldSkipDownload(localPath, srcStat, progress)
		if skipErr != nil {
			return skipErr
		}
		if skip {
			return nil
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	tempPath := localPath + c.config.TempSuffix
	startOffset, dstFile, err := c.prepareDownloadFile(tempPath, size, mode, srcFile)
	if err != nil {
		return fmt.Errorf("prepare local temporary file failed: %w", err)
	}

	var dstStat os.FileInfo
	if dstFile != nil {
		var statErr error
		dstStat, statErr = dstFile.Stat()
		if statErr != nil {
			return fmt.Errorf("stat local temporary file failed: %w", statErr)
		}
		if err := c.writeDownloadTemporaryFile(ctx, srcFile, dstFile, startOffset, size, mode, progress); err != nil {
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
		if rmErr := os.Remove(finalTempPath); rmErr != nil && !os.IsNotExist(rmErr) {
			retErr = errors.Join(retErr, fmt.Errorf("remove final temporary path failed: %w", rmErr))
		}
	}()

	if dstStat != nil {
		stat, err := os.Stat(finalTempPath)
		if err != nil || !os.SameFile(dstStat, stat) {
			return fmt.Errorf("local temporary file was replaced during finalization")
		}
	} else if err := verifyLocalTemporaryFile(finalTempPath); err != nil {
		return err
	}
	if err := os.Chtimes(finalTempPath, srcStat.ModTime(), srcStat.ModTime()); err != nil {
		return fmt.Errorf("set local temporary file timestamps failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(finalTempPath, localPath); err != nil {
		return fmt.Errorf("rename local temporary file failed: %w", err)
	}
	return nil
}

func (c *Client) writeDownloadTemporaryFile(ctx context.Context, srcFile *sftp.File, dstFile *os.File, startOffset, size int64, mode os.FileMode, progress ProgressCallback) (retErr error) {
	defer func() {
		if dstFile != nil {
			retErr = errors.Join(retErr, closeTransferResource(dstFile, "local temporary file"))
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := dstFile.Chmod(mode); err != nil {
		return fmt.Errorf("set local temporary file mode failed: %w", err)
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

func (c *Client) shouldSkipDownload(localPath string, srcStat os.FileInfo, progress ProgressCallback) (bool, error) {
	lStat, err := os.Stat(localPath)
	if err == nil {
		if lStat.Size() == srcStat.Size() && lStat.ModTime().Unix() == srcStat.ModTime().Unix() {
			if progress != nil {
				progress(srcStat.Size())
			}
			return true, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat local destination for skip check failed: %w", err)
	}
	return false, nil
}

func (c *Client) prepareDownloadFile(tempPath string, size int64, mode os.FileMode, srcFile *sftp.File) (int64, *os.File, error) {
	tempInfo, exists, err := inspectLocalTemporaryFile(tempPath)
	if err != nil {
		return 0, nil, err
	}

	startOffset := int64(0)
	flags := os.O_RDWR | os.O_TRUNC
	perm := os.FileMode(0o600)
	if !exists {
		flags = os.O_RDWR | os.O_CREATE | os.O_EXCL
	} else {
		perm = mode.Perm()
		if c.config.EnableResume && tempInfo.Size() <= size && tempInfo.Size() >= c.config.ResumeMinSize {
			startOffset = tempInfo.Size()
			flags = os.O_RDWR
		}
	}

	dstFile, err := os.OpenFile(tempPath, flags, perm)
	if err != nil {
		return 0, nil, err
	}
	openedInfo, statErr := dstFile.Stat()
	if statErr != nil {
		return 0, nil, errors.Join(
			fmt.Errorf("stat opened local temporary file failed: %w", statErr),
			closeTransferResource(dstFile, "local temporary file after stat failure"),
		)
	}
	if !openedInfo.Mode().IsRegular() || (exists && !os.SameFile(tempInfo, openedInfo)) {
		return 0, nil, errors.Join(
			fmt.Errorf("local temporary path %q changed during open", tempPath),
			closeTransferResource(dstFile, "unsafe local temporary file"),
		)
	}
	if exists && startOffset > 0 {
		if err := c.validateResumePrefixDownload(dstFile, srcFile, startOffset); err != nil {
			if !errors.Is(err, errPrefixMismatch) {
				return 0, nil, errors.Join(fmt.Errorf("validate prefix failed: %w", err), closeTransferResource(dstFile, "local temporary file"))
			}
			startOffset = 0
			if _, err := dstFile.Seek(0, 0); err != nil {
				return 0, nil, errors.Join(fmt.Errorf("seek failed: %w", err), closeTransferResource(dstFile, "local temporary file"))
			}
			if err := dstFile.Truncate(0); err != nil {
				return 0, nil, errors.Join(fmt.Errorf("truncate failed: %w", err), closeTransferResource(dstFile, "local temporary file"))
			}
		}
	}
	return startOffset, dstFile, nil
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
	return c.Do(ctx, func(client *sftp.Client) error {
		return removeRemoteEntry(ctx, client, remotePath)
	})
}

func removeRemoteEntry(ctx context.Context, client *sftp.Client, remotePath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := client.Lstat(remotePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lstat remote entry %q failed: %w", remotePath, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		if err := client.Remove(remotePath); err != nil {
			return fmt.Errorf("remove remote entry %q failed: %w", remotePath, err)
		}
		return nil
	}

	entries, err := client.ReadDir(remotePath)
	if err != nil {
		return fmt.Errorf("read remote directory %q failed: %w", remotePath, err)
	}
	for _, entry := range entries {
		child := client.Join(remotePath, entry.Name())
		if err := removeRemoteEntry(ctx, client, child); err != nil {
			return err
		}
	}
	if err := client.RemoveDirectory(remotePath); err != nil {
		return fmt.Errorf("remove remote directory %q failed: %w", remotePath, err)
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
	if srcStat.IsDir() {
		return c.remoteCopyDirectory(ctx, src, dst)
	}
	return c.remoteCopyFile(ctx, src, dst, srcStat)
}

func (c *Client) remoteCopyDirectory(ctx context.Context, src, dst string) error {
	if err := c.SFTPClient().MkdirAll(dst); err != nil {
		return fmt.Errorf("mkdir remote directory failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := c.SFTPClient().ReadDir(src)
	if err != nil {
		return fmt.Errorf("read remote directory failed: %w", err)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		subSrc := c.JoinPath(src, entry.Name())
		subDst := c.JoinPath(dst, entry.Name())
		// Lstat in remoteCopy preserves symbolic links instead of traversing
		// their targets.
		if err := c.remoteCopy(ctx, subSrc, subDst, nil); err != nil {
			return fmt.Errorf("copy remote entry %q to %q failed: %w", subSrc, subDst, err)
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

func (c *Client) remoteCopyFile(ctx context.Context, src, dst string, srcStat os.FileInfo) (retErr error) {
	srcFile, err := c.SFTPClient().Open(src)
	if err != nil {
		return fmt.Errorf("open remote source file failed: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, closeTransferResource(srcFile, "remote source file"))
	}()

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

	if err := copyExactContext(ctx, dstFile, srcFile, srcStat.Size(), nil); err != nil {
		return fmt.Errorf("copy remote source %q to %q failed: %w", src, dst, err)
	}
	if err := dstFile.Close(); err != nil {
		dstFile = nil
		return fmt.Errorf("close remote temporary destination file failed: %w", err)
	}
	dstFile = nil
	if err := c.verifyRemoteTemporaryFile(tempPath); err != nil {
		return err
	}
	if err := c.SFTPClient().Chmod(tempPath, srcStat.Mode()); err != nil {
		return fmt.Errorf("set remote temporary destination mode failed: %w", err)
	}
	if err := c.SFTPClient().Chtimes(tempPath, srcStat.ModTime(), srcStat.ModTime()); err != nil {
		return fmt.Errorf("set remote temporary destination timestamps failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.replaceRemoteFile(tempPath, dst)
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

func (c *Client) uploadDirectory(ctx context.Context, localDir, remoteDir string, progress ProgressCallback) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// 1. 确保远程根目录存在
	if err := c.SFTPClient().MkdirAll(remoteDir); err != nil {
		return fmt.Errorf("create remote destination directory failed: %w", err)
	}

	// 2. 遍历本地目录收集文件
	transferCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, groupCtx := errgroup.WithContext(transferCtx)
	sem := make(chan struct{}, c.config.ConcurrentFiles)

	err := filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if groupCtx.Err() != nil {
			return groupCtx.Err()
		}

		relPath, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}

		remoteDest := c.JoinPath(remoteDir, filepath.ToSlash(relPath))

		if info.IsDir() {
			return c.SFTPClient().MkdirAll(remoteDest)
		}

		loopPath := path
		loopDest := remoteDest
		loopInfo := info

		select {
		case sem <- struct{}{}:
		case <-groupCtx.Done():
			return groupCtx.Err()
		}
		g.Go(func() error {
			defer func() { <-sem }()
			return c.UploadFile(groupCtx, loopPath, loopDest, loopInfo.Size(), loopInfo.Mode(), progress)
		})

		return nil
	})

	return finishTransferGroup(cancel, g, err)
}

func (c *Client) DownloadDirectory(ctx context.Context, remoteDir, localDir string, progress ProgressCallback) error {
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		return c.downloadDirectory(ctx, remoteDir, localDir, progress)
	})
}

func (c *Client) downloadDirectory(ctx context.Context, remoteDir, localDir string, progress ProgressCallback) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return fmt.Errorf("create local download directory failed: %w", err)
	}

	transferCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, groupCtx := errgroup.WithContext(transferCtx)
	sem := make(chan struct{}, c.config.ConcurrentFiles)

	walker := c.SFTPClient().Walk(remoteDir)
	var traversalErr error
	for walker.Step() {
		if err := walker.Err(); err != nil {
			traversalErr = err
			break
		}
		if groupCtx.Err() != nil {
			traversalErr = groupCtx.Err()
			break
		}

		path := walker.Path()
		info := walker.Stat()

		relPath, err := remoteRelativePath(remoteDir, path)
		if err != nil {
			traversalErr = err
			break
		}

		localDest := filepath.Join(localDir, filepath.FromSlash(relPath))

		if info.IsDir() {
			if err := os.MkdirAll(localDest, info.Mode()|0700); err != nil {
				traversalErr = fmt.Errorf("create local directory %q failed: %w", localDest, err)
				break
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(localDest), 0755); err != nil {
			traversalErr = fmt.Errorf("create local parent directory for %q failed: %w", localDest, err)
			break
		}

		loopPath := path
		loopDest := localDest
		loopInfo := info

		select {
		case sem <- struct{}{}:
		case <-groupCtx.Done():
		}
		if groupCtx.Err() != nil {
			traversalErr = groupCtx.Err()
			break
		}
		g.Go(func() error {
			defer func() { <-sem }()
			return c.DownloadFile(groupCtx, loopPath, loopDest, loopInfo.Size(), loopInfo.Mode(), progress)
		})
	}

	if traversalErr == nil {
		traversalErr = walker.Err()
	}
	return finishTransferGroup(cancel, g, traversalErr)
}

func remoteRelativePath(base, target string) (string, error) {
	base = path.Clean(base)
	target = path.Clean(target)
	if target == base {
		return ".", nil
	}

	prefix := base
	if prefix != "/" {
		prefix += "/"
	}
	if !strings.HasPrefix(target, prefix) {
		return "", fmt.Errorf("remote path %q is outside download root %q", target, base)
	}
	return strings.TrimPrefix(target, prefix), nil
}

func finishTransferGroup(cancel context.CancelFunc, group *errgroup.Group, operationErr error) error {
	if operationErr != nil {
		cancel()
	}
	groupErr := group.Wait()
	cancel()
	return errors.Join(operationErr, groupErr)
}

func (c *Client) validateResumePrefixUpload(dstFile io.ReaderAt, srcFile io.ReaderAt, startOffset int64) error {
	return validatePrefix(dstFile, srcFile, startOffset)
}

func (c *Client) validateResumePrefixDownload(dstFile io.ReaderAt, srcFile io.ReaderAt, startOffset int64) error {
	return validatePrefix(dstFile, srcFile, startOffset)
}

func validatePrefix(dstFile io.ReaderAt, srcFile io.ReaderAt, startOffset int64) error {
	const chunkSize = 32 * 1024
	buf1 := make([]byte, chunkSize)
	buf2 := make([]byte, chunkSize)

	var offset int64
	for offset < startOffset {
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
