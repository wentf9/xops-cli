package sftp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/sftp"
	"golang.org/x/sync/errgroup"
)

// Upload 上传入口：支持文件或目录
func (c *Client) Upload(ctx context.Context, localPath, remotePath string, progress ProgressCallback) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("stat local path failed: %w", err)
	}

	if info.IsDir() {
		return c.UploadDirectory(ctx, localPath, remotePath, progress)
	}

	// 检查远程路径是否是目录
	remoteStat, err := c.sftpClient.Stat(remotePath)
	if err == nil && remoteStat.IsDir() {
		// 如果是目录，拼接文件名
		remotePath = c.JoinPath(remotePath, filepath.Base(localPath))
	}

	return c.UploadFile(ctx, localPath, remotePath, info.Size(), info.Mode(), progress)
}

// Download 下载入口：支持文件或目录
func (c *Client) Download(ctx context.Context, remotePath, localPath string, progress ProgressCallback) error {
	info, err := c.sftpClient.Stat(remotePath)
	if err != nil {
		return fmt.Errorf("stat remote path failed: %w", err)
	}

	if info.IsDir() {
		return c.DownloadDirectory(ctx, remotePath, localPath, progress)
	}

	stat, err := os.Stat(localPath)
	if err == nil && stat.IsDir() {
		localPath = filepath.Join(localPath, info.Name())
	}

	return c.DownloadFile(ctx, remotePath, localPath, info.Size(), info.Mode(), progress)
}

// ================== 单文件多线程分块逻辑 ==================

func (c *Client) UploadFile(ctx context.Context, localPath, remotePath string, size int64, mode os.FileMode, progress ProgressCallback) error {
	srcFile, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	srcStat, err := srcFile.Stat()
	if err != nil {
		return err
	}

	// 只有在非强制模式下才检查跳过
	if !c.config.Force && c.shouldSkipUpload(remotePath, srcStat, progress) {
		return nil
	}

	tempPath := remotePath + c.config.TempSuffix
	startOffset, dstFile, err := c.prepareUploadFile(tempPath, size)
	if err != nil {
		return err
	}

	if dstFile != nil {
		defer func() { _ = dstFile.Close() }()
		_ = c.sftpClient.Chmod(tempPath, mode)

		if progress != nil && startOffset > 0 {
			progress(startOffset)
		}

		if err := c.doUpload(ctx, srcFile, dstFile, startOffset, size, progress); err != nil {
			return err
		}
		_ = dstFile.Close()
	}

	_ = c.sftpClient.Chtimes(tempPath, srcStat.ModTime(), srcStat.ModTime())
	_, _ = c.sftpClient.Stat(remotePath)
	_ = c.sftpClient.Remove(remotePath)
	return c.sftpClient.Rename(tempPath, remotePath)
}

func (c *Client) shouldSkipUpload(remotePath string, srcStat os.FileInfo, progress ProgressCallback) bool {
	if rStat, err := c.sftpClient.Stat(remotePath); err == nil {
		if rStat.Size() == srcStat.Size() && rStat.ModTime().Unix() == srcStat.ModTime().Unix() {
			if progress != nil {
				progress(srcStat.Size())
			}
			return true
		}
	}
	return false
}

func (c *Client) prepareUploadFile(tempPath string, size int64) (int64, *sftp.File, error) {
	var startOffset int64
	var dstFile *sftp.File
	var err error

	if c.config.EnableResume {
		if tStat, err := c.sftpClient.Stat(tempPath); err == nil {
			if tStat.Size() < size {
				startOffset = tStat.Size()
				dstFile, err = c.sftpClient.OpenFile(tempPath, os.O_RDWR)
				if err != nil {
					return 0, nil, err
				}
			} else if tStat.Size() == size {
				startOffset = size
			}
		}
	}

	if dstFile == nil && (startOffset < size || size == 0) {
		dstFile, err = c.sftpClient.Create(tempPath)
		if err != nil {
			return 0, nil, err
		}
	}
	return startOffset, dstFile, nil
}

func (c *Client) doUpload(ctx context.Context, srcFile *os.File, dstFile *sftp.File, startOffset, size int64, progress ProgressCallback) error {
	if (size - startOffset) <= 0 {
		return nil
	}
	if (size-startOffset) < c.config.ChunkSize || c.config.ThreadsPerFile <= 1 {
		if startOffset > 0 {
			if _, err := srcFile.Seek(startOffset, io.SeekStart); err != nil {
				return err
			}
		}
		_, err := io.Copy(dstFile, srcFile)
		return err
	}
	return c.parallelTransfer(ctx, srcFile, dstFile, startOffset, size, progress)
}

func (c *Client) DownloadFile(ctx context.Context, remotePath, localPath string, size int64, mode os.FileMode, progress ProgressCallback) error {
	srcFile, err := c.sftpClient.Open(remotePath)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	srcStat, err := srcFile.Stat()
	if err != nil {
		return err
	}

	// 只有在非强制模式下才检查跳过
	if !c.config.Force && c.shouldSkipDownload(localPath, srcStat, progress) {
		return nil
	}

	tempPath := localPath + c.config.TempSuffix
	startOffset, dstFile, err := c.prepareDownloadFile(tempPath, size, mode)
	if err != nil {
		return err
	}

	if dstFile != nil {
		defer func() { _ = dstFile.Close() }()
		_ = os.Chmod(tempPath, mode)

		if progress != nil && startOffset > 0 {
			progress(startOffset)
		}

		if err := c.doDownload(ctx, srcFile, dstFile, startOffset, size, progress); err != nil {
			return err
		}
		_ = dstFile.Close()
	}

	_ = os.Chtimes(tempPath, srcStat.ModTime(), srcStat.ModTime())
	return os.Rename(tempPath, localPath)
}

func (c *Client) shouldSkipDownload(localPath string, srcStat os.FileInfo, progress ProgressCallback) bool {
	if lStat, err := os.Stat(localPath); err == nil {
		if lStat.Size() == srcStat.Size() && lStat.ModTime().Unix() == srcStat.ModTime().Unix() {
			if progress != nil {
				progress(srcStat.Size())
			}
			return true
		}
	}
	return false
}

func (c *Client) prepareDownloadFile(tempPath string, size int64, mode os.FileMode) (int64, *os.File, error) {
	var startOffset int64
	var dstFile *os.File
	var err error

	if c.config.EnableResume {
		if tStat, err := os.Stat(tempPath); err == nil {
			if tStat.Size() < size {
				startOffset = tStat.Size()
				dstFile, err = os.OpenFile(tempPath, os.O_RDWR, mode)
				if err != nil {
					return 0, nil, err
				}
			} else if tStat.Size() == size {
				startOffset = size
			}
		}
	}

	if dstFile == nil && (startOffset < size || size == 0) {
		dstFile, err = os.Create(tempPath)
		if err != nil {
			return 0, nil, err
		}
	}
	return startOffset, dstFile, nil
}

func (c *Client) doDownload(ctx context.Context, srcFile *sftp.File, dstFile *os.File, startOffset, size int64, progress ProgressCallback) error {
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
		_, err := io.Copy(dstFile, srcFile)
		return err
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
	g, _ := errgroup.WithContext(ctx)
	chunkSize := c.config.ChunkSize
	sem := make(chan struct{}, c.config.ThreadsPerFile)

	for offset := startOffset; offset < totalSize; offset += chunkSize {
		currOffset := offset
		currSize := chunkSize
		if currOffset+currSize > totalSize {
			currSize = totalSize - currOffset
		}

		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			buf := make([]byte, currSize)
			n, err := src.ReadAt(buf, currOffset)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if n <= 0 {
				return nil
			}
			_, err = dst.WriteAt(buf[:n], currOffset)
			if err != nil {
				return err
			}
			if progress != nil {
				progress(int64(n))
			}
			return nil
		})
	}
	return g.Wait()
}

// StreamTransfer 简单的流式传输兜底
func (c *Client) StreamTransfer(r io.Reader, w io.Writer, progress ProgressCallback) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, wErr := w.Write(buf[:n]); wErr != nil {
				return wErr
			}
			if progress != nil {
				progress(int64(n))
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ================== 目录并发逻辑 ==================

func (c *Client) UploadDirectory(ctx context.Context, localDir, remoteDir string, progress ProgressCallback) error {
	// 1. 确保远程根目录存在
	_ = c.sftpClient.MkdirAll(remoteDir)

	// 2. 遍历本地目录收集文件
	g, ctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, c.config.ConcurrentFiles)

	err := filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		relPath, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}

		remoteDest := c.JoinPath(remoteDir, filepath.ToSlash(relPath))

		if info.IsDir() {
			return c.sftpClient.MkdirAll(remoteDest)
		}

		loopPath := path
		loopDest := remoteDest
		loopInfo := info

		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			return c.UploadFile(ctx, loopPath, loopDest, loopInfo.Size(), loopInfo.Mode(), progress)
		})

		return nil
	})

	if err != nil {
		return err
	}

	return g.Wait()
}

func (c *Client) DownloadDirectory(ctx context.Context, remoteDir, localDir string, progress ProgressCallback) error {
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, c.config.ConcurrentFiles)

	walker := c.sftpClient.Walk(remoteDir)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}
		if ctx.Err() != nil {
			break
		}

		path := walker.Path()
		info := walker.Stat()

		relPath, err := filepath.Rel(remoteDir, path)
		if err != nil {
			continue
		}

		localDest := filepath.Join(localDir, relPath)

		if info.IsDir() {
			if err := os.MkdirAll(localDest, info.Mode()|0700); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(localDest), 0755); err != nil {
			return err
		}

		loopPath := path
		loopDest := localDest
		loopInfo := info

		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			return c.DownloadFile(ctx, loopPath, loopDest, loopInfo.Size(), loopInfo.Mode(), progress)
		})
	}

	return g.Wait()
}
