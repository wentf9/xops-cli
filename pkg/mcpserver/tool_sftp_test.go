package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

type mockFailingCloser struct {
	err error
}

func (m mockFailingCloser) Close() error {
	return m.err
}

type mockRemoteFileInfo struct {
	size int64
}

func (m mockRemoteFileInfo) Name() string       { return "test.txt" }
func (m mockRemoteFileInfo) Size() int64        { return m.size }
func (m mockRemoteFileInfo) Mode() os.FileMode  { return 0644 }
func (m mockRemoteFileInfo) ModTime() time.Time { return time.Now() }
func (m mockRemoteFileInfo) IsDir() bool        { return false }
func (m mockRemoteFileInfo) Sys() any           { return nil }

type mockRemoteFile struct {
	*bytes.Reader
	closeErr error
	closed   bool
}

func (m *mockRemoteFile) Stat() (os.FileInfo, error) {
	return mockRemoteFileInfo{size: m.Size()}, nil
}

func (m *mockRemoteFile) Close() error {
	m.closed = true
	return m.closeErr
}

// TestMCP_ReadOpenedRemoteFile_CloseError 验证当 remoteFile 的 Close() 发生错误时，readOpenedRemoteFile 能够将其向上传播
func TestMCP_ReadOpenedRemoteFile_CloseError(t *testing.T) {
	expectedCloseErr := errors.New("underlying sftp stream close reset")
	file := &mockRemoteFile{
		Reader:   bytes.NewReader([]byte("file content payload")),
		closeErr: expectedCloseErr,
	}

	_, err := readOpenedRemoteFile(file, ReadFileInput{Path: "/test.txt", Limit: 100})
	if err == nil {
		t.Fatal("expected close error from readOpenedRemoteFile, got nil")
	}
	if !errors.Is(err, expectedCloseErr) {
		t.Errorf("expected error %v, got %v", expectedCloseErr, err)
	}
	if !file.closed {
		t.Error("expected Close() to have been called")
	}
}

// TestMCP_ReadOpenedRemoteFile_Success 验证正常的读取行为与内容解析
func TestMCP_ReadOpenedRemoteFile_Success(t *testing.T) {
	content := "hello world mcp test"
	file := &mockRemoteFile{
		Reader: bytes.NewReader([]byte(content)),
	}

	out, err := readOpenedRemoteFile(file, ReadFileInput{Path: "/test.txt", Limit: 100})
	if err != nil {
		t.Fatalf("unexpected error from readOpenedRemoteFile: %v", err)
	}
	if out.Content != content {
		t.Errorf("expected content %q, got %q", content, out.Content)
	}
	if out.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), out.Size)
	}
	if !out.EOF {
		t.Error("expected EOF to be true")
	}
	if !file.closed {
		t.Error("expected Close() to be called on success")
	}
}

type singleByteRemoteFile struct {
	data     []byte
	pos      int
	closed   bool
	closeErr error
}

func (s *singleByteRemoteFile) Read(p []byte) (n int, err error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = s.data[s.pos]
	s.pos++
	return 1, nil
}

func (s *singleByteRemoteFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		s.pos = int(offset)
	case io.SeekCurrent:
		s.pos += int(offset)
	}
	return int64(s.pos), nil
}

func (s *singleByteRemoteFile) Stat() (os.FileInfo, error) {
	return mockRemoteFileInfo{size: int64(len(s.data))}, nil
}

func (s *singleByteRemoteFile) Close() error {
	s.closed = true
	return s.closeErr
}

// TestMCP_ReadOpenedRemoteFile_SingleByteShortRead 验证每次只返回 1 字节的短读情况下不会误判为 EOF
func TestMCP_ReadOpenedRemoteFile_SingleByteShortRead(t *testing.T) {
	data := []byte("0123456789") // 10 字节
	file := &singleByteRemoteFile{data: data}

	// 第一次读取 5 字节（应读满 5 字节且 EOF 为 false）
	out1, err := readOpenedRemoteFile(file, ReadFileInput{Path: "/f", Limit: 5, Offset: 0})
	if err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	if out1.Content != "01234" {
		t.Errorf("expected content '01234', got %q", out1.Content)
	}
	if out1.EOF {
		t.Error("expected EOF to be false for partial read")
	}

	// 第二次读取剩余 5 字节（limit 为 10，实际读到 5 字节且触达 EOF）
	file2 := &singleByteRemoteFile{data: data}
	out2, err := readOpenedRemoteFile(file2, ReadFileInput{Path: "/f", Limit: 10, Offset: 5})
	if err != nil {
		t.Fatalf("second read failed: %v", err)
	}
	if out2.Content != "56789" {
		t.Errorf("expected content '56789', got %q", out2.Content)
	}
	if !out2.EOF {
		t.Error("expected EOF to be true when reaching end of file")
	}
}

// TestMCP_ReadOpenedRemoteFile_NegativeOffsetAndLimit 验证负数 Offset 与 Limit 被明确拒绝
func TestMCP_ReadOpenedRemoteFile_NegativeOffsetAndLimit(t *testing.T) {
	file := &mockRemoteFile{Reader: bytes.NewReader([]byte("test"))}
	_, err := readOpenedRemoteFile(file, ReadFileInput{Offset: -1, Limit: 10})
	if err == nil || !strings.Contains(err.Error(), "offset cannot be negative") {
		t.Errorf("expected negative offset error, got %v", err)
	}

	file2 := &mockRemoteFile{Reader: bytes.NewReader([]byte("test"))}
	_, err = readOpenedRemoteFile(file2, ReadFileInput{Offset: 0, Limit: -5})
	if err == nil || !strings.Contains(err.Error(), "limit cannot be negative") {
		t.Errorf("expected negative limit error, got %v", err)
	}
}

// TestMCP_ReadOpenedRemoteFile_OffsetBeyondSize 验证 Offset 超过文件大小时正确返回空内容和 EOF
func TestMCP_ReadOpenedRemoteFile_OffsetBeyondSize(t *testing.T) {
	file := &mockRemoteFile{Reader: bytes.NewReader([]byte("short"))}
	out, err := readOpenedRemoteFile(file, ReadFileInput{Offset: 100, Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Content != "" {
		t.Errorf("expected empty content, got %q", out.Content)
	}
	if !out.EOF {
		t.Error("expected EOF to be true when offset exceeds size")
	}
}

// TestMCP_JoinCloseError_Propagation 验证 joinCloseError 正确将关闭错误合并入 handler 命名返回错误
func TestMCP_JoinCloseError_Propagation(t *testing.T) {
	var handlerErr error
	simulatedCloseErr := errors.New("sftp connection reset on close")

	joinCloseError(&handlerErr, mockFailingCloser{err: simulatedCloseErr}, "sftp client")

	if handlerErr == nil {
		t.Fatal("expected handlerErr to be populated with close error")
	}
	if !strings.Contains(handlerErr.Error(), "sftp connection reset on close") {
		t.Errorf("expected handlerErr to contain %q, got: %v", "sftp connection reset on close", handlerErr)
	}
}

// TestMCP_ReadHandler_RequiredFields 验证 readFileHandler 对缺失必需字段的处理
func TestMCP_ReadHandler_RequiredFields(t *testing.T) {
	ctx := context.Background()

	// 缺少 nodeID 和 path 应该返回错误
	_, _, err := readFileHandler(ctx, nil, ReadFileInput{})
	if err == nil {
		t.Error("expected error for empty nodeID and path")
	}

	// 缺少 nodeID
	_, _, err = readFileHandler(ctx, nil, ReadFileInput{Path: "/foo"})
	if err == nil {
		t.Error("expected error for empty nodeID")
	}

	// 缺少 path
	_, _, err = readFileHandler(ctx, nil, ReadFileInput{NodeID: "node1"})
	if err == nil {
		t.Error("expected error for empty path")
	}
}

// TestMCP_WriteHandler_RequiredFields 验证 writeFileHandler 对缺失必需字段的处理
func TestMCP_WriteHandler_RequiredFields(t *testing.T) {
	ctx := context.Background()

	// 全部为空
	_, _, err := writeFileHandler(ctx, nil, WriteFileInput{})
	if err == nil {
		t.Error("expected error for all-empty WriteFileInput")
	}

	// 缺 content
	_, _, err = writeFileHandler(ctx, nil, WriteFileInput{NodeID: "n", Path: "/p"})
	if err == nil {
		t.Error("expected error for empty content")
	}
}
