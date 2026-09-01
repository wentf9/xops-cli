package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type mockCloser struct {
	io.Reader
	closedCount atomic.Int32
}

func (m *mockCloser) Close() error {
	m.closedCount.Add(1)
	return nil
}

type mockWriteCloser struct {
	closedCount atomic.Int32
}

func (m *mockWriteCloser) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (m *mockWriteCloser) Close() error {
	m.closedCount.Add(1)
	return nil
}

// TestPipeCommandStdin_CancelIdempotency 验证 stopAndWait 函数幂等性
func TestPipeCommandStdin_CancelIdempotency(t *testing.T) {
	reader := strings.NewReader("hello")
	writer := &mockWriteCloser{}

	stopAndWait, err := pipeCommandStdin(reader, writer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 多次调用 stopAndWait
	if err := stopAndWait(); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
	if err := stopAndWait(); err != nil {
		t.Errorf("expected nil error on second call, got: %v", err)
	}

	if writer.closedCount.Load() != 1 {
		t.Errorf("expected writer to be closed exactly once, got %d", writer.closedCount.Load())
	}
}

// TestRunCommandWithIO_RejectsUncancelableStdin verifies that an arbitrary
// blocking reader cannot start a command and leak a copy goroutine.
func TestRunCommandWithIO_RejectsUncancelableStdin(t *testing.T) {
	c := &Client{cfg: &ClientConfig{SudoMode: SudoModeNone}}
	callerReader := &mockCloser{Reader: strings.NewReader("some stdin")}
	var stdout, stderr bytes.Buffer

	err := c.RunCommandWithIO(context.Background(), "cat", false, callerReader, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "unsupported command stdin type") {
		t.Fatalf("expected unsupported stdin error, got %v", err)
	}
	if callerReader.closedCount.Load() != 0 {
		t.Errorf("expected caller reader Close count to be 0, got %d", callerReader.closedCount.Load())
	}
}

func TestValidateCommandStdin_RejectsTypedNil(t *testing.T) {
	var (
		fileReader    *os.File
		bufferReader  *bytes.Buffer
		bytesReader   *bytes.Reader
		stringsReader *strings.Reader
	)

	for _, stdin := range []io.Reader{fileReader, bufferReader, bytesReader, stringsReader} {
		if err := validateCommandStdin(stdin); err == nil {
			t.Fatalf("validateCommandStdin(%T) returned nil error", stdin)
		}
	}
}

// TestRunCommandWithIO_ConsecutiveCommands 验证连续调用两次命令时，调用方 stdin 依然可读且正常运作
func TestRunCommandWithIO_ConsecutiveCommands(t *testing.T) {
	recordedCh := make(chan mockExecRecord, 10)
	listener, rawClient := startMockSSHCommandServer(t, recordedCh)
	t.Cleanup(func() {
		_ = listener.Close()
		_ = rawClient.Close()
	})

	c := newClient(rawClient, nil, &ClientConfig{SudoMode: SudoModeNone}, nil, "")

	// 第一次命令
	var stdout1, stderr1 bytes.Buffer
	err := c.RunCommandWithIO(context.Background(), "echo 1", false, strings.NewReader("input1"), &stdout1, &stderr1)
	if err != nil {
		t.Fatalf("first command failed: %v", err)
	}
	<-recordedCh

	// 第二次命令
	var stdout2, stderr2 bytes.Buffer
	err = c.RunCommandWithIO(context.Background(), "echo 2", false, strings.NewReader("input2"), &stdout2, &stderr2)
	if err != nil {
		t.Fatalf("second command failed: %v", err)
	}
	rec := <-recordedCh
	if rec.cmd != "bash -c 'echo 2'" {
		t.Errorf("unexpected command: %s", rec.cmd)
	}
}

func handleHangingConn(t *testing.T, c net.Conn, serverConfig *cryptoSSH.ServerConfig, serverWg *sync.WaitGroup) {
	defer serverWg.Done()
	sConn, chans, reqs, sErr := cryptoSSH.NewServerConn(c, serverConfig)
	if sErr != nil {
		_ = c.Close()
		return
	}
	defer func() {
		if err := sConn.Close(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Logf("sConn Close error: %v", err)
		}
	}()

	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		cryptoSSH.DiscardRequests(reqs)
	}()

	for newCh := range chans {
		ch, chReqs, chErr := newCh.Accept()
		if chErr != nil {
			return
		}
		defer func() {
			if err := ch.Close(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				t.Logf("ch Close error: %v", err)
			}
		}()

		serverWg.Add(1)
		go func() {
			defer serverWg.Done()
			for req := range chReqs {
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			}
		}()

		serverWg.Add(1)
		go func() {
			defer serverWg.Done()
			buf := make([]byte, 1024)
			for {
				if _, rErr := ch.Read(buf); rErr != nil {
					return
				}
			}
		}()
	}
}

func startHangingSSHServer(t *testing.T, serverWg *sync.WaitGroup) (net.Listener, *cryptoSSH.Client, net.Conn) {
	t.Helper()
	listener, serverConfig := startKeepAliveTestSSHServer(t)

	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			serverWg.Add(1)
			go handleHangingConn(t, conn, serverConfig, serverWg)
		}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	clientConfig := &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password("test")},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	}
	sshClientConn, chans, reqs, err := cryptoSSH.NewClientConn(clientConn, listener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("NewClientConn failed: %v", err)
	}
	rawClient := cryptoSSH.NewClient(sshClientConn, chans, reqs)
	return listener, rawClient, clientConn
}

// TestRunCommandWithIO_SuCancellation 验证 SudoModeSu 在 context 取消时能够快速返回，不破坏原始 os.File 且没有残留 goroutine
func TestRunCommandWithIO_SuCancellation(t *testing.T) {
	var serverWg sync.WaitGroup
	listener, rawClient, clientConn := startHangingSSHServer(t, &serverWg)

	cli := newClient(rawClient, clientConn, &ClientConfig{SudoMode: SudoModeSu, SuPwd: "pass"}, nil, "test-node")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	var stdout, stderr bytes.Buffer
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		_ = r.Close()
		_ = w.Close()
	}()

	start := time.Now()
	runErr := cli.RunCommandWithIO(ctx, "sleep 10", true, r, &stdout, &stderr)
	elapsed := time.Since(start)

	if runErr == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if !errors.Is(runErr, context.DeadlineExceeded) && !strings.Contains(runErr.Error(), "deadline exceeded") {
		t.Errorf("expected DeadlineExceeded, got: %v", runErr)
	}
	if elapsed > 1*time.Second {
		t.Errorf("expected fast cancellation within 1s, took %v", elapsed)
	}

	// 验证原始 r 并没有被关闭，依然可用
	if _, err := w.Write([]byte("probe")); err != nil {
		t.Fatalf("write to pipe after cancellation failed: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := r.Read(buf); err != nil || string(buf) != "probe" {
		t.Fatalf("read from pipe after cancellation failed: %v, got %q", err, string(buf))
	}

	// 显式关闭测试服务器与连接，确保退出
	_ = rawClient.Close()
	_ = listener.Close()
	_ = clientConn.Close()
	serverWg.Wait()

	goleak.VerifyNone(t, goleak.IgnoreCurrent())
}

// TestRunCommandWithIO_SudoCancellation 验证 SudoModeSudo 在 context 取消时能够快速返回且保留原始 os.File
func TestRunCommandWithIO_SudoCancellation(t *testing.T) {
	var serverWg sync.WaitGroup
	listener, rawClient, clientConn := startHangingSSHServer(t, &serverWg)

	cli := newClient(rawClient, clientConn, &ClientConfig{SudoMode: SudoModeSudo, Password: "pass"}, nil, "test-node")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	var stdout, stderr bytes.Buffer
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		_ = r.Close()
		_ = w.Close()
	}()

	start := time.Now()
	runErr := cli.RunCommandWithIO(ctx, "sleep 10", true, r, &stdout, &stderr)
	elapsed := time.Since(start)

	if runErr == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if !errors.Is(runErr, context.DeadlineExceeded) && !strings.Contains(runErr.Error(), "deadline exceeded") {
		t.Errorf("expected DeadlineExceeded, got: %v", runErr)
	}
	if elapsed > 1*time.Second {
		t.Errorf("expected fast cancellation within 1s, took %v", elapsed)
	}

	// 验证原始 pipe 依然有效
	if _, err := w.Write([]byte("probe")); err != nil {
		t.Fatalf("write to pipe after cancellation failed: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := r.Read(buf); err != nil || string(buf) != "probe" {
		t.Fatalf("read from pipe after cancellation failed: %v, got %q", err, string(buf))
	}

	_ = rawClient.Close()
	_ = listener.Close()
	_ = clientConn.Close()
	serverWg.Wait()

	goleak.VerifyNone(t, goleak.IgnoreCurrent())
}

// TestClient_RunCommandWithInput 验证 RunCommandWithInput 便利方法与参数验证
func TestClient_RunCommandWithInput(t *testing.T) {
	cli := &Client{}
	var stdout, stderr bytes.Buffer

	// 未连接客户端报错
	err := cli.RunCommandWithInput(context.Background(), "echo test", []byte("input"), &stdout, &stderr)
	if err == nil {
		t.Error("expected error for unconfigured client, got nil")
	}
}

type failingWriteCloser struct {
	io.Writer
	closeErr error
}

func (f *failingWriteCloser) Close() error {
	return f.closeErr
}

// TestSetupStdinPipeline_CloseErrorPropagation 验证 setupStdinPipeline 中的关闭错误能够被正确合并并向上传播
func TestSetupStdinPipeline_CloseErrorPropagation(t *testing.T) {
	sentinelCloseErr := errors.New("sentinel pipe close failed")
	fwc := &failingWriteCloser{Writer: &bytes.Buffer{}, closeErr: sentinelCloseErr}
	_, err := setupStdinPipeline(nil, fwc, "")
	if !errors.Is(err, sentinelCloseErr) {
		t.Errorf("expected setup error to wrap %v, got %v", sentinelCloseErr, err)
	}
}
