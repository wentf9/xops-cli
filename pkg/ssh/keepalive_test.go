package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startKeepAliveTestSSHServer 启动一个最小化 mock SSH 服务端 listener
func startKeepAliveTestSSHServer(t *testing.T) (net.Listener, *ssh.ServerConfig) {
	t.Helper()
	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	sshConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start ssh listener: %v", err)
	}
	return listener, sshConfig
}

// dialKeepAliveTestClient 建立 SSH 客户端连接
func dialKeepAliveTestClient(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	clientConfig := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("test")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		t.Fatalf("failed to dial ssh server: %v", err)
	}
	return client
}

// TestProbeWithTimeout_Success 验证正常连接上心跳探测在超时前返回 nil
func TestProbeWithTimeout_Success(t *testing.T) {
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		sConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			_ = conn.Close()
			return
		}
		defer func() { _ = sConn.Close() }()
		go ssh.DiscardRequests(reqs)
		for range chans {
			// 不接受任何 channel，仅维持连接
		}
	}()

	client := dialKeepAliveTestClient(t, listener.Addr().String())
	defer func() { _ = client.Close() }()

	err := probeWithTimeout(context.Background(), client, 2*time.Second)
	if err != nil {
		t.Errorf("expected nil error on healthy connection, got %v", err)
	}
}

// TestProbeWithTimeout_Timeout 验证服务端停止响应全局请求（网络黑洞）时
// 心跳探测按超时报错，且错误可用 errors.Is(errKeepaliveTimeout) 识别
func TestProbeWithTimeout_Timeout(t *testing.T) {
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	defer func() { _ = listener.Close() }()

	// hang 挂起 goroutine，测试结束时关闭以放行 defer
	hang := make(chan struct{})
	defer close(hang)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		sConn, _, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			_ = conn.Close()
			return
		}
		defer func() { _ = sConn.Close() }()
		// 故意不消费 reqs：客户端的 keepalive (WantReply) 请求永远得不到响应，
		// 模拟网络黑洞场景
		<-hang
		for range reqs {
		}
	}()

	client := dialKeepAliveTestClient(t, listener.Addr().String())
	defer func() { _ = client.Close() }()

	err := probeWithTimeout(context.Background(), client, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error on unresponsive connection, got nil")
	}
	if !errors.Is(err, errKeepaliveTimeout) {
		t.Errorf("expected error wrapping errKeepaliveTimeout, got %v", err)
	}
}

// TestStartKeepAlive_ClosesClientOnFailure 验证心跳失败时 StartKeepAlive 关闭连接并回调 fallback
func TestStartKeepAlive_ClosesClientOnFailure(t *testing.T) {
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	defer func() { _ = listener.Close() }()

	serverClosed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		sConn, _, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			_ = conn.Close()
			return
		}
		go ssh.DiscardRequests(reqs)
		// 握手完成即关闭服务端连接，模拟服务端断开
		_ = sConn.Close()
		close(serverClosed)
	}()

	client := dialKeepAliveTestClient(t, listener.Addr().String())
	<-serverClosed

	fallbackCalled := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	StartKeepAlive(ctx, client, 50*time.Millisecond, 2*time.Second, func(err error) {
		fallbackCalled <- err
	})

	select {
	case err := <-fallbackCalled:
		if err == nil {
			t.Error("expected non-nil error passed to fallback")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fallback not called within 5s after connection dropped")
	}

	// 心跳失败后 client 应已被显式关闭，底层连接不可再用
	_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
	if err == nil {
		t.Error("expected SendRequest to fail after keepalive closed the client")
	}
}

// TestStartKeepAlive_ContextCancel 验证 ctx 取消后心跳协程退出且不触发 fallback
func TestStartKeepAlive_ContextCancel(t *testing.T) {
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	defer func() { _ = listener.Close() }()

	requestSeen := make(chan struct{})
	releaseServer := make(chan struct{})
	defer close(releaseServer)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		sConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			_ = conn.Close()
			return
		}
		defer func() { _ = sConn.Close() }()
		go func() {
			for req := range reqs {
				close(requestSeen)
				<-releaseServer
				_ = req.Reply(true, nil)
				return
			}
		}()
		for range chans {
		}
	}()

	client := dialKeepAliveTestClient(t, listener.Addr().String())
	defer func() { _ = client.Close() }()

	fallbackCalled := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())

	done := StartKeepAlive(ctx, client, 10*time.Millisecond, 2*time.Second, func(err error) {
		fallbackCalled <- err
	})

	select {
	case <-requestSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("keepalive request was not observed by server")
	}

	// 在 SendRequest 阻塞期间取消，必须关闭连接、退出 goroutine，且不触发失败回调。
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("keepalive goroutine did not exit after context cancellation")
	}
	select {
	case callbackErr := <-fallbackCalled:
		t.Errorf("fallback should not be called after ctx cancel, got %v", callbackErr)
	default:
	}
}

func TestStartKeepAlive_DefaultsInvalidDurations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &ssh.Client{}
	done := StartKeepAlive(ctx, client, 0, -time.Second, nil)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("keepalive goroutine did not exit with normalized durations")
	}
}
