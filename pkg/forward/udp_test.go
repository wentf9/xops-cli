package forward

import (
	"context"
	"net"
	"testing"
	"time"
)

// startUDPEchoServer starts a UDP echo server and returns its address.
func startUDPEchoServer(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	})

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()

	return conn.LocalAddr().String()
}

func TestUDPForwarder_ForwardsData(t *testing.T) {
	echoAddr := startUDPEchoServer(t)

	// find a free UDP port for the forwarder
	tmp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("pre-alloc udp: %v", err)
	}
	forwardAddr := tmp.LocalAddr().String()
	if err := tmp.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	}

	f := NewUDPForwarder(forwardAddr, echoAddr)
	errCh := make(chan error, 1)
	go func() { errCh <- f.Run(t.Context()) }()

	time.Sleep(30 * time.Millisecond)

	client, err := net.DialTimeout("udp", forwardAddr, time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	}()

	msg := []byte("ping")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, buf[:n])
	}
}

func TestUDPForwarder_SessionReuse(t *testing.T) {
	echoAddr := startUDPEchoServer(t)

	tmp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("pre-alloc udp: %v", err)
	}
	forwardAddr := tmp.LocalAddr().String()
	if err := tmp.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	}

	f := NewUDPForwarder(forwardAddr, echoAddr)
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- f.Run(t.Context()) }()

	time.Sleep(30 * time.Millisecond)

	client, err := net.DialTimeout("udp", forwardAddr, time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	}()

	// send multiple packets — all should reuse the same upstream session
	for i := range 3 {
		msg := []byte("packet")
		if _, err := client.Write(msg); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if string(buf[:n]) != string(msg) {
			t.Fatalf("packet %d: expected %q, got %q", i, msg, buf[:n])
		}
	}

	f.mu.Lock()
	sessionCount := len(f.sessions)
	f.mu.Unlock()
	if sessionCount != 1 {
		t.Fatalf("expected 1 session, got %d", sessionCount)
	}
}

func TestUDPForwarder_CtxCancel(t *testing.T) {
	echoAddr := startUDPEchoServer(t)

	tmp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("pre-alloc udp: %v", err)
	}
	forwardAddr := tmp.LocalAddr().String()
	if err := tmp.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	f := NewUDPForwarder(forwardAddr, echoAddr)
	errCh := make(chan error, 1)
	go func() { errCh <- f.Run(ctx) }()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned non-nil error after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after ctx cancel")
	}
}

func TestUDPForwarder_SessionCleanupOnCancel(t *testing.T) {
	echoAddr := startUDPEchoServer(t)

	tmp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("pre-alloc udp: %v", err)
	}
	forwardAddr := tmp.LocalAddr().String()
	if err := tmp.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := NewUDPForwarder(forwardAddr, echoAddr)
	errCh := make(chan error, 1)
	go func() { errCh <- f.Run(ctx) }()

	time.Sleep(30 * time.Millisecond)

	client, err := net.DialTimeout("udp", forwardAddr, time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	}()

	msg := []byte("ping")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, buf[:n])
	}

	// 此时 session 应该已建立，数量为 1
	f.mu.Lock()
	sessionCountBefore := len(f.sessions)
	f.mu.Unlock()
	if sessionCountBefore != 1 {
		t.Fatalf("expected 1 session before cancel, got %d", sessionCountBefore)
	}

	// 取消 context 并等待 Run 退出
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned non-nil error after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after ctx cancel")
	}

	// Run 在返回前必须等待 relay 完成清理，因此无需额外 sleep。
	f.mu.Lock()
	sessionCountAfter := len(f.sessions)
	f.mu.Unlock()
	if sessionCountAfter != 0 {
		t.Errorf("expected 0 sessions after cancel, got %d", sessionCountAfter)
	}
}
