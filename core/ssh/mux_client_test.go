package ssh

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func createTestUnixSocket(t *testing.T) (string, net.Listener) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "mux-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	sockPath := filepath.Join(tmpDir, "test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("Listen unix failed: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.RemoveAll(tmpDir)
	})
	return sockPath, ln
}

func TestMuxClient_Handshake(t *testing.T) {
	sockPath, ln := createTestUnixSocket(t)

	// Server goroutine
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Read HELLO from client
		pktType, payload, err := ReadMuxPacket(conn)
		if err != nil || pktType != MUX_MSG_HELLO {
			return
		}
		ver, _, _ := DecodeMuxHello(payload)
		if ver != MuxProtoVersion {
			return
		}

		// Send HELLO response with extension
		exts := []MuxExtension{{Name: "test-ext", Value: "active"}}
		_ = WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, exts))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	if client.serverVer != MuxProtoVersion {
		t.Fatalf("expected server version %d, got %d", MuxProtoVersion, client.serverVer)
	}
	if client.extensions["test-ext"] != "active" {
		t.Fatalf("expected extension test-ext=active, got %v", client.extensions)
	}
}

func TestMuxClient_Handshake_VersionMismatch(t *testing.T) {
	sockPath, ln := createTestUnixSocket(t)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		_, _, _ = ReadMuxPacket(conn)
		// Reply with incompatible version 3
		_ = WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(3, nil))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := DialMuxClient(ctx, sockPath)
	if err == nil {
		t.Fatal("expected version mismatch error, got nil")
	}
}

func TestMuxClient_AliveCheck(t *testing.T) {
	sockPath, ln := createTestUnixSocket(t)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Handshake
		_, _, _ = ReadMuxPacket(conn)
		_ = WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil))

		// Alive check
		pktType, payload, err := ReadMuxPacket(conn)
		if err != nil || pktType != MUX_C_ALIVE_CHECK {
			return
		}
		reqID, _ := DecodeMuxRequestID(payload)
		_ = WriteMuxPacket(conn, MUX_S_ALIVE, EncodeMuxAlive(reqID, 8888))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	pid, err := client.AliveCheck(ctx)
	if err != nil {
		t.Fatalf("AliveCheck failed: %v", err)
	}
	if pid != 8888 {
		t.Fatalf("expected pid 8888, got %d", pid)
	}
}

func TestMuxClient_Terminate_StopListening(t *testing.T) {
	sockPath, ln := createTestUnixSocket(t)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Handshake
		_, _, _ = ReadMuxPacket(conn)
		_ = WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil))

		// 1. Terminate
		pktType, payload, _ := ReadMuxPacket(conn)
		if pktType == MUX_C_TERMINATE {
			reqID, _ := DecodeMuxRequestID(payload)
			_ = WriteMuxPacket(conn, MUX_S_OK, EncodeMuxClientRequestID(reqID))
		}

		// 2. Stop Listening
		pktType, payload, _ = ReadMuxPacket(conn)
		if pktType == MUX_C_STOP_LISTENING {
			reqID, _ := DecodeMuxRequestID(payload)
			_ = WriteMuxPacket(conn, MUX_S_OK, EncodeMuxClientRequestID(reqID))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Terminate(ctx); err != nil {
		t.Fatalf("Terminate failed: %v", err)
	}
	if err := client.StopListening(ctx); err != nil {
		t.Fatalf("StopListening failed: %v", err)
	}
}

func TestMuxClient_Forwarding(t *testing.T) {
	sockPath, ln := createTestUnixSocket(t)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Handshake
		_, _, _ = ReadMuxPacket(conn)
		_ = WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil))

		// Open Forward
		pktType, payload, _ := ReadMuxPacket(conn)
		if pktType == MUX_C_OPEN_FWD {
			req, _ := DecodeMuxFwdRequest(payload)
			_ = WriteMuxPacket(conn, MUX_S_REMOTE_PORT, EncodeMuxRemotePort(req.RequestID, 54321))
		}

		// Close Forward
		pktType, payload, _ = ReadMuxPacket(conn)
		if pktType == MUX_C_CLOSE_FWD {
			req, _ := DecodeMuxFwdRequest(payload)
			_ = WriteMuxPacket(conn, MUX_S_OK, EncodeMuxClientRequestID(req.RequestID))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	fwdReq := ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "0.0.0.0",
		ListenPort:  0,
		ConnectHost: "127.0.0.1",
		ConnectPort: 8080,
	}

	allocPort, err := client.OpenForward(ctx, fwdReq)
	if err != nil {
		t.Fatalf("OpenForward failed: %v", err)
	}
	if allocPort != 54321 {
		t.Fatalf("expected allocated port 54321, got %d", allocPort)
	}

	if err := client.CloseForward(ctx, fwdReq); err != nil {
		t.Fatalf("CloseForward failed: %v", err)
	}
}

func TestMuxClient_StaleSocketDetection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mux-stale-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	sockPath := filepath.Join(tmpDir, "stale.sock")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("syscall.Socket failed: %v", err)
	}
	sa := &syscall.SockaddrUnix{Name: sockPath}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("syscall.Bind failed: %v", err)
	}
	// Close fd without unlinking the path -> creates real dead/stale socket file!
	_ = syscall.Close(fd)

	if !socketPathExists(sockPath) {
		t.Fatalf("expected socket file %q to exist on disk", sockPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err = DialMuxClient(ctx, sockPath)
	if err == nil {
		t.Fatal("expected dial error on closed socket, got nil")
	}
	if !isConnectionRefused(err) {
		t.Fatalf("expected isConnectionRefused=true for err: %v", err)
	}
}

func TestMuxClient_RequestInfo(t *testing.T) {
	sockPath, ln := createTestUnixSocket(t)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Handshake
		pktType, _, _ := ReadMuxPacket(conn)
		if pktType != MUX_MSG_HELLO {
			return
		}
		exts := []MuxExtension{{Name: "info", Value: "1"}}
		_ = WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, exts))

		// Request
		pktType, payload, err := ReadMuxPacket(conn)
		if err != nil || pktType != MUX_C_EXT_INFO {
			return
		}
		reqID, name, err := DecodeMuxExtInfo(payload)
		if err != nil {
			return
		}

		if name == "connection" {
			_ = WriteMuxPacket(conn, MUX_S_EXT_INFO, EncodeMuxExtInfoResponse(reqID, 1, "test connection info"))
		} else {
			_ = WriteMuxPacket(conn, MUX_S_FAILURE, EncodeMuxError(reqID, "unsupported info type"))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	if !client.HasExtension("info") {
		t.Fatal("expected client to have info extension")
	}

	info, err := client.RequestInfo(ctx, "connection")
	if err != nil {
		t.Fatalf("RequestInfo failed: %v", err)
	}
	if info != "test connection info" {
		t.Fatalf("expected 'test connection info', got %q", info)
	}
}
