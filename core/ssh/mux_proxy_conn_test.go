package ssh

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestMuxProxySSHConn_MetadataEnrichment(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	target := TargetContext{
		Host: "example.org",
		Port: 2222,
		User: "deployuser",
	}

	proxyConn := newMuxProxySSHConn(nil, c1, target)

	if proxyConn.User() != "deployuser" {
		t.Fatalf("expected user deployuser, got %q", proxyConn.User())
	}
	if proxyConn.RemoteAddr().String() != "example.org:2222" {
		t.Fatalf("expected remote addr example.org:2222, got %q", proxyConn.RemoteAddr().String())
	}
	if proxyConn.RemoteAddr().Network() != "tcp" {
		t.Fatalf("expected tcp network, got %q", proxyConn.RemoteAddr().Network())
	}
	if proxyConn.RawConn() != c1 {
		t.Fatalf("expected raw conn c1, got %v", proxyConn.RawConn())
	}
	if proxyConn.Target().Host != "example.org" {
		t.Fatalf("expected target host example.org, got %q", proxyConn.Target().Host)
	}

	if err := proxyConn.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
	// Second close should be idempotent
	if err := proxyConn.Close(); err != nil {
		t.Fatalf("second close error: %v", err)
	}
}

func TestValidateTargetCompatibility_ZeroPortNormalization(t *testing.T) {
	cur := ConnectionConfig{
		Address: "10.0.0.1",
		Port:    22,
		User:    "root",
	}
	newCfg := &ClientConfig{
		Address: "10.0.0.1",
		Port:    0,
		User:    "root",
	}
	if err := validateTargetCompatibility(cur, newCfg); err != nil {
		t.Fatalf("expected Port=0 and Port=22 to be compatible, got %v", err)
	}
	curZero := ConnectionConfig{
		Address: "10.0.0.1",
		Port:    0,
		User:    "root",
	}
	newCfg22 := &ClientConfig{
		Address: "10.0.0.1",
		Port:    22,
		User:    "root",
	}
	if err := validateTargetCompatibility(curZero, newCfg22); err != nil {
		t.Fatalf("expected cur.Port=0 and newCfg.Port=22 to be compatible, got %v", err)
	}
	newCfgMismatch := &ClientConfig{
		Address: "10.0.0.1",
		Port:    2222,
		User:    "root",
	}
	if err := validateTargetCompatibility(curZero, newCfgMismatch); !errors.Is(err, ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch for cur.Port=0 vs newCfg.Port=2222, got %v", err)
	}
}

func TestDialControlProxyClient_RespectsEnvironmentPeerUID(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("peer UID verification is only supported on unix platforms")
	}
	if os.Geteuid() == 0 {
		t.Skip("root peer UID is always accepted")
	}

	tmpDir, err := os.MkdirTemp("", "proxy-uid-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	sockPath := filepath.Join(tmpDir, "mux.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen unix failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	wrongUID := strconv.Itoa(os.Geteuid() + 1000)
	env := Environment{LocalUID: wrongUID}
	_, err = DialControlProxyClient(ctx, sockPath, TargetContext{Host: "127.0.0.1", Port: 22, User: "root"}, env, nil, nil)
	if !errors.Is(err, ErrUnauthorizedPeer) {
		t.Fatalf("expected ErrUnauthorizedPeer when Environment.LocalUID mismatches socket owner, got %v", err)
	}
}
