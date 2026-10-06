package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
)

func captureSSHTunnelErrors(t *testing.T) <-chan string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStderr := os.Stderr
	os.Stderr = writer
	ctx, cancel := context.WithCancel(t.Context())
	lines := make(chan string)
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		os.Stderr = originalStderr
		closeTunnelTestResource(t, writer)
		<-done
	})
	go func() {
		defer close(done)
		defer close(lines)
		defer closeTunnelTestResource(t, reader)
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil {
			t.Errorf("read tunnel diagnostics: %v", err)
		}
	}()
	return lines
}

func requestRejectedTunnelConnection(t *testing.T, addr string, socks bool) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTunnelTestResource(t, conn)
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if socks {
		// No-auth greeting followed by CONNECT to 127.0.0.1:20173.
		if _, err := conn.Write([]byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0x4e, 0xcd}); err != nil {
			t.Fatal(err)
		}
		var reply [12]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			t.Fatal(err)
		}
		if want := []byte{5, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0}; !bytes.Equal(reply[:], want) {
			t.Fatalf("SOCKS5 reply = %v, want %v", reply, want)
		}
	}
	var data [1]byte
	if n, err := conn.Read(data[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("rejected connection read = (%d, %v), want EOF", n, err)
	}
}

func TestSSHTunnelsReportRejectedConnections(t *testing.T) {
	for _, mode := range []string{"local", "SOCKS5"} {
		for _, logLevel := range []string{"", "none", "error", "warn"} {
			name := logLevel
			if name == "" {
				name = "default"
			}
			t.Run(mode+"/"+name, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home)
				client, _ := newTunnelTestClient(t)
				originalLevel := logger.LogLevel.Level()
				logger.SetLogLevel(logLevel)
				t.Cleanup(func() { logger.LogLevel.Set(originalLevel) })
				diagnostics := captureSSHTunnelErrors(t)

				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr := listener.Addr().String()
				closeTunnelTestResource(t, listener)
				options := &SshOptions{NoCmd: true}
				if mode == "local" {
					options.LocalForwards = []string{addr + ":127.0.0.1:20173"}
				} else {
					options.DynamicForward = addr
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				group, err := options.startTunnels(ctx, cancel, client)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := group.Close(); err != nil {
						t.Errorf("close rejected tunnels: %v", err)
					}
				})

				// Each rejected channel must be reported while the listener and
				// SSH connection remain available for the next connection.
				for range 2 {
					requestRejectedTunnelConnection(t, addr, mode == "SOCKS5")
					select {
					case line := <-diagnostics:
						for _, want := range []string{
							"ssh " + mode + " forward connection failed:",
							"127.0.0.1:20173",
							"administratively prohibited",
							"test destination unavailable",
						} {
							if !strings.Contains(line, want) {
								t.Errorf("stderr = %q, want %q", line, want)
							}
						}
					case <-time.After(time.Second):
						t.Fatal("server rejected forwarding but no diagnostic reached stderr")
					}
					if ctx.Err() != nil {
						t.Fatalf("channel rejection stopped the SSH session: %v", ctx.Err())
					}
				}
			})
		}
	}
}

func TestSSHTunnelsReturnRemoteForwardRejection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	client, _ := newTunnelTestClient(t)
	options := &SshOptions{NoCmd: true, RemoteForwards: []string{"0:127.0.0.1:20173"}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	group, err := options.startTunnels(ctx, cancel, client)
	defer func() {
		if err := group.Close(); err != nil {
			t.Errorf("close remote tunnel: %v", err)
		}
	}()
	if err == nil || !strings.Contains(err.Error(), "setup remote forward failed:") ||
		!strings.Contains(err.Error(), "request denied by peer") {
		t.Fatalf("startTunnels error = %v, want remote forward rejection", err)
	}
}
