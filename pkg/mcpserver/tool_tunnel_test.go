package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/mcpserver/tunnel"
	"go.uber.org/goleak"
)

func startTunnelEcho(t *testing.T) string {
	t.Helper()
	return startTunnelEchoAt(t, "127.0.0.1:0")
}

func startTunnelEchoAt(t *testing.T, address string) string {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		if address == "[::1]:0" {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer closeTransferTestResource(t, conn)
				stop := context.AfterFunc(ctx, func() { closeTransferTestResource(t, conn) })
				defer stop()
				if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Error(err)
					return
				}
				if _, err := io.Copy(conn, conn); err != nil {
					tunnelFixtureError(t, ctx, err)
				}
			})
		}
	})
	t.Cleanup(func() { cancel(); closeTransferTestResource(t, listener); workers.Wait() })
	return listener.Addr().String()
}

func tunnelTestInput(t *testing.T, target, mode, id string) CreateTunnelInput {
	t.Helper()
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return CreateTunnelInput{RequestID: id, NodeID: "alias", Mode: mode, TargetHost: host, TargetPort: port}
}

func callTunnelTool(t *testing.T, client *mcp.ClientSession, name string, input any) tunnel.Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: input})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("%s: %+v", name, result.Content)
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var output TunnelOutput
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	if output.Tunnel.TunnelID == "" {
		t.Fatalf("missing tunnel: %s", data)
	}
	return output.Tunnel
}

func assertTunnelEcho(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTransferTestResource(t, conn) })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("binary\x00\xff tunnel 文件\n"), 128)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("tunnel corrupted bytes")
	}
	return conn
}

func newTunnelRuntime(t *testing.T, f *tunnelSSHFixture) *Runtime {
	t.Helper()
	r, err := NewRuntime(t.Context(), WithConfigProvider(f.provider))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func waitTunnelState(t *testing.T, r *Runtime, id, state string) tunnel.Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		s, err := r.tunnels.Status(id)
		if err != nil {
			t.Fatal(err)
		}
		if s.State == state {
			return s
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wanted %s, got %+v", state, s)
		}
	}
}

func TestMCPTunnelRoundTripAndConnectionIsolation(t *testing.T) {
	for _, mode := range []string{"local", "remote"} {
		for _, hops := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("%s/%d jumps", mode, hops), func(t *testing.T) {
				t.Cleanup(func() { goleak.VerifyNone(t) })
				f := startTunnelSSHFixture(t, hops)
				target := startTunnelEcho(t)
				r := newTunnelRuntime(t, f)
				client := connectRuntimeTestClient(t, r)
				firstInput := tunnelTestInput(t, target, mode, "first")
				first := callTunnelTool(t, client, "xops_tunnel_create", firstInput)
				if first.State != "running" || strings.HasSuffix(first.ListenAddress, ":0") {
					t.Fatalf("not listening: %+v", first)
				}
				firstConn := assertTunnelEcho(t, first.ListenAddress)
				second := callTunnelTool(t, client, "xops_tunnel_create", tunnelTestInput(t, target, mode, "second"))
				assertTunnelEcho(t, second.ListenAddress)
				retry := callTunnelTool(t, client, "xops_tunnel_create", firstInput)
				if retry.TunnelID != first.TunnelID {
					t.Fatal("retry duplicated listener")
				}
				pooled, err := r.getMCPSFTPClient(t.Context(), "node")
				if err != nil {
					t.Fatal(err)
				}
				defer closeTransferTestResource(t, pooled)
				if _, err := pooled.Cwd(t.Context()); err != nil {
					t.Fatal(err)
				}
				for range 2 {
					stopped := callTunnelTool(t, client, "xops_tunnel_stop", TunnelInput{first.TunnelID})
					if stopped.State != "stopped" {
						t.Fatalf("stop: %+v", stopped)
					}
				}
				if err := firstConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := firstConn.Read(make([]byte, 1)); err == nil {
					t.Fatal("stopped connection still open")
				}
				assertTunnelEcho(t, second.ListenAddress)
				if _, err := pooled.Cwd(t.Context()); err != nil {
					t.Fatal("stopping tunnel broke pooled SFTP:", err)
				}
				command, err := r.connectMCPNode(t.Context(), "node")
				if err != nil {
					t.Fatal(err)
				}
				if text, err := command.Run(t.Context(), "echo test"); err != nil || !strings.Contains(text, "fixture command ok") {
					t.Fatalf("pooled SSH: %q, %v", text, err)
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				if status, err := r.tunnels.Status(second.TunnelID); err != nil || status.State != "stopped" {
					t.Fatalf("runtime cleanup: %+v, %v", status, err)
				}
			})
		}
	}

}

func TestMCPTunnelFailuresAndPendingRemoteCancellation(t *testing.T) {
	t.Run("bind conflict and disconnect", func(t *testing.T) {
		t.Cleanup(func() { goleak.VerifyNone(t) })
		f := startTunnelSSHFixture(t, 1)
		target := startTunnelEcho(t)
		r := newTunnelRuntime(t, f)
		client := connectRuntimeTestClient(t, r)
		input := tunnelTestInput(t, target, "local", "occupied")
		input.ListenPort = input.TargetPort
		failed := callTunnelTool(t, client, "xops_tunnel_create", input)
		if failed.State != "failed" || failed.Error == "" {
			t.Fatalf("bind failure: %+v", failed)
		}
		input.ListenPort, input.RequestID = 0, "disconnect"
		running := callTunnelTool(t, client, "xops_tunnel_create", input)
		f.disconnect(t)
		failed = waitTunnelState(t, r, running.TunnelID, "failed")
		if failed.Error == "" {
			t.Fatal("connection loss not reported")
		}
		listener, err := net.Listen("tcp", running.ListenAddress)
		if err != nil {
			t.Fatal("listener leaked:", err)
		}
		closeTransferTestResource(t, listener)
	})
	t.Run("cancel blocked remote request", func(t *testing.T) {
		t.Cleanup(func() { goleak.VerifyNone(t) })
		f := startTunnelSSHFixture(t, 2)
		f.blockRemote.Store(true)
		r := newTunnelRuntime(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		input := tunnelTestInput(t, startTunnelEcho(t), "remote", "blocked")
		go func() { _, _, err := r.createTunnel(ctx, nil, input); done <- err }()
		select {
		case <-f.remoteSeen:
		case <-time.After(3 * time.Second):
			t.Fatal("remote request not received")
		}
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation hung")
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		states := r.tunnels.List("", "")
		if len(states) != 1 || states[0].State == "running" || states[0].FinishedAt.IsZero() {
			t.Fatalf("pending request survived: %+v", states)
		}
	})
}

// The helper runs the actual StdioTransport in a child process. It receives
// only an ephemeral fixture address; HOME contains the fixture's known_hosts.
func TestMCPStdioTunnelHelper(t *testing.T) {
	if os.Getenv("XOPS_TUNNEL_TEST_HELPER") != "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := Serve(ctx, WithConfigProvider(tunnelFixtureProvider(t, os.Getenv("XOPS_TUNNEL_TEST_ADDRESS"), 0)))
	cancel()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestMCPStdioTunnelProcessRoundTrip(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	f := startTunnelSSHFixture(t, 0)
	target := startTunnelEcho(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMCPStdioTunnelHelper$")
	cmd.Env = append(os.Environ(), "XOPS_TUNNEL_TEST_HELPER=1", "XOPS_TUNNEL_TEST_ADDRESS="+f.address)
	cmd.Stderr = os.Stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "stdio-tunnel-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, session)
	for _, mode := range []string{"local", "remote"} {
		s := callTunnelTool(t, session, "xops_tunnel_create", tunnelTestInput(t, target, mode, mode))
		if s.State != "running" {
			t.Fatalf("stdio create: %+v", s)
		}
		assertTunnelEcho(t, s.ListenAddress)
		stopped := callTunnelTool(t, session, "xops_tunnel_stop", TunnelInput{s.TunnelID})
		if stopped.State != "stopped" {
			t.Fatalf("stdio stop: %+v", stopped)
		}
	}
	remaining := callTunnelTool(t, session, "xops_tunnel_create", tunnelTestInput(t, target, "local", "process-exit"))
	conn := assertTunnelEcho(t, remaining.ListenAddress)
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Success() {
		t.Fatalf("stdio process did not exit cleanly: %v", cmd.ProcessState)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("process exit left tunnel connection open")
	}
}

func TestMCPTunnelApprovalAndAliasPolicy(t *testing.T) {
	for _, protocol := range []string{"2025-11-25", "2026-07-28"} {
		for _, action := range []string{"accept", "decline", "cancel", "unsupported"} {
			t.Run(protocol+"/"+action, func(t *testing.T) {
				f := startTunnelSSHFixture(t, 0)
				cfg := f.provider.Snapshot()
				cfg.Guardrail = &config.GuardrailConfig{Enabled: true, ApprovalThreshold: "dangerous", NodeOverrides: map[string]config.NodeGuardrailCfg{"node": {ApprovalThreshold: "safe"}}}
				f.provider = config.NewProviderWithoutOpenSSH(cfg)
				r := newTunnelRuntime(t, f)
				ct, st := mcp.NewInMemoryTransports()
				if _, err := r.server.Connect(r.ctx, st, nil); err != nil {
					t.Fatal(err)
				}
				var approvals atomic.Int32
				opts := tunnelApprovalOptions(t, action, &approvals)
				client := mcp.NewClient(&mcp.Implementation{Name: "approval-test", Version: "1"}, opts)
				session, err := client.Connect(t.Context(), ct, &mcp.ClientSessionOptions{ProtocolVersion: protocol})
				if err != nil {
					t.Fatal(err)
				}
				defer closeTransferTestResource(t, session)
				input := tunnelTestInput(t, startTunnelEcho(t), "remote", "approval")
				result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_tunnel_create", Arguments: input})
				if err != nil {
					t.Fatal(err)
				}
				if action != "accept" {
					if !result.IsError || len(r.tunnels.List("", "")) != 0 {
						t.Fatal("unapproved tunnel created")
					}
					return
				}
				if result.IsError {
					t.Fatalf("approved creation failed: %+v", result.Content)
				}
				callTunnelTool(t, session, "xops_tunnel_create", input)
				if approvals.Load() != 1 {
					t.Fatalf("retry requested %d approvals", approvals.Load())
				}
				input.TargetPort++
				result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_tunnel_create", Arguments: input})
				if err != nil || !result.IsError {
					t.Fatalf("conflicting retry: %+v, %v", result, err)
				}
				input.Mode, input.RequestID = "local", "alias-policy"
				created := callTunnelTool(t, session, "xops_tunnel_create", input)
				if approvals.Load() != 2 {
					t.Fatal("alias bypassed canonical node approval policy")
				}
				assertTunnelQueryPolicy(t, session, created.TunnelID, &approvals)
			})
		}
	}
}

func tunnelApprovalOptions(t *testing.T, action string, approvals *atomic.Int32) *mcp.ClientOptions {
	t.Helper()
	opts := &mcp.ClientOptions{}
	if action != "unsupported" {
		opts.ElicitationHandler = func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			approvals.Add(1)
			if strings.Contains(req.Params.Message, "Tool:  xops_tunnel_create") && (!strings.Contains(req.Params.Message, "listen=") || !strings.Contains(req.Params.Message, "target=")) {
				t.Error("approval omitted endpoints")
			}
			return &mcp.ElicitResult{Action: action, Content: map[string]any{"approved": action == "accept"}}, nil
		}
	}
	return opts
}

func assertTunnelQueryPolicy(t *testing.T, session *mcp.ClientSession, id string, approvals *atomic.Int32) {
	t.Helper()
	callTunnelTool(t, session, "xops_tunnel_status", TunnelInput{id})
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_tunnel_list", Arguments: ListTunnelsInput{NodeID: "alias"}})
	if err != nil || result.IsError {
		t.Fatalf("query: %+v, %v", result, err)
	}
	if approvals.Load() != 4 {
		t.Fatalf("queries bypassed node policy: approvals = %d, want 4", approvals.Load())
	}
}

func TestMCPTunnelRejectsUnsupportedInput(t *testing.T) {
	r, err := NewRuntime(t.Context(), WithConfigProvider(runtimeTestProvider("node")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	client := connectRuntimeTestClient(t, r)
	for _, input := range []CreateTunnelInput{
		{RequestID: "dynamic", NodeID: "node", Mode: "dynamic", TargetHost: "localhost", TargetPort: 80},
		{RequestID: "bad-node", NodeID: "missing", Mode: "local", TargetHost: "localhost", TargetPort: 80},
		{RequestID: "bad-port", NodeID: "node", Mode: "local", ListenPort: -1, TargetHost: "localhost", TargetPort: 80},
	} {
		result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_tunnel_create", Arguments: input})
		if err != nil || !result.IsError {
			t.Fatalf("invalid input accepted: %+v, %v", result, err)
		}
	}
	if len(r.tunnels.List("", "")) != 0 {
		t.Fatal("invalid input created task")
	}
}

func TestMCPTunnelIPv6AndQueries(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	f := startTunnelSSHFixture(t, 0)
	target := startTunnelEchoAt(t, "[::1]:0")
	r := newTunnelRuntime(t, f)
	client := connectRuntimeTestClient(t, r)
	for _, mode := range []string{"local", "remote"} {
		input := tunnelTestInput(t, target, mode, mode)
		input.ListenHost = "::1"
		created := callTunnelTool(t, client, "xops_tunnel_create", input)
		if created.State != "running" {
			t.Fatalf("IPv6 listener: %+v", created)
		}
		assertTunnelEcho(t, created.ListenAddress)
		status := callTunnelTool(t, client, "xops_tunnel_status", TunnelInput{created.TunnelID})
		if status.ListenAddress != created.ListenAddress || status.ListenScope == status.TargetScope {
			t.Fatalf("query: %+v", status)
		}
	}
	result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_tunnel_list", Arguments: ListTunnelsInput{NodeID: "alias", State: "running"}})
	if err != nil || result.IsError {
		t.Fatalf("list: %+v, %v", result, err)
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var list ListTunnelsOutput
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Tunnels) != 2 {
		t.Fatalf("list: %+v", list)
	}
}
