package mcpruntime_test

import (
	"bufio"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
)

func TestMCPRuntime_StdioTransportLifecycleAndBounds(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newMCPUnitRig(t, mcpUnitOpts{maxMessageBytes: 1024})
	defer rig.close(t)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(c context.Context) error {
			defer func() { _ = outW.Close() }()
			return rig.srv.ServeStdio(c, inR, outW)
		}); err != nil {
			return err
		}
		return n.Go(func(_ context.Context) error {
			defer func() { _ = inW.Close() }()
			driveStdioClientSequence(t, inW, outR)
			return nil
		})
	})
	requireNoErr(t, err, "ServeStdio lifecycle")
}

func driveStdioClientSequence(t *testing.T, inW io.Writer, outR io.Reader) {
	t.Helper()
	scanner := bufio.NewScanner(outR)
	roundTrip := func(line string) protocol.Response {
		if _, err := io.WriteString(inW, line+"\n"); err != nil {
			t.Fatalf("write stdio: %v", err)
		}
		if !scanner.Scan() {
			t.Fatalf("stdio 读取提前结束: err=%v", scanner.Err())
		}
		var r protocol.Response
		requireNoErr(t, jsonv2.Unmarshal(scanner.Bytes(), &r), "unmarshal stdio resp")
		return r
	}

	if r1 := roundTrip(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"stdio-go","version":"1.0"}}}`); r1.Error != nil {
		t.Fatalf("stdio initialize 失败: %+v", r1.Error)
	}
	if _, err := io.WriteString(inW, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"); err != nil {
		t.Fatalf("write notification: %v", err)
	}
	r2 := roundTrip(`{"jsonrpc":"2.0","id":"p2","method":"ping"}`)
	if id2, ok := r2.ID.Get(); r2.Error != nil || !ok || id2.String() != "p2" {
		t.Fatalf("stdio ping 失配: %+v", r2)
	}
	if r3 := roundTrip(`{"jsonrpc":"2.0","id":3,"method":"ping","params":{"pad":"` + strings.Repeat("x", 1500) + `"}}`); r3.Error == nil || r3.Error.Code != protocol.CodeInvalidRequest {
		t.Fatalf("超长消息期望 CodeInvalidRequest(-32600)，实际=%+v", r3.Error)
	}
	if r4 := roundTrip(`{broken-json`); r4.Error == nil || r4.Error.Code != protocol.CodeParseError {
		t.Fatalf("损坏 JSON 期望 CodeParseError(-32700)，实际=%+v", r4.Error)
	}
	if r5 := roundTrip(`{"jsonrpc":"2.0","id":5,"method":"tools/list"}`); r5.Error != nil {
		t.Fatalf("后续 tools/list 失败: %+v", r5.Error)
	}
}

func TestMCPRuntime_StreamableHTTPHardeningAndSessionLifecycle(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newMCPUnitRig(t, mcpUnitOpts{maxMessageBytes: 4096})
	defer rig.close(t)

	if err := rig.srv.ListenAndServeHTTP(context.Background(), "0.0.0.0:0"); !errors.Is(err, mcpruntime.ErrNonLoopbackAddress) {
		t.Fatalf("非回环监听必须返回 ErrNonLoopbackAddress，实际=%v", err)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	requireNoErr(t, err, "Listen 127.0.0.1:0")
	baseURL := "http://" + ln.Addr().String()

	tr := &http.Transport{DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	srvCtx, stopSrv := context.WithCancel(context.Background())
	defer stopSrv()

	runErr := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(_ context.Context) error { return rig.srv.ServeHTTPListener(srvCtx, ln) }); err != nil {
			return err
		}
		return n.Go(func(_ context.Context) error {
			defer func() { _ = rig.srv.Close(context.Background()) }()
			assertHTTPHardeningChecks(t, client, baseURL)
			assertHTTPSessionAndBounds(t, client, baseURL)
			return nil
		})
	})
	requireNoErr(t, runErr, "StreamableHTTP hardening")
}

func assertHTTPHardeningChecks(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	resp, err := client.Get(baseURL + "/healthz")
	requireNoErr(t, err, "GET /healthz")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz 期望 200，实际=%d", resp.StatusCode)
	}
	assertHTTPStatus(t, client, http.MethodPost, baseURL+"/mcp", "evil.example:9999", "", "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, http.StatusForbidden)
	assertHTTPStatus(t, client, http.MethodPost, baseURL+"/mcp", "", "https://evil.example", "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, http.StatusForbidden)
}

func assertHTTPSessionAndBounds(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	initReq, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"http-unit","version":"1.0"}}}`))
	initReq.Header.Set("Content-Type", "application/json")
	initReq.Header.Set("Origin", "http://127.0.0.1")
	initResp, err := client.Do(initReq)
	requireNoErr(t, err, "initialize")
	_ = initResp.Body.Close()
	sid := initResp.Header.Get("Mcp-Session-Id")
	if initResp.StatusCode != http.StatusOK || sid == "" {
		t.Fatalf("HTTP initialize 失败: status=%d sid=%q", initResp.StatusCode, sid)
	}
	assertHTTPStatus(t, client, http.MethodPost, baseURL+"/mcp", "", "", sid, `{"pad":"`+strings.Repeat("A", 4300)+`"}`, http.StatusRequestEntityTooLarge)
	assertHTTPSSEStream(t, client, baseURL, sid)
	assertHTTPStatus(t, client, http.MethodDelete, baseURL+"/mcp", "", "", sid, "", http.StatusNoContent)
}

func assertHTTPSSEStream(t *testing.T, client *http.Client, baseURL, sid string) {
	t.Helper()
	sseCtx, cancelSSE := context.WithCancel(context.Background())
	defer cancelSSE()
	sseReq, err := http.NewRequestWithContext(sseCtx, http.MethodGet, baseURL+"/mcp", nil)
	requireNoErr(t, err, "NewRequest GET SSE")
	sseReq.Header.Set("Mcp-Session-Id", sid)
	sseReq.Header.Set("Accept", "text/event-stream")
	sseResp, err := client.Do(sseReq)
	requireNoErr(t, err, "Do GET /mcp SSE")
	defer func() { _ = sseResp.Body.Close() }()
	if sseResp.StatusCode != http.StatusOK || !strings.HasPrefix(sseResp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("GET /mcp SSE 状态或类型失配: status=%d ct=%q", sseResp.StatusCode, sseResp.Header.Get("Content-Type"))
	}
	line, err := bufio.NewReader(sseResp.Body).ReadString('\n')
	requireNoErr(t, err, "ReadString SSE connected")
	if !strings.HasPrefix(line, ": connected") {
		t.Fatalf("SSE 首帧失配: %q", line)
	}
	cancelSSE()
}

func assertHTTPStatus(t *testing.T, client *http.Client, method, url, host, origin, sid, body string, want int) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	requireNoErr(t, err, "NewRequest")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if host != "" {
		req.Host = host
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := client.Do(req)
	requireNoErr(t, err, "Do "+method+" "+url)
	_ = resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("%s %s 期望 %d，实际=%d", method, url, want, resp.StatusCode)
	}
}
