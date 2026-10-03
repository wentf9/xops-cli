package runtime

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMCPControlClassificationCannotAdmitCalls(t *testing.T) {
	for _, tc := range []struct {
		body  string
		reply bool
	}{
		{`{"jsonrpc":"2.0","id":1,"result":{"action":"accept"}}`, true},
		{`{"jsonrpc":"2.0","id":"approval","error":{"code":-32603,"message":"cancelled"}}`, true},
		{`{"jsonrpc":"2.0","id":1,"result":null}`, true},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","result":{}}`, false},
		{`{"jsonrpc":"2.0","id":1,"method":null,"result":{}}`, false},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`, true},
		{`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"request","reason":"stop"}}`, true},
		{`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":null}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":true}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1.5}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":{},"reason":"stop"}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":3}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":null}}`, false},
		{`{"jsonrpc":"2.0","id":2,"method":"notifications/cancelled","params":{"requestId":1}}`, false},
		{`{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled","params":{"requestId":1}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/cancelled","result":null,"params":{"requestId":1}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, true},
		{`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`, true},
		{`{"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":{"client":"test"}}}`, true},
		{`{"jsonrpc":"2.0","method":"notifications/initialized","params":{"requestId":1}}`, true},
		{`{"jsonrpc":"2.0","method":"notifications/initialized","params":null}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/initialized","params":[]}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/initialized","params":"invalid"}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/initialized","params":1}`, false},
		{`{"jsonrpc":"2.0","id":1,"method":"notifications/initialized"}`, false},
		{`{"jsonrpc":"2.0","id":null,"method":"notifications/initialized"}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/initialized","result":{}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/initialized","error":{"code":-32603}}`, false},
		{`{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`, false},
		{`[{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":1,"method":"tools/call"}]`, false},
		{`[{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}]`, false},
		{`[{"jsonrpc":"2.0","id":1,"result":{}},{"jsonrpc":"2.0","id":2,"method":"tools/call"}]`, false},
		{`{"jsonrpc":"2.0","id":null,"result":{}}`, false},
		{`{"jsonrpc":"2.0","id":true,"result":{}}`, false},
		{`{"jsonrpc":"2.0","id":1,"result":{},"error":{}}`, false},
		{`{"jsonrpc":"2.0","id":1,"result":{}} trailing`, false},
	} {
		if got := isMCPControl([]byte(tc.body)); got != tc.reply {
			t.Errorf("reply=%t for %s", got, tc.body)
		}
	}
}

func TestControlAdmissionIsSeparateAndBounded(t *testing.T) {
	const request = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`
	const reply = `{"jsonrpc":"2.0","id":2,"result":{"action":"accept"}}`
	const cancellation = `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`
	const initialized = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	r := Runtime{http: &HTTPOptions{MaxRequests: 1}}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	release := make(chan struct{})
	releaseAll := sync.OnceFunc(func() { close(release) })
	entered := make(chan string, 2)
	var workers sync.WaitGroup
	defer func() { releaseAll(); workers.Wait() }()
	handler := r.protocolAdmission(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error(err)
			return
		}
		defer closeTransferTestResource(t, req.Body)
		entered <- string(body)
		select {
		case <-release:
		case <-req.Context().Done():
		}
		w.WriteHeader(http.StatusAccepted)
	}), make(chan struct{}, 1))
	occupy := func(body string) {
		workers.Go(func() {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(body)))
		})
		select {
		case got := <-entered:
			if got != body {
				t.Errorf("admission changed body: %s", got)
			}
		case <-ctx.Done():
			t.Fatal("reserved reply was blocked by ordinary requests")
		}
	}
	occupy(request)
	occupy(reply)
	for _, body := range []string{request, reply, cancellation, initialized} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(body)))
		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("unbounded admission: %d", response.Code)
		}
	}
	releaseAll()
	workers.Wait()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(cancellation)))
	if response.Code != http.StatusAccepted {
		t.Fatalf("reply capacity leaked: %d", response.Code)
	}
}

func TestMCPBodyClassificationHasBoundedAdmissionAndSize(t *testing.T) {
	parsers := make(chan struct{}, 1)
	parsers <- struct{}{}
	response := httptest.NewRecorder()
	_, ok := classifyMCPBody(response, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(`{}`)), parsers)
	if ok || response.Code != http.StatusTooManyRequests {
		t.Fatal("body parsing bypassed capacity")
	}
	<-parsers
	response = httptest.NewRecorder()
	_, ok = classifyMCPBody(response, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(strings.Repeat(" ", maxMCPBodyBytes+1))), parsers)
	if ok || response.Code != http.StatusRequestEntityTooLarge || len(parsers) != 0 {
		t.Fatalf("body bound or release: %d slots=%d", response.Code, len(parsers))
	}
}
