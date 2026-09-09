package credentialhelper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	mode := os.Getenv("HELPER_TEST_MODE")

	// 验证 argv 中绝对不包含敏感密码字符串
	for _, arg := range os.Args {
		if strings.Contains(strings.ToLower(arg), "supersecret") {
			_, _ = fmt.Fprintf(os.Stderr, "SECURITY VIOLATION: secret leaked into argv: %s\n", arg)
			os.Exit(99)
		}
	}

	switch mode {
	case "non_interactive":
		var req Request
		if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil || !req.NonInteractive {
			os.Exit(98)
		}
		fmt.Println(`{"code":"locked"}`)
		os.Exit(1)
	case "echo":
		handleEchoHelper(os.Args[len(os.Args)-1])
	case "storage_file":
		handleStorageFileHelper(os.Args[len(os.Args)-1])
	case "error_code":
		code := os.Getenv("HELPER_ERROR_CODE")
		resp := Response{
			Code:    code,
			Message: "injected error details",
		}
		_ = json.NewEncoder(os.Stdout).Encode(resp)
		os.Exit(1)
	case "crash":
		_, _ = fmt.Fprintf(os.Stderr, "critical helper crash occurred")
		os.Exit(2)
	case "hang":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	case "huge_output":
		_, _ = os.Stdout.WriteString(`{"secret":"` + strings.Repeat("B", MaxResponseBytes+100) + `"}`)
		os.Exit(0)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown HELPER_TEST_MODE: %s\n", mode)
		os.Exit(1)
	}
}

func handleEchoHelper(action string) {
	var req Request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "decode stdin error: %v\n", err)
		os.Exit(1)
	}
	switch action {
	case "get":
		resp := Response{Secret: req.Secret}
		if resp.Secret == "" {
			resp.Secret = base64.StdEncoding.EncodeToString([]byte("echo-value"))
		}
		_ = json.NewEncoder(os.Stdout).Encode(resp)
		os.Exit(0)
	case "store", "erase":
		_ = json.NewEncoder(os.Stdout).Encode(Response{})
		os.Exit(0)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown action: %s\n", action)
		os.Exit(1)
	}
}

func handleStorageFileHelper(action string) {
	filePath := os.Getenv("HELPER_STORAGE_FILE")
	dataMap := make(map[string]string)
	if raw, err := os.ReadFile(filePath); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &dataMap)
	}

	var req Request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "decode stdin error: %v\n", err)
		os.Exit(1)
	}

	switch action {
	case "get":
		sec, found := dataMap[req.ItemID]
		if !found {
			_ = json.NewEncoder(os.Stdout).Encode(Response{
				Code:    "not-found",
				Message: fmt.Sprintf("item %q not found", req.ItemID),
			})
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(Response{Secret: sec})
		os.Exit(0)
	case "store":
		dataMap[req.ItemID] = req.Secret
		serialized, _ := json.Marshal(dataMap)
		_ = os.WriteFile(filePath, serialized, 0600)
		_ = json.NewEncoder(os.Stdout).Encode(Response{})
		os.Exit(0)
	case "erase":
		delete(dataMap, req.ItemID)
		serialized, _ := json.Marshal(dataMap)
		_ = os.WriteFile(filePath, serialized, 0600)
		_ = json.NewEncoder(os.Stdout).Encode(Response{})
		os.Exit(0)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown action: %s\n", action)
		os.Exit(1)
	}
}

func FakeHelperOptions(mode string, env ...string) ProcessOptions {
	allEnv := append([]string{
		"GO_WANT_HELPER_PROCESS=1",
		"HELPER_TEST_MODE=" + mode,
	}, env...)
	return ProcessOptions{
		Command: os.Args[0],
		Args:    []string{"-test.run=^TestHelperProcess$", "--"},
		Env:     allEnv,
		Timeout: 10 * time.Second,
	}
}

func fakeHelperOptions(mode string, env ...string) ProcessOptions {
	return FakeHelperOptions(mode, env...)
}

func TestProcessRunEchoSuccess(t *testing.T) {
	ctx := context.Background()
	opts := fakeHelperOptions("echo")
	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "ext",
		ItemID:          "item-1",
		Secret:          base64.StdEncoding.EncodeToString([]byte("supersecret123")),
	}

	resp, err := Run(ctx, opts, ActionGet, req)
	if err != nil {
		t.Fatalf("Run echo failed: %v", err)
	}
	bytesVal, err := DecodeSecretBytes(resp)
	if err != nil {
		t.Fatalf("DecodeSecretBytes failed: %v", err)
	}
	if string(bytesVal) != "supersecret123" {
		t.Fatalf("got %s, want supersecret123", string(bytesVal))
	}
}

func TestProcessRunErrorCodesMapping(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		code        string
		expectedErr error
	}{
		{"not-found", credential.ErrCredentialNotFound},
		{"locked", credential.ErrCredentialStoreLocked},
		{"unavailable", credential.ErrCredentialStoreUnavailable},
		{"denied", credential.ErrCredentialAccessDenied},
		{"read-only", credential.ErrCredentialStoreReadOnly},
	}

	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			opts := fakeHelperOptions("error_code", "HELPER_ERROR_CODE="+tc.code)
			req := &Request{
				ProtocolVersion: 1,
				StoreID:         "ext",
				ItemID:          "item-1",
			}
			_, err := Run(ctx, opts, ActionGet, req)
			if !errors.Is(err, tc.expectedErr) {
				t.Fatalf("code %s: expected %v, got %v", tc.code, tc.expectedErr, err)
			}
		})
	}
}

func TestProcessRunTimeoutAndCancel(t *testing.T) {
	opts := fakeHelperOptions("hang")
	opts.Timeout = 100 * time.Millisecond

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "ext",
		ItemID:          "item-1",
	}

	// 1. 验证内部 Timeout 触发
	_, err := Run(context.Background(), opts, ActionGet, req)
	if !errors.Is(err, credential.ErrCredentialStoreUnavailable) {
		t.Fatalf("expected ErrCredentialStoreUnavailable on timeout, got: %v", err)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 2. 验证外部 Context 取消
	opts.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err = Run(ctx, opts, ActionGet, req)
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("expected cancellation error, got: %v", err)
	}
}

func TestProcessRunCrashAndStderr(t *testing.T) {
	ctx := context.Background()
	opts := fakeHelperOptions("crash")
	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "ext",
		ItemID:          "item-1",
	}

	_, err := Run(ctx, opts, ActionGet, req)
	if err == nil {
		t.Fatalf("expected error on crash")
	}
	if !strings.Contains(err.Error(), "critical helper crash occurred") {
		t.Fatalf("expected stderr output in error, got: %v", err)
	}
}

func TestProcessRunHugeOutput(t *testing.T) {
	ctx := context.Background()
	opts := fakeHelperOptions("huge_output")
	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "ext",
		ItemID:          "item-1",
	}

	_, err := Run(ctx, opts, ActionGet, req)
	if err == nil {
		t.Fatalf("expected size limit error")
	}
	if !strings.Contains(err.Error(), "exceeded maximum limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProcessSecretNotInArgvOrError(t *testing.T) {
	ctx := context.Background()
	opts := fakeHelperOptions("echo")
	secretVal := "supersecret987"
	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "ext",
		ItemID:          "item-1",
		Secret:          base64.StdEncoding.EncodeToString([]byte(secretVal)),
	}

	resp, err := Run(ctx, opts, ActionStore, req)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response")
	}
}

func TestHelperNonInteractiveContract(t *testing.T) {
	ctx := credential.WithoutInteraction(t.Context())
	req := &Request{ProtocolVersion: ProtocolVersion, StoreID: "store", ItemID: "item"}
	// An undeclared helper must be rejected before even attempting execution.
	_, err := Run(ctx, ProcessOptions{Command: "does-not-exist"}, ActionGet, req)
	if !errors.Is(err, credential.ErrCredentialStoreUnavailable) || !strings.Contains(err.Error(), "does not declare") {
		t.Fatalf("untrusted non-interactive helper: %v", err)
	}
	opts := fakeHelperOptions("non_interactive")
	opts.NonInteractive = true
	_, err = Run(ctx, opts, ActionGet, req)
	if !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("helper did not receive nonInteractive: %v", err)
	}
	if req.NonInteractive {
		t.Fatal("caller request was mutated")
	}
}
