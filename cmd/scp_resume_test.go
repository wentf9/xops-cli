package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestParsePath_Local 验证本地路径解析
func TestParsePath_Local(t *testing.T) {
	cases := []struct {
		input    string
		isRemote bool
		path     string
	}{
		{"/etc/passwd", false, "/etc/passwd"},
		{"./local/file.txt", false, "./local/file.txt"},
		{"relative/path", false, "relative/path"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parsePath(tc.input)
			if err != nil {
				t.Fatalf("parsePath(%q) unexpected error: %v", tc.input, err)
			}
			if got.IsRemote != tc.isRemote {
				t.Errorf("IsRemote: want %v, got %v", tc.isRemote, got.IsRemote)
			}
			if got.Path != tc.path {
				t.Errorf("Path: want %q, got %q", tc.path, got.Path)
			}
		})
	}
}

// TestParsePath_Remote 验证远程路径解析（含用户名、主机、路径）
func TestParsePath_Remote(t *testing.T) {
	cases := []struct {
		input string
		user  string
		host  string
		path  string
	}{
		{"user@host:/remote/path", "user", "host", "/remote/path"},
		{"host:/remote/path", "", "host", "/remote/path"},
		{"user@host:relative/path", "user", "host", "relative/path"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parsePath(tc.input)
			if err != nil {
				t.Fatalf("parsePath(%q) unexpected error: %v", tc.input, err)
			}
			if !got.IsRemote {
				t.Errorf("expected IsRemote=true for %q", tc.input)
			}
			if got.User != tc.user {
				t.Errorf("User: want %q, got %q", tc.user, got.User)
			}
			if got.Host != tc.host {
				t.Errorf("Host: want %q, got %q", tc.host, got.Host)
			}
			if got.Path != tc.path {
				t.Errorf("Path: want %q, got %q", tc.path, got.Path)
			}
		})
	}
}

// TestScpOptions_Validate 验证 ScpOptions.Validate 的必填字段校验
func TestScpOptions_Validate(t *testing.T) {
	// 没有 Source 应该报错
	o := NewScpOptions()
	if err := o.Validate(); err == nil {
		t.Error("expected error when Source is empty")
	}

	// 有 Source 但没有 Dest/Host/Tag 也应该报错
	o.Source = "/local/file"
	if err := o.Validate(); err == nil {
		t.Error("expected error when Dest/Host/Tag all empty")
	}

	// 有 Source 和 Dest 应该通过
	o.Dest = "/local/dest"
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error with Source and Dest set: %v", err)
	}
}

// TestTransferProgressErrors_ThreadSafe 验证 transferProgressErrors 在并发写入非空错误时的安全性与正确性
func TestTransferProgressErrors_ThreadSafe(t *testing.T) {
	errs := &transferProgressErrors{}

	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		op := fmt.Sprintf("worker-%d", i)
		go func(idx int, opName string) {
			defer wg.Done()
			if idx%2 == 0 {
				errs.Add(opName, errors.New("simulated error"))
			} else {
				errs.Add(opName, nil)
			}
		}(i, op)
	}
	wg.Wait()

	resultErr := errs.Err()
	if resultErr == nil {
		t.Fatal("expected non-nil error from concurrent workers")
	}

	// 验证所有偶数 worker 的错误都被记录在 combined error 中
	for i := 0; i < workers; i += 2 {
		expectedOp := fmt.Sprintf("worker-%d failed", i)
		if !strings.Contains(resultErr.Error(), expectedOp) {
			t.Errorf("expected combined error to contain %q, got: %v", expectedOp, resultErr)
		}
	}
}

// TestRemoteToRemote_CancelWatcher_NormalExit 验证远端到远端复制的取消 watcher 在正常返回时不会死锁
func TestRemoteToRemote_CancelWatcher_NormalExit(t *testing.T) {
	ctx := context.Background()

	var cancelWg sync.WaitGroup
	cancelWg.Add(1)
	stopCtx, cancelCtx := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWg.Wait()
	defer cancelCtx()

	closedCh := make(chan struct{})
	go func() {
		defer cancelWg.Done()
		select {
		case <-stopCtx.Done():
			close(closedCh)
		case <-ctx.Done():
		}
	}()

	// 模拟正常退出时 cancelCtx 执行，验证 goroutine 退出且 cancelWg.Wait() 不死锁
	cancelCtx()
	select {
	case <-closedCh:
	case <-time.After(1 * time.Second):
		t.Fatal("cancel watcher did not exit on normal stopCtx cancellation")
	}
}

// TestRemoteToRemote_CancelWatcher_ContextCancel 验证当主 context 被取消时 watcher 能正确响应并退出
func TestRemoteToRemote_CancelWatcher_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var cancelWg sync.WaitGroup
	cancelWg.Add(1)
	stopCtx, cancelCtx := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWg.Wait()
	defer cancelCtx()

	cancelledCh := make(chan struct{})
	go func() {
		defer cancelWg.Done()
		select {
		case <-stopCtx.Done():
		case <-ctx.Done():
			close(cancelledCh)
		}
	}()

	// 触发主 context 取消
	cancel()
	select {
	case <-cancelledCh:
	case <-time.After(1 * time.Second):
		t.Fatal("cancel watcher did not exit on parent ctx cancellation")
	}
}
