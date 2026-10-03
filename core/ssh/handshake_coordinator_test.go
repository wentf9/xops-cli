package ssh

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type fakeDeadlineConn struct {
	net.Conn
	setDeadlineErr  error
	setDeadlineFunc func(t time.Time) error
}

func (c *fakeDeadlineConn) SetDeadline(t time.Time) error {
	if c.setDeadlineFunc != nil {
		return c.setDeadlineFunc(t)
	}
	return c.setDeadlineErr
}

func (c *fakeDeadlineConn) Close() error {
	return nil
}

func TestHandshakeCoordinator_SetConn_DeadlineError(t *testing.T) {
	fc := &fakeDeadlineConn{setDeadlineErr: errors.New("simulated set deadline failure")}
	hc := newHandshakeCoordinator(t.Context(), 5*time.Second)
	defer hc.Close()

	err := hc.SetConn(fc)
	if err == nil {
		t.Fatal("expected SetConn error, got nil")
	}
	if !strings.Contains(err.Error(), "set initial handshake deadline failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestHandshakeCoordinator_SetConn_DeadlineNotSupportedIgnored(t *testing.T) {
	fc := &fakeDeadlineConn{setDeadlineErr: errors.New("deadline not supported")}
	hc := newHandshakeCoordinator(t.Context(), 5*time.Second)
	defer hc.Close()

	err := hc.SetConn(fc)
	if err != nil {
		t.Fatalf("expected unsupported deadline to be ignored, got: %v", err)
	}
}

func TestHandshakeCoordinator_Pause_ClearDeadlineError(t *testing.T) {
	fc := &fakeDeadlineConn{setDeadlineErr: errors.New("simulated pause deadline failure")}
	hc := newHandshakeCoordinator(t.Context(), 5*time.Second)
	defer hc.Close()

	hc.conn = fc
	err := hc.Pause()
	if err == nil {
		t.Fatal("expected Pause error, got nil")
	}
	if !strings.Contains(err.Error(), "clear handshake deadline on pause failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestHandshakeCoordinator_Pause_DeadlineNotSupportedIgnored(t *testing.T) {
	fc := &fakeDeadlineConn{setDeadlineErr: errors.New("deadline not supported by channel")}
	hc := newHandshakeCoordinator(t.Context(), 5*time.Second)
	defer hc.Close()

	hc.conn = fc
	err := hc.Pause()
	if err != nil {
		t.Fatalf("expected unsupported deadline to be ignored, got: %v", err)
	}
}

func TestHandshakeCoordinator_Resume_RestoreDeadlineError(t *testing.T) {
	hc := newHandshakeCoordinator(t.Context(), 5*time.Second)
	defer hc.Close()

	// 先正常 Pause
	if err := hc.Pause(); err != nil {
		t.Fatalf("unexpected pause error: %v", err)
	}

	// 注入 Resume 时的错误
	fc := &fakeDeadlineConn{setDeadlineErr: errors.New("simulated resume deadline failure")}
	hc.conn = fc

	err := hc.Resume()
	if err == nil {
		t.Fatal("expected Resume error, got nil")
	}
	if !strings.Contains(err.Error(), "restore handshake deadline on resume failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestHandshakeCoordinator_Resume_DeadlineNotSupportedIgnored(t *testing.T) {
	hc := newHandshakeCoordinator(t.Context(), 5*time.Second)
	defer hc.Close()

	if err := hc.Pause(); err != nil {
		t.Fatalf("unexpected pause error: %v", err)
	}
	hc.conn = &fakeDeadlineConn{setDeadlineErr: errors.New("deadline not supported")}

	err := hc.Resume()
	if err != nil {
		t.Fatalf("expected unsupported deadline to be ignored, got: %v", err)
	}
}

func TestCoordinatingPrompter_PauseFailure_PropagatesError(t *testing.T) {
	hc := newHandshakeCoordinator(t.Context(), 5*time.Second)
	defer hc.Close()

	hc.conn = &fakeDeadlineConn{setDeadlineErr: errors.New("pause error")}
	mockPrompter := &testDelayPrompter{passphrase: "super-secret"}
	prompter := &coordinatingPrompter{prompter: mockPrompter, coordinator: hc}

	res, err := prompter.PromptSecret(t.Context(), SecretRequest{})
	if err == nil {
		t.Fatal("expected Pause error to propagate, got nil")
	}
	if res != "" {
		t.Fatalf("expected empty secret on Pause failure, got: %q", res)
	}
	if !strings.Contains(err.Error(), "clear handshake deadline on pause failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCoordinatingPrompter_ResumeFailure_PropagatesErrorAndClearsResult(t *testing.T) {
	hc := newHandshakeCoordinator(t.Context(), 5*time.Second)
	defer hc.Close()

	fc := &fakeDeadlineConn{
		setDeadlineFunc: func(tm time.Time) error {
			if tm.IsZero() {
				// Pause: 清除 deadline 成功
				return nil
			}
			// Resume: 恢复 deadline 失败
			return errors.New("resume deadline failed")
		},
	}
	hc.conn = fc

	mockPrompter := &testDelayPrompter{passphrase: "super-secret"}
	prompter := &coordinatingPrompter{prompter: mockPrompter, coordinator: hc}

	res, err := prompter.PromptSecret(t.Context(), SecretRequest{})
	if err == nil {
		t.Fatal("expected Resume error to propagate, got nil")
	}
	if res != "" {
		t.Fatalf("expected empty secret on Resume failure, got: %q", res)
	}
	if !strings.Contains(err.Error(), "restore handshake deadline on resume failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandshakeCoordinator_ClosedConnectionIgnored(t *testing.T) {
	hc := newHandshakeCoordinator(t.Context(), 5*time.Second)
	defer hc.Close()

	// 1. net.ErrClosed 在 Resume 阶段被忽略
	if err := hc.Pause(); err != nil {
		t.Fatalf("unexpected pause error: %v", err)
	}
	hc.conn = &fakeDeadlineConn{setDeadlineErr: net.ErrClosed}
	if err := hc.Resume(); err != nil {
		t.Fatalf("expected net.ErrClosed to be ignored on Resume, got: %v", err)
	}

	// 2. "use of closed network connection" 在 Pause 阶段被忽略
	hc.conn = &fakeDeadlineConn{setDeadlineErr: errors.New("set tcp 127.0.0.1:1234: use of closed network connection")}
	if err := hc.Pause(); err != nil {
		t.Fatalf("expected closed connection to be ignored on Pause, got: %v", err)
	}

	// 3. net.ErrClosed 在 SetConn 阶段被忽略
	if err := hc.SetConn(&fakeDeadlineConn{setDeadlineErr: net.ErrClosed}); err != nil {
		t.Fatalf("expected net.ErrClosed to be ignored on SetConn, got: %v", err)
	}
}

func TestCoordinatingPrompter_PromptErrorPreservedWhenResumeFails(t *testing.T) {
	hc := newHandshakeCoordinator(t.Context(), 5*time.Second)
	defer hc.Close()

	resumeErr := errors.New("simulated resume failure")
	hc.conn = &fakeDeadlineConn{
		setDeadlineFunc: func(tm time.Time) error {
			if tm.IsZero() {
				return nil
			}
			return resumeErr
		},
	}

	wantErr := context.DeadlineExceeded
	mockPrompter := &testDelayPrompter{err: wantErr}
	prompter := &coordinatingPrompter{prompter: mockPrompter, coordinator: hc}

	res, err := prompter.PromptSecret(t.Context(), SecretRequest{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected original prompt error %v, got %v", wantErr, err)
	}
	if !errors.Is(err, resumeErr) {
		t.Fatalf("expected joined resume error %v, got %v", resumeErr, err)
	}
	if res != "" {
		t.Fatalf("expected empty secret on prompt error, got: %q", res)
	}
}

func TestCoordinatingPrompter_FirstPauseFailure_FailClosedForSubsequentPrompts(t *testing.T) {
	hc := newHandshakeCoordinator(t.Context(), 5*time.Second)
	defer hc.Close()

	simulatedPauseErr := errors.New("simulated clear deadline failure")
	fc := &fakeDeadlineConn{
		setDeadlineFunc: func(tm time.Time) error {
			if tm.IsZero() {
				return simulatedPauseErr
			}
			return nil
		},
	}
	hc.conn = fc

	mockPrompter := &testDelayPrompter{passphrase: "pwd1"}
	prompter := &coordinatingPrompter{prompter: mockPrompter, coordinator: hc}

	// 第一次 Pause 失败
	res1, err1 := prompter.PromptSecret(t.Context(), SecretRequest{})
	if err1 == nil {
		t.Fatal("expected first prompt to fail on pause error, got nil")
	}
	if res1 != "" {
		t.Fatalf("expected empty secret on first failure, got: %q", res1)
	}
	if !errors.Is(err1, simulatedPauseErr) {
		t.Fatalf("expected simulatedPauseErr, got: %v", err1)
	}

	// 验证协调器已进入 fail-closed 状态：上下文已取消
	if err := hc.Context().Err(); err == nil {
		t.Fatal("expected coordinator context to be canceled after pause failure")
	}

	// 模拟后续认证尝试（例如 public-key 失败后尝试 password）
	mockPrompter.passphrase = "pwd2"
	res2, err2 := prompter.PromptSecret(t.Context(), SecretRequest{})
	if err2 == nil {
		t.Fatal("expected second prompt to fail immediately on closed coordinator, got nil")
	}
	if res2 != "" {
		t.Fatalf("expected empty secret on second failure, got: %q", res2)
	}
	if !errors.Is(err2, ErrHandshakeClosed) {
		t.Fatalf("expected ErrHandshakeClosed on subsequent prompt, got: %v", err2)
	}
}

func TestHandshakeCoordinator_TimeoutSetsDeadlineExceededCause(t *testing.T) {
	timeout := 20 * time.Millisecond
	hc := newHandshakeCoordinator(t.Context(), timeout)
	defer hc.Close()

	select {
	case <-hc.Context().Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for coordinator timer to expire")
	}

	if !errors.Is(hc.Err(), context.DeadlineExceeded) {
		t.Fatalf("expected coordinator cause to be context.DeadlineExceeded, got: %v", hc.Err())
	}
	if !errors.Is(context.Cause(hc.Context()), context.DeadlineExceeded) {
		t.Fatalf("expected context.Cause to be context.DeadlineExceeded, got: %v", context.Cause(hc.Context()))
	}
}

func TestCoordinatingPrompter_ExpiredCoordinator_DoesNotCallPrompter(t *testing.T) {
	timeout := 20 * time.Millisecond
	hc := newHandshakeCoordinator(t.Context(), timeout)
	defer hc.Close()

	select {
	case <-hc.Context().Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for coordinator timer to expire")
	}

	called := false
	mockPrompter := &testDelayPrompter{
		passphrase: "secret",
		onPrompt: func() {
			called = true
		},
	}
	prompter := &coordinatingPrompter{prompter: mockPrompter, coordinator: hc}

	res, err := prompter.PromptSecret(context.Background(), SecretRequest{})
	if err == nil {
		t.Fatal("expected prompt to fail when coordinator is expired, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
	if res != "" {
		t.Fatalf("expected empty secret, got: %q", res)
	}
	if called {
		t.Fatal("expected underlying prompter NOT to be called after timeout")
	}
}

func TestHandshakeCoordinator_InternalTimeoutPrecedesParentDeadline_MaintainsDeadlineExceeded(t *testing.T) {
	parentCtx, parentCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer parentCancel()

	// 协调器内部握手超时 10ms，早于父 context 的 50ms
	hc := newHandshakeCoordinator(parentCtx, 10*time.Millisecond)
	defer hc.Close()

	// 等待二者均已到期（100ms > 50ms > 10ms）
	time.Sleep(100 * time.Millisecond)

	if parentCtx.Err() == nil {
		t.Fatal("expected parent context to be expired")
	}

	err := hc.Err()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected coordinator Err to wrap context.DeadlineExceeded, got: %v", err)
	}
	if errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("coordinator Err was downgraded to context.Canceled: %v", err)
	}
}
