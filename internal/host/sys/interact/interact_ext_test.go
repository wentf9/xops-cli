package interact_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/sys/interact"
	"go.uber.org/goleak"
)

// 编译期接口契约断言（ADR-002 / P4-T4）。
var _ ports.InteractionPort = (*interact.Interaction)(nil)

// TestTCKInteraction 验证 InteractionPort 适配器完整通过 core/ports/tck.RunInteractionSuite。
func TestTCKInteraction(t *testing.T) {
	defer goleak.VerifyNone(t)
	tck.RunInteractionSuite(t, tck.InteractionFixture{
		NewInteraction: func(t *testing.T) ports.InteractionPort {
			t.Helper()
			// RunInteractionSuite 在子测试 1 依次触发 Confirm、PromptApproval、PromptText，
			// 在子测试 2 触发 PromptSecret，每次子测试都会调用 NewInteraction。
			in := strings.NewReader("yes\napprove\ntck-tag-ok\n")
			if strings.Contains(t.Name(), "PromptSecret") {
				in = strings.NewReader(tck.TestSecretTokenA + "\n")
			}
			var out bytes.Buffer
			ui, err := interact.NewStreamInteraction(interact.StreamSpec{
				In:          in,
				Out:         &out,
				Interactive: true,
			})
			if err != nil {
				t.Fatalf("NewStreamInteraction 失败: %v", err)
			}
			return ui
		},
		ExpectedSecret: tck.TestSecretTokenA,
		ExpectedText:   "tck-tag-ok",
	})
}

// TestInteractionFailClosedAndPipeUnavailable 验证零值失败关闭与非 TTY 管道返回 ErrInteractionUnavailable。
func TestInteractionFailClosedAndPipeUnavailable(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	var zero interact.Interaction
	if zero.CanInteract() {
		t.Fatal("零值 Interaction.CanInteract() 必须为 false")
	}
	cReq, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{Message: "Delete host?", Risk: security.RiskDangerous})
	if err != nil {
		t.Fatalf("NewConfirmRequest 失败: %v", err)
	}
	if v, err := zero.Confirm(ctx, cReq); v != security.VerdictDeny || !errors.Is(err, ports.ErrInteractionUnavailable) {
		t.Fatalf("零值 Confirm 期望 (VerdictDeny, ErrInteractionUnavailable)，实际得到 (%v, %v)", v, err)
	}

	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe 失败: %v", err)
	}
	defer func() {
		_ = rPipe.Close()
		_ = wPipe.Close()
	}()
	fileUI, err := interact.NewFileInteraction(rPipe, wPipe)
	if err != nil {
		t.Fatalf("NewFileInteraction 失败: %v", err)
	}
	if fileUI.CanInteract() {
		t.Fatal("管道文件句柄 CanInteract() 必须为 false")
	}
	if v, err := fileUI.Confirm(ctx, cReq); v != security.VerdictDeny || !errors.Is(err, ports.ErrInteractionUnavailable) {
		t.Fatalf("非 TTY Confirm 期望 ErrInteractionUnavailable，实际得到 (%v, %v)", v, err)
	}
}

// TestInteractionDefaultDenyAndEmptySecretReject 验证 Confirm 默认拒绝以及 PromptSecret 拒绝空输入。
func TestInteractionDefaultDenyAndEmptySecretReject(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	cReq, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{Message: "Delete host?", Risk: security.RiskDangerous})
	if err != nil {
		t.Fatalf("NewConfirmRequest 失败: %v", err)
	}
	for _, ans := range []string{"\n", "no\n", "maybe\n", "yess\n"} {
		var out bytes.Buffer
		ui, sErr := interact.NewStreamInteraction(interact.StreamSpec{
			In:          strings.NewReader(ans),
			Out:         &out,
			Interactive: true,
		})
		if sErr != nil {
			t.Fatalf("NewStreamInteraction 失败: %v", sErr)
		}
		v, cErr := ui.Confirm(ctx, cReq)
		if cErr != nil || v != security.VerdictDeny {
			t.Fatalf("Confirm(%q) 期望 (VerdictDeny, nil)，实际得到 (%v, %v)", ans, v, cErr)
		}
	}

	sReq, err := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{Prompt: "Passphrase:"})
	if err != nil {
		t.Fatalf("NewSecretPromptRequest 失败: %v", err)
	}
	var out bytes.Buffer
	ui, err := interact.NewStreamInteraction(interact.StreamSpec{
		In:          strings.NewReader("\r\n"),
		Out:         &out,
		Interactive: true,
	})
	if err != nil {
		t.Fatalf("NewStreamInteraction 失败: %v", err)
	}
	if err := ui.PromptSecret(ctx, sReq, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("空机密输入期望 ErrInvalidArgument，实际得到: %v", err)
	}
}

// TestInteraction_OverlongLineRejectsAndDrains 验证超长输入行（>4096B）严格返回 ErrLimitExceeded 并排空残余尾部，
// 杜绝尾部字符（如 "y\n"）泄漏并误触发后续 Confirm 确认。
func TestInteraction_OverlongLineRejectsAndDrains(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	overlong := strings.Repeat("a", 4100) + "y\nno\n"
	var out bytes.Buffer
	ui, err := interact.NewStreamInteraction(interact.StreamSpec{
		In:          strings.NewReader(overlong),
		Out:         &out,
		Interactive: true,
	})
	if err != nil {
		t.Fatalf("NewStreamInteraction 失败: %v", err)
	}
	tReq, err := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{Prompt: "Input:"})
	if err != nil {
		t.Fatalf("NewTextPromptRequest 失败: %v", err)
	}
	if _, err := ui.PromptText(ctx, tReq); !errors.Is(err, ports.ErrLimitExceeded) {
		t.Fatalf("超长输入行 PromptText = %v, 期望 ErrLimitExceeded", err)
	}
	cReq, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{Message: "Proceed?", Risk: security.RiskDangerous})
	if err != nil {
		t.Fatalf("NewConfirmRequest 失败: %v", err)
	}
	v, err := ui.Confirm(ctx, cReq)
	if err != nil || v != security.VerdictDeny {
		t.Fatalf("排空后后续 Confirm 应读取下一行 no 并返回 VerdictDeny，实际得到 (%v, %v)", v, err)
	}
}
