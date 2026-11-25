package sys

import (
	"errors"
	"slices"
	"testing"

	"github.com/wentf9/xops-cli/core/ports"
)

// TestMergeProcessEnvPreservesSpecialVarsAndOverridePrecedence 验证 mergeProcessEnv：
//   - 完整保留 Windows 驱动器工作目录特殊项（如 "=C:=C:\work"）；
//   - 将 overrides 追加至末尾，确保在 Windows 大小写不敏感去重下（如 "Path" vs "PATH"）显式覆盖始终生效。
func TestMergeProcessEnvPreservesSpecialVarsAndOverridePrecedence(t *testing.T) {
	base := []string{"=C:=C:\\work", "Path=C:\\old", "KEEP=1"}
	got := mergeProcessEnv(base, map[string]string{
		"PATH": "C:\\new",
		"A":    "alpha",
	})
	want := []string{"=C:=C:\\work", "Path=C:\\old", "KEEP=1", "A=alpha", "PATH=C:\\new"}
	if !slices.Equal(got, want) {
		t.Fatalf("mergeProcessEnv = %v, 期望 %v", got, want)
	}
	// 验证不修改原 base 底层数组。
	if !slices.Equal(base, []string{"=C:=C:\\work", "Path=C:\\old", "KEEP=1"}) {
		t.Fatalf("mergeProcessEnv 不得修改原 base 切片: %v", base)
	}
}

// TestTerminalHandleResizeEventsNilAfterExpiry 验证 terminalHandle 失效后 ResizeEvents 与所有操作统一失败关闭。
func TestTerminalHandleResizeEventsNilAfterExpiry(t *testing.T) {
	ch := make(chan ports.TerminalSize, 1)
	term, err := NewStreamTerminal(StreamTerminalSpec{Interactive: false})
	if err != nil {
		t.Fatalf("NewStreamTerminal 失败: %v", err)
	}
	h := term.newHandle(ch)
	if h.ResizeEvents() == nil {
		t.Fatal("活跃句柄 ResizeEvents() 不应为 nil")
	}
	h.expire()
	if h.ResizeEvents() != nil {
		t.Fatal("失效句柄 ResizeEvents() 必须返回 nil")
	}
	if _, err := h.Size(); !errors.Is(err, ports.ErrHandleExpired) {
		t.Fatalf("失效句柄 Size() = %v, 期望 ErrHandleExpired", err)
	}
}
