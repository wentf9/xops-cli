package mcpruntime

import (
	"errors"
	"strings"
	"testing"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

func TestCheckLoopbackHostName_PreservesPolicyMessage(t *testing.T) {
	err := checkLoopbackHostName("8.8.8.8")
	if !errors.Is(err, ErrNonLoopbackAddress) {
		t.Fatalf("非回环主机期望 ErrNonLoopbackAddress，实际=%v", err)
	}
	if id, ok := domi18n.ErrorID(err); !ok || id != domi18n.KeyMCPNonLoopbackHost {
		t.Fatalf("ErrorID 期望 %q，实际 ok=%v id=%q", domi18n.KeyMCPNonLoopbackHost, ok, id)
	}
	if !strings.Contains(err.Error(), "127.0.0.1 / ::1 / localhost") || !strings.Contains(err.Error(), "8.8.8.8") {
		t.Fatalf("错误文本必须保留回环策略说明与主机地址，实际=%q", err.Error())
	}
}
