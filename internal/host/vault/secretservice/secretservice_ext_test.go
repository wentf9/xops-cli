package secretservice_test

import (
	"testing"

	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/vault/secretservice"
	"go.uber.org/goleak"
)

// 编译期接口契约断言。
var _ ports.SecretVault = (*secretservice.Store)(nil)

func TestParseSessionBusUnixSocket(t *testing.T) {
	defer goleak.VerifyNone(t)
	valid := map[string]string{
		"unix:path=/run/user/1000/bus":                  "/run/user/1000/bus",
		"unix:path=/tmp/my%20bus,guid=1234567890abcdef": "/tmp/my bus",
		"unix:abstract=/tmp/dbus-abc,guid=deadbeef":     "\x00/tmp/dbus-abc",
	}
	for raw, want := range valid {
		got, err := secretservice.ParseSessionBusUnixSocket(raw)
		if err != nil || got != want {
			t.Fatalf("ParseSessionBusUnixSocket(%q) = (%q, %v), 期望 (%q, nil)", raw, got, err, want)
		}
	}
	for _, bad := range []string{
		"",
		"tcp:host=127.0.0.1,port=1234",
		"unix:path=/run/a;unix:path=/run/b",
		"unix:path=relative/sock",
		"unix:path=/run/a,abstract=/tmp/b",
		"unix:guid=1234",
	} {
		if _, err := secretservice.ParseSessionBusUnixSocket(bad); err == nil {
			t.Fatalf("ParseSessionBusUnixSocket(%q) 期望失败", bad)
		}
	}
}
