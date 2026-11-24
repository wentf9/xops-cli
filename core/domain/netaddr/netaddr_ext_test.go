package netaddr_test

import (
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

// TestExternalOpaqueContract 验证外部包经导出构造器使用 netaddr 值对象（遵循 //xops:opaque 契约）。
func TestExternalOpaqueContract(t *testing.T) {
	host, err := netaddr.ParseCanonicalHost("FE80::1%eth0")
	if err != nil {
		t.Fatalf("ParseCanonicalHost 失败: %v", err)
	}
	hp, err := netaddr.NewHostPort(host, 2222)
	if err != nil {
		t.Fatalf("NewHostPort 失败: %v", err)
	}
	ep, err := netaddr.NewEndpointFromHostPort(hp)
	if err != nil {
		t.Fatalf("NewEndpointFromHostPort 失败: %v", err)
	}
	if ep.String() != "[fe80::1%eth0]:2222" || ep.KnownHostsKey() != "[fe80::1%eth0]:2222" {
		t.Fatalf("外置包 Endpoint 格式化异常: str=%q kh=%q", ep.String(), ep.KnownHostsKey())
	}

	raw, err := jsonv2.Marshal(ep, jsonv2.Deterministic(true))
	if err != nil || string(raw) != `"[fe80::1%eth0]:2222"` {
		t.Fatalf("外置包 Marshal(Endpoint) = (%s, %v)", raw, err)
	}
	var decoded netaddr.Endpoint
	if err := jsonv2.Unmarshal(raw, &decoded); err != nil || !decoded.Equal(ep) {
		t.Fatalf("外置包 Unmarshal(Endpoint) = (%+v, %v)", decoded, err)
	}
}
