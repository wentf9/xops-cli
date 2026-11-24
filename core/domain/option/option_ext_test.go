package option_test

import (
	"encoding"
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
)

type textValCodec interface {
	encoding.TextAppender
	encoding.TextMarshaler
}

type textFullCodec interface {
	textValCodec
	encoding.TextUnmarshaler
}

type jsonFullCodec interface {
	jsonv2.MarshalerTo
	jsonv2.UnmarshalerFrom
}

// 编译期接口契约静态断言（迁移自生产代码，保持 prod LOC 充裕余量）。
var (
	_ textFullCodec      = (*option.PathEntry)(nil)
	_ textFullCodec      = (*option.HopTarget)(nil)
	_ textFullCodec      = (*option.SanitizedCmd)(nil)
	_ textFullCodec      = (*option.ControlMasterMode)(nil)
	_ textFullCodec      = (*option.ControlPersistSpec)(nil)
	_ textFullCodec      = (*option.OptionKey)(nil)
	_ textFullCodec      = (*option.StrictHostKeyCheckingMode)(nil)
	_ textFullCodec      = (*option.Username)(nil)
	_ textFullCodec      = (*option.HostNameSpec)(nil)
	_ textFullCodec      = (*option.OriginKind)(nil)
	_ jsonFullCodec      = (*option.PathList)(nil)
	_ jsonFullCodec      = (*option.KnownHostsList)(nil)
	_ jsonFullCodec      = (*option.AlgoPolicy)(nil)
	_ jsonFullCodec      = (*option.EnvFilter)(nil)
	_ jsonFullCodec      = (*option.ControlPolicy)(nil)
	_ jsonFullCodec      = (*option.OptionLayer)(nil)
	_ jsonFullCodec      = (*option.EffectivePolicy)(nil)
	_ jsonv2.MarshalerTo = (*option.ProxyUnset)(nil)
	_ jsonv2.MarshalerTo = (*option.ProxyDisabled)(nil)
	_ jsonv2.MarshalerTo = (*option.ProxyJumpChain)(nil)
	_ jsonv2.MarshalerTo = (*option.ProxyCommandSpec)(nil)
	_ option.ProxyRoute  = (*option.ProxyUnset)(nil)
	_ option.ProxyRoute  = (*option.ProxyDisabled)(nil)
	_ option.ProxyRoute  = (*option.ProxyJumpChain)(nil)
	_ option.ProxyRoute  = (*option.ProxyCommandSpec)(nil)
)

func assertValueTextCodec[T textValCodec]()       {}
func assertValueJSONCodec[T jsonv2.MarshalerTo]() {}

// TestExternalValueReceiverCodecs 从外部包编译期证明全部值类型实现值接收者 TextAppender/TextMarshaler 与 MarshalerTo。
func TestExternalValueReceiverCodecs(_ *testing.T) {
	assertValueTextCodec[option.PathEntry]()
	assertValueTextCodec[option.HopTarget]()
	assertValueTextCodec[option.SanitizedCmd]()
	assertValueTextCodec[option.ControlMasterMode]()
	assertValueTextCodec[option.ControlPersistSpec]()
	assertValueTextCodec[option.OptionKey]()
	assertValueTextCodec[option.StrictHostKeyCheckingMode]()
	assertValueTextCodec[option.Username]()
	assertValueTextCodec[option.HostNameSpec]()
	assertValueTextCodec[option.OriginKind]()

	assertValueJSONCodec[option.PathList]()
	assertValueJSONCodec[option.KnownHostsList]()
	assertValueJSONCodec[option.AlgoPolicy]()
	assertValueJSONCodec[option.EnvFilter]()
	assertValueJSONCodec[option.ControlPolicy]()
	assertValueJSONCodec[option.OptionLayer]()
	assertValueJSONCodec[option.EffectivePolicy]()
	assertValueJSONCodec[option.ProxyUnset]()
	assertValueJSONCodec[option.ProxyDisabled]()
	assertValueJSONCodec[option.ProxyJumpChain]()
	assertValueJSONCodec[option.ProxyCommandSpec]()
}

func TestExternalSealedProxyRouteExhaustiveSwitch(t *testing.T) {
	jump, err := option.ParseProxyJump("alice@bastion.example.com:2222")
	if err != nil {
		t.Fatalf("ParseProxyJump 失败: %v", err)
	}
	cmd, err := option.ParseProxyCommand("ssh -W %h:%p gateway.example.com")
	if err != nil {
		t.Fatalf("ParseProxyCommand 失败: %v", err)
	}

	routes := []struct {
		route option.ProxyRoute
		want  string
	}{
		{option.NewProxyUnset(), "unset"},
		{option.NewProxyDisabled(), "disabled:all"},
		{option.NewProxyJumpDisabled(), "disabled:jump"},
		{jump, "jump:alice@bastion.example.com:2222"},
		{cmd, "cmd:ssh -W %h:%p gateway.example.com"},
	}
	for _, tc := range routes {
		got := classifyProxyRouteExt(t, tc.route)
		if got != tc.want {
			t.Fatalf("ProxyRoute 分类错误: got=%q want=%q", got, tc.want)
		}
	}
}

func classifyProxyRouteExt(t *testing.T, route option.ProxyRoute) string {
	t.Helper()
	switch v := route.(type) {
	case *option.ProxyUnset:
		return "unset"
	case *option.ProxyDisabled:
		if v.IsJumpOnly() {
			return "disabled:jump"
		}
		return "disabled:all"
	case *option.ProxyJumpChain:
		head, ok := v.Hops().Head()
		if !ok {
			t.Fatalf("ProxyJumpChain.Hops().Head() 返回空")
		}
		return "jump:" + head.String()
	case *option.ProxyCommandSpec:
		return "cmd:" + v.Command().String()
	default:
		t.Fatalf("未处理的 ProxyRoute 变体: %T", route)
		return ""
	}
}

func TestExternalResolveEffectivePolicyEndToEnd(t *testing.T) {
	ep, err := netaddr.ParseEndpoint("db01.internal:22")
	if err != nil {
		t.Fatalf("ParseEndpoint 失败: %v", err)
	}
	t1, err := option.ParseOptionLayer("Port 2222", "User dba")
	if err != nil {
		t.Fatalf("ParseOptionLayer(t1) 失败: %v", err)
	}
	t3Global, err := option.ParseOptionLayer("StrictHostKeyChecking yes", "UserKnownHostsFile ~/.ssh/xops_pinned")
	if err != nil {
		t.Fatalf("ParseOptionLayer(t3) 失败: %v", err)
	}
	t4OpenSSH, err := option.ParseOptionLayer("ControlMaster auto", "ControlPath ~/.ssh/cm-%C", "ProxyJump bastion.example.com", "BatchMode yes")
	if err != nil {
		t.Fatalf("ParseOptionLayer(t4) 失败: %v", err)
	}
	pol, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, t1, option.UnsetOptionLayer(), t3Global, t4OpenSSH)
	if err != nil {
		t.Fatalf("ResolveEffectivePolicy 失败: %v", err)
	}
	if !pol.IsValid() || pol.Endpoint().String() != "db01.internal:2222" || !pol.Control().IsEnabled() {
		t.Fatalf("外部调用求解结果异常: ep=%s ctrl=%v", pol.Endpoint(), pol.Control().IsEnabled())
	}
	if pol.StrictHostKeyChecking() != option.StrictHostKeyCheckingYes || pol.BatchMode() || classifyProxyRouteExt(t, pol.Proxy()) != "unset" {
		t.Fatalf("OriginManaged 应完整保留 t3 并严格裁剪 t4 的 ProxyJump 与 BatchMode")
	}
}
