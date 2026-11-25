package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/internal/sim"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

func mustLocalEnv(t *testing.T, extra map[string]string) *sim.SimEnvPort {
	t.Helper()
	id, err := ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{
		LocalHost: "workstation.local",
		LocalUser: "localops",
		LocalUID:  "1000",
		HomeDir:   "/home/localops",
	})
	if err != nil {
		t.Fatalf("NewLocalIdentityInfo: %v", err)
	}
	return sim.NewSimEnvPort(extra, id)
}

func mustVirtualHost(t *testing.T, alias, hostName string, port uint16, user string, layer option.OptionLayer) ports.OpenSSHVirtualHost {
	t.Helper()
	layer, epOpt := applyVirtualHostEndpoint(t, layer, hostName, port)
	layer, userOpt := applyVirtualHostUser(t, layer, user)
	vh, err := ports.NewOpenSSHVirtualHost(ports.OpenSSHVirtualHostSpec{
		Alias:      alias,
		SourceFile: "/home/localops/.ssh/config",
		Endpoint:   epOpt,
		User:       userOpt,
		Proxy:      layer.Proxy(),
		Layer:      layer,
	})
	if err != nil {
		t.Fatalf("NewOpenSSHVirtualHost(%q): %v", alias, err)
	}
	return vh
}

func applyVirtualHostEndpoint(t *testing.T, layer option.OptionLayer, hostName string, port uint16) (option.OptionLayer, algebraic.Option[netaddr.Endpoint]) {
	t.Helper()
	if port != 0 {
		layer = layer.WithPort(port)
	}
	if hostName == "" {
		return layer, algebraic.None[netaddr.Endpoint]()
	}
	hn, err := option.ParseHostNameSpec(hostName)
	if err != nil {
		t.Fatalf("ParseHostNameSpec(%q): %v", hostName, err)
	}
	layer = layer.WithHostName(hn)
	ch, err := netaddr.ParseCanonicalHost(hostName)
	if err != nil {
		return layer, algebraic.None[netaddr.Endpoint]()
	}
	p := port
	if p == 0 {
		p = netaddr.DefaultSSHPort
	}
	ep, err := netaddr.NewEndpoint(ch, p)
	if err != nil {
		return layer, algebraic.None[netaddr.Endpoint]()
	}
	return layer, algebraic.Some(ep)
}

func applyVirtualHostUser(t *testing.T, layer option.OptionLayer, user string) (option.OptionLayer, algebraic.Option[option.Username]) {
	t.Helper()
	if user == "" {
		return layer, algebraic.None[option.Username]()
	}
	u, err := option.ParseUsername(user)
	if err != nil {
		t.Fatalf("ParseUsername(%q): %v", user, err)
	}
	return layer.WithUser(u), algebraic.Some(u)
}

func mustProxyJump(t *testing.T, raw string) option.ProxyRoute {
	t.Helper()
	r, err := option.ParseProxyJump(raw)
	if err != nil {
		t.Fatalf("ParseProxyJump(%q): %v", raw, err)
	}
	return r
}

func TestResolveTarget_AdHocAndTierPrecedence(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	env := mustLocalEnv(t, nil)

	t3 := option.UnsetOptionLayer().WithServerAliveInterval(algebraic.FromStdDuration(30 * time.Second))
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		Env:           env,
		GlobalOptions: t3,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// 测试 1：临时 user@ipv4:port 目标，t1 端口优先于内联端口、无 -l 时取内联用户。
	cli := option.UnsetOptionLayer().WithBatchMode(true).WithIdentitiesOnly(false)
	res, err := svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{
		Target:     "alice@198.51.100.10:2222",
		CLIOptions: cli,
	})
	if err != nil {
		t.Fatalf("ResolveTarget(ad-hoc): %v", err)
	}
	if !res.IsValid() || res.OriginKind() != option.OriginAdHoc {
		t.Fatalf("期望有效 OriginAdHoc，实际 valid=%v origin=%s", res.IsValid(), res.OriginKind())
	}
	hop, ok := res.Plan().Target()
	if !ok || hop.Endpoint().String() != "198.51.100.10:2222" || hop.Username().String() != "alice" {
		t.Fatalf("末跳解析结果失配: ep=%s user=%s", hop.Endpoint(), hop.Username())
	}
	if hop.Transport().ServerAliveInterval().Std() != 30*time.Second || !hop.Transport().BatchMode() {
		t.Fatalf("四层选项合并结果失配: alive=%v batch=%v", hop.Transport().ServerAliveInterval(), hop.Transport().BatchMode())
	}

	// 测试 2：省略用户名时回退本机身份用户名，支持方括号 IPv6 与裸 IPv6。
	for _, tc := range []struct {
		target string
		wantEP string
	}{
		{"[2001:db8::1]:2200", "[2001:db8::1]:2200"},
		{"2001:db8::2", "[2001:db8::2]:22"},
	} {
		r, err := svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: tc.target})
		if err != nil {
			t.Fatalf("ResolveTarget(%q): %v", tc.target, err)
		}
		targetHop, _ := r.Plan().Target()
		if targetHop.Endpoint().String() != tc.wantEP || targetHop.Username().String() != "localops" {
			t.Fatalf("目标 %q 期望 ep=%s user=localops，实际 ep=%s user=%s", tc.target, tc.wantEP, targetHop.Endpoint(), targetHop.Username())
		}
	}
}

func TestResolveTarget_AdHocTrimsTier4PerINVD2(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	env := mustLocalEnv(t, nil)

	idList, err := option.ParsePathListEntries([]string{"/etc/should-not-leak"})
	if err != nil {
		t.Fatalf("ParsePathListEntries: %v", err)
	}
	// OpenSSH 源中包含与 IP 同名的配置，显式以 OriginAdHoc 解析时必须按 INV-D2 裁剪非 Mux/Transport 项。
	t4Layer := option.UnsetOptionLayer().
		WithServerAliveInterval(algebraic.FromStdDuration(45 * time.Second)).
		WithIdentityFiles(idList)
	vh := mustVirtualHost(t, "198.51.100.20", "198.51.100.20", 22, "t4user", t4Layer)
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH: sim.NewSimOpenSSHConfigSource(vh),
		Env:     env,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	res, err := svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{
		Target:         "198.51.100.20",
		ExplicitOrigin: algebraic.Some(option.OriginAdHoc),
	})
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	hop, _ := res.Plan().Target()
	if hop.Username().String() != "localops" {
		t.Fatalf("OriginAdHoc 不得采纳 t4 User，期望 localops，实际=%s", hop.Username())
	}
	if hop.Transport().ServerAliveInterval().Std() != 45*time.Second {
		t.Fatalf("OriginAdHoc 应保留 t4 Transport 选项 ServerAliveInterval=45s，实际=%v", hop.Transport().ServerAliveInterval())
	}
	if hop.Transport().IdentityFiles().IsSet() {
		t.Fatalf("OriginAdHoc 不得采纳 t4 IdentityFile，实际=%v", hop.Transport().IdentityFiles().RawItems())
	}
}

func TestResolveTarget_OpenSSHVirtualAndRecursiveProxyJump(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	env := mustLocalEnv(t, map[string]string{"KEY_TAG": "prod"})
	svc := mustNewDiamondJumpService(t, env)

	res, err := svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: "prod_db"})
	if err != nil {
		t.Fatalf("ResolveTarget(prod_db): %v", err)
	}
	if res.OriginKind() != option.OriginOpenSSHVirtual {
		t.Fatalf("期望 OriginOpenSSHVirtual，实际=%s", res.OriginKind())
	}
	hops := res.Plan().HopSlice()
	if len(hops) != 3 {
		t.Fatalf("期望 3 跳计划 [jump1, jump2, prod_db]，实际=%d 跳", len(hops))
	}
	wantEPs := [3]string{"198.51.100.1:2201", "198.51.100.2:2202", "198.51.100.3:2203"}
	wantUsers := [3]string{"j1", "j2", "deploy"}
	for i := range 3 {
		if hops[i].HopIndex() != uint32(i) || hops[i].Endpoint().String() != wantEPs[i] || hops[i].Username().String() != wantUsers[i] {
			t.Fatalf("hop[%d] 失配: idx=%d ep=%s user=%s", i, hops[i].HopIndex(), hops[i].Endpoint(), hops[i].Username())
		}
	}
	assertExpandedPrivateKeyAuth(t, hops[2])
}

func mustNewDiamondJumpService(t *testing.T, env ports.EnvPort) *ucinv.Service {
	t.Helper()
	idTpl, err := option.ParsePathListEntries([]string{"/keys/%r_${KEY_TAG}_ed25519"})
	if err != nil {
		t.Fatalf("ParsePathListEntries: %v", err)
	}
	certTpl, err := option.ParsePathListEntries([]string{"/keys/%r_${KEY_TAG}_ed25519-cert.pub"})
	if err != nil {
		t.Fatalf("ParsePathListEntries(cert): %v", err)
	}
	sendEnv, err := option.ParseEnvFilter("LANG LC_*")
	if err != nil {
		t.Fatalf("ParseEnvFilter: %v", err)
	}
	jump1 := mustVirtualHost(t, "jump1", "198.51.100.1", 2201, "j1", option.UnsetOptionLayer())
	jump2 := mustVirtualHost(t, "jump2", "198.51.100.2", 2202, "j2", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "jump1")))
	appLayer := option.UnsetOptionLayer().
		WithProxyRoute(mustProxyJump(t, "jump1,jump2")).
		WithIdentityFiles(idTpl).
		WithCertificateFiles(certTpl).
		WithIdentitiesOnly(true).
		WithBatchMode(true).
		WithSendEnv(sendEnv)
	app := mustVirtualHost(t, "prod_db", "198.51.100.3", 2203, "deploy", appLayer)
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH: sim.NewSimOpenSSHConfigSource(jump1, jump2, app),
		Env:     env,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func assertExpandedPrivateKeyAuth(t *testing.T, hop plan.HopSpec) {
	t.Helper()
	pk, ok := hop.Auth().(*inventory.AuthPrivateKey)
	if !ok {
		t.Fatalf("期望末跳认证为 *AuthPrivateKey，实际=%T", hop.Auth())
	}
	if got := pk.KeyPaths().Slice()[0].String(); got != "/keys/deploy_prod_ed25519" {
		t.Fatalf("期望展开后私钥路径 /keys/deploy_prod_ed25519，实际=%q", got)
	}
	if certs := pk.CertPaths(); len(certs) != 1 || certs[0].String() != "/keys/deploy_prod_ed25519-cert.pub" {
		t.Fatalf("证书路径展开失配: %v", certs)
	}
	if !hop.Transport().SendEnv().Match("LC_ALL") || hop.Transport().SendEnv().Match("SECRET_TOKEN") {
		t.Fatalf("SendEnv 规则未正确保留在末跳策略中")
	}
}

func TestResolveTarget_ProxyJumpCycleAndDepthGuard(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	env := mustLocalEnv(t, nil)

	a := mustVirtualHost(t, "node-a", "198.51.100.11", 22, "u", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "node-b")))
	b := mustVirtualHost(t, "node-b", "198.51.100.12", 22, "u", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "node-a")))
	self := mustVirtualHost(t, "node-self", "198.51.100.13", 22, "u", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "node-self")))

	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH:      sim.NewSimOpenSSHConfigSource(a, b, self),
		Env:          env,
		MaxJumpDepth: 2,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: "node-a"}); !errors.Is(err, ucinv.ErrProxyJumpCycle) {
		t.Fatalf("多跳环路期望 ErrProxyJumpCycle，实际=%v", err)
	}
	if _, err := svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: "node-self"}); !errors.Is(err, ucinv.ErrProxyJumpCycle) {
		t.Fatalf("自环期望 ErrProxyJumpCycle，实际=%v", err)
	}

	// 深度超过 MaxJumpDepth=2：h3 -> h2 -> h1 -> h0（深度 3）。
	h0 := mustVirtualHost(t, "h0", "198.51.100.30", 22, "u", option.UnsetOptionLayer())
	h1 := mustVirtualHost(t, "h1", "198.51.100.31", 22, "u", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "h0")))
	h2 := mustVirtualHost(t, "h2", "198.51.100.32", 22, "u", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "h1")))
	h3 := mustVirtualHost(t, "h3", "198.51.100.33", 22, "u", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "h2")))
	deepSvc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH:      sim.NewSimOpenSSHConfigSource(h0, h1, h2, h3),
		Env:          env,
		MaxJumpDepth: 2,
	})
	if err != nil {
		t.Fatalf("NewService(deep): %v", err)
	}
	if _, err := deepSvc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: "h3"}); !errors.Is(err, ucinv.ErrProxyJumpDepthExceeded) {
		t.Fatalf("深度超限期望 ErrProxyJumpDepthExceeded，实际=%v", err)
	}
}

func TestResolveTarget_AuthMatrixAndFailClosedGuards(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	env := mustLocalEnv(t, nil)

	// 零值 Service 与零值 ResolvedTarget 严格失败关闭。
	var zeroSvc ucinv.Service
	if _, err := zeroSvc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: "198.51.100.1"}); !errors.Is(err, ucinv.ErrServiceNotInitialized) {
		t.Fatalf("零值 Service 期望 ErrServiceNotInitialized，实际=%v", err)
	}
	var zeroRes ucinv.ResolvedTarget
	if zeroRes.IsValid() || !zeroRes.IsZero() || zeroRes.OriginKind() != option.OriginInvalid {
		t.Fatalf("零值 ResolvedTarget 必须失败关闭")
	}

	svc, err := ucinv.NewService(ucinv.ServiceConfig{Env: env})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	// IdentityFile=none + IdentitiesOnly=true + BatchMode=true -> 无可用认证方式（fail-closed）。
	noAuthCLI := option.UnsetOptionLayer().
		WithIdentityFiles(option.DisabledPathList()).
		WithIdentitiesOnly(true).
		WithBatchMode(true)
	if _, err := svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{
		Target:     "alice@198.51.100.1",
		CLIOptions: noAuthCLI,
	}); !errors.Is(err, ucinv.ErrNoAuthMethod) {
		t.Fatalf("无可用认证期望 ErrNoAuthMethod，实际=%v", err)
	}

	// IdentityFile=none + IdentitiesOnly=false + BatchMode=true -> 单一 *AuthAgent（绝不回退默认私钥）。
	agentOnlyCLI := option.UnsetOptionLayer().
		WithIdentityFiles(option.DisabledPathList()).
		WithIdentitiesOnly(false).
		WithBatchMode(true)
	resAgent, err := svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{
		Target:     "alice@198.51.100.1",
		CLIOptions: agentOnlyCLI,
	})
	if err != nil {
		t.Fatalf("ResolveTarget(agentOnly): %v", err)
	}
	targetHop, _ := resAgent.Plan().Target()
	if _, ok := targetHop.Auth().(*inventory.AuthAgent); !ok {
		t.Fatalf("期望单一 *AuthAgent，实际=%T", targetHop.Auth())
	}

	// 默认组合认证（Agent + Default PrivateKey + Interactive KI）。
	resDef, err := svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: "alice@198.51.100.1"})
	if err != nil {
		t.Fatalf("ResolveTarget(default): %v", err)
	}
	defHop, _ := resDef.Plan().Target()
	comp, ok := defHop.Auth().(*inventory.AuthComposite)
	if !ok || len(comp.Methods()) != 3 {
		t.Fatalf("默认认证期望 3 项 AuthComposite，实际=%T", defHop.Auth())
	}

	// 无效目标规格与缺失用户名均失败关闭。
	for _, bad := range []string{"", "   ", "a@b@c", "host:0", "host:022", "host:70000", "bad host", "[::1]extra", "user@"} {
		if _, err := svc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: bad}); !errors.Is(err, ucinv.ErrInvalidTarget) {
			t.Fatalf("非法目标 %q 期望 ErrInvalidTarget，实际=%v", bad, err)
		}
	}
	noEnvSvc, err := ucinv.NewService(ucinv.ServiceConfig{})
	if err != nil {
		t.Fatalf("NewService(noEnv): %v", err)
	}
	if _, err := noEnvSvc.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: "198.51.100.1"}); !errors.Is(err, ucinv.ErrMissingUsername) {
		t.Fatalf("缺失用户名期望 ErrMissingUsername，实际=%v", err)
	}
}
