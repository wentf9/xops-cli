package inventory_test

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/internal/sim"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

// spyOpenSSHSource 用于验证 ResolveTier4 候选端点推导与通配符非规范虚拟别名升级顺序。
type spyOpenSSHSource struct {
	virtuals []ports.OpenSSHVirtualHost
	tiers    map[string]option.OptionLayer
	seenEP   map[string]algebraic.Option[netaddr.Endpoint]
}

func (s *spyOpenSSHSource) ListVirtualHosts(context.Context) ([]ports.OpenSSHVirtualHost, error) {
	return append([]ports.OpenSSHVirtualHost(nil), s.virtuals...), nil
}

func (s *spyOpenSSHSource) ResolveTier4(
	_ context.Context,
	orig option.OriginalHostSpec,
	ep algebraic.Option[netaddr.Endpoint],
) (option.OptionLayer, error) {
	if s.seenEP != nil {
		s.seenEP[orig.String()] = ep
	}
	if layer, ok := s.tiers[orig.String()]; ok {
		return layer, nil
	}
	return option.UnsetOptionLayer(), nil
}

func TestResolveTarget_ProxyJumpRightToLeftOverrideCycleAndDepth(t *testing.T) {
	defer goleak.VerifyNone(t)
	assertCommaChainCycleRejected(t)
	assertDiamondCrossCycleRejected(t)
	assertCommaChainOverrideAndPercentJ(t)
	assertCommaChainEnforcesMaxJumpDepth(t)
}

func assertCommaChainCycleRejected(t *testing.T) {
	t.Helper()
	svc, err := ucinv.NewService(ucinv.ServiceConfig{Env: mustLocalEnv(t, nil)})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cli := option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "198.51.100.1,198.51.100.2,198.51.100.1"))
	if _, err := svc.ResolveTarget(context.Background(), ucinv.ResolveTargetRequest{
		Target:     "ops@198.51.100.9",
		CLIOptions: cli,
	}); !errors.Is(err, ucinv.ErrProxyJumpCycle) || !errors.Is(err, inventory.ErrProxyJumpCycle) {
		t.Fatalf("-J j1,j2,j1 环路期望 ErrProxyJumpCycle，实际=%v", err)
	}
}

func assertDiamondCrossCycleRejected(t *testing.T) {
	t.Helper()
	jump1 := mustVirtualHost(t, "jump1", "198.51.100.1", 22, "u1", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "jump2")))
	jump2 := mustVirtualHost(t, "jump2", "198.51.100.2", 22, "u2", option.UnsetOptionLayer())
	app := mustVirtualHost(t, "app", "198.51.100.3", 22, "u3", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "jump1,jump2")))
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH: sim.NewSimOpenSSHConfigSource(jump1, jump2, app),
		Env:     mustLocalEnv(t, nil),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := svc.ResolveTarget(context.Background(), ucinv.ResolveTargetRequest{Target: "app"}); !errors.Is(err, ucinv.ErrProxyJumpCycle) {
		t.Fatalf("交叉环路 jump1->jump2 + app->jump1,jump2 期望 ErrProxyJumpCycle，实际=%v", err)
	}
}

func assertCommaChainOverrideAndPercentJ(t *testing.T) {
	t.Helper()
	oldBastion := mustVirtualHost(t, "old-bastion", "198.51.100.99", 22, "old", option.UnsetOptionLayer())
	newBastion := mustVirtualHost(t, "new-bastion", "198.51.100.10", 22, "new", option.UnsetOptionLayer())
	idPctJ, err := option.ParsePathListEntries([]string{"/keys/%j_key"})
	if err != nil {
		t.Fatalf("ParsePathListEntries: %v", err)
	}
	j2 := mustVirtualHost(t, "j2", "198.51.100.20", 22, "mid", option.UnsetOptionLayer().
		WithProxyRoute(mustProxyJump(t, "old-bastion")).
		WithIdentityFiles(idPctJ).
		WithIdentitiesOnly(true).
		WithBatchMode(true))
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH: sim.NewSimOpenSSHConfigSource(oldBastion, newBastion, j2),
		Env:     mustLocalEnv(t, nil),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	res, err := svc.ResolveTarget(context.Background(), ucinv.ResolveTargetRequest{
		Target:     "ops@198.51.100.30",
		CLIOptions: option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "new-bastion,j2")),
	})
	if err != nil {
		t.Fatalf("ResolveTarget(-J new-bastion,j2): %v", err)
	}
	hops := res.Plan().HopSlice()
	if len(hops) != 3 || hops[0].Endpoint().Host().String() != "198.51.100.10" || hops[1].Endpoint().Host().String() != "198.51.100.20" {
		t.Fatalf("期望 [new-bastion, j2, target]（覆盖 old-bastion），实际=%d 跳 %+v", len(hops), hops)
	}
	pk, ok := hops[1].Auth().(*inventory.AuthPrivateKey)
	if !ok || pk.KeyPaths().Slice()[0].String() != "/keys/new-bastion_key" {
		t.Fatalf("中间跳 %%j 展开失配，期望 /keys/new-bastion_key，实际=%#v", hops[1].Auth())
	}
}

func assertCommaChainEnforcesMaxJumpDepth(t *testing.T) {
	t.Helper()
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		Env:          mustLocalEnv(t, nil),
		MaxJumpDepth: 2,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cli := option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "198.51.100.1,198.51.100.2,198.51.100.3"))
	if _, err := svc.ResolveTarget(context.Background(), ucinv.ResolveTargetRequest{
		Target:     "ops@198.51.100.9",
		CLIOptions: cli,
	}); !errors.Is(err, ucinv.ErrProxyJumpDepthExceeded) {
		t.Fatalf("逗号链深度超限期望 ErrProxyJumpDepthExceeded，实际=%v", err)
	}
}

func TestResolveTarget_INVD3VirtualBastionWildcardOriginTier4EPAndPercentBoundary(t *testing.T) {
	defer goleak.VerifyNone(t)
	assertVirtualBastionInheritsPolicyNotLeafKeys(t)
	assertWildcardVirtualJumpOriginSettlesBeforeT1(t)
	assertResolveTier4CandidateEndpointUsesT1AndT3(t)
	assertPercentExpansionSingleBoundaryRejectsPercent(t)
}

func assertVirtualBastionInheritsPolicyNotLeafKeys(t *testing.T) {
	t.Helper()
	bastionKey, _ := option.ParsePathListEntries([]string{"/keys/bastion_id"})
	leafKey, _ := option.ParsePathListEntries([]string{"/keys/leaf_id"})
	bastion := mustVirtualHost(t, "bastion", "198.51.100.10", 22, "jump", option.UnsetOptionLayer().
		WithIdentityFiles(bastionKey).
		WithIdentitiesOnly(true).
		WithBatchMode(false).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingNo))
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH: sim.NewSimOpenSSHConfigSource(bastion),
		Env:     mustLocalEnv(t, nil),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cli := option.UnsetOptionLayer().
		WithProxyRoute(mustProxyJump(t, "bastion")).
		WithBatchMode(true).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingYes).
		WithIdentityFiles(leafKey).
		WithIdentitiesOnly(true)
	res, err := svc.ResolveTarget(context.Background(), ucinv.ResolveTargetRequest{
		Target:     "ops@198.51.100.20",
		CLIOptions: cli,
	})
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	hop0, _ := res.Plan().HopAt(0)
	if !hop0.Transport().BatchMode() || hop0.Transport().StrictHostKeyChecking() != option.StrictHostKeyCheckingYes {
		t.Fatalf("INV-D3 失配：虚拟跳板必须继承 CLI BatchMode/StrictHostKeyChecking")
	}
	pk, ok := hop0.Auth().(*inventory.AuthPrivateKey)
	if !ok || pk.KeyPaths().Slice()[0].String() != "/keys/bastion_id" {
		t.Fatalf("虚拟跳板不应被叶节点 -i 覆盖，期望 /keys/bastion_id，实际=%#v", hop0.Auth())
	}
}

func assertWildcardVirtualJumpOriginSettlesBeforeT1(t *testing.T) {
	t.Helper()
	wildHN, _ := option.ParseHostNameSpec("198.51.100.55")
	wildKey, _ := option.ParsePathListEntries([]string{"/keys/wild_jump_id"})
	leafKey, _ := option.ParsePathListEntries([]string{"/keys/leaf_only_id"})
	spy := &spyOpenSSHSource{
		tiers: map[string]option.OptionLayer{
			"corp_gw": option.UnsetOptionLayer().
				WithHostName(wildHN).
				WithIdentityFiles(wildKey).
				WithIdentitiesOnly(true),
		},
	}
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH: spy,
		Env:     mustLocalEnv(t, nil),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cli := option.UnsetOptionLayer().
		WithProxyRoute(mustProxyJump(t, "corp_gw")).
		WithBatchMode(true).
		WithIdentityFiles(leafKey).
		WithIdentitiesOnly(true)
	res, err := svc.ResolveTarget(context.Background(), ucinv.ResolveTargetRequest{
		Target:     "ops@198.51.100.66",
		CLIOptions: cli,
	})
	if err != nil {
		t.Fatalf("ResolveTarget(wildcard jump): %v", err)
	}
	hop0, _ := res.Plan().HopAt(0)
	pk, ok := hop0.Auth().(*inventory.AuthPrivateKey)
	if !ok || pk.KeyPaths().Slice()[0].String() != "/keys/wild_jump_id" {
		t.Fatalf("通配符虚拟跳板升级后不得被叶节点认证兜底污染，期望 /keys/wild_jump_id，实际=%#v", hop0.Auth())
	}
}

func assertResolveTier4CandidateEndpointUsesT1AndT3(t *testing.T) {
	t.Helper()
	overrideHN, _ := option.ParseHostNameSpec("198.51.100.88")
	spy := &spyOpenSSHSource{
		seenEP: make(map[string]algebraic.Option[netaddr.Endpoint]),
	}
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH:       spy,
		Env:           mustLocalEnv(t, nil),
		GlobalOptions: option.UnsetOptionLayer().WithPort(2288),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	_, err = svc.ResolveTarget(context.Background(), ucinv.ResolveTargetRequest{
		Target:     "ops@198.51.100.1",
		CLIOptions: option.UnsetOptionLayer().WithHostName(overrideHN),
	})
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	ep, ok := spy.seenEP["198.51.100.1"].Get()
	if !ok || ep.String() != "198.51.100.88:2288" {
		t.Fatalf("ResolveTier4 候选端点失配，期望 198.51.100.88:2288，实际 ok=%v ep=%v", ok, ep)
	}
}

func assertPercentExpansionSingleBoundaryRejectsPercent(t *testing.T) {
	t.Helper()
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		Env: mustLocalEnv(t, map[string]string{"BAD_PCT": "bad%hval"}),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	for _, rawPath := range []string{"/keys/my%%h_key", "/keys/${BAD_PCT}_key"} {
		pl, pErr := option.ParsePathListEntries([]string{rawPath})
		if pErr != nil {
			t.Fatalf("ParsePathListEntries(%q): %v", rawPath, pErr)
		}
		_, rErr := svc.ResolveTarget(context.Background(), ucinv.ResolveTargetRequest{
			Target:     "ops@198.51.100.1",
			CLIOptions: option.UnsetOptionLayer().WithIdentityFiles(pl).WithIdentitiesOnly(true).WithBatchMode(true),
		})
		if !errors.Is(rErr, ucinv.ErrInvalidTarget) {
			t.Fatalf("含残留 %% 路径 %q 必须单边界失败关闭返回 ErrInvalidTarget，实际=%v", rawPath, rErr)
		}
	}
}
