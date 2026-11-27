package cmdasset

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

type nodeUpsertFlags struct {
	common      clikit.CommonFlags
	idRaw       string
	hostRaw     string
	identRaw    string
	aliases     []inventory.Alias
	tags        []inventory.Tag
	jumpRaw     string
	proxyCmdRaw string
	dialectRaw  string
	interpRaw   string
	loginRaw    string
	privRefRaw  string
	desc        string
	expRevRaw   string
	gcOld       bool
}

func runNodeUpsert(ctx context.Context, rt *clikit.Runtime, isUpdate bool, args []string) int {
	f, err := parseNodeUpsertFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, HostsHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	req, err := buildNodeMutationReq(f)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		var res engine.MutationResult
		action := "create_node"
		if isUpdate {
			action = "update_node"
			res, err = client.UpdateNode(ctx, req)
		} else {
			res, err = client.CreateNode(ctx, req)
		}
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		return renderMutationResult(rt, action, res, jsonOut)
	})
}

func parseNodeUpsertFlags(args []string) (nodeUpsertFlags, error) {
	var f nodeUpsertFlags
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseNodeToken(cur, &f); err != nil {
			return f, err
		}
		if f.common.ShowHelp {
			return f, nil
		}
	}
	return f, nil
}

func parseNodeToken(cur *clikit.FlagCursor, f *nodeUpsertFlags) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &f.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	if tok == "-h" {
		f.common.ShowHelp = true
		return nil
	}
	name, inlineVal, hasEq, isLong := clikit.ParseLongFlagName(tok)
	if !isLong {
		return fmt.Errorf("%w: node 未知参数 %q", clikit.ErrUsage, tok)
	}
	if name == "gc-old-secrets" {
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		f.gcOld = v
		return err
	}
	val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	return applyNodeFlagValue(name, val, tok, f)
}

func applyNodeFlagValue(name, val, rawTok string, f *nodeUpsertFlags) error {
	switch name {
	case "id":
		f.idRaw = val
	case "host":
		f.hostRaw = val
	case "identity":
		f.identRaw = val
	case "alias", "aliases":
		return parseAliasesCSV(val, &f.aliases)
	case "tag", "tags":
		return parseTagsCSV(val, &f.tags)
	case "jump", "proxy-jump":
		f.jumpRaw = val
	case "proxy-command":
		f.proxyCmdRaw = val
	case "dialect":
		f.dialectRaw = val
	case "interpreter":
		f.interpRaw = val
	case "login":
		f.loginRaw = val
	case "priv-password-ref":
		f.privRefRaw = val
	case "desc", "description":
		f.desc = val
	case "expected-revision":
		f.expRevRaw = val
	default:
		return fmt.Errorf("%w: node 未知选项 %q", clikit.ErrUsage, rawTok)
	}
	return nil
}

func buildNodeMutationReq(f nodeUpsertFlags) (engine.NodeMutationRequest, error) {
	id, err := inventory.ParseNodeID(f.idRaw)
	if err != nil {
		return engine.NodeMutationRequest{}, fmt.Errorf("%w: --id 非法: %w", clikit.ErrUsage, err)
	}
	hostID, err := inventory.ParseHostID(f.hostRaw)
	if err != nil {
		return engine.NodeMutationRequest{}, fmt.Errorf("%w: --host 非法: %w", clikit.ErrUsage, err)
	}
	identID, err := inventory.ParseIdentityID(f.identRaw)
	if err != nil {
		return engine.NodeMutationRequest{}, fmt.Errorf("%w: --identity 非法: %w", clikit.ErrUsage, err)
	}
	proxy, err := buildNodeProxyRoute(f.jumpRaw, f.proxyCmdRaw)
	if err != nil {
		return engine.NodeMutationRequest{}, err
	}
	profOpt, err := buildOptionalNodeProfile(f.dialectRaw, f.interpRaw, f.loginRaw)
	if err != nil {
		return engine.NodeMutationRequest{}, err
	}
	var privOpt algebraic.Option[secret.Ref]
	if strings.TrimSpace(f.privRefRaw) != "" {
		ref, err := secret.ParseRef(f.privRefRaw)
		if err != nil {
			return engine.NodeMutationRequest{}, fmt.Errorf("%w: --priv-password-ref 非法: %w", clikit.ErrUsage, err)
		}
		privOpt = algebraic.Some(ref)
	}
	expRev, err := parseOptionalRevision(f.expRevRaw)
	if err != nil {
		return engine.NodeMutationRequest{}, err
	}
	node, err := inventory.NewNode(inventory.NodeSpec{
		ID: id, HostRef: hostID, IdentityRef: identID, Aliases: f.aliases, Tags: f.tags,
		Proxy: proxy, Execution: profOpt, PrivilegePasswordRef: privOpt,
		Origin: inventory.NewOriginManaged(), Description: f.desc,
	})
	if err != nil {
		return engine.NodeMutationRequest{}, fmt.Errorf("%w: %w", clikit.ErrUsage, err)
	}
	return engine.NodeMutationRequest{Node: node, ExpectedRevision: expRev, GCUnreferencedOldSecrets: f.gcOld}, nil
}

func buildNodeProxyRoute(jumpRaw, proxyCmdRaw string) (option.ProxyRoute, error) {
	hasJump, hasCmd := strings.TrimSpace(jumpRaw) != "", strings.TrimSpace(proxyCmdRaw) != ""
	if hasJump && hasCmd {
		return nil, fmt.Errorf("%w: --jump 与 --proxy-command 不能同时指定", clikit.ErrUsage)
	}
	if hasJump {
		p, err := option.ParseOptionKV("ProxyJump", jumpRaw)
		if err != nil {
			return nil, fmt.Errorf("%w: --jump 非法: %w", clikit.ErrUsage, err)
		}
		return p.Layer().Proxy(), nil
	}
	if hasCmd {
		p, err := option.ParseOptionKV("ProxyCommand", proxyCmdRaw)
		if err != nil {
			return nil, fmt.Errorf("%w: --proxy-command 非法: %w", clikit.ErrUsage, err)
		}
		return p.Layer().Proxy(), nil
	}
	return option.NewProxyUnset(), nil
}

func buildOptionalNodeProfile(dialectRaw, interpRaw, loginRaw string) (algebraic.Option[execution.LaunchProfile], error) {
	var dOpt algebraic.Option[execution.LaunchDialect]
	if strings.TrimSpace(dialectRaw) != "" {
		d, err := execution.ParseLaunchDialect(dialectRaw)
		if err != nil {
			return algebraic.None[execution.LaunchProfile](), fmt.Errorf("%w: --dialect 非法: %w", clikit.ErrUsage, err)
		}
		dOpt = algebraic.Some(d)
	}
	var interp execution.Interpreter
	if strings.TrimSpace(interpRaw) != "" {
		var err error
		interp, err = execution.ParseInterpreter(interpRaw)
		if err != nil {
			return algebraic.None[execution.LaunchProfile](), fmt.Errorf("%w: --interpreter 非法: %w", clikit.ErrUsage, err)
		}
	}
	var login execution.LoginMode
	if strings.TrimSpace(loginRaw) != "" {
		var err error
		login, err = execution.ParseLoginMode(loginRaw)
		if err != nil {
			return algebraic.None[execution.LaunchProfile](), fmt.Errorf("%w: --login 非法: %w", clikit.ErrUsage, err)
		}
	}
	return clikit.BuildOptionalLaunchProfile(dOpt, interp, login)
}

type assetDeleteFlags struct {
	common    clikit.CommonFlags
	expRevRaw string
	delUnused bool
	reqUnref  bool
	pos       []string
}

func runAssetDelete(ctx context.Context, rt *clikit.Runtime, kind string, args []string) int {
	f, err := parseAssetDeleteFlags(kind, args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, HostsHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	if len(f.pos) != 1 {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: delete-%s 需要恰好 1 个资产 ID", clikit.ErrUsage, kind))
	}
	expRev, err := parseOptionalRevision(f.expRevRaw)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	req := engine.DeleteAssetRequest{
		ID: f.pos[0], ExpectedRevision: expRev,
		DeleteUnusedSecrets: f.delUnused, RequireSecretsUnreferenced: f.reqUnref,
	}
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		res, err := dispatchDeleteAsset(ctx, client, kind, req)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		return renderMutationResult(rt, "delete_"+kind, res, jsonOut)
	})
}

func parseAssetDeleteFlags(kind string, args []string) (assetDeleteFlags, error) {
	var f assetDeleteFlags
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseAssetDeleteToken(cur, kind, &f); err != nil {
			return f, err
		}
		if f.common.ShowHelp {
			return f, nil
		}
	}
	return f, nil
}

func parseAssetDeleteToken(cur *clikit.FlagCursor, kind string, f *assetDeleteFlags) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &f.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	if tok == "-h" {
		f.common.ShowHelp = true
		return nil
	}
	if strings.HasPrefix(tok, "--") {
		return applyAssetDeleteLongFlag(cur, kind, tok, f)
	}
	if strings.HasPrefix(tok, "-") && tok != "-" {
		return fmt.Errorf("%w: delete-%s 未知选项 %q", clikit.ErrUsage, kind, tok)
	}
	f.pos = append(f.pos, tok)
	return nil
}

func applyAssetDeleteLongFlag(cur *clikit.FlagCursor, kind, tok string, f *assetDeleteFlags) error {
	name, inlineVal, hasEq := clikit.SplitLongFlag(tok)
	switch name {
	case "expected-revision":
		val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		f.expRevRaw = val
		return err
	case "delete-unused-secrets":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		f.delUnused = v
		return err
	case "require-unreferenced":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		f.reqUnref = v
		return err
	default:
		return fmt.Errorf("%w: delete-%s 未知选项 %q", clikit.ErrUsage, kind, tok)
	}
}

func dispatchDeleteAsset(ctx context.Context, client clikit.InventoryClient, kind string, req engine.DeleteAssetRequest) (engine.MutationResult, error) {
	switch kind {
	case "host":
		return client.DeleteHost(ctx, req)
	case "identity":
		return client.DeleteIdentity(ctx, req)
	default:
		return client.DeleteNode(ctx, req)
	}
}
