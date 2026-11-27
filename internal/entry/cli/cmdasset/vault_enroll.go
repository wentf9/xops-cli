package cmdasset

import (
	"context"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

type enrollPasswordFlags struct {
	common    clikit.CommonFlags
	idRaw     string
	userRaw   string
	refRaw    string
	store     string
	desc      string
	tags      []inventory.Tag
	expRevRaw string
	replace   bool
}

// runVaultEnrollPassword 通过 ExecuteVaultSagaInteractive 交互式采集口令并原子写入密码认证 Identity（零明文 CLI 参数）。
func runVaultEnrollPassword(ctx context.Context, rt *clikit.Runtime, args []string) int {
	f, err := parseEnrollPasswordFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	req, err := buildEnrollPasswordSagaReq(f)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireVaultClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		res, err := client.ExecuteVaultSagaInteractive(ctx, req)
		return renderSagaResult(rt, "enroll_password", res, err, jsonOut)
	})
}

func parseEnrollPasswordFlags(args []string) (enrollPasswordFlags, error) {
	var f enrollPasswordFlags
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseEnrollPasswordToken(cur, &f); err != nil {
			return f, err
		}
		if f.common.ShowHelp {
			return f, nil
		}
	}
	return f, nil
}

func parseEnrollPasswordToken(cur *clikit.FlagCursor, f *enrollPasswordFlags) error {
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
		return fmt.Errorf("%w: vault enroll-password 未知参数 %q", clikit.ErrUsage, tok)
	}
	if name == "replace" {
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		f.replace = v
		return err
	}
	val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	return applyEnrollPasswordFlag(name, val, tok, f)
}

func applyEnrollPasswordFlag(name, val, rawTok string, f *enrollPasswordFlags) error {
	switch name {
	case "id", "identity-id":
		f.idRaw = val
	case "user":
		f.userRaw = val
	case "ref":
		f.refRaw = val
	case "store":
		f.store = val
	case "desc", "description":
		f.desc = val
	case "tag", "tags":
		return parseTagsCSV(val, &f.tags)
	case "expected-revision":
		f.expRevRaw = val
	default:
		return fmt.Errorf("%w: vault enroll-password 未知选项 %q", clikit.ErrUsage, rawTok)
	}
	return nil
}

func buildEnrollPasswordSagaReq(f enrollPasswordFlags) (engine.InteractiveVaultSagaRequest, error) {
	id, err := inventory.ParseIdentityID(f.idRaw)
	if err != nil {
		return engine.InteractiveVaultSagaRequest{}, fmt.Errorf("%w: --id 非法: %w", clikit.ErrUsage, err)
	}
	user, err := option.ParseUsername(f.userRaw)
	if err != nil {
		return engine.InteractiveVaultSagaRequest{}, fmt.Errorf("%w: --user 非法: %w", clikit.ErrUsage, err)
	}
	newRef, store, err := parseTargetRefOrStore(f.refRaw, f.store, "enroll-password")
	if err != nil {
		return engine.InteractiveVaultSagaRequest{}, err
	}
	expRev, err := parseOptionalRevision(f.expRevRaw)
	if err != nil {
		return engine.InteractiveVaultSagaRequest{}, err
	}
	prompt, err := engine.NewSecretPromptRequest(engine.SecretPromptRequestSpec{
		Title: "Enroll SSH Password", Prompt: "Enter SSH login password", Subject: id.String(),
	})
	if err != nil {
		return engine.InteractiveVaultSagaRequest{}, err
	}
	return engine.InteractiveVaultSagaRequest{
		Prompt: prompt,
		Saga: engine.VaultSagaRequest{
			NewRef:           newRef,
			TargetStore:      store,
			ExpectedRevision: expRev,
			ScopeSummary:     "enroll password identity " + id.String(),
			MutateGraph: func(_ context.Context, snap engine.InventorySnapshot, ref secret.Ref) (inventory.Graph, error) {
				return upsertPasswordIdentityInGraph(snap.Graph(), id, user, ref, f.desc, f.tags, f.replace)
			},
		},
	}, nil
}

// upsertPasswordIdentityInGraph 在资产图快照中原子新增或替换密码认证 Identity，并保留全部既有元数据与 KnownStores。
func upsertPasswordIdentityInGraph(
	g inventory.Graph,
	id inventory.IdentityID,
	user option.Username,
	ref secret.Ref,
	desc string,
	tags []inventory.Tag,
	replace bool,
) (out inventory.Graph, err error) {
	auth, aErr := inventory.NewAuthPassword(ref)
	if aErr != nil {
		return out, aErr
	}
	ident, iErr := inventory.NewIdentity(inventory.IdentitySpec{ID: id, User: user, Auth: auth, Description: desc, Tags: tags})
	if iErr != nil {
		return out, iErr
	}
	idents := g.Identities()
	replaced := false
	for i, existing := range idents {
		if existing.ID() == id {
			if !replace {
				return out, fmt.Errorf("%w: identity %s 已存在（可传 --replace 覆盖）", engine.ErrAlreadyExists, id)
			}
			idents[i] = ident
			replaced = true
			break
		}
	}
	if !replaced {
		idents = append(idents, ident)
	}
	return inventory.NewGraph(inventory.GraphSpec{
		Hosts:        g.Hosts(),
		Identities:   idents,
		Nodes:        g.Nodes(),
		OpenSSHNodes: g.OpenSSHNodes(),
		KnownStores:  g.KnownStores(),
	})
}

type setNodePrivFlags struct {
	common    clikit.CommonFlags
	nodeRaw   string
	refRaw    string
	store     string
	expRevRaw string
}

// runVaultSetNodePrivilege 通过 ExecuteVaultSagaInteractive 交互式采集提权密码并原子绑定至目标 Node。
func runVaultSetNodePrivilege(ctx context.Context, rt *clikit.Runtime, args []string) int {
	f, err := parseSetNodePrivFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	req, err := buildSetNodePrivSagaReq(f)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireVaultClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		res, err := client.ExecuteVaultSagaInteractive(ctx, req)
		return renderSagaResult(rt, "set_node_privilege", res, err, jsonOut)
	})
}

func parseSetNodePrivFlags(args []string) (setNodePrivFlags, error) {
	var f setNodePrivFlags
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseSetNodePrivToken(cur, &f); err != nil {
			return f, err
		}
		if f.common.ShowHelp {
			return f, nil
		}
	}
	return f, nil
}

func parseSetNodePrivToken(cur *clikit.FlagCursor, f *setNodePrivFlags) error {
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
		return fmt.Errorf("%w: vault set-node-privilege 未知参数 %q", clikit.ErrUsage, tok)
	}
	val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	switch name {
	case "node", "node-id":
		f.nodeRaw = val
	case "ref":
		f.refRaw = val
	case "store":
		f.store = val
	case "expected-revision":
		f.expRevRaw = val
	default:
		return fmt.Errorf("%w: vault set-node-privilege 未知选项 %q", clikit.ErrUsage, tok)
	}
	return nil
}

func buildSetNodePrivSagaReq(f setNodePrivFlags) (engine.InteractiveVaultSagaRequest, error) {
	nodeID, err := inventory.ParseNodeID(f.nodeRaw)
	if err != nil {
		return engine.InteractiveVaultSagaRequest{}, fmt.Errorf("%w: --node 非法: %w", clikit.ErrUsage, err)
	}
	newRef, store, err := parseTargetRefOrStore(f.refRaw, f.store, "set-node-privilege")
	if err != nil {
		return engine.InteractiveVaultSagaRequest{}, err
	}
	expRev, err := parseOptionalRevision(f.expRevRaw)
	if err != nil {
		return engine.InteractiveVaultSagaRequest{}, err
	}
	prompt, err := engine.NewSecretPromptRequest(engine.SecretPromptRequestSpec{
		Title: "Set Node Privilege Secret", Prompt: "Enter sudo/su/doas privilege password", Subject: nodeID.String(),
	})
	if err != nil {
		return engine.InteractiveVaultSagaRequest{}, err
	}
	return engine.InteractiveVaultSagaRequest{
		Prompt: prompt,
		Saga: engine.VaultSagaRequest{
			NewRef:           newRef,
			TargetStore:      store,
			ExpectedRevision: expRev,
			ScopeSummary:     "set privilege secret for node " + nodeID.String(),
			MutateGraph: func(_ context.Context, snap engine.InventorySnapshot, ref secret.Ref) (inventory.Graph, error) {
				return bindNodePrivilegeInGraph(snap.Graph(), nodeID, ref)
			},
		},
	}, nil
}

// bindNodePrivilegeInGraph 在资产图快照中原子更新目标 Node 的提权密码引用，并保留全部其他属性与元数据。
func bindNodePrivilegeInGraph(g inventory.Graph, nodeID inventory.NodeID, ref secret.Ref) (out inventory.Graph, err error) {
	nodes := g.Nodes()
	for i, existing := range nodes {
		if existing.ID() != nodeID {
			continue
		}
		updated, nErr := inventory.NewNode(inventory.NodeSpec{
			ID:                   existing.ID(),
			HostRef:              existing.HostRef(),
			IdentityRef:          existing.IdentityRef(),
			Aliases:              existing.Aliases(),
			Tags:                 existing.Tags(),
			Proxy:                existing.Proxy(),
			Execution:            existing.Execution(),
			Options:              existing.Options(),
			PrivilegePasswordRef: algebraic.Some(ref),
			Origin:               existing.Origin(),
			Description:          existing.Description(),
		})
		if nErr != nil {
			return out, nErr
		}
		nodes[i] = updated
		return inventory.NewGraph(inventory.GraphSpec{
			Hosts:        g.Hosts(),
			Identities:   g.Identities(),
			Nodes:        nodes,
			OpenSSHNodes: g.OpenSSHNodes(),
			KnownStores:  g.KnownStores(),
		})
	}
	return out, fmt.Errorf("%w: node %s 不存在", engine.ErrNotFound, nodeID)
}
