package cmdasset

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

// RunHosts 执行 `xops hosts`（别名 `host` / `inventory`）全量资产查询、目标解析、DAG 校验与 CAS CRUD 命令。
func RunHosts(ctx context.Context, rt *clikit.Runtime, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(rt.Stdout, HostsHelpText())
		return clikit.ExitOK
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "list", "ls":
		return runHostsList(ctx, rt, rest)
	case "get", "show":
		return runHostsGet(ctx, rt, rest)
	case "resolve":
		return runHostsResolve(ctx, rt, rest)
	case "validate-dag":
		return runHostsValidateDAG(ctx, rt, rest)
	case "check-secret-refs":
		return runHostsCheckSecretRefs(ctx, rt, rest)
	case "add-host", "create-host", "update-host":
		return runHostUpsert(ctx, rt, sub == "update-host", rest)
	case "delete-host":
		return runAssetDelete(ctx, rt, "host", rest)
	case "add-identity", "create-identity", "update-identity":
		return runIdentityUpsert(ctx, rt, sub == "update-identity", rest)
	case "delete-identity":
		return runAssetDelete(ctx, rt, "identity", rest)
	case "add-node", "create-node", "update-node":
		return runNodeUpsert(ctx, rt, sub == "update-node", rest)
	case "delete-node":
		return runAssetDelete(ctx, rt, "node", rest)
	default:
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(rest)), fmt.Errorf("%w: 未知 hosts 子命令 %q", clikit.ErrUsage, sub))
	}
}

type hostsListFlags struct {
	common    clikit.CommonFlags
	kind      string
	filterTag string
}

func runHostsList(ctx context.Context, rt *clikit.Runtime, args []string) int {
	f, err := parseHostsListFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, HostsHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		return executeHostsList(ctx, rt, client, f.kind, f.filterTag, jsonOut)
	})
}

func parseHostsListFlags(args []string) (hostsListFlags, error) {
	f := hostsListFlags{kind: "nodes"}
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseHostsListToken(cur, &f); err != nil {
			return f, err
		}
		if f.common.ShowHelp {
			return f, nil
		}
	}
	return f, nil
}

func parseHostsListToken(cur *clikit.FlagCursor, f *hostsListFlags) error {
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
		return fmt.Errorf("%w: hosts list 未知参数 %q", clikit.ErrUsage, tok)
	}
	val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	switch name {
	case "kind":
		f.kind = strings.ToLower(strings.TrimSpace(val))
	case "tag":
		f.filterTag = strings.TrimSpace(val)
	default:
		return fmt.Errorf("%w: hosts list 未知参数 %q", clikit.ErrUsage, tok)
	}
	return nil
}

func executeHostsList(ctx context.Context, rt *clikit.Runtime, client clikit.InventoryClient, kind, filterTag string, jsonOut bool) int {
	switch kind {
	case "nodes", "node":
		return renderNodesList(ctx, rt, client, filterTag, jsonOut)
	case "hosts", "host":
		return renderHostsList(ctx, rt, client, jsonOut)
	case "identities", "identity":
		return renderIdentitiesList(ctx, rt, client, jsonOut)
	case "all":
		return renderAllAssetsList(ctx, rt, client, jsonOut)
	default:
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: --kind 必须为 nodes|hosts|identities|all，实际=%q", clikit.ErrUsage, kind))
	}
}

func renderNodesList(ctx context.Context, rt *clikit.Runtime, client clikit.InventoryClient, filterTag string, jsonOut bool) int {
	nodes, rev, err := client.ListNodes(ctx, engine.InventoryQueryRequest{})
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	nodes = filterNodesByTag(nodes, filterTag)
	type view struct {
		OK       bool             `json:"ok"`
		Revision engine.Revision  `json:"revision"`
		Nodes    []inventory.Node `json:"nodes"`
	}
	return rt.WriteResult(jsonOut, view{OK: true, Revision: rev, Nodes: nodes}, func(w io.Writer) {
		for _, n := range nodes {
			_, _ = fmt.Fprintf(w, "%-20s host=%-18s identity=%-18s origin=%s\n", n.ID(), n.HostRef(), n.IdentityRef(), n.OriginKind())
		}
	})
}

func renderHostsList(ctx context.Context, rt *clikit.Runtime, client clikit.InventoryClient, jsonOut bool) int {
	hosts, rev, err := client.ListHosts(ctx, engine.InventoryQueryRequest{})
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	type view struct {
		OK       bool             `json:"ok"`
		Revision engine.Revision  `json:"revision"`
		Hosts    []inventory.Host `json:"hosts"`
	}
	return rt.WriteResult(jsonOut, view{OK: true, Revision: rev, Hosts: hosts}, func(w io.Writer) {
		for _, h := range hosts {
			_, _ = fmt.Fprintf(w, "%-20s endpoint=%s\n", h.ID(), h.Endpoint())
		}
	})
}

func renderIdentitiesList(ctx context.Context, rt *clikit.Runtime, client clikit.InventoryClient, jsonOut bool) int {
	idents, rev, err := client.ListIdentities(ctx, engine.InventoryQueryRequest{})
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	type view struct {
		OK         bool                 `json:"ok"`
		Revision   engine.Revision      `json:"revision"`
		Identities []inventory.Identity `json:"identities"`
	}
	return rt.WriteResult(jsonOut, view{OK: true, Revision: rev, Identities: idents}, func(w io.Writer) {
		for _, id := range idents {
			_, _ = fmt.Fprintf(w, "%-20s user=%-14s auth=%s\n", id.ID(), id.User(), id.Auth().Kind())
		}
	})
}

func renderAllAssetsList(ctx context.Context, rt *clikit.Runtime, client clikit.InventoryClient, jsonOut bool) int {
	snap, err := client.GetInventorySnapshot(ctx, engine.InventoryQueryRequest{})
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	g := snap.Graph()
	type view struct {
		OK         bool                 `json:"ok"`
		Revision   engine.Revision      `json:"revision"`
		Hosts      []inventory.Host     `json:"hosts"`
		Identities []inventory.Identity `json:"identities"`
		Nodes      []inventory.Node     `json:"nodes"`
	}
	return rt.WriteResult(jsonOut, view{OK: true, Revision: snap.Revision(), Hosts: g.Hosts(), Identities: g.Identities(), Nodes: g.Nodes()}, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "revision=%s hosts=%d identities=%d nodes=%d\n", snap.Revision(), len(g.Hosts()), len(g.Identities()), len(g.Nodes()))
	})
}

func filterNodesByTag(nodes []inventory.Node, filterTag string) []inventory.Node {
	if filterTag == "" {
		return nodes
	}
	var out []inventory.Node
	for _, n := range nodes {
		for _, t := range n.Tags() {
			if t.String() == filterTag {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

type hostsGetFlags struct {
	common clikit.CommonFlags
	kind   string
	pos    []string
}

func runHostsGet(ctx context.Context, rt *clikit.Runtime, args []string) int {
	f, err := parseHostsGetFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, HostsHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	if len(f.pos) != 1 {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: hosts get 需要恰好 1 个资产 ID", clikit.ErrUsage))
	}
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		return executeHostsGet(ctx, rt, client, f.kind, f.pos[0], jsonOut)
	})
}

func parseHostsGetFlags(args []string) (hostsGetFlags, error) {
	f := hostsGetFlags{kind: "node"}
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseHostsGetToken(cur, &f); err != nil {
			return f, err
		}
		if f.common.ShowHelp {
			return f, nil
		}
	}
	return f, nil
}

func parseHostsGetToken(cur *clikit.FlagCursor, f *hostsGetFlags) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &f.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	if tok == "-h" {
		f.common.ShowHelp = true
		return nil
	}
	if strings.HasPrefix(tok, "-") && tok != "-" {
		name, inlineVal, hasEq, isLong := clikit.ParseLongFlagName(tok)
		if !isLong || name != "kind" {
			return fmt.Errorf("%w: hosts get 未知参数 %q", clikit.ErrUsage, tok)
		}
		val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return err
		}
		f.kind = strings.ToLower(strings.TrimSpace(val))
		return nil
	}
	f.pos = append(f.pos, tok)
	return nil
}

func executeHostsGet(ctx context.Context, rt *clikit.Runtime, client clikit.InventoryClient, kind, rawID string, jsonOut bool) int {
	switch kind {
	case "node":
		return renderGetNode(ctx, rt, client, rawID, jsonOut)
	case "host":
		return renderGetHost(ctx, rt, client, rawID, jsonOut)
	case "identity":
		return renderGetIdentity(ctx, rt, client, rawID, jsonOut)
	default:
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: --kind 必须为 node|host|identity，实际=%q", clikit.ErrUsage, kind))
	}
}

func renderGetNode(ctx context.Context, rt *clikit.Runtime, client clikit.InventoryClient, rawID string, jsonOut bool) int {
	id, err := inventory.ParseNodeID(rawID)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: NodeID 非法: %w", clikit.ErrUsage, err))
	}
	item, rev, err := client.GetNode(ctx, id, engine.InventoryQueryRequest{})
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	type view struct {
		OK       bool            `json:"ok"`
		Revision engine.Revision `json:"revision"`
		Node     inventory.Node  `json:"node"`
	}
	return rt.WriteResult(jsonOut, view{OK: true, Revision: rev, Node: item}, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "node=%s host=%s identity=%s origin=%s revision=%s\n", item.ID(), item.HostRef(), item.IdentityRef(), item.OriginKind(), rev)
	})
}

func renderGetHost(ctx context.Context, rt *clikit.Runtime, client clikit.InventoryClient, rawID string, jsonOut bool) int {
	id, err := inventory.ParseHostID(rawID)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: HostID 非法: %w", clikit.ErrUsage, err))
	}
	item, rev, err := client.GetHost(ctx, id, engine.InventoryQueryRequest{})
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	type view struct {
		OK       bool            `json:"ok"`
		Revision engine.Revision `json:"revision"`
		Host     inventory.Host  `json:"host"`
	}
	return rt.WriteResult(jsonOut, view{OK: true, Revision: rev, Host: item}, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "host=%s endpoint=%s revision=%s\n", item.ID(), item.Endpoint(), rev)
	})
}

func renderGetIdentity(ctx context.Context, rt *clikit.Runtime, client clikit.InventoryClient, rawID string, jsonOut bool) int {
	id, err := inventory.ParseIdentityID(rawID)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: IdentityID 非法: %w", clikit.ErrUsage, err))
	}
	item, rev, err := client.GetIdentity(ctx, id, engine.InventoryQueryRequest{})
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	type view struct {
		OK       bool               `json:"ok"`
		Revision engine.Revision    `json:"revision"`
		Identity inventory.Identity `json:"identity"`
	}
	return rt.WriteResult(jsonOut, view{OK: true, Revision: rev, Identity: item}, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "identity=%s user=%s auth=%s revision=%s\n", item.ID(), item.User(), item.Auth().Kind(), rev)
	})
}
