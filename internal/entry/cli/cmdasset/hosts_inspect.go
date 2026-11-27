package cmdasset

import (
	"context"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type hostsResolveFlags struct {
	common  clikit.CommonFlags
	cliOpts option.OptionLayer
	pos     []string
}

func runHostsResolve(ctx context.Context, rt *clikit.Runtime, args []string) int {
	f, err := parseHostsResolveFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("hosts", args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, HostsHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	if len(f.pos) != 1 || strings.TrimSpace(f.pos[0]) == "" {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.Str("cmd", "hosts resolve"), i18n.Int("count", 1), i18n.Str("usage", "<target>")))
	}
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		res, err := client.ResolveTarget(ctx, engine.ResolveTargetRequest{Target: f.pos[0], CLIOptions: f.cliOpts})
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		return renderResolvedTarget(rt, res, jsonOut)
	})
}

func parseHostsResolveFlags(args []string) (hostsResolveFlags, error) {
	f := hostsResolveFlags{cliOpts: option.UnsetOptionLayer()}
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		done, err := parseHostsResolveToken(cur, &f)
		if err != nil {
			return f, err
		}
		if done || f.common.ShowHelp {
			break
		}
	}
	return f, nil
}

func parseHostsResolveToken(cur *clikit.FlagCursor, f *hostsResolveFlags) (bool, error) {
	tok := cur.Peek()
	if tok == "--" {
		cur.Next()
		f.pos = append(f.pos, cur.Rest()...)
		return true, nil
	}
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &f.common); err != nil || consumed {
		return false, err
	}
	if strings.HasPrefix(tok, "-") && tok != "-" {
		cur.Next()
		return false, parseResolveShortCluster(cur, tok[1:], &f.cliOpts, &f.common)
	}
	f.pos = append(f.pos, cur.Next())
	return false, nil
}

func parseResolveShortCluster(cur *clikit.FlagCursor, cluster string, layer *option.OptionLayer, common *clikit.CommonFlags) error {
	if cluster == "" {
		return nil
	}
	ch := cluster[0]
	rest := cluster[1:]
	if ch == 'h' {
		common.ShowHelp = true
		return nil
	}
	if ok, err := clikit.ApplyCommonSSHShortOption(cur, ch, rest, layer, &common.ConfigFile); ok || err != nil {
		return err
	}
	r, _ := utf8.DecodeRuneInString(cluster)
	return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownShortFlag, i18n.BoundStr("flag", string(r)))
}

func renderResolvedTarget(rt *clikit.Runtime, res engine.ResolvedTarget, jsonOut bool) int {
	targetHop, _ := res.Plan().Target()
	type view struct {
		OK         bool   `json:"ok"`
		NodeID     string `json:"node_id"`
		Origin     string `json:"origin"`
		Endpoint   string `json:"endpoint"`
		HopCount   int    `json:"hop_count"`
		PlanDigest string `json:"plan_digest"`
	}
	v := view{
		OK:         true,
		NodeID:     res.NodeID(),
		Origin:     res.OriginKind().String(),
		Endpoint:   targetHop.Endpoint().String(),
		HopCount:   res.Plan().Len(),
		PlanDigest: res.Plan().PlanDigest().String(),
	}
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, v, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(
			i18n.KeyCLIHostsResolved,
			i18n.BoundStr("node", v.NodeID),
			i18n.Str("origin", v.Origin),
			i18n.BoundStr("endpoint", v.Endpoint),
			i18n.Int("hops", v.HopCount),
			i18n.Str("digest", v.PlanDigest),
		))
	})
}

func runHostsValidateDAG(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, err := parseCommonOnly("validate-dag", args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("hosts", args)), err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, HostsHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	initOpts := rt.EffectiveInitOptions(common.ConfigFile, common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		rep, err := client.ValidateDAG(ctx, engine.InventoryQueryRequest{})
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		loc := rt.Loc()
		return rt.WriteResult(jsonOut, rep, func(w io.Writer) {
			_, _ = fmt.Fprintln(w, loc.T(
				i18n.KeyCLIHostsDAGValid,
				i18n.Int("max_depth", rep.MaxObservedDepth),
				i18n.Int("nodes", len(rep.TopoOrder)),
				i18n.Int("cycles", len(rep.Cycles)),
			))
		})
	})
}

type secretRefCheckFlags struct {
	common  clikit.CommonFlags
	refRaw  string
	storeID string
}

func runHostsCheckSecretRefs(ctx context.Context, rt *clikit.Runtime, args []string) int {
	f, err := parseSecretRefCheckFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("hosts", args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, HostsHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	req, err := buildSecretRefCheckReq(f.refRaw, f.storeID)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		refs, err := client.CheckSecretReferences(ctx, req)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		type view struct {
			OK         bool                        `json:"ok"`
			References []inventory.SecretReference `json:"references"`
		}
		loc := rt.Loc()
		return rt.WriteResult(jsonOut, view{OK: true, References: refs}, func(w io.Writer) {
			_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLIHostsFoundRefs, i18n.Int("count", len(refs))))
			for _, r := range refs {
				_, _ = fmt.Fprintf(w, "  %s owner=%s ref=%s\n", r.Location, r.OwnerID, r.Ref)
			}
		})
	})
}

func parseSecretRefCheckFlags(args []string) (secretRefCheckFlags, error) {
	var f secretRefCheckFlags
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseSecretRefCheckToken(cur, &f); err != nil {
			return f, err
		}
		if f.common.ShowHelp {
			return f, nil
		}
	}
	return f, nil
}

func parseSecretRefCheckToken(cur *clikit.FlagCursor, f *secretRefCheckFlags) error {
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
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", tok))
	}
	val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	switch name {
	case "ref":
		f.refRaw = val
	case "store":
		f.storeID = val
	default:
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", tok))
	}
	return nil
}

func buildSecretRefCheckReq(refRaw, storeID string) (engine.SecretRefCheckRequest, error) {
	hasRef, hasStore := strings.TrimSpace(refRaw) != "", strings.TrimSpace(storeID) != ""
	if hasRef == hasStore {
		return engine.SecretRefCheckRequest{}, i18n.EF(clikit.ErrUsage, i18n.KeyCLIExactlyOneFlagRequired, i18n.Str("flag_a", "--ref"), i18n.Str("flag_b", "--store"))
	}
	var req engine.SecretRefCheckRequest
	if hasRef {
		ref, err := secret.ParseRef(refRaw)
		if err != nil {
			return engine.SecretRefCheckRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--ref"), i18n.BoundStr("value", refRaw))
		}
		req.Ref = ref
	} else {
		req.StoreID = strings.TrimSpace(storeID)
	}
	return req, nil
}
