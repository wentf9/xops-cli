package cmdops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

type doctorArgs struct {
	common         clikit.CommonFlags
	scope          string
	checkVault     bool
	checkKeys      bool
	skipVaultProbe bool
}

type doctorAggregateView struct {
	OK        bool                        `json:"ok"`
	Healthy   bool                        `json:"healthy"`
	Scope     string                      `json:"scope"`
	Inventory *engine.InventoryDoctorRep  `json:"inventory,omitzero"`
	Vault     *engine.CredentialDoctorRep `json:"vault,omitzero"`
	VaultNote string                      `json:"vault_note,omitzero"`
}

// RunDoctor 执行 `xops doctor` 只读零泄露系统健康诊断（整合 InventoryDoctor 与 VaultDoctor）。
func RunDoctor(ctx context.Context, rt *clikit.Runtime, args []string) int {
	parsed, err := parseDoctorArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, DoctorHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.common.JSON)
	initOpts := rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		return executeDoctor(ctx, rt, runner, parsed, jsonOut)
	})
}

func executeDoctor(ctx context.Context, rt *clikit.Runtime, runner clikit.SessionRunner, parsed doctorArgs, jsonOut bool) int {
	view := doctorAggregateView{OK: true, Healthy: true, Scope: parsed.scope}
	if parsed.scope == "all" || parsed.scope == "inventory" {
		invClient, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		rep, err := invClient.InventoryDoctor(ctx, engine.InventoryDoctorRequest{
			CheckVaultSecrets: parsed.checkVault,
			CheckPrivateKeys:  parsed.checkKeys,
		})
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		view.Inventory = &rep
		if !rep.Healthy {
			view.Healthy = false
		}
	}
	if parsed.scope == "all" || parsed.scope == "vault" {
		if code := runVaultDoctorSection(ctx, rt, runner, parsed, &view, jsonOut); code != clikit.ExitOK {
			return code
		}
	}
	code := clikit.ExitOK
	if !view.Healthy {
		code = clikit.ExitGeneral
	}
	if rt.WriteResult(jsonOut, view, func(w io.Writer) { renderDoctorText(w, view) }) != clikit.ExitOK {
		return clikit.ExitGeneral
	}
	return code
}

func runVaultDoctorSection(ctx context.Context, rt *clikit.Runtime, runner clikit.SessionRunner, parsed doctorArgs, view *doctorAggregateView, jsonOut bool) int {
	vClient, err := requireVaultClient(runner)
	if err != nil {
		if parsed.scope == "vault" {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		view.VaultNote = "vault capability not available on current runner"
		return clikit.ExitOK
	}
	rep, err := vClient.VaultDoctor(ctx, engine.VaultDoctorRequest{SkipSecretProbe: parsed.skipVaultProbe})
	if err != nil {
		if parsed.scope == "all" && errors.Is(err, engine.ErrVaultUnavailable) {
			view.VaultNote = "vault not configured"
			return clikit.ExitOK
		}
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	view.Vault = &rep
	if !rep.Healthy {
		view.Healthy = false
	}
	return clikit.ExitOK
}

func renderDoctorText(w io.Writer, view doctorAggregateView) {
	_, _ = fmt.Fprintf(w, "doctor scope=%s healthy=%v\n", view.Scope, view.Healthy)
	if view.Inventory != nil {
		inv := view.Inventory
		_, _ = fmt.Fprintf(w, "  inventory: healthy=%v hosts=%d identities=%d nodes=%d dag_depth=%d errors=%d warns=%d\n",
			inv.Healthy, inv.HostCount, inv.IdentityCount, inv.NodeCount, inv.DAGMaxDepth, inv.ErrorCount, inv.WarnCount)
		for _, f := range inv.Findings {
			_, _ = fmt.Fprintf(w, "    [%s] %s (%s): %s\n", f.Severity, f.Code, f.Subject, f.Message)
		}
	}
	if view.Vault != nil {
		v := view.Vault
		_, _ = fmt.Fprintf(w, "  vault: healthy=%v refs=%d distinct=%d findings=%d\n",
			v.Healthy, v.ReferencedCount, v.DistinctRefCount, len(v.Findings))
		for _, f := range v.Findings {
			_, _ = fmt.Fprintf(w, "    [%s] %s (%s): %s\n", f.Severity, f.Code, f.Subject, f.Message)
		}
	} else if view.VaultNote != "" {
		_, _ = fmt.Fprintf(w, "  vault: %s\n", view.VaultNote)
	}
}

func parseDoctorArgs(args []string) (doctorArgs, error) {
	out := doctorArgs{scope: "all"}
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseDoctorToken(cur, &out); err != nil {
			return doctorArgs{}, err
		}
		if out.common.ShowHelp {
			return out, nil
		}
	}
	return out, nil
}

func parseDoctorToken(cur *clikit.FlagCursor, out *doctorArgs) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &out.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	if tok == "-h" {
		out.common.ShowHelp = true
		return nil
	}
	return applyDoctorLongFlag(cur, tok, out)
}

func applyDoctorLongFlag(cur *clikit.FlagCursor, rawTok string, out *doctorArgs) error {
	name, inlineVal, hasEq := clikit.SplitLongFlag(rawTok)
	switch name {
	case "scope":
		val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return err
		}
		s := strings.ToLower(strings.TrimSpace(val))
		if s != "all" && s != "inventory" && s != "vault" {
			return fmt.Errorf("%w: --scope 必须为 all|inventory|vault，实际=%q", clikit.ErrUsage, val)
		}
		out.scope = s
		return nil
	case "check-vault":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.checkVault = v
		return err
	case "check-keys":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.checkKeys = v
		return err
	case "skip-vault-probe":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.skipVaultProbe = v
		return err
	default:
		return fmt.Errorf("%w: doctor 未知选项 %q", clikit.ErrUsage, rawTok)
	}
}
