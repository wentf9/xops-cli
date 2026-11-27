package cmdops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
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
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("doctor", args)), err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, DoctorHelpText(rt.Loc()))
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
	loc := rt.Loc()
	if rt.WriteResult(jsonOut, view, func(w io.Writer) { renderDoctorText(loc, w, view) }) != clikit.ExitOK {
		return clikit.ExitGeneral
	}
	return code
}

func runVaultDoctorSection(ctx context.Context, rt *clikit.Runtime, runner clikit.SessionRunner, parsed doctorArgs, view *doctorAggregateView, jsonOut bool) int {
	loc := rt.Loc()
	vClient, err := requireVaultClient(runner)
	if err != nil {
		if parsed.scope == "vault" {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		view.VaultNote = loc.T(i18n.KeyCLIDoctorVaultNoCap)
		return clikit.ExitOK
	}
	rep, err := vClient.VaultDoctor(ctx, engine.VaultDoctorRequest{SkipSecretProbe: parsed.skipVaultProbe})
	if err != nil {
		if parsed.scope == "all" && errors.Is(err, engine.ErrVaultUnavailable) {
			view.VaultNote = loc.T(i18n.KeyCLIDoctorVaultNotConfigured)
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

func renderDoctorText(loc *i18n.Localizer, w io.Writer, view doctorAggregateView) {
	eff := clikit.EnsureLocalizer(loc)
	_, _ = fmt.Fprintln(w, eff.T(i18n.KeyCLIDoctorSummary,
		i18n.Str("scope", view.Scope),
		i18n.Bool("healthy", view.Healthy),
	))
	if view.Inventory != nil {
		inv := view.Inventory
		_, _ = fmt.Fprintln(w, eff.T(i18n.KeyCLIDoctorInventory,
			i18n.Bool("healthy", inv.Healthy),
			i18n.Int("hosts", inv.HostCount),
			i18n.Int("identities", inv.IdentityCount),
			i18n.Int("nodes", inv.NodeCount),
			i18n.Int("dag_depth", inv.DAGMaxDepth),
			i18n.Int("errors", inv.ErrorCount),
			i18n.Int("warns", inv.WarnCount),
		))
		for _, f := range inv.Findings {
			renderDoctorFindingLine(eff, w, f)
		}
	}
	if view.Vault != nil {
		v := view.Vault
		_, _ = fmt.Fprintln(w, eff.T(i18n.KeyCLIDoctorVault,
			i18n.Bool("healthy", v.Healthy),
			i18n.Int("refs", v.ReferencedCount),
			i18n.Int("distinct", v.DistinctRefCount),
			i18n.Int("findings", len(v.Findings)),
		))
		for _, f := range v.Findings {
			renderDoctorFindingLine(eff, w, f)
		}
	} else if view.VaultNote != "" {
		_, _ = fmt.Fprintln(w, eff.T(i18n.KeyCLIDoctorVaultNote, i18n.BoundStr("note", view.VaultNote)))
	}
}

func renderDoctorFindingLine(eff *i18n.Localizer, w io.Writer, f engine.DoctorFinding) {
	sev := doctorSeverityLabel(eff, f.Severity)
	msg := renderDoctorFindingMessage(eff, f)
	if f.Subject != "" {
		_, _ = fmt.Fprintln(w, eff.T(i18n.KeyCLIDoctorFindingLineSubj,
			i18n.BoundStr("severity", sev),
			i18n.BoundStr("code", f.Code),
			i18n.BoundStr("subject", f.Subject),
			i18n.BoundStr("message", msg),
		))
		return
	}
	_, _ = fmt.Fprintln(w, eff.T(i18n.KeyCLIDoctorFindingLine,
		i18n.BoundStr("severity", sev),
		i18n.BoundStr("code", f.Code),
		i18n.BoundStr("message", msg),
	))
}

func doctorSeverityLabel(eff *i18n.Localizer, sev engine.DoctorSeverity) string {
	switch sev {
	case engine.DoctorSeverityInfo:
		return eff.T(i18n.KeyCLIDoctorSevInfo)
	case engine.DoctorSeverityWarn:
		return eff.T(i18n.KeyCLIDoctorSevWarn)
	case engine.DoctorSeverityError:
		return eff.T(i18n.KeyCLIDoctorSevError)
	default:
		return sev.String()
	}
}

func renderDoctorFindingMessage(eff *i18n.Localizer, f engine.DoctorFinding) string {
	if msg, ok := f.Localized.Get(); ok && msg.IsValid() {
		head := eff.Render(msg)
		if f.Cause != nil {
			head = eff.T(domi18n.KeyCommonErrorJoin,
				i18n.BoundStr("head", head),
				i18n.BoundStr("tail", eff.RenderError(f.Cause)),
			)
		}
		return security.SanitizePromptText(head)
	}
	return security.SanitizePromptText(f.Message)
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
	name, inlineVal, hasEq, isLong := clikit.ParseLongFlagName(rawTok)
	if !isLong {
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnexpectedArg, i18n.BoundStr("arg", rawTok))
	}
	switch name {
	case "scope":
		val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return err
		}
		s := strings.ToLower(strings.TrimSpace(val))
		if s != "all" && s != "inventory" && s != "vault" {
			return i18n.EF(clikit.ErrUsage, i18n.KeyCLIInvalidFlagValueEnum, i18n.Str("flag", "--scope"), i18n.Str("allowed", "all|inventory|vault"), i18n.BoundStr("value", val))
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
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", rawTok))
	}
}
