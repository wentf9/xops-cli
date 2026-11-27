package cmdasset

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// RunVault 执行 `xops creds` 与 `xops vault` 凭据库全生命周期与安全回收子命令族。
func RunVault(ctx context.Context, rt *clikit.Runtime, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "status":
		return runVaultStatus(ctx, rt, rest)
	case "init":
		return runVaultInitOrUnlock(ctx, rt, true, rest)
	case "unlock":
		return runVaultInitOrUnlock(ctx, rt, false, rest)
	case "lock":
		return runVaultLock(ctx, rt, rest)
	case "doctor":
		return runVaultDoctor(ctx, rt, rest)
	case "refs":
		return runVaultRefs(ctx, rt, rest)
	case "delete", "rm":
		return runVaultDelete(ctx, rt, rest)
	case "gc":
		return runVaultGC(ctx, rt, rest)
	case "enroll-key":
		return runVaultEnrollKey(ctx, rt, rest)
	case "enroll-password":
		return runVaultEnrollPassword(ctx, rt, rest)
	case "set-node-privilege":
		return runVaultSetNodePrivilege(ctx, rt, rest)
	case "rotate":
		return runVaultRotate(ctx, rt, rest)
	default:
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(rest)), i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownSubcommand, i18n.Str("cmd", "vault"), i18n.BoundStr("sub", sub)))
	}
}

func parseCommonOnly(_ string, args []string) (clikit.CommonFlags, error) {
	var common clikit.CommonFlags
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &common); err != nil || consumed {
			if err != nil {
				return common, err
			}
			continue
		}
		tok := cur.Next()
		if tok == "-h" {
			common.ShowHelp = true
			return common, nil
		}
		return common, i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", tok))
	}
	return common, nil
}

func runVaultStatus(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, err := parseCommonOnly("status", args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	initOpts := rt.EffectiveInitOptions(common.ConfigFile, common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireVaultClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		st, err := client.VaultStatus(ctx, engine.VaultOpRequest{})
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		loc := rt.Loc()
		return rt.WriteResult(jsonOut, st, func(w io.Writer) {
			stores := strings.Join(st.KnownStores(), ",")
			if st.Detail() != "" {
				_, _ = fmt.Fprintln(w, loc.T(
					i18n.KeyCLIVaultStatusDetail,
					i18n.Str("state", st.State().String()),
					i18n.BoundStr("stores", stores),
					i18n.BoundStr("detail", st.Detail()),
				))
				return
			}
			_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLIVaultStatus, i18n.Str("state", st.State().String()), i18n.BoundStr("stores", stores)))
		})
	})
}

func runVaultInitOrUnlock(ctx context.Context, rt *clikit.Runtime, isInit bool, args []string) int {
	sub := "unlock"
	if isInit {
		sub = "init"
	}
	common, err := parseCommonOnly(sub, args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	req, err := buildInteractiveVaultReq(sub, isInit)
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	initOpts := rt.EffectiveInitOptions(common.ConfigFile, common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireVaultClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		if isInit {
			err = client.VaultInitInteractive(ctx, req)
		} else {
			err = client.VaultUnlockInteractive(ctx, req)
		}
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		type view struct {
			OK     bool   `json:"ok"`
			Action string `json:"action"`
		}
		loc := rt.Loc()
		return rt.WriteResult(jsonOut, view{OK: true, Action: "vault_" + sub}, func(w io.Writer) {
			_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLIVaultActionOK, i18n.Str("action", sub)))
		})
	})
}

func buildInteractiveVaultReq(sub string, isInit bool) (engine.InteractiveVaultOpRequest, error) {
	titleID := i18n.KeyInteractVaultUnlockTitle
	if isInit {
		titleID = i18n.KeyInteractVaultInitTitle
	}
	prompt, err := newVaultSecretPrompt(titleID, i18n.KeyInteractVaultMasterPrompt, "vault")
	if err != nil {
		return engine.InteractiveVaultOpRequest{}, err
	}
	req := engine.InteractiveVaultOpRequest{Prompt: prompt, ScopeSummary: "vault " + sub}
	if isInit {
		confirm, cErr := newVaultSecretPrompt(i18n.KeyInteractVaultConfirmTitle, i18n.KeyInteractVaultConfirmPrompt, "vault")
		if cErr != nil {
			return engine.InteractiveVaultOpRequest{}, cErr
		}
		req.ConfirmPrompt = algebraic.Some(confirm)
	}
	return req, nil
}

func runVaultLock(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, err := parseCommonOnly("lock", args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	initOpts := rt.EffectiveInitOptions(common.ConfigFile, common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireVaultClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		if err := client.VaultLock(ctx, engine.VaultOpRequest{ScopeSummary: "vault lock"}); err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		type view struct {
			OK     bool   `json:"ok"`
			Action string `json:"action"`
		}
		loc := rt.Loc()
		return rt.WriteResult(jsonOut, view{OK: true, Action: "vault_lock"}, func(w io.Writer) {
			_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLIVaultLocked))
		})
	})
}

func runVaultDoctor(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, skipProbe, err := parseVaultDoctorFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	initOpts := rt.EffectiveInitOptions(common.ConfigFile, common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireVaultClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		rep, err := client.VaultDoctor(ctx, engine.VaultDoctorRequest{SkipSecretProbe: skipProbe})
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		code := clikit.ExitOK
		if !rep.Healthy {
			code = clikit.ExitGeneral
		}
		loc := rt.Loc()
		if rt.WriteResult(jsonOut, rep, func(w io.Writer) {
			_, _ = fmt.Fprintln(w, loc.T(
				i18n.KeyCLIVaultDoctorSummary,
				i18n.Bool("healthy", rep.Healthy),
				i18n.Int("refs", rep.ReferencedCount),
				i18n.Int("findings", len(rep.Findings)),
			))
			for _, f := range rep.Findings {
				_, _ = fmt.Fprintf(w, "  [%s] %s (%s): %s\n", f.Severity, f.Code, f.Subject, f.Message)
			}
		}) != clikit.ExitOK {
			return clikit.ExitGeneral
		}
		return code
	})
}

func parseVaultDoctorFlags(args []string) (clikit.CommonFlags, bool, error) {
	var common clikit.CommonFlags
	skipProbe := false
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &common); err != nil || consumed {
			if err != nil {
				return common, false, err
			}
			continue
		}
		tok := cur.Next()
		if tok == "-h" {
			common.ShowHelp = true
			return common, false, nil
		}
		name, inlineVal, hasEq, isLong := clikit.ParseLongFlagName(tok)
		if isLong && name == "skip-probe" {
			v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
			if err != nil {
				return common, false, err
			}
			skipProbe = v
			continue
		}
		return common, false, i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", tok))
	}
	return common, skipProbe, nil
}

func parseVaultPositionalArgs(args []string) (clikit.CommonFlags, []string, error) {
	var common clikit.CommonFlags
	var pos []string
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &common); err != nil || consumed {
			if err != nil {
				return common, nil, err
			}
			continue
		}
		tok := cur.Next()
		if tok == "-h" {
			common.ShowHelp = true
			return common, nil, nil
		}
		if strings.HasPrefix(tok, "-") && tok != "-" {
			return common, nil, i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", tok))
		}
		pos = append(pos, tok)
	}
	return common, pos, nil
}
