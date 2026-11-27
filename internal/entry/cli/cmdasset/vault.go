package cmdasset

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

// RunVault 执行 `xops creds` 与 `xops vault` 凭据库全生命周期与安全回收子命令族。
func RunVault(ctx context.Context, rt *clikit.Runtime, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
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
	default:
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, fmt.Errorf("%w: 未知 creds/vault 子命令 %q", clikit.ErrUsage, sub))
	}
}

func parseCommonOnly(sub string, args []string) (clikit.CommonFlags, error) {
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
		return common, fmt.Errorf("%w: vault %s 未知参数 %q", clikit.ErrUsage, sub, tok)
	}
	return common, nil
}

func runVaultStatus(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, err := parseCommonOnly("status", args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
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
		return rt.WriteResult(jsonOut, st, func(w io.Writer) {
			_, _ = fmt.Fprintf(w, "vault state=%s stores=%s", st.State(), strings.Join(st.KnownStores(), ","))
			if st.Detail() != "" {
				_, _ = fmt.Fprintf(w, " detail=%s", st.Detail())
			}
			_, _ = io.WriteString(w, "\n")
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
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
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
		return rt.WriteResult(jsonOut, view{OK: true, Action: "vault_" + sub}, func(w io.Writer) {
			_, _ = fmt.Fprintf(w, "vault %s succeeded\n", sub)
		})
	})
}

func buildInteractiveVaultReq(sub string, isInit bool) (engine.InteractiveVaultOpRequest, error) {
	prompt, err := engine.NewSecretPromptRequest(engine.SecretPromptRequestSpec{
		Title: "Vault " + sub, Prompt: "Master passphrase", Subject: "vault",
	})
	if err != nil {
		return engine.InteractiveVaultOpRequest{}, err
	}
	req := engine.InteractiveVaultOpRequest{Prompt: prompt, ScopeSummary: "vault " + sub}
	if isInit {
		confirm, cErr := engine.NewSecretPromptRequest(engine.SecretPromptRequestSpec{
			Title: "Confirm Vault Passphrase", Prompt: "Confirm master passphrase", Subject: "vault",
		})
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
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
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
		return rt.WriteResult(jsonOut, view{OK: true, Action: "vault_lock"}, func(w io.Writer) {
			_, _ = io.WriteString(w, "vault locked\n")
		})
	})
}

func runVaultDoctor(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, skipProbe, err := parseVaultDoctorFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
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
		if rt.WriteResult(jsonOut, rep, func(w io.Writer) {
			_, _ = fmt.Fprintf(w, "vault doctor healthy=%v refs=%d findings=%d\n", rep.Healthy, rep.ReferencedCount, len(rep.Findings))
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
		name, inlineVal, hasEq := clikit.SplitLongFlag(tok)
		if name == "skip-probe" {
			v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
			if err != nil {
				return common, false, err
			}
			skipProbe = v
			continue
		}
		return common, false, fmt.Errorf("%w: vault doctor 未知参数 %q", clikit.ErrUsage, tok)
	}
	return common, skipProbe, nil
}

func parseVaultPositionalArgs(sub string, args []string) (clikit.CommonFlags, []string, error) {
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
			return common, nil, fmt.Errorf("%w: vault %s 未知选项 %q", clikit.ErrUsage, sub, tok)
		}
		pos = append(pos, tok)
	}
	return common, pos, nil
}
