package cmdasset

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type rotateSecretFlags struct {
	common    clikit.CommonFlags
	newRefRaw string
	store     string
	expRevRaw string
	pos       []string
}

type sagaResultView struct {
	OK                  bool                              `json:"ok"`
	Action              string                            `json:"action"`
	State               string                            `json:"state,omitzero"`
	NewRef              string                            `json:"new_ref,omitzero"`
	OldRef              string                            `json:"old_ref,omitzero"`
	Revision            algebraic.Option[engine.Revision] `json:"revision,omitzero"`
	OldDeleted          bool                              `json:"old_deleted,omitzero"`
	Compensated         bool                              `json:"compensated,omitzero"`
	UncertainDurability bool                              `json:"uncertain_durability,omitzero"`
	DoNotRetry          bool                              `json:"do_not_retry,omitzero"`
	Error               string                            `json:"error,omitzero"`
	ErrorCode           string                            `json:"error_code,omitzero"`
}

// runVaultRotate 通过 RotateSecretInteractive 交互式采集新机密并将资产图全部 5 处位置中的旧引用安全轮换至新引用。
func runVaultRotate(ctx context.Context, rt *clikit.Runtime, args []string) int {
	f, err := parseRotateSecretFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("vault", args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	req, err := buildRotateSecretReq(f)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireVaultClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		res, err := client.RotateSecretInteractive(ctx, req)
		return renderSagaResult(rt, "rotate_secret", res, err, jsonOut)
	})
}

func parseRotateSecretFlags(args []string) (rotateSecretFlags, error) {
	var f rotateSecretFlags
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseRotateSecretToken(cur, &f); err != nil {
			return f, err
		}
		if f.common.ShowHelp {
			return f, nil
		}
	}
	return f, nil
}

func parseRotateSecretToken(cur *clikit.FlagCursor, f *rotateSecretFlags) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &f.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	if tok == "-h" {
		f.common.ShowHelp = true
		return nil
	}
	if !strings.HasPrefix(tok, "-") {
		f.pos = append(f.pos, tok)
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
	case "new-ref":
		f.newRefRaw = val
	case "store":
		f.store = val
	case "expected-revision":
		f.expRevRaw = val
	default:
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", tok))
	}
	return nil
}

func buildRotateSecretReq(f rotateSecretFlags) (engine.InteractiveRotateSecretRequest, error) {
	if len(f.pos) != 1 {
		return engine.InteractiveRotateSecretRequest{}, i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.Str("cmd", "vault rotate"), i18n.Int("count", 1), i18n.Str("usage", "<store>/<item>"))
	}
	oldRef, err := secret.ParseRef(f.pos[0])
	if err != nil {
		return engine.InteractiveRotateSecretRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Msg("field", i18n.NewMessage(i18n.KeyCLIFieldSecretRef)), i18n.BoundStr("value", f.pos[0]))
	}
	newRef, store, err := parseTargetRefOrStore(f.newRefRaw, f.store)
	if err != nil {
		return engine.InteractiveRotateSecretRequest{}, err
	}
	expRev, err := parseOptionalRevision(f.expRevRaw)
	if err != nil {
		return engine.InteractiveRotateSecretRequest{}, err
	}
	prompt, err := newVaultSecretPrompt(i18n.KeyInteractVaultRotateTitle, i18n.KeyInteractVaultRotatePrompt, oldRef.String())
	if err != nil {
		return engine.InteractiveRotateSecretRequest{}, err
	}
	return engine.InteractiveRotateSecretRequest{
		Prompt: prompt,
		Rotate: engine.RotateSecretRequest{
			OldRef:           oldRef,
			NewRef:           newRef,
			TargetStore:      store,
			ExpectedRevision: expRev,
			ScopeSummary:     "rotate secret " + oldRef.String(),
		},
	}, nil
}

// parseTargetRefOrStore 严格校验 --ref/--new-ref 与 --store 互斥二选一约束，对齐 VaultSagaRequest 不变量。
func parseTargetRefOrStore(refRaw, storeRaw string) (ref secret.Ref, store string, err error) {
	trimmedRef, trimmedStore := strings.TrimSpace(refRaw), strings.TrimSpace(storeRaw)
	if (trimmedRef == "") == (trimmedStore == "") {
		return ref, "", i18n.EF(clikit.ErrUsage, i18n.KeyCLIExactlyOneFlagRequired, i18n.Str("flag_a", "--ref/--new-ref"), i18n.Str("flag_b", "--store"))
	}
	if trimmedRef != "" {
		parsed, pErr := secret.ParseRef(trimmedRef)
		if pErr != nil {
			return ref, "", i18n.WrapS(clikit.ErrUsage, pErr, i18n.KeyCLIInvalidField, i18n.Msg("field", i18n.NewMessage(i18n.KeyCLIFieldSecretRef)), i18n.BoundStr("value", trimmedRef))
		}
		return parsed, "", nil
	}
	return ref, trimmedStore, nil
}

// renderSagaResult 渲染 VaultSagaFSM 终态结果；对回滚、不确定持久性（Applied && !Durable）与未知结果严格失败关闭并提示禁重试。
func renderSagaResult(rt *clikit.Runtime, action string, res engine.SagaResult, runErr error, jsonOut bool) int {
	uncertainDur := res.IsUncertainDurability() || errors.Is(runErr, engine.ErrUncertainDurability)
	uncertainFail := res.IsFailedUncertain() || errors.Is(runErr, engine.ErrOutcomeUnknown)
	if runErr != nil && !res.IsValid() && !uncertainDur && !uncertainFail {
		return rt.Fail(clikit.ExitGeneral, jsonOut, runErr)
	}
	completed := !res.IsValid() || res.StateKind() == fsm.VaultSagaKindCompleted
	ok := runErr == nil && completed && !uncertainDur && !uncertainFail
	code := clikit.ExitOK
	if !ok {
		code = clikit.ExitGeneral
	}
	loc := rt.Loc()
	v := buildSagaResultView(loc, action, res, runErr, ok, uncertainDur, uncertainFail)
	if rt.WriteResult(jsonOut, v, func(w io.Writer) {
		writeSagaResultText(rt, loc, w, v, runErr)
	}) != clikit.ExitOK {
		return clikit.ExitGeneral
	}
	return code
}

func buildSagaResultView(loc *i18n.Localizer, action string, res engine.SagaResult, runErr error, ok, uncertainDur, uncertainFail bool) sagaResultView {
	v := sagaResultView{
		OK:                  ok,
		Action:              action,
		Revision:            res.Revision(),
		OldDeleted:          res.OldDeleted(),
		Compensated:         res.Compensated(),
		UncertainDurability: uncertainDur,
		DoNotRetry:          uncertainDur || uncertainFail,
	}
	if res.IsValid() {
		v.State = res.StateKind().String()
	}
	if res.NewRef().IsValid() {
		v.NewRef = res.NewRef().String()
	}
	if oldRef, hasOld := res.OldRef().Get(); hasOld && oldRef.IsValid() {
		v.OldRef = oldRef.String()
	}
	if runErr != nil {
		v.Error = loc.RenderError(runErr)
		v.ErrorCode = clikit.ClassifyErrorCode(runErr)
	}
	return v
}

func writeSagaResultText(rt *clikit.Runtime, loc *i18n.Localizer, w io.Writer, v sagaResultView, runErr error) {
	_, _ = fmt.Fprintln(w, loc.T(
		i18n.KeyCLIVaultSagaResult,
		i18n.Str("action", v.Action),
		i18n.Str("state", v.State),
		i18n.BoundStr("new_ref", v.NewRef),
		i18n.Bool("old_deleted", v.OldDeleted),
		i18n.Bool("compensated", v.Compensated),
	))
	if v.DoNotRetry {
		rt.WriteErr(loc.T(i18n.KeyCLIVaultSagaUncertain, i18n.Str("action", v.Action)))
	}
	if runErr != nil {
		rt.WriteErr(loc.RenderError(runErr))
	}
}
