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
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
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
		return fmt.Errorf("%w: vault rotate 未知选项 %q", clikit.ErrUsage, tok)
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
		return fmt.Errorf("%w: vault rotate 未知选项 %q", clikit.ErrUsage, tok)
	}
	return nil
}

func buildRotateSecretReq(f rotateSecretFlags) (engine.InteractiveRotateSecretRequest, error) {
	if len(f.pos) != 1 {
		return engine.InteractiveRotateSecretRequest{}, fmt.Errorf("%w: vault rotate 需要恰好 1 个旧凭据引用 <store>/<item>", clikit.ErrUsage)
	}
	oldRef, err := secret.ParseRef(f.pos[0])
	if err != nil {
		return engine.InteractiveRotateSecretRequest{}, fmt.Errorf("%w: 旧凭据引用非法: %w", clikit.ErrUsage, err)
	}
	newRef, store, err := parseTargetRefOrStore(f.newRefRaw, f.store, "rotate")
	if err != nil {
		return engine.InteractiveRotateSecretRequest{}, err
	}
	expRev, err := parseOptionalRevision(f.expRevRaw)
	if err != nil {
		return engine.InteractiveRotateSecretRequest{}, err
	}
	prompt, err := engine.NewSecretPromptRequest(engine.SecretPromptRequestSpec{
		Title: "Rotate Secret", Prompt: "Enter new secret value", Subject: oldRef.String(),
	})
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
func parseTargetRefOrStore(refRaw, storeRaw, sub string) (ref secret.Ref, store string, err error) {
	trimmedRef, trimmedStore := strings.TrimSpace(refRaw), strings.TrimSpace(storeRaw)
	if (trimmedRef == "") == (trimmedStore == "") {
		return ref, "", fmt.Errorf("%w: vault %s 必须二选一指定 --ref/--new-ref <store>/<item> 或 --store <store_id>", clikit.ErrUsage, sub)
	}
	if trimmedRef != "" {
		parsed, pErr := secret.ParseRef(trimmedRef)
		if pErr != nil {
			return ref, "", fmt.Errorf("%w: 凭据引用 %q 非法: %w", clikit.ErrUsage, trimmedRef, pErr)
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
	v := buildSagaResultView(action, res, runErr, ok, uncertainDur, uncertainFail)
	if rt.WriteResult(jsonOut, v, func(w io.Writer) {
		writeSagaResultText(rt, w, v, runErr)
	}) != clikit.ExitOK {
		return clikit.ExitGeneral
	}
	return code
}

func buildSagaResultView(action string, res engine.SagaResult, runErr error, ok, uncertainDur, uncertainFail bool) sagaResultView {
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
		v.Error = runErr.Error()
		v.ErrorCode = clikit.ClassifyErrorCode(runErr)
	}
	return v
}

func writeSagaResultText(rt *clikit.Runtime, w io.Writer, v sagaResultView, runErr error) {
	_, _ = fmt.Fprintf(w, "%s state=%s new_ref=%s old_deleted=%v compensated=%v\n",
		v.Action, v.State, v.NewRef, v.OldDeleted, v.Compensated)
	if v.DoNotRetry {
		rt.WriteErr(v.Action + ": uncertain outcome or durability (do not retry or delete credentials)")
	}
	if runErr != nil {
		rt.WriteErr(runErr.Error())
	}
}
