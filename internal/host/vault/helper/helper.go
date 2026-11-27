package helper

import (
	"bytes"
	"context"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// HelperSpec 是构造不可变外部凭据助手适配器 HelperVault 的显式入参规格（非持久化 DTO）。
type HelperSpec struct {
	Process  ports.ProcessPort
	Command  string
	Args     []string
	WorkDir  algebraic.Option[pathalg.LocalDir]
	Env      map[string]string
	Timeout  algebraic.Option[algebraic.Duration]
	ReadOnly bool
}

// HelperVault 实现 ports.SecretVault，通过注入的 ports.ProcessPort 以纯 stdin/stdout JSON 协议调用外部凭据助手；
// 零值恒无效并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type HelperVault struct {
	proc     ports.ProcessPort
	baseSpec ports.ProcessSpec
	readOnly bool
	valid    bool
}

type helperResponse struct {
	SecretB64 *string `json:"secret_b64,omitzero"`
	Code      string  `json:"code,omitzero"`
	Message   string  `json:"message,omitzero"`
}

// NewHelperVault 校验 ProcessPort 与子进程执行规格并构造外部凭据助手适配器。
func NewHelperVault(spec HelperSpec) (*HelperVault, error) {
	if spec.Process == nil {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNilDependency, i18n.Str("field", "HelperSpec.Process"))
	}
	timeout := spec.Timeout
	if timeout.IsNone() {
		timeout = algebraic.Some(algebraic.FromStdDuration(DefaultHelperTimeout))
	}
	procSpec, err := ports.NewProcessSpec(ports.ProcessSpecInput{
		Command:        spec.Command,
		Args:           slices.Clone(spec.Args),
		WorkDir:        spec.WorkDir,
		Env:            maps.Clone(spec.Env),
		Timeout:        timeout,
		MaxOutputBytes: algebraic.Some(MaxHelperResponseBytes),
	})
	if err != nil {
		return nil, err
	}
	return &HelperVault{
		proc:     spec.Process,
		baseSpec: procSpec,
		readOnly: spec.ReadOnly,
		valid:    true,
	}, nil
}

// WithSecret 调用外部助手 action=get 读取机密，解码后在同步闭包内借出 *secret.SecretBox 并于退出前无条件清零。
//
//xops:syncclosure
//xops:borrowed
func (v *HelperVault) WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error {
	if err := v.checkBase(ctx, ref); err != nil {
		return err
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	reqBytes := buildNonSecretRequest("get", ref)
	res, err := v.proc.Run(ctx, v.baseSpec, bytes.NewReader(reqBytes))
	if err != nil {
		return err
	}
	raw, err := decodeSecretResponse(res)
	if err != nil {
		return err
	}
	defer clear(raw)
	return secret.WithBytes(raw, func(box *secret.SecretBox) error { return fn(box) })
}

// PutAndVerify 调用外部助手 action=store 写入借用的 SecretBox（明文仅经 stdin 管道传入），
// 随后立即回读并执行常量时间 SecretBox.Equal 校验，失配返回 ports.ErrSecretVerifyFailed。
func (v *HelperVault) PutAndVerify(
	ctx context.Context,
	ref secret.Ref,
	//xops:borrowed
	box *secret.SecretBox,
) error {
	if err := v.checkBase(ctx, ref); err != nil {
		return err
	}
	if !box.IsValid() {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidSecretBox)
	}
	if v.readOnly {
		return i18n.EF(ports.ErrPermissionDenied, i18n.KeyHostVaultHelperReadOnly)
	}
	if err := v.execStore(ctx, ref, box); err != nil {
		return err
	}
	verifyErr := v.WithSecret(ctx, ref, func(got *secret.SecretBox) error {
		if !got.Equal(box) {
			return ports.ErrSecretVerifyFailed
		}
		return nil
	})
	if verifyErr != nil && !errors.Is(verifyErr, ports.ErrSecretVerifyFailed) && ctx.Err() == nil {
		return domi18n.WrapSentinel(ports.ErrSecretVerifyFailed, verifyErr)
	}
	return verifyErr
}

func (v *HelperVault) execStore(
	ctx context.Context,
	ref secret.Ref,
	//xops:borrowed
	box *secret.SecretBox,
) error {
	prefix := `{"protocol_version":2,"non_interactive":true,"action":"store","store":"` + ref.Store() + `","item":"` + ref.Item() + `","secret_b64":"`
	var res ports.ProcessResult
	err := box.Use(func(plain []byte) error {
		// store 与 item 已由 secret.Ref 校验为纯 ASCII 安全标识符，base64 直接写入可清零局部切片，
		// 避免构造不可零化的 Go string 副本并规避 JSON 序列化汇点。
		b64Len := base64.StdEncoding.EncodedLen(len(plain))
		payload := make([]byte, len(prefix)+b64Len+2)
		defer clear(payload)
		copy(payload, prefix)
		base64.StdEncoding.Encode(payload[len(prefix):len(prefix)+b64Len], plain)
		copy(payload[len(prefix)+b64Len:], `"}`)
		var runErr error
		res, runErr = v.proc.Run(ctx, v.baseSpec, bytes.NewReader(payload))
		return runErr
	})
	if err != nil {
		return err
	}
	return checkStatusResponse(res)
}

// Delete 调用外部助手 action=erase 删除指定凭据引用。
func (v *HelperVault) Delete(ctx context.Context, ref secret.Ref) error {
	if err := v.checkBase(ctx, ref); err != nil {
		return err
	}
	if v.readOnly {
		return i18n.EF(ports.ErrPermissionDenied, i18n.KeyHostVaultHelperReadOnly)
	}
	reqBytes := buildNonSecretRequest("erase", ref)
	res, err := v.proc.Run(ctx, v.baseSpec, bytes.NewReader(reqBytes))
	if err != nil {
		return err
	}
	return checkStatusResponse(res)
}

func (v *HelperVault) checkBase(ctx context.Context, ref secret.Ref) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if v == nil || !v.valid {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNotInitialized, i18n.Str("component", "HelperVault"))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !ref.IsValid() {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidSecretRef)
	}
	return nil
}

func buildNonSecretRequest(action string, ref secret.Ref) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"protocol_version":2,"non_interactive":true,"action":"`)
	buf.WriteString(action)
	buf.WriteString(`","store":"`)
	buf.WriteString(ref.Store())
	buf.WriteString(`","item":"`)
	buf.WriteString(ref.Item())
	buf.WriteString(`"}`)
	return buf.Bytes()
}

func decodeSecretResponse(res ports.ProcessResult) ([]byte, error) {
	resp, err := parseHelperResponse(res)
	if err != nil {
		return nil, err
	}
	if resp.Code != "" {
		return nil, mapHelperErrorCode(resp.Code)
	}
	if !res.Succeeded() {
		return nil, i18n.EF(ports.ErrUnsupported, i18n.KeyHostVaultHelperNonZeroExit)
	}
	if resp.SecretB64 == nil {
		return nil, ports.ErrSecretNotFound
	}
	raw, err := base64.StdEncoding.DecodeString(*resp.SecretB64)
	if err != nil {
		return nil, i18n.EF(ErrProtocol, i18n.KeyHostVaultHelperBase64Failed)
	}
	return raw, nil
}

func checkStatusResponse(res ports.ProcessResult) error {
	rawOut := res.Stdout()
	defer clear(rawOut)
	out := bytes.TrimSpace(rawOut)
	if len(out) == 0 {
		if res.Succeeded() {
			return nil
		}
		return i18n.EF(ports.ErrUnsupported, i18n.KeyHostVaultHelperNonZeroExit)
	}
	resp, err := parseHelperResponse(res)
	if err != nil {
		return err
	}
	if resp.Code != "" {
		return mapHelperErrorCode(resp.Code)
	}
	if !res.Succeeded() {
		return i18n.EF(ports.ErrUnsupported, i18n.KeyHostVaultHelperNonZeroExit)
	}
	return nil
}

func parseHelperResponse(res ports.ProcessResult) (helperResponse, error) {
	if !res.IsValid() || res.Truncated() {
		return helperResponse{}, i18n.EF(ErrProtocol, i18n.KeyHostVaultHelperBadResponse)
	}
	rawOut := res.Stdout()
	defer clear(rawOut)
	out := bytes.TrimSpace(rawOut)
	if len(out) == 0 {
		return helperResponse{}, i18n.EF(ErrProtocol, i18n.KeyHostVaultHelperBadResponse)
	}
	var resp helperResponse
	if err := jsonv2.Unmarshal(out, &resp, jsonv2.RejectUnknownMembers(true)); err != nil {
		return helperResponse{}, i18n.EF(ErrProtocol, i18n.KeyHostVaultHelperBadResponse)
	}
	return resp, nil
}

// mapHelperErrorCode 仅将受控错误码映射为规范哨兵错误，绝不回显非受控助手原始诊断文本以防凭据反射泄漏。
func mapHelperErrorCode(code string) error {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "ok":
		return nil
	case "not-found", "not_found":
		return ports.ErrSecretNotFound
	case "locked":
		return ports.ErrVaultLocked
	case "denied", "permission-denied", "permission_denied":
		return ports.ErrPermissionDenied
	case "unavailable", "unsupported":
		return ports.ErrUnsupported
	case "invalid":
		return ports.ErrInvalidArgument
	default:
		return errors.Join(ErrProtocol, ports.ErrUnsupported)
	}
}
