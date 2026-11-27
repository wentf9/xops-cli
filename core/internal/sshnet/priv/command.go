package priv

import (
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/ports"
)

type handshakeTokens struct {
	prompt string
	ready  string
}

func generateHandshakeTokens(entropy ports.Entropy) (handshakeTokens, error) {
	r := rand.Reader
	if entropy != nil {
		r = entropy
	}
	var raw [nonceRawBytes * 2]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return handshakeTokens{}, domi18n.WrapS(ports.ErrEntropyShortRead, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "generate privilege handshake tokens"))
	}
	return handshakeTokens{
		prompt: "[xops-priv-prompt-" + hex.EncodeToString(raw[:nonceRawBytes]) + "]",
		ready:  "[xops-priv-ready-" + hex.EncodeToString(raw[nonceRawBytes:]) + "]",
	}, nil
}

// buildEscalationPlan 按 sudo / su / doas 协议规则包装不可变 CommandPlan，
// 拒绝显式非 POSIX 启动方言（cmd / powershell / raw），并在提权壳内部先输出随机就绪帧 readyToken
// 至 stderr 再执行目标命令，实现认证阶段与命令载荷的严格隔离。
func buildEscalationPlan(req ports.PrivilegeRequest, tokens handshakeTokens) (execution.CommandPlan, string, bool, error) {
	var zero execution.CommandPlan
	cmd := req.Command()
	if dialect := cmd.Profile().Dialect(); dialect != execution.DialectUnknown && dialect != execution.DialectPOSIX {
		return zero, "", false, domi18n.EF(ports.ErrUnsupported, domi18n.KeyPrivDialectPOSIXOnly, domi18n.Str("dialect", dialect.String()))
	}
	innerCmd, err := cmd.RenderCommand()
	if err != nil {
		return zero, "", false, domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "render privilege target command"))
	}
	scriptBody, hasScript := cmd.StdinPayload()

	qReady, err := execution.QuotePOSIX(tokens.ready)
	if err != nil {
		return zero, "", false, domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "quote ready frame token"))
	}
	elevBody := "printf '%s' " + qReady + " >&2; " + innerCmd
	qElevBody, err := execution.QuotePOSIX(elevBody)
	if err != nil {
		return zero, "", false, domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "quote privilege payload"))
	}

	wrapped, err := formatPrivilegeWrapper(req, tokens.prompt, qElevBody)
	if err != nil {
		return zero, "", false, err
	}
	// 本包直接借用 RemoteSession.StdoutPipe()/StderrPipe()，外层会话不计量借出管道字节；
	// 目标命令真实的 MaxOutputBytes 截断预算由 priv 的 streamScanner 在就绪后作为唯一权威精确执行。
	plan, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:           execution.PlanKindCommand,
		Profile:        execution.DefaultServerLaunchProfile(),
		Command:        wrapped,
		MaxOutputBytes: algebraic.Some(cmd.MaxOutputBytes()),
	})
	if err != nil {
		return zero, "", false, domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "build privilege command plan"))
	}
	return plan, scriptBody, hasScript, nil
}

func formatPrivilegeWrapper(req ports.PrivilegeRequest, promptToken, qElevBody string) (string, error) {
	switch req.Method() {
	case ports.PrivilegeMethodSudo:
		return formatSudoWrapper(req, promptToken, qElevBody)
	case ports.PrivilegeMethodSu:
		return formatSuWrapper(req, qElevBody)
	case ports.PrivilegeMethodDoas:
		return formatDoasWrapper(req, qElevBody)
	default:
		return "", domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonNotSupported, domi18n.Str("feature", "privilege method "+req.Method().String()))
	}
}

func formatSudoWrapper(req ports.PrivilegeRequest, promptToken, qElevBody string) (string, error) {
	var prefix string
	if req.NonInteractive() {
		prefix = "LC_ALL=C sudo -n"
	} else {
		qPrompt, err := execution.QuotePOSIX(promptToken)
		if err != nil {
			return "", domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "quote sudo prompt token"))
		}
		prefix = "LC_ALL=C sudo -S -p " + qPrompt
	}
	if u, hasUser := req.TargetUser().Get(); hasUser {
		qUser, uErr := execution.QuotePOSIX(u.String())
		if uErr != nil {
			return "", domi18n.WrapS(ports.ErrInvalidArgument, uErr, domi18n.KeyCommonOpFailed, domi18n.Str("op", "quote target user"))
		}
		prefix += " -u " + qUser
	}
	return prefix + " -- /bin/sh -c " + qElevBody, nil
}

func formatSuWrapper(req ports.PrivilegeRequest, qElevBody string) (string, error) {
	targetUser := "root"
	if u, hasUser := req.TargetUser().Get(); hasUser {
		targetUser = u.String()
	}
	qUser, err := execution.QuotePOSIX(targetUser)
	if err != nil {
		return "", domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "quote su target user"))
	}
	qInner, err := execution.QuotePOSIX("exec /bin/sh -c " + qElevBody)
	if err != nil {
		return "", domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "quote su payload"))
	}
	return "LC_ALL=C su " + qUser + " -c " + qInner, nil
}

func formatDoasWrapper(req ports.PrivilegeRequest, qElevBody string) (string, error) {
	prefix := "LC_ALL=C doas"
	if req.NonInteractive() {
		prefix += " -n"
	}
	if u, hasUser := req.TargetUser().Get(); hasUser {
		qUser, err := execution.QuotePOSIX(u.String())
		if err != nil {
			return "", domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "quote doas target user"))
		}
		prefix += " -u " + qUser
	}
	return prefix + " -- /bin/sh -c " + qElevBody, nil
}
