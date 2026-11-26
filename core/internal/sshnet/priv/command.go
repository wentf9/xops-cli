package priv

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
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
		return handshakeTokens{}, fmt.Errorf("%w: 生成提权随机令牌失败: %w", ports.ErrEntropyShortRead, err)
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
		return zero, "", false, fmt.Errorf("%w: 提权仅支持 POSIX 启动方言（拒绝 %s）", ports.ErrUnsupported, dialect)
	}
	innerCmd, err := cmd.RenderCommand()
	if err != nil {
		return zero, "", false, fmt.Errorf("%w: 渲染提权目标命令失败: %w", ports.ErrInvalidArgument, err)
	}
	scriptBody, hasScript := cmd.StdinPayload()

	qReady, err := execution.QuotePOSIX(tokens.ready)
	if err != nil {
		return zero, "", false, fmt.Errorf("%w: 引用就绪帧令牌失败: %w", ports.ErrInvalidArgument, err)
	}
	elevBody := "printf '%s' " + qReady + " >&2; " + innerCmd
	qElevBody, err := execution.QuotePOSIX(elevBody)
	if err != nil {
		return zero, "", false, fmt.Errorf("%w: 引用提权执行体失败: %w", ports.ErrInvalidArgument, err)
	}

	wrapped, err := formatPrivilegeWrapper(req, tokens.prompt, qElevBody)
	if err != nil {
		return zero, "", false, err
	}
	// 外层会话使用 MaxAllowedOutputBytes，避免握手前提示/就绪帧计入目标命令的 MaxOutputBytes 配额；
	// 目标命令真实的 MaxOutputBytes 截断预算由 priv 的 streamScanner 在就绪后精确执行。
	plan, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:           execution.PlanKindCommand,
		Profile:        execution.DefaultServerLaunchProfile(),
		Command:        wrapped,
		MaxOutputBytes: algebraic.Some(execution.MaxAllowedOutputBytes),
	})
	if err != nil {
		return zero, "", false, fmt.Errorf("%w: 构造提权包装计划失败: %w", ports.ErrInvalidArgument, err)
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
		return "", fmt.Errorf("%w: 不支持的提权方式 %s", ports.ErrInvalidArgument, req.Method())
	}
}

func formatSudoWrapper(req ports.PrivilegeRequest, promptToken, qElevBody string) (string, error) {
	var prefix string
	if req.NonInteractive() {
		prefix = "LC_ALL=C sudo -n"
	} else {
		qPrompt, err := execution.QuotePOSIX(promptToken)
		if err != nil {
			return "", fmt.Errorf("%w: 引用 sudo 提示令牌失败: %w", ports.ErrInvalidArgument, err)
		}
		prefix = "LC_ALL=C sudo -S -p " + qPrompt
	}
	if u, hasUser := req.TargetUser().Get(); hasUser {
		qUser, uErr := execution.QuotePOSIX(u.String())
		if uErr != nil {
			return "", fmt.Errorf("%w: 引用目标用户失败: %w", ports.ErrInvalidArgument, uErr)
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
		return "", fmt.Errorf("%w: 引用 su 目标用户失败: %w", ports.ErrInvalidArgument, err)
	}
	qInner, err := execution.QuotePOSIX("exec /bin/sh -c " + qElevBody)
	if err != nil {
		return "", fmt.Errorf("%w: 引用 su 执行载荷失败: %w", ports.ErrInvalidArgument, err)
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
			return "", fmt.Errorf("%w: 引用 doas 目标用户失败: %w", ports.ErrInvalidArgument, err)
		}
		prefix += " -u " + qUser
	}
	return prefix + " -- /bin/sh -c " + qElevBody, nil
}
