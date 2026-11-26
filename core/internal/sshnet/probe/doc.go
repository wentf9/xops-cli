// Package probe 实现 XOps v2 的规范化两阶段远端 Shell 探测适配器（ports.ShellProbePort，P4-T1）。
//
// 核心安全与协议不变量：
//   - 本包不进入明文机密白名单，全包零行内 nolint 豁免、0 裸 go 语句与 0 path/filepath 导入；
//   - 阶段 1 探测远端外层合法启动方言（posix / cmd / powershell）与规范 OS 族；
//   - 阶段 2 在已确认的合法启动方言上枚举并校验可用解释器集合（bash / sh / zsh / powershell / pwsh / cmd），
//     产出经 execution.LaunchProfile 兼容性矩阵验证的不可变 ports.ShellProbeResult；
//   - 严格失败关闭（Fail-Closed）：未知/不支持的外层 Shell（如 fish/csh/受限菜单）、输出截断、
//     重复或畸形帧、缺失结束帧、传输错误或上下文取消均立即返回错误，绝不盲猜回退。
package probe

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultCommandTimeout        = 5 * time.Second
	defaultMaxOutputBytes uint64 = 16 << 10 // 单次探测命令输出上限（16 KiB）
	maxAllowedOutputBytes uint64 = 1 << 20  // 配置允许的最大探测输出上限（1 MiB）
	maxFrameValueBytes           = 1024
)

// ErrProbeFailed 标识两阶段远端 Shell 探测无法确认合法启动方言或可用解释器（Fail-Closed）。
var ErrProbeFailed = errors.New("sshnet/probe: 远端 Shell 探测失败或结果不可信")

// Config 描述 Prober 的显式运行期配置（零全局状态与隐式环境变量）。
type Config struct {
	// CommandTimeout 可选覆盖单次探测命令的超时时长（<= 0 时默认 5s）。
	CommandTimeout time.Duration
	// MaxOutputBytes 可选覆盖单次探测命令的输出字节上限（0 时默认 16 KiB，超过 1 MiB 拒绝）。
	MaxOutputBytes uint64
	// ServerVersionHint 可选提供远端 SSH 版本串（如含 "OpenSSH_for_Windows" 时优先探测 cmd/powershell）。
	ServerVersionHint string
	// Stage1Only 为 true 时仅执行阶段 1 方言探测并返回 ProbeStage=1 + InterpreterServer；默认执行完整两阶段探测。
	Stage1Only bool
}

// Prober 实现 ports.ShellProbePort，通过两阶段帧协议确定性识别远端启动方言与推荐解释器；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type Prober struct {
	commandTimeout time.Duration
	maxOutputBytes uint64
	preferWindows  bool
	stage1Only     bool
	valid          bool
}

// NewProber 校验配置并构造不可变 Prober 实例。
func NewProber(cfg Config) (*Prober, error) {
	if cfg.CommandTimeout < 0 {
		return nil, fmt.Errorf("%w: CommandTimeout 不能为负", ports.ErrInvalidArgument)
	}
	if cfg.MaxOutputBytes > maxAllowedOutputBytes {
		return nil, fmt.Errorf("%w: MaxOutputBytes 超过上限 %d", ports.ErrInvalidArgument, maxAllowedOutputBytes)
	}
	timeout := cfg.CommandTimeout
	if timeout == 0 {
		timeout = defaultCommandTimeout
	}
	maxOut := cfg.MaxOutputBytes
	if maxOut == 0 {
		maxOut = defaultMaxOutputBytes
	}
	preferWin := strings.Contains(cfg.ServerVersionHint, "OpenSSH_for_Windows") ||
		strings.Contains(cfg.ServerVersionHint, "Microsoft:Windows")
	return &Prober{
		commandTimeout: timeout,
		maxOutputBytes: maxOut,
		preferWindows:  preferWin,
		stage1Only:     cfg.Stage1Only,
		valid:          true,
	}, nil
}
