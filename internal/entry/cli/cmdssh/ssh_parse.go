package cmdssh

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

// SSHCommandArgs 保存 `xops ssh` 参数解析产出的强类型命令行参数、Tier-1（CLI）选项层与 OpenSSH 控制标志。
type SSHCommandArgs struct {
	// TargetSpec 为目标连接规格（[user@]host[:port]、IPv6 或 OpenSSH 虚拟主机别名）。
	TargetSpec string
	// CommandArgs 为紧随目标之后的远端命令及参数切片；为空时进入交互式 Shell。
	CommandArgs []string
	// CLIOptions 为按命令行出现顺序折叠的 Tier-1 OpenSSH 选项层（-p/-l/-i/-J/-o/-M/-S）。
	CLIOptions option.OptionLayer
	// RequestTTY 为由 -t/-tt/-T 推导的伪终端分配策略（未指定时为零值 RequestTTYUnset）。
	RequestTTY engine.RequestTTYMode
	// ConfigFile 为 `-F <configfile>` 指定的 OpenSSH 配置文件路径覆写（空串表示使用默认配置）。
	ConfigFile string
	// Policy 为 `--policy` 指定的策略配置档覆盖。
	Policy engine.PolicyProfile
	// JSON 为 true 时以确定性 JSON/v2 输出非交互命令或控制结果。
	JSON bool
	// Forwards 为由 -L/-R/-D/-w 解析产出的有序强类型转发规格列表。
	Forwards []engine.ForwardSpec
	// TUNMode 为 -w 所用的隧道封装模式（默认 point_to_point，可通过 --tun-mode 切换为 ethernet）。
	TUNMode engine.TUNMode
	// MuxAction 为 `-O <ctl_cmd>` 解析产出的多路复用控制动作（未指定时为零值 MuxActionInvalid）。
	MuxAction engine.MuxControlAction
	// ControlSocket 为 `-S <ctl_path>` 显式指定的控制套接字路径。
	ControlSocket string
	// MasterCount 为 `-M` 出现次数（1 对应 ControlMaster=yes，>=2 对应 ControlMaster=ask）。
	MasterCount int
	// NoCommand 为 `-N`（不执行远端命令，仅维持隧道或 ControlMaster）。
	NoCommand bool
	// Background 为 `-f`（请求后台化/移交 muxdaemon）。
	Background bool
	// StdioForward 为 `-W <host:port>` 指定的 stdio 转发目标端点。
	StdioForward algebraic.Option[netaddr.HostPort]
	// ShowHelp 为 true 时表示用户显式请求查看 `xops ssh` 帮助信息。
	ShowHelp bool
}

type sshFlagParser struct {
	cur        *clikit.FlagCursor
	layer      option.OptionLayer
	common     clikit.CommonFlags
	ttyMode    engine.RequestTTYMode
	ttyCount   int
	forwards   []engine.ForwardSpec
	rawTUNs    []string
	tunMode    engine.TUNMode
	muxAction  engine.MuxControlAction
	ctlSocket  string
	masterCnt  int
	noCommand  bool
	background bool
	stdioFwd   algebraic.Option[netaddr.HostPort]
	stopFlags  bool
}

// ParseSSHArgs 按 OpenSSH ssh(1) 标准短选项习惯解析 `xops ssh` 后续参数列表：
//   - 支持 -p/-l/-i/-J/-L/-R/-D/-o/-O/-M/-S/-F/-t/-tt/-T/-N/-f/-W/-w、--json、--policy、--tun-mode、-- 与 -h/--help；
//   - 遇到首个非选项位置参数（[user@]host）后立即停止选项解析，确保远端命令自带的 `-flag` 完整透传。
func ParseSSHArgs(args []string) (SSHCommandArgs, error) {
	p := &sshFlagParser{
		cur:     clikit.NewFlagCursor(args),
		layer:   option.UnsetOptionLayer(),
		tunMode: engine.TUNModePointToPoint,
	}
	for p.cur.HasNext() && !p.stopFlags {
		done, err := p.parseNextToken()
		if err != nil {
			return SSHCommandArgs{}, err
		}
		if done {
			break
		}
	}
	if p.common.ShowHelp {
		return SSHCommandArgs{ShowHelp: true}, nil
	}
	return p.finish()
}

func (p *sshFlagParser) parseNextToken() (bool, error) {
	tok := p.cur.Peek()
	if tok == "--" {
		p.cur.Next()
		p.stopFlags = true
		return true, nil
	}
	if tok == "-h" || tok == "--help" {
		p.common.ShowHelp = true
		return true, nil
	}
	if !strings.HasPrefix(tok, "-") || tok == "-" {
		return true, nil
	}
	if strings.HasPrefix(tok, "--") {
		return false, p.parseLongFlag()
	}
	p.cur.Next()
	return false, p.parseShortCluster(tok[1:])
}

func (p *sshFlagParser) parseLongFlag() error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(p.cur, &p.common); err != nil || consumed {
		if p.common.ShowHelp {
			p.stopFlags = true
		}
		return err
	}
	tok := p.cur.Next()
	name, inlineVal, hasEq := clikit.SplitLongFlag(tok)
	if name == "tun-mode" {
		raw, err := p.cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return err
		}
		m, err := engine.ParseTUNMode(raw)
		if err != nil {
			return fmt.Errorf("%w: --tun-mode 参数 %q 非法: %w", clikit.ErrUsage, raw, err)
		}
		p.tunMode = m
		return nil
	}
	return fmt.Errorf("%w: 未知长选项 %q", clikit.ErrUsage, tok)
}

func (p *sshFlagParser) parseShortCluster(cluster string) error {
	for i := 0; i < len(cluster); i++ {
		ch := cluster[i]
		handled, stop, err := p.applyShortFlag(ch, cluster[i+1:])
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
		if !handled {
			r, _ := utf8.DecodeRuneInString(cluster[i:])
			return fmt.Errorf("%w: 未知短选项 -%c", clikit.ErrUsage, r)
		}
	}
	return nil
}

func (p *sshFlagParser) applyShortFlag(ch byte, rest string) (handled, stop bool, err error) {
	if ok, err := p.applyShortBoolFlag(ch); ok || err != nil {
		return ok, p.stopFlags, err
	}
	if ok, err := clikit.ApplyCommonSSHShortOption(p.cur, ch, rest, &p.layer, &p.common.ConfigFile); ok || err != nil {
		return ok, true, err
	}
	return p.applySSHExtraValueFlag(ch, rest)
}

func (p *sshFlagParser) applyShortBoolFlag(ch byte) (bool, error) {
	switch ch {
	case 'h':
		p.common.ShowHelp = true
		p.stopFlags = true
		return true, nil
	case 't':
		p.ttyCount++
		if p.ttyCount >= 2 {
			p.ttyMode = engine.RequestTTYForce
		} else {
			p.ttyMode = engine.RequestTTYYes
		}
		return true, nil
	case 'T':
		p.ttyCount = 0
		p.ttyMode = engine.RequestTTYNo
		return true, nil
	case 'N':
		p.noCommand = true
		return true, nil
	case 'f':
		p.background = true
		return true, nil
	case 'M':
		p.masterCnt++
		mode := "yes"
		if p.masterCnt >= 2 {
			mode = "ask"
		}
		return true, clikit.ApplyOptionKV(&p.layer, "ControlMaster", mode, "-M")
	default:
		return false, nil
	}
}

func (p *sshFlagParser) applySSHExtraValueFlag(ch byte, rest string) (bool, bool, error) {
	switch ch {
	case 'L', 'R', 'D', 'O', 'S', 'W', 'w':
		val, err := p.cur.ConsumeShortArg(ch, rest)
		if err != nil {
			return false, true, err
		}
		return true, true, p.applyExtraValue(ch, val)
	default:
		return false, false, nil
	}
}

func (p *sshFlagParser) applyExtraValue(ch byte, val string) error {
	switch ch {
	case 'L':
		return p.appendForward(engine.ForwardLocal, val)
	case 'R':
		return p.appendForward(engine.ForwardRemote, val)
	case 'D':
		return p.appendForward(engine.ForwardDynamic, val)
	case 'w':
		p.rawTUNs = append(p.rawTUNs, val)
		return nil
	case 'O':
		act, err := engine.ParseMuxControlAction(val)
		if err != nil {
			return fmt.Errorf("%w: -O 控制动作 %q 非法: %w", clikit.ErrUsage, val, err)
		}
		p.muxAction = act
		return nil
	case 'S':
		p.ctlSocket = val
		return clikit.ApplyOptionKV(&p.layer, "ControlPath", val, "-S")
	case 'W':
		hp, err := netaddr.ParseHostPort(strings.TrimSpace(val))
		if err != nil {
			return fmt.Errorf("%w: -W 参数 %q 必须为 host:port: %w", clikit.ErrUsage, val, err)
		}
		p.stdioFwd = algebraic.Some(hp)
		return nil
	default:
		return fmt.Errorf("%w: 不支持的选项 -%c", clikit.ErrUsage, ch)
	}
}

func (p *sshFlagParser) appendForward(dir engine.ForwardDirection, val string) error {
	spec, err := clikit.ParseForwardFlagSpec(dir, val)
	if err != nil {
		return err
	}
	p.forwards = append(p.forwards, spec)
	return nil
}

func (p *sshFlagParser) finish() (SSHCommandArgs, error) {
	if p.common.ShowHelp {
		return SSHCommandArgs{ShowHelp: true}, nil
	}
	pos := p.cur.Rest()
	if len(pos) == 0 {
		return SSHCommandArgs{}, fmt.Errorf("%w: 缺少目标主机 [user@]host", clikit.ErrUsage)
	}
	target := strings.TrimSpace(pos[0])
	if target == "" {
		return SSHCommandArgs{}, fmt.Errorf("%w: 目标主机不能为空", clikit.ErrUsage)
	}
	for _, rawTUN := range p.rawTUNs {
		spec, err := clikit.ParseTUNForwardSpec(p.tunMode, rawTUN)
		if err != nil {
			return SSHCommandArgs{}, err
		}
		p.forwards = append(p.forwards, spec)
	}
	if err := p.layer.Validate(); err != nil {
		return SSHCommandArgs{}, fmt.Errorf("%w: CLI 选项层校验失败: %w", clikit.ErrUsage, err)
	}
	var cmdArgs []string
	if len(pos) > 1 {
		cmdArgs = append([]string(nil), pos[1:]...)
	}
	if err := validateSSHFlagCombinations(p, cmdArgs); err != nil {
		return SSHCommandArgs{}, err
	}
	return SSHCommandArgs{
		TargetSpec:    target,
		CommandArgs:   cmdArgs,
		CLIOptions:    p.layer,
		RequestTTY:    p.ttyMode,
		ConfigFile:    p.common.ConfigFile,
		Policy:        p.common.Policy,
		JSON:          p.common.JSON,
		Forwards:      p.forwards,
		TUNMode:       p.tunMode,
		MuxAction:     p.muxAction,
		ControlSocket: p.ctlSocket,
		MasterCount:   p.masterCnt,
		NoCommand:     p.noCommand,
		Background:    p.background,
		StdioForward:  p.stdioFwd,
	}, nil
}

func validateSSHFlagCombinations(p *sshFlagParser, cmdArgs []string) error {
	if p.noCommand && len(cmdArgs) > 0 {
		return fmt.Errorf("%w: -N 模式下不得同时提供远端命令参数", clikit.ErrUsage)
	}
	if p.stdioFwd.IsSome() && len(cmdArgs) > 0 {
		return fmt.Errorf("%w: -W 模式下不得同时提供远端命令参数", clikit.ErrUsage)
	}
	if p.muxAction.IsValid() && len(cmdArgs) > 0 {
		return fmt.Errorf("%w: -O 控制模式下不得同时提供远端命令参数", clikit.ErrUsage)
	}
	if p.muxAction.IsValid() && p.background {
		return fmt.Errorf("%w: -O 控制模式不能与 -f 后台守护模式同时使用", clikit.ErrUsage)
	}
	if p.background && len(cmdArgs) > 0 {
		return fmt.Errorf("%w: -f 后台守护模式不支持附带远端命令，请配合 -N / -M 或转发规则使用", clikit.ErrUsage)
	}
	if p.background && !p.noCommand && p.masterCnt == 0 && len(p.forwards) == 0 {
		return fmt.Errorf("%w: -f 后台守护模式至少需要配合 -N、-M 或转发规则（-L/-R/-D/-w）", clikit.ErrUsage)
	}
	return nil
}
