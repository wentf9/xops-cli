package cli

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
)

// SSHCommandArgs 保存 `xops ssh` 参数解析产出的强类型命令行参数与 Tier-1（CLI）选项层。
type SSHCommandArgs struct {
	// TargetSpec 为目标连接规格（[user@]host[:port]、IPv6 或 OpenSSH 虚拟主机别名）。
	TargetSpec string
	// CommandArgs 为紧随目标之后的远端命令及参数切片；为空时进入交互式 Shell。
	CommandArgs []string
	// CLIOptions 为按命令行出现顺序折叠的 Tier-1 OpenSSH 选项层（-p/-l/-i/-J/-o）。
	CLIOptions option.OptionLayer
	// RequestTTY 为由 -t/-tt/-T 推导的伪终端分配策略（未指定时为零值 RequestTTYUnset）。
	RequestTTY engine.RequestTTYMode
	// ConfigFile 为 `-F <configfile>` 指定的 OpenSSH 配置文件路径覆写（空串表示使用默认配置）。
	ConfigFile string
	// ShowHelp 为 true 时表示用户显式请求查看 `xops ssh` 帮助信息。
	ShowHelp bool
}

type sshFlagParser struct {
	args       []string
	idx        int
	layer      option.OptionLayer
	ttyMode    engine.RequestTTYMode
	ttyCount   int
	configFile string
	showHelp   bool
	stopFlags  bool
}

// ParseSSHArgs 按 OpenSSH ssh(1) 短选项习惯解析 `xops ssh` 后续参数列表：
//   - 支持 -p <port>、-l <user>、-i <identity_file>（可重复）、-J <proxy_jump>、
//     -o <Key=Value>（可重复，严格经 option.ParseOption 解析）、-t / -tt / -T、-F <configfile>、
//     -- 分隔符及 -h/--help；
//   - 遇到首个非选项位置参数（[user@]host）后立即停止选项解析，确保远端命令自带的 `-flag` 完整透传。
func ParseSSHArgs(args []string) (SSHCommandArgs, error) {
	p := &sshFlagParser{
		args:  args,
		layer: option.UnsetOptionLayer(),
	}
	for p.idx < len(p.args) && !p.stopFlags {
		cur := p.args[p.idx]
		if cur == "--" {
			p.idx++
			p.stopFlags = true
			break
		}
		if cur == "-h" || cur == "--help" {
			p.showHelp = true
			return SSHCommandArgs{ShowHelp: true}, nil
		}
		if !strings.HasPrefix(cur, "-") || cur == "-" {
			break
		}
		if strings.HasPrefix(cur, "--") {
			return SSHCommandArgs{}, fmt.Errorf("%w: 未知长选项 %q", ErrUsage, cur)
		}
		if err := p.parseShortCluster(cur[1:]); err != nil {
			return SSHCommandArgs{}, err
		}
	}
	return p.finish()
}

func (p *sshFlagParser) finish() (SSHCommandArgs, error) {
	if p.showHelp {
		return SSHCommandArgs{ShowHelp: true}, nil
	}
	pos := p.args[p.idx:]
	if len(pos) == 0 {
		return SSHCommandArgs{}, fmt.Errorf("%w: 缺少目标主机 [user@]host", ErrUsage)
	}
	target := strings.TrimSpace(pos[0])
	if target == "" {
		return SSHCommandArgs{}, fmt.Errorf("%w: 目标主机不能为空", ErrUsage)
	}
	if err := p.layer.Validate(); err != nil {
		return SSHCommandArgs{}, fmt.Errorf("%w: CLI 选项层校验失败: %w", ErrUsage, err)
	}
	var cmdArgs []string
	if len(pos) > 1 {
		cmdArgs = append([]string(nil), pos[1:]...)
	}
	return SSHCommandArgs{
		TargetSpec:  target,
		CommandArgs: cmdArgs,
		CLIOptions:  p.layer,
		RequestTTY:  p.ttyMode,
		ConfigFile:  p.configFile,
	}, nil
}

// parseShortCluster 解析单个短选项簇（如 `-tt`、`-p2222`、`-tp 2222` 或 `-oStrictHostKeyChecking=yes`）。
func (p *sshFlagParser) parseShortCluster(cluster string) error {
	p.idx++
	for i := 0; i < len(cluster); i++ {
		ch := cluster[i]
		switch ch {
		case 'h':
			p.showHelp = true
			p.stopFlags = true
			return nil
		case 't':
			p.ttyCount++
			if p.ttyCount >= 2 {
				p.ttyMode = engine.RequestTTYForce
			} else {
				p.ttyMode = engine.RequestTTYYes
			}
		case 'T':
			p.ttyCount = 0
			p.ttyMode = engine.RequestTTYNo
		case 'p', 'l', 'i', 'J', 'o', 'F':
			val, err := p.consumeShortArg(ch, cluster[i+1:])
			if err != nil {
				return err
			}
			return p.applyValueFlag(ch, val)
		default:
			r, _ := utf8.DecodeRuneInString(cluster[i:])
			return fmt.Errorf("%w: 未知短选项 -%c", ErrUsage, r)
		}
	}
	return nil
}

func (p *sshFlagParser) consumeShortArg(flagChar byte, remainder string) (string, error) {
	if remainder != "" {
		return remainder, nil
	}
	if p.idx >= len(p.args) {
		return "", fmt.Errorf("%w: 选项 -%c 缺少参数值", ErrUsage, flagChar)
	}
	val := p.args[p.idx]
	p.idx++
	return val, nil
}

func (p *sshFlagParser) applyValueFlag(flagChar byte, val string) error {
	switch flagChar {
	case 'p':
		return p.applyOptionKV("Port", val, "-p")
	case 'l':
		return p.applyOptionKV("User", val, "-l")
	case 'J':
		return p.applyOptionKV("ProxyJump", val, "-J")
	case 'i':
		return p.applyIdentityFile(val)
	case 'o':
		return p.applyRawOption(val)
	case 'F':
		return p.applyConfigFile(val)
	default:
		return fmt.Errorf("%w: 不支持的选项 -%c", ErrUsage, flagChar)
	}
}

func (p *sshFlagParser) applyOptionKV(key, val, flagLabel string) error {
	parsed, err := option.ParseOptionKV(key, val)
	if err != nil {
		return fmt.Errorf("%w: %s 参数 %q 非法: %w", ErrUsage, flagLabel, val, err)
	}
	p.layer = p.layer.ApplyParsedOption(parsed)
	return nil
}

// applyIdentityFile 直接经 option.ParsePathListEntries 构造并按序累加入 t1，
// 使含空格的跨平台本地密钥路径（如 Windows 用户目录）与 `-i none` 均能免引号安全解析。
func (p *sshFlagParser) applyIdentityFile(val string) error {
	pl, err := option.ParsePathListEntries([]string{val})
	if err != nil {
		return fmt.Errorf("%w: -i 参数 %q 非法: %w", ErrUsage, val, err)
	}
	p.layer = p.layer.Compose(option.UnsetOptionLayer().WithIdentityFiles(pl))
	return nil
}

func (p *sshFlagParser) applyRawOption(directive string) error {
	parsed, err := option.ParseOption(directive)
	if err != nil {
		return fmt.Errorf("%w: -o 选项 %q 无效: %w", ErrUsage, directive, err)
	}
	p.layer = p.layer.ApplyParsedOption(parsed)
	return nil
}

func (p *sshFlagParser) applyConfigFile(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%w: -F 配置文件路径不能为空", ErrUsage)
	}
	p.configFile = raw
	return nil
}
