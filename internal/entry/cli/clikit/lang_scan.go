package clikit

import (
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// PreScanResult 保存统一词法预扫描识别出的语言覆盖与 CLI `--json` 输出开关。
type PreScanResult struct {
	Locale algebraic.Option[domi18n.Locale]
	JSON   bool
}

// ScanPreFlags 以统一的命令与选项语法感知状态机预扫描命令行中的 `--lang` 与 `--json`（末次覆盖语义）：
//   - 全局前置区跳过已知带值选项的值 token（-F / --policy / --ssh-config），遇 `--` 立即停止；
//   - 进入 `ssh` 或 `exec` 子命令后，跳过对应带值短/长选项的值 token（支持短选项簇、`-h` 立即短路与紧贴参数），
//     一旦遇到 `--` 或首个位置参数（目标主机或远端命令起点）立即停止，彻底避免误拦远端命令自带的 `--lang` 或 `--json`；
//   - 进入其余子命令后，跳过对应带值选项的值 token，扫描 `--` 之前全部位置以同时支持前置、中置与后置 `--lang` / `--json`；
//   - 任一有效扫描位置出现缺值或非法 `--lang` 时记录首个错误并继续完成同一边界内的 `--json` 扫描，
//     最终失败关闭返回清空 Locale（保留准确 JSON 标志）的 PreScanResult 与包装 ErrUsage 的结构化错误。
func ScanPreFlags(args []string) (PreScanResult, error) {
	var firstErr error
	res := scanPreFlagsInto(args, &firstErr)
	if firstErr != nil {
		res.Locale = algebraic.None[domi18n.Locale]()
		return res, firstErr
	}
	return res, nil
}

func scanPreFlagsInto(args []string, firstErr *error) PreScanResult {
	var res PreScanResult
	idx, cmd, stopped := scanGlobalPrePrefix(args, &res, firstErr)
	if !stopped && idx < len(args) {
		scanSubcommandPreInto(cmd, args[idx:], &res, firstErr)
	}
	return res
}

// ScanLangFlag 以命令与选项语法感知方式预扫描命令行中的 `--lang <v>` / `--lang=<v>`（末次覆盖语义），
// 作为 ScanPreFlags 的薄包装供仅关心语言覆盖的调用方使用。
func ScanLangFlag(args []string) (algebraic.Option[domi18n.Locale], error) {
	res, err := ScanPreFlags(args)
	if err != nil {
		return algebraic.None[domi18n.Locale](), err
	}
	return res.Locale, nil
}

// HasJSONFlagForCommand 在已知子命令上下文 cmd 下，复用与 ScanPreFlags 相同的命令与带值选项词法状态机
// 判断 args 是否声明了 CLI `--json`（兼容 `--json=true/false` 末次生效），
// 专供各子命令语法报错早退路径使用，避免将 ssh/exec 远端命令或选项值中的 `--json` 误判为 JSON 输出模式。
func HasJSONFlagForCommand(cmd string, args []string) bool {
	var res PreScanResult
	scanSubcommandPreInto(cmd, args, &res, nil)
	return res.JSON
}

func scanSubcommandPreInto(cmd string, args []string, res *PreScanResult, firstErr *error) {
	if cmd == "ssh" || cmd == "exec" {
		scanSSHOrExecPre(args, cmd, res, firstErr)
		return
	}
	scanGeneralSubcommandPre(args, cmd, res, firstErr)
}

func scanGlobalPrePrefix(args []string, res *PreScanResult, firstErr *error) (int, string, bool) {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" {
			return i + 1, "", true
		}
		if tok == "-h" || tok == "--help" || tok == "-V" || tok == "--version" {
			return i + 1, tok, false
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			return i + 1, tok, false
		}
		i += consumePrefixPreToken(args, i, res, firstErr)
	}
	return len(args), "", true
}

func consumePrefixPreToken(args []string, idx int, res *PreScanResult, firstErr *error) int {
	tok := args[idx]
	if strings.HasPrefix(tok, "--") {
		name, inlineVal, hasEq := SplitLongFlag(tok)
		if name == "lang" {
			return parseLangOptionAt(args, idx, inlineVal, hasEq, &res.Locale, firstErr)
		}
		if name == "json" {
			applyJSONFlagToken(inlineVal, hasEq, &res.JSON)
			return 0
		}
		if !hasEq && (name == "policy" || name == "ssh-config") {
			return skipNextValue(args, idx)
		}
		return 0
	}
	if tok == "-F" {
		return skipNextValue(args, idx)
	}
	return 0
}

func scanSSHOrExecPre(args []string, cmd string, res *PreScanResult, firstErr *error) {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" || !strings.HasPrefix(tok, "-") || tok == "-" {
			return
		}
		if strings.HasPrefix(tok, "--") {
			i += consumeSubcommandLongToken(args, i, cmd, res, firstErr)
			continue
		}
		i += skipShortClusterValue(args, i, cmd, tok[1:])
	}
}

func scanGeneralSubcommandPre(args []string, cmd string, res *PreScanResult, firstErr *error) {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" {
			return
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			continue
		}
		if strings.HasPrefix(tok, "--") {
			i += consumeSubcommandLongToken(args, i, cmd, res, firstErr)
			continue
		}
		i += skipShortClusterValue(args, i, cmd, tok[1:])
	}
}

func consumeSubcommandLongToken(args []string, idx int, cmd string, res *PreScanResult, firstErr *error) int {
	name, inlineVal, hasEq := SplitLongFlag(args[idx])
	if name == "lang" {
		return parseLangOptionAt(args, idx, inlineVal, hasEq, &res.Locale, firstErr)
	}
	if name == "json" {
		applyJSONFlagToken(inlineVal, hasEq, &res.JSON)
		return 0
	}
	if !hasEq && isValueTakingLongFlag(cmd, name) {
		return skipNextValue(args, idx)
	}
	return 0
}

func applyJSONFlagToken(inlineVal string, hasEq bool, dst *bool) {
	if !hasEq {
		*dst = true
		return
	}
	switch strings.ToLower(strings.TrimSpace(inlineVal)) {
	case "true", "1", "t", "yes":
		*dst = true
	case "false", "0", "f", "no":
		*dst = false
	}
}

func parseLangOptionAt(
	args []string,
	idx int,
	inlineVal string,
	hasEq bool,
	found *algebraic.Option[domi18n.Locale],
	firstErr *error,
) int {
	skip := 0
	raw := inlineVal
	if !hasEq {
		if idx+1 >= len(args) {
			recordFirstErr(firstErr, i18n.EF(ErrUsage, i18n.KeyCLIMissingLongValue, i18n.Str("flag", "lang")))
			return 0
		}
		raw = args[idx+1]
		skip = 1
	}
	loc, err := domi18n.ParseLocale(raw)
	if err != nil {
		recordFirstErr(firstErr, i18n.WrapS(ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--lang"), i18n.BoundStr("value", raw)))
		return skip
	}
	*found = algebraic.Some(loc)
	return skip
}

func recordFirstErr(dst *error, err error) {
	if dst != nil && *dst == nil {
		*dst = err
	}
}

func skipNextValue(args []string, idx int) int {
	if idx+1 < len(args) {
		return 1
	}
	return 0
}

// skipShortClusterValue 按 OpenSSH 短选项簇规则判断当前短标志是否需要消耗下一参数 token：
//   - 遇到 `-h` 帮助短标志时立即短路（与各子命令解析器一致），停止后续字符的参数值消费，防止 `-hl --lang=...` 误吞 `--lang`；
//   - 遇到带值短标志且其后仍有紧贴字符时，余串即为参数值（不消耗下一 token）；
//   - 位于短簇末尾时才消耗下一 token。
func skipShortClusterValue(args []string, idx int, cmd, cluster string) int {
	for i := range len(cluster) {
		ch := cluster[i]
		if ch == 'h' {
			return 0
		}
		if isValueTakingShortFlag(cmd, ch) {
			if i+1 < len(cluster) {
				return 0
			}
			return skipNextValue(args, idx)
		}
	}
	return 0
}

func isValueTakingShortFlag(cmd string, ch byte) bool {
	switch cmd {
	case "ssh":
		return isSSHShortValue(ch)
	case "exec", "hosts", "host", "inventory", "playbook", "play":
		return isCommonSSHShortValue(ch)
	case "tunnel", "forward":
		return isCommonSSHShortValue(ch) || ch == 'L' || ch == 'R' || ch == 'D' || ch == 'w'
	case "mux":
		return isCommonSSHShortValue(ch) || ch == 'S' || ch == 'L' || ch == 'R' || ch == 'D' || ch == 'w'
	case "scp":
		return ch == 'P' || ch == 'l' || ch == 'i' || ch == 'J' || ch == 'o' || ch == 'F'
	case "sftp":
		return ch == 'P' || isCommonSSHShortValue(ch)
	case "config", "tui", "mcp", "creds", "cred", "vault", "audit":
		return ch == 'F'
	default:
		return false
	}
}

func isCommonSSHShortValue(ch byte) bool {
	switch ch {
	case 'p', 'l', 'i', 'J', 'o', 'F':
		return true
	default:
		return false
	}
}

func isSSHShortValue(ch byte) bool {
	if isCommonSSHShortValue(ch) {
		return true
	}
	switch ch {
	case 'L', 'R', 'D', 'O', 'S', 'W', 'w':
		return true
	default:
		return false
	}
}

func isValueTakingLongFlag(cmd, name string) bool {
	if name == "policy" || name == "ssh-config" {
		return true
	}
	switch cmd {
	case "ssh", "tunnel", "forward":
		return name == "tun-mode"
	case "mux":
		return name == "socket" || name == "tun-mode"
	case "exec":
		return isExecValueLongFlag(name)
	case "scp":
		return isSCPValueLongFlag(name)
	case "sftp":
		return isSFTPValueLongFlag(name)
	case "hosts", "host", "inventory":
		return isHostsValueLongFlag(name)
	case "creds", "cred", "vault":
		return isVaultValueLongFlag(name)
	case "config", "playbook", "play", "doctor", "audit", "mcp", "tui":
		return isOpsOrConfigValueLongFlag(cmd, name)
	default:
		return false
	}
}

func isExecValueLongFlag(name string) bool {
	switch name {
	case "nodes", "tags", "target", "targets", "exclude-nodes", "exclude-tags",
		"concurrency", "out-dir", "max-output-bytes", "timeout",
		"dialect", "interpreter", "login", "workdir", "env",
		"privilege-user", "sudo-user", "password-ref":
		return true
	default:
		return false
	}
}

func isSCPValueLongFlag(name string) bool {
	switch name {
	case "symlink-policy", "local-root", "perm", "chunk-size",
		"concurrency", "max-files", "max-bytes", "expected-digest":
		return true
	default:
		return false
	}
}

func isSFTPValueLongFlag(name string) bool {
	switch name {
	case "dir", "max-bytes", "perm", "local-root", "file", "symlink-policy", "old", "new":
		return true
	default:
		return false
	}
}

func isHostsValueLongFlag(name string) bool {
	switch name {
	case "kind", "tag", "tags", "ref", "store", "id", "address", "endpoint",
		"alias", "aliases", "desc", "description", "expected-revision",
		"user", "auth-kind", "password-ref", "key-path", "cert-path",
		"passphrase-ref", "key-fingerprint", "agent-spec",
		"host", "identity", "jump", "proxy-jump", "proxy-command",
		"dialect", "interpreter", "login", "priv-password-ref":
		return true
	default:
		return false
	}
}

func isVaultValueLongFlag(name string) bool {
	switch name {
	case "id", "identity-id", "user", "ref", "new-ref", "store",
		"desc", "description", "tag", "tags", "expected-revision",
		"node", "node-id", "key", "key-path", "cert", "cert-path", "fingerprint":
		return true
	default:
		return false
	}
}

func isOpsOrConfigValueLongFlag(cmd, name string) bool {
	switch cmd {
	case "config":
		return name == "format" || name == "file" || name == "source-name" || name == "expected-revision" || name == "symlink-policy"
	case "playbook", "play":
		return isPlaybookValueLongFlag(name)
	case "doctor":
		return name == "scope"
	case "audit":
		return name == "limit" || name == "phase" || name == "outcome" || name == "node" || name == "op-id" || name == "trace-id"
	case "mcp":
		return name == "transport" || name == "listen" || name == "transfer-root" || name == "artifact-root" || name == "allowed-origin" || name == "allowed-host"
	case "tui":
		return name == "node" || name == "refresh"
	default:
		return false
	}
}

func isPlaybookValueLongFlag(name string) bool {
	switch name {
	case "file", "target", "targets", "concurrency", "timeout", "var",
		"scoped-root", "symlink-policy", "dialect", "interpreter", "login":
		return true
	default:
		return false
	}
}
