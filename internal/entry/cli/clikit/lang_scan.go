package clikit

import (
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// ScanLangFlag 以命令与选项语法感知方式预扫描命令行中的 `--lang <v>` / `--lang=<v>`（末次覆盖语义）：
//   - 全局前置区跳过已知带值选项的值 token（-F / --policy / --ssh-config），遇 `--` 立即停止；
//   - 进入 `ssh` 或 `exec` 子命令后，跳过对应带值短/长选项的值 token（完整支持短选项簇与紧贴参数），
//     一旦遇到 `--` 或首个位置参数（目标主机）立即停止，彻底避免误拦远端命令自带的 `--lang=...` 参数；
//   - 进入其余子命令（含 version / help / --help / hosts / creds / scp / sftp / tunnel / mux / playbook / doctor / audit / config / mcp / tui）后，
//     跳过对应带值选项的值 token，扫描 `--` 之前全部位置以同时支持前置与后置 `--lang`；
//   - 任一有效扫描位置出现缺值或非法 `--lang` 均失败关闭返回包装 ErrUsage 的结构化错误。
func ScanLangFlag(args []string) (algebraic.Option[domi18n.Locale], error) {
	var found algebraic.Option[domi18n.Locale]
	idx, cmd, stopped, err := scanGlobalLangPrefix(args, &found)
	if err != nil || stopped || idx >= len(args) {
		return found, err
	}
	if cmd == "ssh" || cmd == "exec" {
		if err := scanSSHOrExecLang(args[idx:], cmd, &found); err != nil {
			return algebraic.None[domi18n.Locale](), err
		}
		return found, nil
	}
	if err := scanGeneralSubcommandLang(args[idx:], cmd, &found); err != nil {
		return algebraic.None[domi18n.Locale](), err
	}
	return found, nil
}

func scanGlobalLangPrefix(args []string, found *algebraic.Option[domi18n.Locale]) (int, string, bool, error) {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" {
			return i + 1, "", true, nil
		}
		if tok == "-h" || tok == "--help" || tok == "-V" || tok == "--version" {
			return i + 1, tok, false, nil
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			return i + 1, tok, false, nil
		}
		skip, err := consumePrefixLangToken(args, i, found)
		if err != nil {
			return i, "", true, err
		}
		i += skip
	}
	return len(args), "", true, nil
}

func consumePrefixLangToken(args []string, idx int, found *algebraic.Option[domi18n.Locale]) (int, error) {
	tok := args[idx]
	if strings.HasPrefix(tok, "--") {
		name, inlineVal, hasEq := SplitLongFlag(tok)
		if name == "lang" {
			return parseLangOptionAt(args, idx, inlineVal, hasEq, found)
		}
		if !hasEq && (name == "policy" || name == "ssh-config") {
			return skipNextValue(args, idx), nil
		}
		return 0, nil
	}
	if tok == "-F" {
		return skipNextValue(args, idx), nil
	}
	return 0, nil
}

func scanSSHOrExecLang(args []string, cmd string, found *algebraic.Option[domi18n.Locale]) error {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" || !strings.HasPrefix(tok, "-") || tok == "-" {
			return nil
		}
		if strings.HasPrefix(tok, "--") {
			skip, err := consumeSubcommandLongToken(args, i, cmd, found)
			if err != nil {
				return err
			}
			i += skip
			continue
		}
		i += skipShortClusterValue(args, i, cmd, tok[1:])
	}
	return nil
}

func scanGeneralSubcommandLang(args []string, cmd string, found *algebraic.Option[domi18n.Locale]) error {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" {
			return nil
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			continue
		}
		if strings.HasPrefix(tok, "--") {
			skip, err := consumeSubcommandLongToken(args, i, cmd, found)
			if err != nil {
				return err
			}
			i += skip
			continue
		}
		i += skipShortClusterValue(args, i, cmd, tok[1:])
	}
	return nil
}

func consumeSubcommandLongToken(args []string, idx int, cmd string, found *algebraic.Option[domi18n.Locale]) (int, error) {
	name, inlineVal, hasEq := SplitLongFlag(args[idx])
	if name == "lang" {
		return parseLangOptionAt(args, idx, inlineVal, hasEq, found)
	}
	if !hasEq && isValueTakingLongFlag(cmd, name) {
		return skipNextValue(args, idx), nil
	}
	return 0, nil
}

func parseLangOptionAt(args []string, idx int, inlineVal string, hasEq bool, found *algebraic.Option[domi18n.Locale]) (int, error) {
	skip := 0
	raw := inlineVal
	if !hasEq {
		if idx+1 >= len(args) {
			return 0, i18n.EF(ErrUsage, i18n.KeyCLIMissingLongValue, i18n.Str("flag", "lang"))
		}
		raw = args[idx+1]
		skip = 1
	}
	loc, err := domi18n.ParseLocale(raw)
	if err != nil {
		return 0, i18n.WrapS(ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--lang"), i18n.BoundStr("value", raw))
	}
	*found = algebraic.Some(loc)
	return skip, nil
}

func skipNextValue(args []string, idx int) int {
	if idx+1 < len(args) {
		return 1
	}
	return 0
}

// skipShortClusterValue 按 OpenSSH 短选项簇规则判断当前短标志是否需要消耗下一参数 token：
// 遇到带值短标志且其后仍有紧贴字符时，余串即为参数值（不消耗下一 token）；
// 位于短簇末尾时才消耗下一 token。
func skipShortClusterValue(args []string, idx int, cmd, cluster string) int {
	for i := range len(cluster) {
		if isValueTakingShortFlag(cmd, cluster[i]) {
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
	case "config", "tui", "mcp":
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
