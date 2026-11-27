package cmdtransfer

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

// splitSCPEndpoint 区分远端 `[user@]host:<path>` 与本地路径（保护 Windows 盘符 `C:\...` / `C:/...` 不被误判为远端主机）。
func splitSCPEndpoint(raw string) (host, remotePath string, isRemote bool) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) >= 3 && isASCIIAlpha(trimmed[0]) && trimmed[1] == ':' && (trimmed[2] == '\\' || trimmed[2] == '/') {
		return "", "", false
	}
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "./") || strings.HasPrefix(trimmed, "../") {
		return "", "", false
	}
	if idx := findRemoteColon(trimmed); idx > 0 && idx+1 < len(trimmed) {
		return trimmed[:idx], trimmed[idx+1:], true
	}
	return "", "", false
}

func findRemoteColon(s string) int {
	inBracket := false
	for i := range len(s) {
		switch s[i] {
		case '[':
			inBracket = true
		case ']':
			inBracket = false
		case '/', '\\':
			if !inBracket {
				return -1
			}
		case ':':
			if !inBracket {
				return i
			}
		}
	}
	return -1
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func parseSCPArgs(args []string) (scpArgs, error) {
	out := scpArgs{
		cliOpts:       option.UnsetOptionLayer(),
		symlinkPolicy: pathalg.SymlinkReject,
	}
	cur := clikit.NewFlagCursor(args)
	var pos []string
	for cur.HasNext() {
		tok := cur.Peek()
		if tok == "--" {
			cur.Next()
			pos = append(pos, cur.Rest()...)
			break
		}
		if tok == "-h" || tok == "--help" {
			out.common.ShowHelp = true
			return out, nil
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			pos = append(pos, cur.Next())
			continue
		}
		if err := parseSCPFlag(cur, &out); err != nil {
			return scpArgs{}, err
		}
		if out.common.ShowHelp {
			return out, nil
		}
	}
	if len(pos) != 2 {
		return scpArgs{}, fmt.Errorf("%w: scp 需要恰好 2 个位置参数 <source> <dest>", clikit.ErrUsage)
	}
	out.srcRaw, out.dstRaw = pos[0], pos[1]
	if err := out.cliOpts.Validate(); err != nil {
		return scpArgs{}, fmt.Errorf("%w: CLI 选项层校验失败: %w", clikit.ErrUsage, err)
	}
	return out, nil
}

func parseSCPFlag(cur *clikit.FlagCursor, out *scpArgs) error {
	if strings.HasPrefix(cur.Peek(), "--") {
		return parseSCPLongFlag(cur, out)
	}
	tok := cur.Next()
	return parseSCPShortCluster(cur, tok[1:], out)
}

func parseSCPShortCluster(cur *clikit.FlagCursor, cluster string, out *scpArgs) error {
	for i := 0; i < len(cluster); i++ {
		ch := cluster[i]
		switch ch {
		case 'h':
			out.common.ShowHelp = true
			return nil
		case 'r':
			out.recursive = true
		case 'p':
			out.preserve = true
		case 'P':
			val, err := cur.ConsumeShortArg('P', cluster[i+1:])
			if err != nil {
				return err
			}
			return clikit.ApplyOptionKV(&out.cliOpts, "Port", val, "-P")
		case 'l', 'i', 'J', 'o', 'F':
			_, err := clikit.ApplyCommonSSHShortOption(cur, ch, cluster[i+1:], &out.cliOpts, &out.common.ConfigFile)
			return err
		default:
			r, _ := utf8.DecodeRuneInString(cluster[i:])
			return fmt.Errorf("%w: scp 未知短选项 -%c", clikit.ErrUsage, r)
		}
	}
	return nil
}

func parseSCPLongFlag(cur *clikit.FlagCursor, out *scpArgs) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &out.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	name, inlineVal, hasEq := clikit.SplitLongFlag(tok)
	if handled, err := parseSCPBoolLongFlag(name, inlineVal, hasEq, out); handled || err != nil {
		return err
	}
	return parseSCPValueLongFlag(cur, name, inlineVal, hasEq, tok, out)
}

func parseSCPBoolLongFlag(name, inlineVal string, hasEq bool, out *scpArgs) (bool, error) {
	switch name {
	case "recursive":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.recursive = v
		return true, err
	case "preserve":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.preserve = v
		return true, err
	case "resume":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.resume = v
		return true, err
	case "no-clobber":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.noClobber = v
		return true, err
	case "expand-into-dir":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.expandIntoDir = v
		return true, err
	default:
		return false, nil
	}
}

func parseSCPValueLongFlag(cur *clikit.FlagCursor, name, inlineVal string, hasEq bool, rawTok string, out *scpArgs) error {
	raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	switch name {
	case "symlink-policy":
		p, pErr := pathalg.ParseSymlinkPolicy(raw)
		if pErr != nil {
			return fmt.Errorf("%w: --symlink-policy 非法: %w", clikit.ErrUsage, pErr)
		}
		out.symlinkPolicy = p
	case "local-root":
		d, dErr := pathalg.ParseLocalDir(raw)
		if dErr != nil {
			return fmt.Errorf("%w: --local-root 非法: %w", clikit.ErrUsage, dErr)
		}
		out.localRoot = algebraic.Some(d)
	case "perm":
		mode, mErr := clikit.ParseOctalPerm("--perm", raw)
		if mErr != nil {
			return mErr
		}
		out.perm = algebraic.Some(mode)
	case "chunk-size":
		out.chunkSize, err = clikit.ParseNonNegInt64("--chunk-size", raw)
	case "concurrency":
		out.concurrency, err = clikit.ParsePositiveInt("--concurrency", raw)
	case "max-files":
		out.maxFiles, err = clikit.ParsePositiveInt("--max-files", raw)
	case "max-bytes":
		out.maxTotalBytes, err = clikit.ParseNonNegUint64("--max-bytes", raw)
	case "expected-digest":
		dig, dErr := security.ParseDigest(raw)
		if dErr != nil {
			return fmt.Errorf("%w: --expected-digest 非法: %w", clikit.ErrUsage, dErr)
		}
		out.expectedDigest = algebraic.Some(dig)
	default:
		return fmt.Errorf("%w: scp 未知长选项 %q", clikit.ErrUsage, rawTok)
	}
	return err
}
