package cmdops

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

type tuiArgs struct {
	common      clikit.CommonFlags
	initialNode string
	refresh     algebraic.Option[algebraic.Duration]
	noAltScreen bool
}

// RunTUI 解析 `xops tui` 参数并通过组合根注入的 AppConfig.RunTUI 回调启动终端工作台（未注入严格失败关闭）。
func RunTUI(ctx context.Context, rt *clikit.Runtime, args []string) int {
	parsed, err := parseTUIArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, TUIHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.common.JSON)
	if rt.Hooks.RunTUI == nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, fmt.Errorf("%w: 未注入 RunTUI 回调，无法启动 TUI 工作台", clikit.ErrNotConfigured))
	}
	req := clikit.TUIStartRequest{
		InitOptions:     rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy),
		InitialNode:     parsed.initialNode,
		RefreshInterval: parsed.refresh,
		NoAltScreen:     parsed.noAltScreen,
		Stdin:           rt.Stdin,
		Stdout:          rt.Stdout,
		Stderr:          rt.Stderr,
	}
	if err := rt.Hooks.RunTUI(ctx, req); err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	return clikit.ExitOK
}

func parseTUIArgs(args []string) (tuiArgs, error) {
	var out tuiArgs
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseTUIToken(cur, &out); err != nil {
			return tuiArgs{}, err
		}
		if out.common.ShowHelp {
			return out, nil
		}
	}
	return out, nil
}

func parseTUIToken(cur *clikit.FlagCursor, out *tuiArgs) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &out.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	if tok == "-h" {
		out.common.ShowHelp = true
		return nil
	}
	if tok == "-F" {
		val, err := cur.ConsumeShortArg('F', "")
		if err != nil {
			return err
		}
		return clikit.SetConfigFile(&out.common.ConfigFile, val)
	}
	return applyTUILongFlag(cur, tok, out)
}

func applyTUILongFlag(cur *clikit.FlagCursor, rawTok string, out *tuiArgs) error {
	name, inlineVal, hasEq := clikit.SplitLongFlag(rawTok)
	switch name {
	case "node":
		val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		out.initialNode = strings.TrimSpace(val)
		return err
	case "refresh":
		val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return err
		}
		d, err := clikit.ParsePositiveDuration("--refresh", val)
		if err == nil {
			out.refresh = algebraic.Some(d)
		}
		return err
	case "no-alt-screen":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.noAltScreen = v
		return err
	default:
		return fmt.Errorf("%w: tui 未知选项 %q", clikit.ErrUsage, rawTok)
	}
}

type mcpArgs struct {
	common           clikit.CommonFlags
	transport        string
	listenAddr       string
	transferRoot     algebraic.Option[pathalg.LocalDir]
	artifactRoot     algebraic.Option[pathalg.LocalDir]
	allowNonLoopback bool
	allowedOrigins   []string
	allowedHosts     []string
}

// RunMCP 解析 `xops mcp [serve]` 参数并通过组合根注入的 AppConfig.RunMCP 回调启动 MCP 宿主入口（未注入严格失败关闭）。
func RunMCP(ctx context.Context, rt *clikit.Runtime, args []string) int {
	parsed, err := parseMCPArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, MCPHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.common.JSON)
	if rt.Hooks.RunMCP == nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, fmt.Errorf("%w: 未注入 RunMCP 回调，无法启动 MCP 服务", clikit.ErrNotConfigured))
	}
	req := clikit.MCPStartRequest{
		InitOptions:          rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy),
		Transport:            parsed.transport,
		ListenAddr:           parsed.listenAddr,
		TransferRoot:         parsed.transferRoot,
		ArtifactRoot:         parsed.artifactRoot,
		AllowNonLoopbackHTTP: parsed.allowNonLoopback,
		HTTPAllowedOrigins:   parsed.allowedOrigins,
		HTTPAllowedHosts:     parsed.allowedHosts,
		Stdin:                rt.Stdin,
		Stdout:               rt.Stdout,
		Stderr:               rt.Stderr,
	}
	if err := rt.Hooks.RunMCP(ctx, req); err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	return clikit.ExitOK
}

func parseMCPArgs(args []string) (mcpArgs, error) {
	out := mcpArgs{transport: "stdio"}
	rest := args
	if len(rest) > 0 && rest[0] == "serve" {
		rest = rest[1:]
	}
	cur := clikit.NewFlagCursor(rest)
	for cur.HasNext() {
		if err := parseMCPToken(cur, &out); err != nil {
			return mcpArgs{}, err
		}
		if out.common.ShowHelp {
			return out, nil
		}
	}
	if out.transport == "http" && strings.TrimSpace(out.listenAddr) == "" {
		out.listenAddr = "127.0.0.1:8080"
	}
	return out, nil
}

func parseMCPToken(cur *clikit.FlagCursor, out *mcpArgs) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &out.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	if tok == "-h" {
		out.common.ShowHelp = true
		return nil
	}
	if tok == "-F" {
		val, err := cur.ConsumeShortArg('F', "")
		if err != nil {
			return err
		}
		return clikit.SetConfigFile(&out.common.ConfigFile, val)
	}
	return parseMCPLongFlag(cur, tok, out)
}

func parseMCPLongFlag(cur *clikit.FlagCursor, rawTok string, out *mcpArgs) error {
	name, inlineVal, hasEq := clikit.SplitLongFlag(rawTok)
	if name == "allow-non-loopback" {
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.allowNonLoopback = v
		return err
	}
	val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	switch name {
	case "transport":
		t := strings.ToLower(strings.TrimSpace(val))
		if t != "stdio" && t != "http" {
			return fmt.Errorf("%w: --transport 必须为 stdio|http，实际=%q", clikit.ErrUsage, val)
		}
		out.transport = t
	case "listen":
		out.listenAddr = strings.TrimSpace(val)
	case "transfer-root":
		d, err := pathalg.ParseLocalDir(val)
		if err != nil {
			return fmt.Errorf("%w: --transfer-root 非法: %w", clikit.ErrUsage, err)
		}
		out.transferRoot = algebraic.Some(d)
	case "artifact-root":
		d, err := pathalg.ParseLocalDir(val)
		if err != nil {
			return fmt.Errorf("%w: --artifact-root 非法: %w", clikit.ErrUsage, err)
		}
		out.artifactRoot = algebraic.Some(d)
	case "allowed-origin":
		out.allowedOrigins = append(out.allowedOrigins, clikit.SplitCSV(val)...)
	case "allowed-host":
		out.allowedHosts = append(out.allowedHosts, clikit.SplitCSV(val)...)
	default:
		return fmt.Errorf("%w: mcp 未知选项 %q", clikit.ErrUsage, rawTok)
	}
	return nil
}
