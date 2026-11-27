package cmdasset

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

const maxConfigImportBytes int64 = 16 << 20

type importArgs struct {
	common        clikit.CommonFlags
	format        string
	filePath      string
	sourceName    string
	symlinkPolicy pathalg.SymlinkPolicy
	expRevRaw     string
	planOnly      bool
	dryRun        bool
}

// RunConfig 执行 `xops config` 命令族（`config import` 与 `config formats`，100% 零 v1 兼容代码）。
func RunConfig(ctx context.Context, rt *clikit.Runtime, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(rt.Stdout, ConfigHelpText())
		return clikit.ExitOK
	}
	switch args[0] {
	case "import":
		return runConfigImport(ctx, rt, args[1:])
	case "formats":
		return runConfigFormats(ctx, rt, args[1:])
	default:
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, fmt.Errorf("%w: 未知 config 子命令 %q", clikit.ErrUsage, args[0]))
	}
}

func runConfigFormats(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, err := parseCommonOnly("formats", args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, ConfigHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	initOpts := rt.EffectiveInitOptions(common.ConfigFile, common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		formats := client.SupportedImportFormats()
		type view struct {
			OK      bool     `json:"ok"`
			Formats []string `json:"formats"`
		}
		return rt.WriteResult(jsonOut, view{OK: true, Formats: formats}, func(w io.Writer) {
			if len(formats) == 0 {
				_, _ = io.WriteString(w, "no registered import formats\n")
				return
			}
			for _, f := range formats {
				_, _ = fmt.Fprintf(w, "%s\n", f)
			}
		})
	})
}

func runConfigImport(ctx context.Context, rt *clikit.Runtime, args []string) int {
	parsed, err := parseImportArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, ConfigHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.common.JSON)
	expRev, err := parseOptionalRevision(parsed.expRevRaw)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	raw, inferredName, err := rt.ReadLocalInput(ctx, parsed.filePath, parsed.symlinkPolicy, maxConfigImportBytes)
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	sourceName := strings.TrimSpace(parsed.sourceName)
	if sourceName == "" {
		sourceName = inferredName
	}
	initOpts := rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		req := engine.ImportRequest{
			Format:           parsed.format,
			SourceName:       sourceName,
			Reader:           bytes.NewReader(raw),
			ExpectedRevision: expRev,
			DryRun:           parsed.dryRun,
		}
		if parsed.planOnly {
			return executePlanImport(ctx, rt, client, req, jsonOut)
		}
		return executeApplyImport(ctx, rt, client, req, jsonOut)
	})
}

func executePlanImport(ctx context.Context, rt *clikit.Runtime, client clikit.InventoryClient, req engine.ImportRequest, jsonOut bool) int {
	preview, err := client.PlanImport(ctx, req)
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	rep := preview.Report()
	type view struct {
		OK           bool                   `json:"ok"`
		BaseRevision engine.Revision        `json:"base_revision"`
		Report       inventory.ImportReport `json:"report"`
	}
	return rt.WriteResult(jsonOut, view{OK: true, BaseRevision: preview.BaseRevision(), Report: rep}, func(w io.Writer) {
		renderImportReportText(w, "plan", preview.BaseRevision(), false, rep)
	})
}

func executeApplyImport(ctx context.Context, rt *clikit.Runtime, client clikit.InventoryClient, req engine.ImportRequest, jsonOut bool) int {
	res, err := client.ApplyImport(ctx, req)
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	rep := res.Report()
	type view struct {
		OK         bool                                       `json:"ok"`
		Applied    bool                                       `json:"applied"`
		Revision   engine.Revision                            `json:"revision"`
		Durability algebraic.Option[engine.DurabilityOutcome] `json:"durability,omitzero"`
		Report     inventory.ImportReport                     `json:"report"`
	}
	return rt.WriteResult(jsonOut, view{
		OK: true, Applied: res.Applied(), Revision: res.Revision(), Durability: res.Durability(), Report: rep,
	}, func(w io.Writer) {
		renderImportReportText(w, "import", res.Revision(), res.Applied(), rep)
	})
}

func renderImportReportText(w io.Writer, label string, rev engine.Revision, applied bool, rep inventory.ImportReport) {
	_, _ = fmt.Fprintf(w, "%s (%s) revision=%s applied=%v add=%d unchanged=%d conflict=%d warnings=%d\n",
		label, rep.SourceFormat, rev, applied, rep.AddCount, rep.UnchangedCount, rep.ConflictCount, len(rep.Warnings))
	for _, entry := range rep.Entries {
		_, _ = fmt.Fprintf(w, "  [%s] %s/%s %s\n", entry.Action, entry.AssetKind, entry.AssetID, entry.Reason)
	}
	for _, warn := range rep.Warnings {
		_, _ = fmt.Fprintf(w, "  [warn] %s (%s): %s\n", warn.Code(), warn.Subject(), warn.Message())
	}
}

func parseImportArgs(args []string) (importArgs, error) {
	out := importArgs{symlinkPolicy: pathalg.SymlinkReject}
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseImportToken(cur, &out); err != nil {
			return importArgs{}, err
		}
		if out.common.ShowHelp {
			return out, nil
		}
	}
	if strings.TrimSpace(out.format) == "" {
		return importArgs{}, fmt.Errorf("%w: config import 必须指定 --format <format>（如 openssh / csv）", clikit.ErrUsage)
	}
	return out, nil
}

func parseImportToken(cur *clikit.FlagCursor, out *importArgs) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &out.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	if tok == "-h" {
		out.common.ShowHelp = true
		return nil
	}
	if !strings.HasPrefix(tok, "--") {
		if out.filePath == "" {
			out.filePath = tok
			return nil
		}
		return fmt.Errorf("%w: config import 多余位置参数 %q", clikit.ErrUsage, tok)
	}
	return parseImportLongFlag(cur, tok, out)
}

func parseImportLongFlag(cur *clikit.FlagCursor, rawTok string, out *importArgs) error {
	name, inlineVal, hasEq := clikit.SplitLongFlag(rawTok)
	switch name {
	case "plan":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.planOnly = v
		return err
	case "dry-run":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.dryRun = v
		return err
	case "stdin":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		if err == nil && v {
			out.filePath = "-"
		}
		return err
	}
	val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	switch name {
	case "format":
		out.format = strings.ToLower(strings.TrimSpace(val))
	case "file":
		out.filePath = val
	case "source-name":
		out.sourceName = val
	case "expected-revision":
		out.expRevRaw = val
	case "symlink-policy":
		p, err := pathalg.ParseSymlinkPolicy(val)
		if err != nil {
			return fmt.Errorf("%w: --symlink-policy 非法: %w", clikit.ErrUsage, err)
		}
		out.symlinkPolicy = p
	default:
		return fmt.Errorf("%w: config import 未知选项 %q", clikit.ErrUsage, rawTok)
	}
	return nil
}
