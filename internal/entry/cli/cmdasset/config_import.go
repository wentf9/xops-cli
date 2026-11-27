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
	"github.com/wentf9/xops-cli/internal/i18n"
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
		_, _ = io.WriteString(rt.Stdout, ConfigHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	switch args[0] {
	case "import":
		return runConfigImport(ctx, rt, args[1:])
	case "formats":
		return runConfigFormats(ctx, rt, args[1:])
	default:
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args[1:])), i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownSubcommand, i18n.Str("cmd", "config"), i18n.BoundStr("sub", args[0])))
	}
}

func runConfigFormats(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, err := parseCommonOnly("formats", args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, ConfigHelpText(rt.Loc()))
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
		loc := rt.Loc()
		return rt.WriteResult(jsonOut, view{OK: true, Formats: formats}, func(w io.Writer) {
			if len(formats) == 0 {
				_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLIConfigNoFormats))
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
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, ConfigHelpText(rt.Loc()))
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
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, view{OK: true, BaseRevision: preview.BaseRevision(), Report: rep}, func(w io.Writer) {
		renderImportReportText(loc, w, "plan", preview.BaseRevision(), false, rep)
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
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, view{
		OK: true, Applied: res.Applied(), Revision: res.Revision(), Durability: res.Durability(), Report: rep,
	}, func(w io.Writer) {
		renderImportReportText(loc, w, "import", res.Revision(), res.Applied(), rep)
	})
}

func renderImportReportText(loc *i18n.Localizer, w io.Writer, label string, rev engine.Revision, applied bool, rep inventory.ImportReport) {
	_, _ = fmt.Fprintln(w, loc.T(
		i18n.KeyCLIConfigImportSummary,
		i18n.Str("label", label),
		i18n.BoundStr("format", rep.SourceFormat),
		i18n.BoundStr("revision", rev.String()),
		i18n.Bool("applied", applied),
		i18n.Int("add", rep.AddCount),
		i18n.Int("unchanged", rep.UnchangedCount),
		i18n.Int("conflict", rep.ConflictCount),
		i18n.Int("warnings", len(rep.Warnings)),
	))
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
		return importArgs{}, i18n.EF(clikit.ErrUsage, i18n.KeyCLIMissingRequiredFlag, i18n.Str("cmd", "config import"), i18n.Str("flag", "--format"))
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
	if strings.HasPrefix(tok, "-F") {
		val, err := cur.ConsumeShortArg('F', tok[2:])
		if err != nil {
			return err
		}
		return clikit.SetConfigFile(&out.common.ConfigFile, val)
	}
	if strings.HasPrefix(tok, "--") {
		return parseImportLongFlag(cur, tok, out)
	}
	if strings.HasPrefix(tok, "-") && tok != "-" {
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownShortFlag, i18n.BoundStr("flag", strings.TrimPrefix(tok, "-")))
	}
	if out.filePath == "" {
		out.filePath = tok
		return nil
	}
	return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnexpectedArg, i18n.BoundStr("arg", tok))
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
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--symlink-policy"), i18n.BoundStr("value", val))
		}
		out.symlinkPolicy = p
	default:
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", rawTok))
	}
	return nil
}
