package cmdtransfer

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

const defaultSFTPWriteMaxBytes int64 = 16 << 20

func dispatchSFTPOp(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed sftpArgs, jsonOut bool) int {
	switch parsed.sub {
	case "ls":
		return runSFTPLS(ctx, rt, client, parsed, jsonOut)
	case "stat":
		return runSFTPStat(ctx, rt, client, parsed, jsonOut)
	case "cat", "read":
		return runSFTPRead(ctx, rt, client, parsed, jsonOut)
	case "write":
		return runSFTPWrite(ctx, rt, client, parsed, jsonOut)
	case "patch":
		return runSFTPPatch(ctx, rt, client, parsed, jsonOut)
	case "mkdir", "rm", "rmdir", "realpath", "readlink":
		return runSFTPSimplePathOp(ctx, rt, client, parsed, jsonOut)
	case "mv", "rename":
		return runSFTPRename(ctx, rt, client, parsed, jsonOut)
	case "chmod":
		return runSFTPChmod(ctx, rt, client, parsed, jsonOut)
	case "recover":
		return runSFTPRecover(ctx, rt, client, parsed, jsonOut)
	default:
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownSubcommand, i18n.Str("cmd", "sftp"), i18n.BoundStr("sub", parsed.sub)))
	}
}

func requireTargetAndRemotePath(parsed sftpArgs) (target string, rp pathalg.RemotePath, err error) {
	if len(parsed.pos) != 2 {
		return "", rp, i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.BoundStr("cmd", "sftp "+parsed.sub), i18n.Int("count", 2), i18n.Str("usage", "<target> <remote_path>"))
	}
	parsedPath, pErr := pathalg.ParseRemotePath(parsed.pos[1])
	if pErr != nil {
		return "", rp, i18n.WrapS(clikit.ErrUsage, pErr, i18n.KeyCLIInvalidField, i18n.Msg("field", i18n.NewMessage(i18n.KeyCLIFieldRemotePath)), i18n.BoundStr("value", parsed.pos[1]))
	}
	return parsed.pos[0], parsedPath, nil
}

func runSFTPLS(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed sftpArgs, jsonOut bool) int {
	target, rp, err := requireTargetAndRemotePath(parsed)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	res, err := client.ListRemoteDir(ctx, engine.RemotePathOpRequest{
		RemoteCall: sftpRemoteCall(target, parsed.cliOpts),
		Path:       rp,
	})
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	type lsView struct {
		OK      bool                    `json:"ok"`
		Path    pathalg.RemotePath      `json:"path"`
		Entries []engine.RemoteDirEntry `json:"entries"`
	}
	return rt.WriteResult(jsonOut, lsView{OK: true, Path: res.Path, Entries: res.Entries}, func(w io.Writer) {
		for _, e := range res.Entries {
			_, _ = fmt.Fprintf(w, "%-8s %10d %04o %s\n", e.FileType(), e.Size(), e.Perm(), e.Name())
		}
	})
}

func runSFTPStat(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed sftpArgs, jsonOut bool) int {
	target, rp, err := requireTargetAndRemotePath(parsed)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	st, err := client.StatRemoteFile(ctx, engine.RemoteStatRequest{
		RemoteCall:     sftpRemoteCall(target, parsed.cliOpts),
		Path:           rp,
		FollowSymlinks: parsed.followSymlinks,
	})
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, st, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(
			i18n.KeyCLISFTPStat,
			i18n.BoundStr("path", st.Path().String()),
			i18n.Str("type", st.FileType().String()),
			i18n.Int64("size", st.Size()),
			i18n.Str("mode", fmt.Sprintf("%04o", st.Perm())),
		))
	})
}

func runSFTPRead(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed sftpArgs, jsonOut bool) int {
	target, rp, err := requireTargetAndRemotePath(parsed)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	res, err := client.ReadRemoteFile(ctx, engine.RemoteFileReadRequest{
		RemoteCall: sftpRemoteCall(target, parsed.cliOpts),
		Path:       rp,
		MaxBytes:   parsed.maxBytes,
	})
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	type readView struct {
		OK            bool                  `json:"ok"`
		Stat          engine.RemoteFileStat `json:"stat"`
		Digest        security.Digest       `json:"digest"`
		Encoding      string                `json:"encoding"`
		Content       string                `json:"content,omitzero"`
		ContentBase64 string                `json:"content_base64,omitzero"`
	}
	v := readView{OK: true, Stat: res.Stat, Digest: res.Digest}
	if utf8.Valid(res.Content) {
		v.Encoding = "utf-8"
		v.Content = string(res.Content)
	} else {
		v.Encoding = "base64"
		v.ContentBase64 = base64.StdEncoding.EncodeToString(res.Content)
	}
	return rt.WriteResult(jsonOut, v, func(w io.Writer) {
		_, _ = w.Write(res.Content)
	})
}

func runSFTPWrite(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed sftpArgs, jsonOut bool) int {
	target, rp, err := requireTargetAndRemotePath(parsed)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	limit := parsed.maxBytes
	if limit <= 0 {
		limit = defaultSFTPWriteMaxBytes
	}
	content, _, err := rt.ReadLocalInput(ctx, parsed.filePath, parsed.symlinkPolicy, limit)
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	res, err := client.WriteRemoteFile(ctx, engine.RemoteFileWriteRequest{
		RemoteCall:    sftpRemoteCall(target, parsed.cliOpts),
		Path:          rp,
		Content:       content,
		Perm:          parsed.perm,
		NoClobber:     parsed.noClobber,
		CreateParents: parsed.createParents,
	})
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	type writeView struct {
		OK           bool                  `json:"ok"`
		Stat         engine.RemoteFileStat `json:"stat"`
		BytesWritten int64                 `json:"bytes_written"`
		Digest       security.Digest       `json:"digest"`
	}
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, writeView{OK: true, Stat: res.Stat, BytesWritten: res.BytesWritten, Digest: res.Digest}, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(
			i18n.KeyCLISFTPWrote,
			i18n.Int64("bytes", res.BytesWritten),
			i18n.BoundStr("target", target),
			i18n.BoundStr("path", rp.String()),
			i18n.Str("digest", res.Digest.String()),
		))
	})
}

func runSFTPPatch(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed sftpArgs, jsonOut bool) int {
	target, rp, err := requireTargetAndRemotePath(parsed)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	edit, err := engine.NewTextEdit(parsed.oldText, parsed.newText, parsed.replaceAll)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--old"), i18n.BoundStr("value", parsed.oldText)))
	}
	res, err := client.PatchRemoteFile(ctx, engine.RemoteFilePatchRequest{
		RemoteCall: sftpRemoteCall(target, parsed.cliOpts),
		Path:       rp,
		Edits:      []engine.TextEdit{edit},
		MaxBytes:   parsed.maxBytes,
	})
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	type patchView struct {
		OK           bool               `json:"ok"`
		Path         pathalg.RemotePath `json:"path"`
		Replacements int                `json:"replacements"`
		BytesWritten int64              `json:"bytes_written"`
		BeforeDigest security.Digest    `json:"before_digest"`
		AfterDigest  security.Digest    `json:"after_digest"`
	}
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, patchView{
		OK: true, Path: rp, Replacements: res.Replacements, BytesWritten: res.BytesWritten,
		BeforeDigest: res.BeforeDigest, AfterDigest: res.AfterDigest,
	}, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(
			i18n.KeyCLISFTPPatch,
			i18n.BoundStr("path", rp.String()),
			i18n.Int("replacements", res.Replacements),
			i18n.Int64("bytes", res.BytesWritten),
		))
	})
}

func runSFTPSimplePathOp(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed sftpArgs, jsonOut bool) int {
	target, rp, err := requireTargetAndRemotePath(parsed)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	req := engine.RemotePathOpRequest{
		RemoteCall: sftpRemoteCall(target, parsed.cliOpts),
		Path:       rp,
		Perm:       parsed.perm,
	}
	type pathOpView struct {
		OK     bool               `json:"ok"`
		Action string             `json:"action"`
		Path   pathalg.RemotePath `json:"path"`
		Result string             `json:"result,omitzero"`
	}
	switch parsed.sub {
	case "mkdir":
		err = client.MkdirRemoteAll(ctx, req)
	case "rm":
		err = client.RemoveRemoteFile(ctx, req)
	case "rmdir":
		err = client.RemoveRemoteDir(ctx, req)
	case "realpath":
		var resolved pathalg.RemotePath
		resolved, err = client.RealPathRemote(ctx, req)
		if err == nil {
			return rt.WriteResult(jsonOut, pathOpView{OK: true, Action: "realpath", Path: rp, Result: resolved.String()}, func(w io.Writer) {
				_, _ = fmt.Fprintf(w, "%s\n", resolved)
			})
		}
	case "readlink":
		var link string
		link, err = client.ReadLinkRemote(ctx, req)
		if err == nil {
			return rt.WriteResult(jsonOut, pathOpView{OK: true, Action: "readlink", Path: rp, Result: link}, func(w io.Writer) {
				_, _ = fmt.Fprintf(w, "%s\n", link)
			})
		}
	}
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, pathOpView{OK: true, Action: parsed.sub, Path: rp}, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLISFTPActionOK, i18n.Str("action", parsed.sub), i18n.BoundStr("path", rp.String())))
	})
}

func runSFTPRename(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed sftpArgs, jsonOut bool) int {
	if len(parsed.pos) != 3 {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.BoundStr("cmd", "sftp "+parsed.sub), i18n.Int("count", 3), i18n.Str("usage", "<target> <old_path> <new_path>")))
	}
	oldPath, err := pathalg.ParseRemotePath(parsed.pos[1])
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Msg("field", i18n.NewMessage(i18n.KeyCLIFieldOldPath)), i18n.BoundStr("value", parsed.pos[1])))
	}
	newPath, err := pathalg.ParseRemotePath(parsed.pos[2])
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Msg("field", i18n.NewMessage(i18n.KeyCLIFieldNewPath)), i18n.BoundStr("value", parsed.pos[2])))
	}
	err = client.RenameRemoteFile(ctx, engine.RemoteRenameRequest{
		RemoteCall: sftpRemoteCall(parsed.pos[0], parsed.cliOpts),
		OldPath:    oldPath,
		NewPath:    newPath,
		NoClobber:  parsed.noClobber,
	})
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	type mvView struct {
		OK      bool               `json:"ok"`
		OldPath pathalg.RemotePath `json:"old_path"`
		NewPath pathalg.RemotePath `json:"new_path"`
	}
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, mvView{OK: true, OldPath: oldPath, NewPath: newPath}, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLISFTPRenamed, i18n.BoundStr("old", oldPath.String()), i18n.BoundStr("new", newPath.String())))
	})
}

func runSFTPChmod(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed sftpArgs, jsonOut bool) int {
	if len(parsed.pos) != 3 {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.Str("cmd", "sftp chmod"), i18n.Int("count", 3), i18n.Str("usage", "<target> <mode> <remote_path>")))
	}
	mode, err := clikit.ParseOctalPerm("mode", parsed.pos[1])
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	rp, err := pathalg.ParseRemotePath(parsed.pos[2])
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Msg("field", i18n.NewMessage(i18n.KeyCLIFieldRemotePath)), i18n.BoundStr("value", parsed.pos[2])))
	}
	err = client.ChmodRemote(ctx, engine.RemotePathOpRequest{
		RemoteCall: sftpRemoteCall(parsed.pos[0], parsed.cliOpts),
		Path:       rp,
		Perm:       algebraic.Some(mode),
	})
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	type chmodView struct {
		OK   bool               `json:"ok"`
		Path pathalg.RemotePath `json:"path"`
		Mode string             `json:"mode"`
	}
	modeStr := fmt.Sprintf("%04o", mode)
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, chmodView{OK: true, Path: rp, Mode: modeStr}, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLISFTPChmodOK, i18n.Str("mode", modeStr), i18n.BoundStr("path", rp.String())))
	})
}

func runSFTPRecover(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed sftpArgs, jsonOut bool) int {
	if len(parsed.pos) == 0 {
		return runSFTPRecoverAll(ctx, rt, client, parsed, jsonOut)
	}
	if len(parsed.pos) != 2 {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLISFTPRecoverUsage))
	}
	tid, err := security.ParseOperationID(parsed.pos[1])
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Msg("field", i18n.NewMessage(i18n.KeyCLIFieldTransferID)), i18n.BoundStr("value", parsed.pos[1])))
	}
	res, err := client.RecoverTransfer(ctx, engine.RecoverTransferRequest{
		RemoteCall:        sftpRemoteCall(parsed.pos[0], parsed.cliOpts),
		TransferID:        tid,
		LocalRootForClean: parsed.localRoot,
		PruneSuperseded:   parsed.prune,
	})
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	type recOneView struct {
		OK              bool                 `json:"ok"`
		TransferID      security.OperationID `json:"transfer_id"`
		SelectedGen     uint64               `json:"selected_generation"`
		UncertainCommit bool                 `json:"uncertain_commit,omitzero"`
		DoNotRetry      bool                 `json:"do_not_retry,omitzero"`
	}
	code := clikit.ExitOK
	if res.UncertainCommit {
		code = clikit.ExitGeneral
	}
	loc := rt.Loc()
	if rt.WriteResult(jsonOut, recOneView{
		OK: !res.UncertainCommit, TransferID: res.TransferID, SelectedGen: res.SelectedGen,
		UncertainCommit: res.UncertainCommit, DoNotRetry: res.UncertainCommit,
	}, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(
			i18n.KeyCLISFTPRecoveredOne,
			i18n.Str("id", res.TransferID.String()),
			i18n.Uint64("generation", res.SelectedGen),
			i18n.Bool("uncertain", res.UncertainCommit),
		))
		if res.UncertainCommit {
			rt.WriteErr(loc.T(i18n.KeyCLISFTPRecoverUncertainInspect, i18n.Str("id", res.TransferID.String())))
		}
	}) != clikit.ExitOK {
		return clikit.ExitGeneral
	}
	return code
}

func runSFTPRecoverAll(ctx context.Context, rt *clikit.Runtime, client clikit.TransferClient, parsed sftpArgs, jsonOut bool) int {
	res, err := client.RecoverAllTransfers(ctx, engine.RecoverAllTransfersRequest{PruneSuperseded: parsed.prune})
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	type recAllView struct {
		OK             bool           `json:"ok"`
		FailedCount    int            `json:"failed_count,omitzero"`
		UncertainCount int            `json:"uncertain_count,omitzero"`
		Entries        []recEntryView `json:"entries"`
	}
	loc := rt.Loc()
	v := recAllView{OK: true}
	for _, e := range res.Entries {
		item := recEntryView{TransferID: e.TransferID, SelectedGen: e.Result.SelectedGen, UncertainCommit: e.Result.UncertainCommit}
		if e.Err != nil {
			item.Error = loc.RenderError(e.Err)
			v.FailedCount++
		}
		if e.Result.UncertainCommit {
			v.UncertainCount++
		}
		v.Entries = append(v.Entries, item)
	}
	v.OK = v.FailedCount == 0 && v.UncertainCount == 0
	code := clikit.ExitOK
	if !v.OK {
		code = clikit.ExitGeneral
	}
	if rt.WriteResult(jsonOut, v, func(w io.Writer) {
		writeRecoverAllText(rt, loc, w, v.FailedCount, v.UncertainCount, v.Entries)
	}) != clikit.ExitOK {
		return clikit.ExitGeneral
	}
	return code
}

type recEntryView struct {
	TransferID      security.OperationID `json:"transfer_id"`
	SelectedGen     uint64               `json:"selected_generation"`
	UncertainCommit bool                 `json:"uncertain_commit,omitzero"`
	Error           string               `json:"error,omitzero"`
}

func writeRecoverAllText(rt *clikit.Runtime, loc *i18n.Localizer, w io.Writer, failedCount, uncertainCount int, entries []recEntryView) {
	_, _ = fmt.Fprintln(w, loc.T(
		i18n.KeyCLISFTPRecoveredAll,
		i18n.Int("count", len(entries)),
		i18n.Int("failed", failedCount),
		i18n.Int("uncertain", uncertainCount),
	))
	for _, item := range entries {
		tid := item.TransferID.String()
		_, _ = fmt.Fprintln(w, loc.T(
			i18n.KeyCLISFTPRecoverEntry,
			i18n.Str("id", tid),
			i18n.Uint64("generation", item.SelectedGen),
			i18n.Bool("uncertain", item.UncertainCommit),
		))
		if item.Error != "" {
			rt.WriteErr(loc.T(i18n.KeyCLISFTPRecoverError, i18n.Str("id", tid), i18n.BoundStr("err", item.Error)))
		}
		if item.UncertainCommit {
			rt.WriteErr(loc.T(i18n.KeyCLISFTPRecoverUncertainNoRetry, i18n.Str("id", tid)))
		}
	}
}
