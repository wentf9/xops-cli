package tools

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"fmt"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

type fileEditArg struct {
	OldText    string `json:"old_text"`
	NewText    string `json:"new_text"`
	ReplaceAll bool   `json:"replace_all,omitzero"`
}

type fileArgs struct {
	Action         string                                           `json:"action"`
	Target         string                                           `json:"target"`
	Path           string                                           `json:"path,omitzero"`
	OldPath        string                                           `json:"old_path,omitzero"`
	NewPath        string                                           `json:"new_path,omitzero"`
	Content        algebraic.Option[string]                         `json:"content,omitzero"`
	ContentB64     algebraic.Option[string]                         `json:"content_b64,omitzero"`
	Edits          []fileEditArg                                    `json:"edits,omitzero"`
	Perm           algebraic.Option[uint32]                         `json:"perm,omitzero"`
	NoClobber      bool                                             `json:"no_clobber,omitzero"`
	CreateParents  bool                                             `json:"create_parents,omitzero"`
	FollowSymlinks bool                                             `json:"follow_symlinks,omitzero"`
	MaxBytes       int64                                            `json:"max_bytes,omitzero"`
	ExpectedAnchor algebraic.Option[ports.RemoteFileAnchor]         `json:"expected_anchor,omitzero"`
	ExpectedDigest string                                           `json:"expected_digest,omitzero"`
	Risk           algebraic.Option[security.RiskLevel]             `json:"risk,omitzero"`
	Approval       algebraic.Option[protocol.ApprovalSubmissionDTO] `json:"approval,omitzero"`
}

func (r *Registry) callFile(ctx context.Context, rawArgs jsontext.Value) (protocol.CallToolResult, error) {
	if r.transfer == nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: TransferService 未配置", ErrServiceUnavailable)
	}
	args, err := decodeToolArgs[fileArgs](rawArgs)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	base, err := r.buildTransferCallBase(ctx, args.Target, args.Risk, args.Approval)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	switch args.Action {
	case "read":
		return r.fileRead(ctx, base, args)
	case "write":
		return r.fileWrite(ctx, base, args)
	case "patch":
		return r.filePatch(ctx, base, args)
	case "stat":
		return r.fileStat(ctx, base, args)
	case "rename":
		return r.fileRename(ctx, base, args)
	case "list", "mkdir", "remove", "removedir":
		return r.fileWorkspaceOp(ctx, base, args)
	default:
		return protocol.CallToolResult{}, fmt.Errorf("%w: 未知 file action %q", protocol.ErrInvalidParams, args.Action)
	}
}

func (r *Registry) fileRead(ctx context.Context, base uctrans.CallBase, args fileArgs) (protocol.CallToolResult, error) {
	rp, err := parseRemotePathParam("path", args.Path)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	res, err := r.transfer.ReadFile(ctx, uctrans.ReadFileRequest{
		CallBase: base,
		Path:     rp,
		MaxBytes: args.MaxBytes,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	utf8Content := ""
	if utf8.Valid(res.Content) {
		utf8Content = string(res.Content)
	}
	return protocol.NewToolSuccessResult(struct {
		Stat       ports.RemoteFileStat `json:"stat"`
		Digest     security.Digest      `json:"digest"`
		Content    string               `json:"content,omitzero"`
		ContentB64 string               `json:"content_b64"`
		IsUTF8     bool                 `json:"is_utf8"`
	}{
		Stat:       res.Stat,
		Digest:     res.Digest,
		Content:    utf8Content,
		ContentB64: base64.StdEncoding.EncodeToString(res.Content),
		IsUTF8:     utf8.Valid(res.Content),
	})
}

func (r *Registry) fileWrite(ctx context.Context, base uctrans.CallBase, args fileArgs) (protocol.CallToolResult, error) {
	rp, err := parseRemotePathParam("path", args.Path)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	data, err := decodeTextOrBase64(args.Content, args.ContentB64)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	permOpt, err := parseOptionalPerm(args.Perm)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	res, err := r.transfer.WriteFile(ctx, uctrans.WriteFileRequest{
		CallBase:       base,
		Path:           rp,
		Content:        data,
		Perm:           permOpt,
		NoClobber:      args.NoClobber,
		CreateParents:  args.CreateParents,
		ExpectedAnchor: args.ExpectedAnchor,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		Stat         ports.RemoteFileStat `json:"stat"`
		BytesWritten int64                `json:"bytes_written"`
		Digest       security.Digest      `json:"digest"`
	}{res.Stat, res.BytesWritten, res.Digest})
}

func (r *Registry) filePatch(ctx context.Context, base uctrans.CallBase, args fileArgs) (protocol.CallToolResult, error) {
	rp, err := parseRemotePathParam("path", args.Path)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	if len(args.Edits) == 0 {
		return protocol.CallToolResult{}, fmt.Errorf("%w: edits 不能为空", protocol.ErrInvalidParams)
	}
	edits := make([]uctrans.TextEdit, 0, len(args.Edits))
	for i, e := range args.Edits {
		te, eErr := uctrans.NewTextEdit(e.OldText, e.NewText, e.ReplaceAll)
		if eErr != nil {
			return protocol.CallToolResult{}, fmt.Errorf("%w: edits[%d] 无效: %w", protocol.ErrInvalidParams, i, eErr)
		}
		edits = append(edits, te)
	}
	expDigest, err := parseOptionalDigest(args.ExpectedDigest)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	res, err := r.transfer.PatchFile(ctx, uctrans.PatchFileRequest{
		CallBase:       base,
		Path:           rp,
		Edits:          edits,
		ExpectedAnchor: args.ExpectedAnchor,
		ExpectedDigest: expDigest,
		MaxBytes:       args.MaxBytes,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		BeforeStat   ports.RemoteFileStat `json:"before_stat"`
		AfterStat    ports.RemoteFileStat `json:"after_stat"`
		BeforeDigest security.Digest      `json:"before_digest"`
		AfterDigest  security.Digest      `json:"after_digest"`
		Replacements int                  `json:"replacements"`
		BytesWritten int64                `json:"bytes_written"`
	}{
		res.BeforeStat, res.AfterStat, res.BeforeDigest, res.AfterDigest, res.Replacements, res.BytesWritten,
	})
}

func (r *Registry) fileStat(ctx context.Context, base uctrans.CallBase, args fileArgs) (protocol.CallToolResult, error) {
	rp, err := parseRemotePathParam("path", args.Path)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	st, err := r.transfer.Stat(ctx, uctrans.StatRequest{
		CallBase:       base,
		Path:           rp,
		FollowSymlinks: args.FollowSymlinks,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		Stat ports.RemoteFileStat `json:"stat"`
	}{st})
}

func (r *Registry) fileRename(ctx context.Context, base uctrans.CallBase, args fileArgs) (protocol.CallToolResult, error) {
	oldP, err := parseRemotePathParam("old_path", args.OldPath)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	newP, err := parseRemotePathParam("new_path", args.NewPath)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	if err := r.transfer.RenameFile(ctx, uctrans.RenameFileRequest{
		CallBase:       base,
		OldPath:        oldP,
		NewPath:        newP,
		NoClobber:      args.NoClobber,
		ExpectedAnchor: args.ExpectedAnchor,
	}); err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		Renamed bool               `json:"renamed"`
		OldPath pathalg.RemotePath `json:"old_path"`
		NewPath pathalg.RemotePath `json:"new_path"`
	}{true, oldP, newP})
}

func (r *Registry) fileWorkspaceOp(ctx context.Context, base uctrans.CallBase, args fileArgs) (protocol.CallToolResult, error) {
	rp, err := parseRemotePathParam("path", args.Path)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	switch args.Action {
	case "list":
		res, err := r.transfer.ListDir(ctx, uctrans.ListDirRequest{CallBase: base, Path: rp})
		if err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(struct {
			Path    pathalg.RemotePath     `json:"path"`
			Entries []ports.RemoteDirEntry `json:"entries"`
		}{res.Path, res.Entries})
	case "mkdir":
		permOpt, err := parseOptionalPerm(args.Perm)
		if err != nil {
			return protocol.CallToolResult{}, err
		}
		if err := r.transfer.MkdirAll(ctx, uctrans.MkdirAllRequest{CallBase: base, Path: rp, Perm: permOpt}); err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(struct {
			Created bool               `json:"created"`
			Path    pathalg.RemotePath `json:"path"`
		}{true, rp})
	case "remove":
		if err := r.transfer.Remove(ctx, uctrans.RemoveRequest{CallBase: base, Path: rp}); err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(struct {
			Removed bool               `json:"removed"`
			Path    pathalg.RemotePath `json:"path"`
		}{true, rp})
	default: // removedir
		if err := r.transfer.RemoveDir(ctx, uctrans.RemoveDirRequest{CallBase: base, Path: rp}); err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(struct {
			RemovedDir bool               `json:"removed_dir"`
			Path       pathalg.RemotePath `json:"path"`
		}{true, rp})
	}
}
