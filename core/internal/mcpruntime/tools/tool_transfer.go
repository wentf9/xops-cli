package tools

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

type transferArgs struct {
	Action          string                                                  `json:"action"`
	Target          string                                                  `json:"target,omitzero"`
	Direction       string                                                  `json:"direction,omitzero"`
	TransferID      string                                                  `json:"transfer_id,omitzero"`
	Handle          algebraic.Option[plan.ManagedHandle[plan.KindTransfer]] `json:"handle,omitzero"`
	HandleToken     string                                                  `json:"handle_token,omitzero"`
	RemotePath      string                                                  `json:"remote_path,omitzero"`
	LocalDest       string                                                  `json:"local_dest,omitzero"`
	TotalBytes      uint64                                                  `json:"total_bytes,omitzero"`
	ExpectedDigest  string                                                  `json:"expected_digest,omitzero"`
	Offset          uint64                                                  `json:"offset,omitzero"`
	DataB64         string                                                  `json:"data_b64,omitzero"`
	MaxChunkBytes   uint64                                                  `json:"max_chunk_bytes,omitzero"`
	Reason          string                                                  `json:"reason,omitzero"`
	StartNextGen    bool                                                    `json:"start_next_gen,omitzero"`
	PruneSuperseded bool                                                    `json:"prune_superseded,omitzero"`
	All             bool                                                    `json:"all,omitzero"`
	NoClobber       bool                                                    `json:"no_clobber,omitzero"`
	PreserveTimes   bool                                                    `json:"preserve_times,omitzero"`
	Perm            algebraic.Option[uint32]                                `json:"perm,omitzero"`
	ExpectedAnchor  algebraic.Option[ports.RemoteFileAnchor]                `json:"expected_anchor,omitzero"`
	Risk            algebraic.Option[security.RiskLevel]                    `json:"risk,omitzero"`
	Approval        algebraic.Option[protocol.ApprovalSubmissionDTO]        `json:"approval,omitzero"`
}

func (r *Registry) callTransfer(ctx context.Context, rawArgs jsontext.Value) (protocol.CallToolResult, error) {
	if r.transfer == nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: TransferService 未配置", ErrServiceUnavailable)
	}
	args, err := decodeToolArgs[transferArgs](rawArgs)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	if args.Action == "recover" && args.All {
		return r.transferRecoverAll(ctx, args)
	}
	base, err := r.buildTransferCallBase(ctx, args.Target, args.Risk, args.Approval)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	switch args.Action {
	case "start":
		return r.transferStart(ctx, base, args)
	case "chunk":
		return r.transferChunk(ctx, base, args)
	case "pull":
		return r.transferPull(ctx, base, args)
	case "commit":
		return r.transferCommit(ctx, base, args)
	case "abort":
		return r.transferAbort(ctx, base, args)
	case "resume":
		return r.transferResume(ctx, base, args)
	case "recover":
		return r.transferRecoverOne(ctx, base, args)
	case "inspect":
		return r.transferInspect(ctx, base, args)
	default:
		return protocol.CallToolResult{}, fmt.Errorf("%w: 未知 transfer action %q", protocol.ErrInvalidParams, args.Action)
	}
}

func (r *Registry) transferStart(ctx context.Context, base uctrans.CallBase, args transferArgs) (protocol.CallToolResult, error) {
	dir, err := fsm.ParseTransferDirection(args.Direction)
	if err != nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: direction 须为 upload 或 download: %w", protocol.ErrInvalidParams, err)
	}
	dest, sessOpts, err := r.buildTransferDestAndOpts(dir, args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	tidOpt, err := parseOptionalOpID(args.TransferID)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	expDig, err := parseOptionalDigest(args.ExpectedDigest)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	info, err := r.transfer.StartTransfer(ctx, uctrans.StartTransferRequest{
		CallBase:               base,
		TransferSessionOptions: sessOpts,
		TransferID:             tidOpt,
		Dest:                   dest,
		TotalBytes:             args.TotalBytes,
		ExpectedDigest:         expDig,
		JournalVersion:         fsm.JournalVersionV2,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return r.recordAndEncodeTransferHandle(base, info, sessOpts.LocalRoot)
}

func (r *Registry) buildTransferDestAndOpts(dir fsm.TransferDirection, args transferArgs) (fsm.TransferDest, uctrans.TransferSessionOptions, error) {
	zeroDest := zeroVal[fsm.TransferDest]()
	permOpt, err := parseOptionalPerm(args.Perm)
	if err != nil {
		return zeroDest, uctrans.TransferSessionOptions{}, err
	}
	rp, err := parseRemotePathParam("remote_path", args.RemotePath)
	if err != nil {
		return zeroDest, uctrans.TransferSessionOptions{}, err
	}
	opts := uctrans.TransferSessionOptions{
		NoClobber:      args.NoClobber,
		PreserveTimes:  args.PreserveTimes,
		ExpectedAnchor: args.ExpectedAnchor,
		Perm:           permOpt,
	}
	if dir == fsm.TransferDirectionUpload {
		dest, dErr := fsm.NewUploadDest(rp)
		return dest, opts, dErr
	}
	localRoot, okRoot := r.transferRoot.Get()
	if !okRoot || !localRoot.IsValid() {
		return zeroDest, uctrans.TransferSessionOptions{}, fmt.Errorf("%w: 下载流式传输需要服务端配置沙箱 TransferRoot", uctrans.ErrScopedFSUnavailable)
	}
	localDest, lErr := pathalg.ParseLocalRootedDest(args.LocalDest)
	if lErr != nil {
		return zeroDest, uctrans.TransferSessionOptions{}, fmt.Errorf("%w: local_dest 必须为沙箱相对路径: %w", protocol.ErrInvalidParams, lErr)
	}
	dest, dErr := fsm.NewDownloadDest(localDest)
	if dErr != nil {
		return zeroDest, uctrans.TransferSessionOptions{}, dErr
	}
	opts.LocalRoot = algebraic.Some(localRoot)
	opts.RemoteSource = algebraic.Some(rp)
	return dest, opts, nil
}

func (r *Registry) recordAndEncodeTransferHandle(
	base uctrans.CallBase,
	info uctrans.TransferHandleInfo,
	localRoot algebraic.Option[pathalg.LocalDir],
) (protocol.CallToolResult, error) {
	b := TransferBinding{
		transferID: info.TransferID,
		plan:       base.Plan,
		nodeID:     base.NodeID,
		handle:     info.Handle,
		direction:  info.Meta.Direction(),
		localRoot:  localRoot,
		localDest:  info.Meta.Dest().Local(),
		totalBytes: info.Meta.TotalBytes(),
		valid:      true,
	}
	r.mu.Lock()
	if len(r.transfers) >= r.maxHandles {
		for k := range r.transfers {
			delete(r.transfers, k)
			break
		}
	}
	r.transfers[info.TransferID.String()] = b
	r.mu.Unlock()
	return protocol.NewToolSuccessResult(struct {
		TransferID     security.OperationID                  `json:"transfer_id"`
		Handle         plan.ManagedHandle[plan.KindTransfer] `json:"handle"`
		HandleToken    string                                `json:"handle_token"`
		Direction      fsm.TransferDirection                 `json:"direction"`
		Generation     uint64                                `json:"generation"`
		TotalBytes     uint64                                `json:"total_bytes"`
		StateKind      fsm.TransferStateKind                 `json:"state_kind"`
		HTTPStreamPath string                                `json:"http_stream_path"`
	}{
		TransferID:     info.TransferID,
		Handle:         info.Handle,
		HandleToken:    info.Handle.String(),
		Direction:      info.Meta.Direction(),
		Generation:     info.Meta.Generation(),
		TotalBytes:     info.Meta.TotalBytes(),
		StateKind:      info.State.Kind(),
		HTTPStreamPath: "/transfers/" + info.TransferID.String() + "/stream",
	})
}

func (r *Registry) resolveTransferHandle(args transferArgs) (plan.ManagedHandle[plan.KindTransfer], error) {
	if h, ok := args.Handle.Get(); ok {
		if !h.IsValid() {
			return zeroVal[plan.ManagedHandle[plan.KindTransfer]](), fmt.Errorf("%w: handle 无效", protocol.ErrInvalidParams)
		}
		return h, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if tid := strings.TrimSpace(args.TransferID); tid != "" {
		if b, ok := r.transfers[tid]; ok && b.IsValid() {
			return b.handle, nil
		}
	}
	if tok := strings.TrimSpace(args.HandleToken); tok != "" {
		for _, b := range r.transfers {
			if b.IsValid() && b.handle.String() == tok {
				return b.handle, nil
			}
		}
	}
	return zeroVal[plan.ManagedHandle[plan.KindTransfer]](), fmt.Errorf("%w: 未找到对应的传输受管句柄", ErrHandleNotFound)
}

func (r *Registry) transferChunk(ctx context.Context, base uctrans.CallBase, args transferArgs) (protocol.CallToolResult, error) {
	h, err := r.resolveTransferHandle(args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	data, err := decodeBase64Strict(args.DataB64)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	res, err := r.transfer.WriteTransferChunk(ctx, uctrans.WriteTransferChunkRequest{
		CallBase: base,
		Handle:   h,
		Offset:   args.Offset,
		Data:     data,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		TransferID  security.OperationID  `json:"transfer_id"`
		NextOffset  uint64                `json:"next_offset"`
		TotalBytes  uint64                `json:"total_bytes"`
		ChunkDigest security.Digest       `json:"chunk_digest"`
		StateKind   fsm.TransferStateKind `json:"state_kind"`
	}{res.TransferID, res.NextOffset, res.TotalBytes, res.ChunkDigest, res.StateKind})
}

func (r *Registry) transferPull(ctx context.Context, base uctrans.CallBase, args transferArgs) (protocol.CallToolResult, error) {
	h, err := r.resolveTransferHandle(args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	res, err := r.transfer.PullTransferChunk(ctx, uctrans.PullTransferChunkRequest{
		CallBase:      base,
		Handle:        h,
		MaxChunkBytes: args.MaxChunkBytes,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		TransferID  security.OperationID  `json:"transfer_id"`
		Offset      uint64                `json:"offset"`
		BytesPulled uint64                `json:"bytes_pulled"`
		NextOffset  uint64                `json:"next_offset"`
		TotalBytes  uint64                `json:"total_bytes"`
		ChunkDigest security.Digest       `json:"chunk_digest"`
		StateKind   fsm.TransferStateKind `json:"state_kind"`
	}{res.TransferID, res.Offset, res.BytesPulled, res.NextOffset, res.TotalBytes, res.ChunkDigest, res.StateKind})
}

func (r *Registry) transferCommit(ctx context.Context, base uctrans.CallBase, args transferArgs) (protocol.CallToolResult, error) {
	h, err := r.resolveTransferHandle(args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	res, err := r.transfer.CommitTransfer(ctx, uctrans.CommitTransferRequest{CallBase: base, Handle: h})
	if res.TransferID.IsValid() {
		r.DropTransfer(res.TransferID)
	}
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		TransferID   security.OperationID              `json:"transfer_id"`
		StateKind    fsm.TransferStateKind             `json:"state_kind"`
		ActualDigest algebraic.Option[security.Digest] `json:"actual_digest,omitzero"`
		Generation   uint64                            `json:"generation"`
	}{res.TransferID, res.State.Kind(), res.ActualDigest, res.Generation})
}

func (r *Registry) transferAbort(ctx context.Context, base uctrans.CallBase, args transferArgs) (protocol.CallToolResult, error) {
	h, err := r.resolveTransferHandle(args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	if err := r.transfer.AbortTransfer(ctx, uctrans.AbortTransferRequest{
		CallBase: base, Handle: h, Reason: args.Reason,
	}); err != nil {
		return protocol.CallToolResult{}, err
	}
	r.dropTransferByHandle(h)
	return protocol.NewToolSuccessResult(struct {
		Aborted     bool   `json:"aborted"`
		HandleToken string `json:"handle_token"`
	}{true, h.String()})
}

func (r *Registry) dropTransferByHandle(h plan.ManagedHandle[plan.KindTransfer]) {
	r.mu.Lock()
	for k, b := range r.transfers {
		if b.handle.Equal(h) {
			delete(r.transfers, k)
		}
	}
	r.mu.Unlock()
}

func (r *Registry) transferResume(ctx context.Context, base uctrans.CallBase, args transferArgs) (protocol.CallToolResult, error) {
	tid, err := security.ParseOperationID(args.TransferID)
	if err != nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: transfer_id 无效: %w", protocol.ErrInvalidParams, err)
	}
	permOpt, err := parseOptionalPerm(args.Perm)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	var remoteSrc algebraic.Option[pathalg.RemotePath]
	if args.RemotePath != "" {
		rp, pErr := parseRemotePathParam("remote_path", args.RemotePath)
		if pErr != nil {
			return protocol.CallToolResult{}, pErr
		}
		remoteSrc = algebraic.Some(rp)
	}
	opts := uctrans.TransferSessionOptions{
		LocalRoot:      r.transferRoot,
		RemoteSource:   remoteSrc,
		NoClobber:      args.NoClobber,
		PreserveTimes:  args.PreserveTimes,
		ExpectedAnchor: args.ExpectedAnchor,
		Perm:           permOpt,
	}
	info, err := r.transfer.ResumeTransfer(ctx, uctrans.ResumeTransferRequest{
		CallBase:               base,
		TransferSessionOptions: opts,
		TransferID:             tid,
		StartNextGen:           args.StartNextGen,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return r.recordAndEncodeTransferHandle(base, info, r.transferRoot)
}

func (r *Registry) transferRecoverOne(ctx context.Context, base uctrans.CallBase, args transferArgs) (protocol.CallToolResult, error) {
	tid, err := security.ParseOperationID(args.TransferID)
	if err != nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: transfer_id 无效: %w", protocol.ErrInvalidParams, err)
	}
	res, err := r.transfer.RecoverTransfer(ctx, uctrans.RecoverTransferRequest{
		CallBase:          base,
		TransferID:        tid,
		PruneSuperseded:   args.PruneSuperseded,
		LocalRootForClean: r.transferRoot,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(transferRecoveryDTO(res))
}

func (r *Registry) transferRecoverAll(ctx context.Context, args transferArgs) (protocol.CallToolResult, error) {
	res, err := r.transfer.RecoverAllTransfers(ctx, uctrans.RecoverAllRequest{PruneSuperseded: args.PruneSuperseded})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	type entryDTO struct {
		TransferID        security.OperationID  `json:"transfer_id"`
		StateKind         fsm.TransferStateKind `json:"state_kind,omitzero"`
		SelectedGen       uint64                `json:"selected_gen"`
		PrunedGenerations []uint64              `json:"pruned_generations,omitzero"`
		UncertainCommit   bool                  `json:"uncertain_commit,omitzero"`
		Error             string                `json:"error,omitzero"`
	}
	items := make([]entryDTO, 0, len(res.Entries))
	for _, e := range res.Entries {
		item := entryDTO{
			TransferID:        e.TransferID,
			SelectedGen:       e.Result.SelectedGen,
			PrunedGenerations: e.Result.PrunedGenerations,
			UncertainCommit:   e.Result.UncertainCommit,
		}
		if e.Result.State != nil && e.Result.State.IsValid() {
			item.StateKind = e.Result.State.Kind()
		}
		if e.Err != nil {
			item.Error = security.SanitizePromptText(e.Err.Error())
		}
		items = append(items, item)
	}
	return protocol.NewToolSuccessResult(struct {
		Entries []entryDTO `json:"entries"`
	}{items})
}

func (r *Registry) transferInspect(ctx context.Context, base uctrans.CallBase, args transferArgs) (protocol.CallToolResult, error) {
	tid, err := security.ParseOperationID(args.TransferID)
	if err != nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: transfer_id 无效: %w", protocol.ErrInvalidParams, err)
	}
	snap, err := r.transfer.InspectTransfer(ctx, uctrans.InspectTransferRequest{
		CallBase:   base,
		TransferID: tid,
		Handle:     args.Handle,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		TransferID security.OperationID  `json:"transfer_id"`
		LiveHandle bool                  `json:"live_handle"`
		IsTerminal bool                  `json:"is_terminal"`
		Direction  fsm.TransferDirection `json:"direction,omitzero"`
		Generation uint64                `json:"generation"`
		TotalBytes uint64                `json:"total_bytes"`
		StateKind  fsm.TransferStateKind `json:"state_kind"`
		Offset     uint64                `json:"offset"`
		ChunkCount uint64                `json:"chunk_count"`
	}{
		TransferID: snap.TransferID,
		LiveHandle: snap.LiveHandle,
		IsTerminal: snap.IsTerminal,
		Direction:  snap.Meta.Direction(),
		Generation: snap.Meta.Generation(),
		TotalBytes: snap.Meta.TotalBytes(),
		StateKind:  snap.StateKind,
		Offset:     snap.Offset,
		ChunkCount: snap.ChunkCount,
	})
}

func transferRecoveryDTO(res uctrans.TransferRecoveryResult) any {
	kind := fsm.TransferKindInvalid
	if res.State != nil && res.State.IsValid() {
		kind = res.State.Kind()
	}
	return struct {
		TransferID        security.OperationID  `json:"transfer_id"`
		StateKind         fsm.TransferStateKind `json:"state_kind,omitzero"`
		SelectedGen       uint64                `json:"selected_gen"`
		PrunedGenerations []uint64              `json:"pruned_generations,omitzero"`
		UncertainCommit   bool                  `json:"uncertain_commit,omitzero"`
	}{res.TransferID, kind, res.SelectedGen, res.PrunedGenerations, res.UncertainCommit}
}

func parseOptionalOpID(raw string) (algebraic.Option[security.OperationID], error) {
	if strings.TrimSpace(raw) == "" {
		return algebraic.None[security.OperationID](), nil
	}
	id, err := security.ParseOperationID(raw)
	if err != nil {
		return algebraic.None[security.OperationID](), fmt.Errorf("%w: transfer_id 无效: %w", protocol.ErrInvalidParams, err)
	}
	return algebraic.Some(id), nil
}
