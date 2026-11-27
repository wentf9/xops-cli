package tools

import (
	"context"
	"encoding/json/jsontext"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
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
		return protocol.CallToolResult{}, domi18n.EF(ErrServiceUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "TransferService"))
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
		return protocol.CallToolResult{}, domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "transfer action"), domi18n.BoundStr("value", args.Action))
	}
}

func (r *Registry) transferStart(ctx context.Context, base uctrans.CallBase, args transferArgs) (protocol.CallToolResult, error) {
	dir, err := fsm.ParseTransferDirection(args.Direction)
	if err != nil {
		return protocol.CallToolResult{}, domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "direction"))
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
		CallBase: base, TransferSessionOptions: sessOpts, TransferID: tidOpt, Dest: dest,
		TotalBytes: args.TotalBytes, ExpectedDigest: expDig, JournalVersion: fsm.JournalVersionV2,
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
		NoClobber: args.NoClobber, PreserveTimes: args.PreserveTimes, ExpectedAnchor: args.ExpectedAnchor, Perm: permOpt,
	}
	if dir == fsm.TransferDirectionUpload {
		dest, dErr := fsm.NewUploadDest(rp)
		return dest, opts, dErr
	}
	localRoot, okRoot := r.transferRoot.Get()
	if !okRoot || !localRoot.IsValid() {
		return zeroDest, uctrans.TransferSessionOptions{}, domi18n.EF(uctrans.ErrScopedFSUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "TransferRoot"))
	}
	localDest, lErr := pathalg.ParseLocalRootedDest(args.LocalDest)
	if lErr != nil {
		return zeroDest, uctrans.TransferSessionOptions{}, domi18n.WrapS(protocol.ErrInvalidParams, lErr, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "local_dest"))
	}
	dest, dErr := fsm.NewDownloadDest(localDest)
	if dErr != nil {
		return zeroDest, uctrans.TransferSessionOptions{}, dErr
	}
	opts.LocalRoot, opts.RemoteSource = algebraic.Some(localRoot), algebraic.Some(rp)
	return dest, opts, nil
}

func (r *Registry) recordAndEncodeTransferHandle(base uctrans.CallBase, info uctrans.TransferHandleInfo, localRoot algebraic.Option[pathalg.LocalDir]) (protocol.CallToolResult, error) {
	b := TransferBinding{
		transferID: info.TransferID, plan: base.Plan, nodeID: base.NodeID, handle: info.Handle,
		direction: info.Meta.Direction(), localRoot: localRoot, localDest: info.Meta.Dest().Local(),
		totalBytes: info.Meta.TotalBytes(), valid: true,
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
		info.TransferID, info.Handle, info.Handle.String(), info.Meta.Direction(),
		info.Meta.Generation(), info.Meta.TotalBytes(), info.State.Kind(), "/transfers/" + info.TransferID.String() + "/stream",
	})
}

func (r *Registry) resolveTransferHandle(args transferArgs) (plan.ManagedHandle[plan.KindTransfer], error) {
	if h, ok := args.Handle.Get(); ok {
		if !h.IsValid() {
			return zeroVal[plan.ManagedHandle[plan.KindTransfer]](), domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "handle"))
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
	return zeroVal[plan.ManagedHandle[plan.KindTransfer]](), ErrHandleNotFound
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
	res, err := r.transfer.WriteTransferChunk(ctx, uctrans.WriteTransferChunkRequest{CallBase: base, Handle: h, Offset: args.Offset, Data: data})
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
	res, err := r.transfer.PullTransferChunk(ctx, uctrans.PullTransferChunkRequest{CallBase: base, Handle: h, MaxChunkBytes: args.MaxChunkBytes})
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
	if err := r.transfer.AbortTransfer(ctx, uctrans.AbortTransferRequest{CallBase: base, Handle: h, Reason: args.Reason}); err != nil {
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
		return protocol.CallToolResult{}, domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "transfer_id"))
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
		LocalRoot: r.transferRoot, RemoteSource: remoteSrc, NoClobber: args.NoClobber,
		PreserveTimes: args.PreserveTimes, ExpectedAnchor: args.ExpectedAnchor, Perm: permOpt,
	}
	info, err := r.transfer.ResumeTransfer(ctx, uctrans.ResumeTransferRequest{
		CallBase: base, TransferSessionOptions: opts, TransferID: tid, StartNextGen: args.StartNextGen,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return r.recordAndEncodeTransferHandle(base, info, r.transferRoot)
}

func (r *Registry) transferRecoverOne(ctx context.Context, base uctrans.CallBase, args transferArgs) (protocol.CallToolResult, error) {
	tid, err := security.ParseOperationID(args.TransferID)
	if err != nil {
		return protocol.CallToolResult{}, domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "transfer_id"))
	}
	res, err := r.transfer.RecoverTransfer(ctx, uctrans.RecoverTransferRequest{
		CallBase: base, TransferID: tid, PruneSuperseded: args.PruneSuperseded, LocalRootForClean: r.transferRoot,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(transferRecoveryDTO(res))
}

// transferRecoverAll 将 MCP 暴露的全量日志恢复/裁剪收口进 gate.WithAuthorized[CapTransfer] 与审计闭环（ADR-008）：
// 只读扫描基准风险为 RiskSafe，开启 prune_superseded 裁剪旧世代日志时基准风险升至 RiskModerate（与调用方 risk 取格并）。
func (r *Registry) transferRecoverAll(ctx context.Context, args transferArgs) (protocol.CallToolResult, error) {
	riskOpt, approval, err := validateApprovalAndRisk(args.Risk, args.Approval)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	effRisk := security.RiskSafe
	summary := "recover all transfer journals"
	if args.PruneSuperseded {
		effRisk = security.RiskModerate
		summary = "recover and prune superseded transfer journals"
	}
	if rv, ok := riskOpt.Get(); ok {
		effRisk = security.FoldRisks(effRisk, rv)
	}
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityKindOf[security.CapTransfer](),
		Tool:       protocol.ToolNameTransfer,
		Action:     "recover_all",
		Parameters: map[string]string{"prune_superseded": strconv.FormatBool(args.PruneSuperseded)},
	})
	if err != nil {
		return protocol.CallToolResult{}, domi18n.WrapSentinel(protocol.ErrInvalidParams, err)
	}
	gReq, err := gate.NewGateRequest[security.CapTransfer](gate.GateRequestSpec[security.CapTransfer]{
		Binding: binding, Risk: effRisk, ScopeSummary: summary, Approval: approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, domi18n.WrapSentinel(protocol.ErrInvalidParams, err)
	}
	var res uctrans.RecoverAllResult
	if err := gate.WithAuthorized[security.CapTransfer](ctx, r.gate, gReq, func(authCtx context.Context, _ gate.Authorized[security.CapTransfer]) error {
		var rErr error
		res, rErr = r.transfer.RecoverAllTransfers(authCtx, uctrans.RecoverAllRequest{PruneSuperseded: args.PruneSuperseded})
		return rErr
	}); err != nil {
		return protocol.CallToolResult{}, err
	}
	return encodeRecoverAllResult(res)
}

func encodeRecoverAllResult(res uctrans.RecoverAllResult) (protocol.CallToolResult, error) {
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
			TransferID: e.TransferID, SelectedGen: e.Result.SelectedGen,
			PrunedGenerations: e.Result.PrunedGenerations, UncertainCommit: e.Result.UncertainCommit,
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
	tid, handleOpt, err := r.resolveTransferInspectID(args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	snap, err := r.transfer.InspectTransfer(ctx, uctrans.InspectTransferRequest{
		CallBase: base, TransferID: tid, Handle: handleOpt,
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
		snap.TransferID, snap.LiveHandle, snap.IsTerminal, snap.Meta.Direction(),
		snap.Meta.Generation(), snap.Meta.TotalBytes(), snap.StateKind, snap.Offset, snap.ChunkCount,
	})
}

func (r *Registry) resolveTransferInspectID(args transferArgs) (security.OperationID, algebraic.Option[plan.ManagedHandle[plan.KindTransfer]], error) {
	var zeroID security.OperationID
	if rawID := strings.TrimSpace(args.TransferID); rawID != "" {
		tid, err := security.ParseOperationID(rawID)
		if err != nil {
			return zeroID, algebraic.None[plan.ManagedHandle[plan.KindTransfer]](), domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "transfer_id"))
		}
		return tid, args.Handle, nil
	}
	tok := strings.TrimSpace(args.HandleToken)
	expH, hasExpH := args.Handle.Get()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.transfers {
		if !b.IsValid() {
			continue
		}
		if (tok != "" && b.handle.String() == tok) || (hasExpH && b.handle.Equal(expH)) {
			hOpt := args.Handle
			if !hasExpH {
				hOpt = algebraic.Some(b.handle)
			}
			return b.transferID, hOpt, nil
		}
	}
	return zeroID, algebraic.None[plan.ManagedHandle[plan.KindTransfer]](), domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonOneOfRequired, domi18n.Str("options", "transfer_id, handle_token"))
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
