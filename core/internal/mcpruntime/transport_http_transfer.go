package mcpruntime

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/tools"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	headerStartOffset   = "X-Xops-Start-Offset"
	headerApproval      = "X-Xops-Approval"
	headerTransferID    = "X-Xops-Transfer-Id"
	headerTransferState = "X-Xops-Transfer-State"
	headerTransferHash  = "X-Xops-Transfer-Digest"
)

// handleTransferHTTP 承载最高 10 GiB 流式上传与下载 HTTP 端点（`/transfers/{transfer_id}/stream`）：
//   - 严格强制 IsClosed() 停机门禁、Prepare 启动期对账门禁与 Gate.IsHalted() 熔断门禁；
//   - 全程采用定长分片缓冲（httpChunkSize，默认 1 MiB）直连 usecase/transfer，永不整包缓存在内存；
//   - 物理不接触 OperatorReadFS：下载流仅经 ScopedRootFS.WithRoot -> WithReadRegular 有界流式读取已原子提交产物；
//   - 完整支持 StrictAgentProfile + NoElicitFallbackChallenge 两步审批闭环，绝不提前销毁待审批/可重试绑定或重放单次审批令牌。
func (s *Server) handleTransferHTTP(w http.ResponseWriter, r *http.Request) {
	if err := s.ensureHTTPServiceReady(w, r); err != nil {
		return
	}
	sid := strings.TrimSpace(r.Header.Get(headerMCPSessionID))
	if sid == "" || !s.hasHTTPSession(sid) {
		writeHTTPJSONError(w, http.StatusUnauthorized, "invalid_session", "transfer stream endpoint requires a valid Mcp-Session-Id", false)
		return
	}
	tid, err := parseTransferStreamPath(r.URL.Path)
	if err != nil {
		writeHTTPJSONError(w, http.StatusNotFound, "not_found", "invalid transfer stream path (expected /transfers/{transfer_id}/stream)", false)
		return
	}
	binding, found := s.registry.LookupTransfer(tid)
	if !found {
		writeHTTPJSONError(w, http.StatusNotFound, "transfer_not_found", "active streaming transfer binding not found or already finalized", false)
		return
	}
	if s.registry.TransferService() == nil {
		writeHTTPJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "TransferService is not configured", false)
		return
	}
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		s.handleHTTPStreamUpload(w, r, binding)
	case http.MethodGet:
		s.handleHTTPStreamDownload(w, r, binding)
	default:
		w.Header().Set("Allow", "GET, PUT, POST")
		writeHTTPJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET, PUT, and POST are allowed", false)
	}
}

func parseTransferStreamPath(urlPath string) (security.OperationID, error) {
	var zeroID security.OperationID
	trimmed := strings.TrimPrefix(urlPath, "/transfers/")
	idStr, suffix, ok := strings.Cut(trimmed, "/")
	if !ok || suffix != "stream" || idStr == "" {
		return zeroID, domi18n.E(domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "transfer stream path"), domi18n.BoundStr("value", urlPath))
	}
	tid, err := security.ParseOperationID(idStr)
	if err != nil {
		return zeroID, err
	}
	return tid, nil
}

func (s *Server) handleHTTPStreamUpload(w http.ResponseWriter, r *http.Request, binding tools.TransferBinding) {
	if binding.Direction() != fsm.TransferDirectionUpload {
		writeHTTPJSONError(w, http.StatusBadRequest, "direction_mismatch", "transfer session direction is not upload", false)
		return
	}
	startOffset, err := parseStartOffsetHeader(r.Header.Get(headerStartOffset))
	if err != nil {
		writeHTTPJSONError(w, http.StatusBadRequest, "invalid_offset", protocol.SanitizeErrorMessage(err.Error()), false)
		return
	}
	approvalOpt, err := parseApprovalHeader(r.Header.Get(headerApproval))
	if err != nil {
		writeHTTPJSONError(w, http.StatusBadRequest, "invalid_approval", protocol.SanitizeErrorMessage(err.Error()), false)
		return
	}
	written, nextOffset, lastState, approvalConsumed, err := s.streamUploadBody(r, binding, startOffset, approvalOpt)
	if err != nil {
		writeUploadStreamErr(w, err)
		return
	}
	commitApproval := approvalOpt
	if written > 0 && approvalConsumed {
		// 单次审批信封仅允许被首个分片消费；若本次请求已消费该审批，则 CommitTransfer 传 None（留 Verifying 供二次提交）。
		commitApproval = algebraic.None[gate.ApprovalSubmission]()
	}
	committed, actualDigest, finalState, err := s.maybeCommitHTTPUpload(r, binding, nextOffset, lastState, commitApproval)
	if err != nil {
		writeClassifiedHTTPError(w, err)
		return
	}
	writeHTTPJSON(w, http.StatusOK, struct {
		TransferID   security.OperationID              `json:"transfer_id"`
		BytesWritten uint64                            `json:"bytes_written"`
		NextOffset   uint64                            `json:"next_offset"`
		TotalBytes   uint64                            `json:"total_bytes"`
		StateKind    fsm.TransferStateKind             `json:"state_kind"`
		Committed    bool                              `json:"committed"`
		ActualDigest algebraic.Option[security.Digest] `json:"actual_digest,omitzero"`
	}{binding.TransferID(), written, nextOffset, binding.TotalBytes(), finalState, committed, actualDigest})
}

func (s *Server) streamUploadBody(
	r *http.Request,
	binding tools.TransferBinding,
	offset uint64,
	approval algebraic.Option[gate.ApprovalSubmission],
) (written, nextOffset uint64, lastState fsm.TransferStateKind, approvalConsumed bool, err error) {
	buf := make([]byte, s.httpChunkSize)
	lastState = fsm.TransferKindStreaming
	for {
		if s.gate.IsHalted() {
			s.registry.ClearTrackedHandles()
			return 0, 0, fsm.TransferKindInvalid, approvalConsumed, gate.ErrGateHalted
		}
		n, readErr := io.ReadFull(r.Body, buf)
		if n > 0 {
			chunkApproval := takeOnceApproval(approval, &approvalConsumed)
			offset, lastState, err = s.writeOneUploadChunk(r, binding, offset, buf[:n], chunkApproval)
			if err != nil {
				return 0, 0, fsm.TransferKindInvalid, approvalConsumed, err
			}
			written += uint64(n)
		}
		if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
			return written, offset, lastState, approvalConsumed, nil
		}
		if readErr != nil {
			return 0, 0, fsm.TransferKindInvalid, approvalConsumed, domi18n.WrapSentinel(protocol.ErrInvalidParams, readErr)
		}
	}
}

func takeOnceApproval(approval algebraic.Option[gate.ApprovalSubmission], consumed *bool) algebraic.Option[gate.ApprovalSubmission] {
	if *consumed || !approval.IsSome() {
		return algebraic.None[gate.ApprovalSubmission]()
	}
	*consumed = true
	return approval
}

func (s *Server) writeOneUploadChunk(
	r *http.Request,
	binding tools.TransferBinding,
	offset uint64,
	chunk []byte,
	approval algebraic.Option[gate.ApprovalSubmission],
) (uint64, fsm.TransferStateKind, error) {
	// 严格以减法边界检查防止恶意 X-Xops-Start-Offset 触发 uint64 回绕。
	if offset > binding.TotalBytes() || uint64(len(chunk)) > binding.TotalBytes()-offset {
		return 0, fsm.TransferKindInvalid, ErrMessageTooLarge
	}
	chunkRes, err := s.registry.TransferService().WriteTransferChunk(r.Context(), uctrans.WriteTransferChunkRequest{
		CallBase: uctrans.CallBase{Plan: binding.Plan(), NodeID: binding.NodeID(), Approval: approval},
		Handle:   binding.Handle(),
		Offset:   offset,
		Data:     chunk,
	})
	if err != nil {
		return 0, fsm.TransferKindInvalid, err
	}
	return chunkRes.NextOffset, chunkRes.StateKind, nil
}

func writeUploadStreamErr(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrMessageTooLarge) {
		writeHTTPJSONError(w, http.StatusRequestEntityTooLarge, "transfer_size_exceeded", "upload stream byte count exceeds declared total_bytes limit", false)
		return
	}
	writeClassifiedHTTPError(w, err)
}

func (s *Server) maybeCommitHTTPUpload(
	r *http.Request,
	binding tools.TransferBinding,
	offset uint64,
	lastState fsm.TransferStateKind,
	approval algebraic.Option[gate.ApprovalSubmission],
) (bool, algebraic.Option[security.Digest], fsm.TransferStateKind, error) {
	if r.URL.Query().Get("commit") != "true" || offset != binding.TotalBytes() {
		return false, algebraic.None[security.Digest](), lastState, nil
	}
	cRes, cErr := s.registry.TransferService().CommitTransfer(r.Context(), uctrans.CommitTransferRequest{
		CallBase: uctrans.CallBase{Plan: binding.Plan(), NodeID: binding.NodeID(), Approval: approval},
		Handle:   binding.Handle(),
	})
	// 仅在 CommitTransfer 真正进入终态并释放槽位（cErr==nil 或 cRes.TransferID.IsValid()）或 Gate 已熔断时摘除绑定，
	// 绝不在 ApprovalChallengeError/审批失配/瞬态核验失败时提前销毁绑定。
	if cErr == nil || cRes.TransferID.IsValid() || s.gate.IsHalted() {
		s.registry.DropTransfer(binding.TransferID())
	}
	if cErr != nil {
		return false, algebraic.None[security.Digest](), fsm.TransferKindInvalid, cErr
	}
	return true, cRes.ActualDigest, cRes.State.Kind(), nil
}

func (s *Server) handleHTTPStreamDownload(w http.ResponseWriter, r *http.Request, binding tools.TransferBinding) {
	if binding.Direction() != fsm.TransferDirectionDownload {
		writeHTTPJSONError(w, http.StatusBadRequest, "direction_mismatch", "transfer session direction is not download", false)
		return
	}
	approvalOpt, err := parseApprovalHeader(r.Header.Get(headerApproval))
	if err != nil {
		writeHTTPJSONError(w, http.StatusBadRequest, "invalid_approval", protocol.SanitizeErrorMessage(err.Error()), false)
		return
	}
	scopedFS := s.registry.ScopedFS()
	localRoot, okRoot := binding.LocalRoot().Get()
	localDest, okDest := binding.LocalDest().Get()
	if scopedFS == nil || !okRoot || !okDest {
		writeHTTPJSONError(w, http.StatusServiceUnavailable, "scoped_fs_unavailable", "sandbox ScopedRootFS or destination binding is missing", false)
		return
	}
	// 先探测实时状态：已在 Verifying（例如上次 GET 拉取完分片后因 CommitTransfer 挑战 428 返回）则跳过拉取直进 CommitTransfer；
	// 拉取阶段恒传 Approval: None，严禁将 commit 审批回执错喂给 PullTransferChunk。
	unapprovedBase := uctrans.CallBase{Plan: binding.Plan(), NodeID: binding.NodeID()}
	snap, inspErr := s.registry.TransferService().InspectTransfer(r.Context(), uctrans.InspectTransferRequest{
		CallBase:   unapprovedBase,
		TransferID: binding.TransferID(),
		Handle:     algebraic.Some(binding.Handle()),
	})
	if inspErr != nil {
		writeClassifiedHTTPError(w, inspErr)
		return
	}
	if snap.StateKind != fsm.TransferKindVerifying {
		if err := s.pullAllDownloadChunks(r, binding, unapprovedBase); err != nil {
			writeClassifiedHTTPError(w, err)
			return
		}
	}
	commitBase := uctrans.CallBase{Plan: binding.Plan(), NodeID: binding.NodeID(), Approval: approvalOpt}
	commitRes, cErr := s.registry.TransferService().CommitTransfer(r.Context(), uctrans.CommitTransferRequest{
		CallBase: commitBase,
		Handle:   binding.Handle(),
	})
	if cErr == nil || commitRes.TransferID.IsValid() || s.gate.IsHalted() {
		s.registry.DropTransfer(binding.TransferID())
	}
	if cErr != nil {
		writeClassifiedHTTPError(w, cErr)
		return
	}
	s.streamCommittedDownload(w, scopedFS, localRoot, localDest, binding, commitRes)
}

func (s *Server) pullAllDownloadChunks(
	r *http.Request,
	binding tools.TransferBinding,
	base uctrans.CallBase,
) error {
	tSvc := s.registry.TransferService()
	for binding.TotalBytes() > 0 {
		if s.gate.IsHalted() {
			s.registry.ClearTrackedHandles()
			return gate.ErrGateHalted
		}
		pullRes, pErr := tSvc.PullTransferChunk(r.Context(), uctrans.PullTransferChunkRequest{
			CallBase:      base,
			Handle:        binding.Handle(),
			MaxChunkBytes: uint64(s.httpChunkSize),
		})
		if pErr != nil {
			return pErr
		}
		if pullRes.StateKind == fsm.TransferKindVerifying || pullRes.NextOffset >= binding.TotalBytes() {
			return nil
		}
	}
	return nil
}

func (s *Server) streamCommittedDownload(
	w http.ResponseWriter,
	scopedFS ports.ScopedRootFS,
	localRoot pathalg.LocalDir,
	localDest pathalg.LocalRootedDest,
	binding tools.TransferBinding,
	commitRes uctrans.CommitTransferResult,
) {
	limits, lErr := ports.NewReadLimits(max(int64(binding.TotalBytes()), 1))
	if lErr != nil {
		writeHTTPJSONError(w, http.StatusInternalServerError, "invalid_limits", protocol.SanitizeErrorMessage(lErr.Error()), false)
		return
	}
	buf := make([]byte, s.httpChunkSize)
	headersWritten := false
	streamErr := scopedFS.WithRoot(localRoot, func(root ports.RootHandle) error {
		return root.WithReadRegular(localDest, limits, func(rd ports.BoundedReadHandle, size int64) error {
			w.Header().Set(headerContentType, "application/octet-stream")
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			w.Header().Set(headerTransferID, binding.TransferID().String())
			w.Header().Set(headerTransferState, commitRes.State.Kind().String())
			if dig, ok := commitRes.ActualDigest.Get(); ok {
				w.Header().Set(headerTransferHash, dig.String())
			}
			headersWritten = true
			w.WriteHeader(http.StatusOK)
			n, cpErr := io.CopyBuffer(w, rd, buf)
			if cpErr == nil && n != size {
				return io.ErrUnexpectedEOF
			}
			return cpErr
		})
	})
	if streamErr != nil {
		s.emitDiag(events.SeverityWarn, "mcp_http_download_stream_error", streamErr.Error(), map[string]string{
			"transfer_id": binding.TransferID().String(),
		})
		if !headersWritten {
			// 写响应头前失败严禁静默返回 200 OK 空体，必须显式返回错误状态码与 JSON 载荷。
			writeClassifiedHTTPError(w, streamErr)
			return
		}
		// 响应头已发送后中途截断/I/O 失败：触发 net/http.ErrAbortHandler 显式中止连接，防止客户端误认干净 EOF。
		panic(http.ErrAbortHandler)
	}
}

func parseStartOffsetHeader(raw string) (uint64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return 0, domi18n.Wrap(err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", headerStartOffset), domi18n.BoundStr("value", raw))
	}
	return v, nil
}

func parseApprovalHeader(raw string) (algebraic.Option[gate.ApprovalSubmission], error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return algebraic.None[gate.ApprovalSubmission](), nil
	}
	var in protocol.ApprovalSubmissionDTO
	if err := protocol.UnmarshalStrict([]byte(trimmed), &in); err != nil {
		return algebraic.None[gate.ApprovalSubmission](), domi18n.Wrap(err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", headerApproval))
	}
	return protocol.DecodeApprovalSubmission(algebraic.Some(in))
}

func writeClassifiedHTTPError(w http.ResponseWriter, err error) {
	code, payload := protocol.ClassifyError(err)
	status := http.StatusInternalServerError
	switch code {
	case protocol.CodeGateHalted, protocol.CodeUncertainOutcome:
		status = http.StatusServiceUnavailable
	case protocol.CodeApprovalRequired:
		status = http.StatusPreconditionRequired
	case protocol.CodeAuthorizationDenied:
		status = http.StatusForbidden
	case protocol.CodeInvalidParams:
		status = http.StatusBadRequest
	case protocol.CodeInvalidState:
		status = http.StatusConflict
	}
	writeHTTPJSON(w, status, payload)
}
