package mcpruntime

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
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
//   - 全程采用定长分片缓冲（httpChunkSize，默认 1 MiB）直连 usecase/transfer，永不整包缓存在内存；
//   - 物理不接触 OperatorReadFS：下载流仅经 ScopedRootFS.WithRoot -> WithReadRegular 有界流式读取已原子提交产物；
//   - 每片读写前均校验 Gate.IsHalted()，熔断即刻中止返回 503；遇 TransferUncertainCommit 忠实返回 503 零重试。
func (s *Server) handleTransferHTTP(w http.ResponseWriter, r *http.Request) {
	if s.gate.IsHalted() {
		s.registry.ClearTrackedHandles()
		writeHTTPJSONError(w, http.StatusServiceUnavailable, "gate_halted", gate.ErrGateHalted.Error(), true)
		return
	}
	sid := strings.TrimSpace(r.Header.Get(headerMCPSessionID))
	if sid == "" || !s.hasHTTPSession(sid) {
		writeHTTPJSONError(w, http.StatusUnauthorized, "invalid_session", "传输流端点要求有效的 Mcp-Session-Id", false)
		return
	}
	tid, err := parseTransferStreamPath(r.URL.Path)
	if err != nil {
		writeHTTPJSONError(w, http.StatusNotFound, "not_found", "无效的传输流端点路径（应为 /transfers/{transfer_id}/stream）", false)
		return
	}
	binding, found := s.registry.LookupTransfer(tid)
	if !found {
		writeHTTPJSONError(w, http.StatusNotFound, "transfer_not_found", "未找到活跃流式传输绑定或已终结", false)
		return
	}
	if s.registry.TransferService() == nil {
		writeHTTPJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "TransferService 未装配", false)
		return
	}
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		s.handleHTTPStreamUpload(w, r, binding)
	case http.MethodGet:
		s.handleHTTPStreamDownload(w, r, binding)
	default:
		w.Header().Set("Allow", "GET, PUT, POST")
		writeHTTPJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "仅允许 GET/PUT/POST", false)
	}
}

func parseTransferStreamPath(urlPath string) (security.OperationID, error) {
	var zeroID security.OperationID
	trimmed := strings.TrimPrefix(urlPath, "/transfers/")
	idStr, suffix, ok := strings.Cut(trimmed, "/")
	if !ok || suffix != "stream" || idStr == "" {
		return zeroID, errors.New("无效传输流路径")
	}
	tid, err := security.ParseOperationID(idStr)
	if err != nil {
		return zeroID, err
	}
	return tid, nil
}

func (s *Server) handleHTTPStreamUpload(w http.ResponseWriter, r *http.Request, binding tools.TransferBinding) {
	if binding.Direction() != fsm.TransferDirectionUpload {
		writeHTTPJSONError(w, http.StatusBadRequest, "direction_mismatch", "当前传输会话方向不是 upload", false)
		return
	}
	startOffset, err := parseStartOffsetHeader(r.Header.Get(headerStartOffset))
	if err != nil {
		writeHTTPJSONError(w, http.StatusBadRequest, "invalid_offset", err.Error(), false)
		return
	}
	approvalOpt, err := parseApprovalHeader(r.Header.Get(headerApproval))
	if err != nil {
		writeHTTPJSONError(w, http.StatusBadRequest, "invalid_approval", err.Error(), false)
		return
	}
	written, nextOffset, lastState, err := s.streamUploadBody(r, binding, startOffset, approvalOpt)
	if err != nil {
		writeUploadStreamErr(w, err)
		return
	}
	committed, actualDigest, finalState, err := s.maybeCommitHTTPUpload(r, binding, nextOffset, lastState, approvalOpt)
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
) (written, nextOffset uint64, lastState fsm.TransferStateKind, err error) {
	buf := make([]byte, s.httpChunkSize)
	lastState = fsm.TransferKindStreaming
	for {
		if s.gate.IsHalted() {
			s.registry.ClearTrackedHandles()
			return 0, 0, fsm.TransferKindInvalid, gate.ErrGateHalted
		}
		n, readErr := io.ReadFull(r.Body, buf)
		if n > 0 {
			offset, lastState, err = s.writeOneUploadChunk(r, binding, offset, buf[:n], approval)
			if err != nil {
				return 0, 0, fsm.TransferKindInvalid, err
			}
			written += uint64(n)
		}
		if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
			return written, offset, lastState, nil
		}
		if readErr != nil {
			return 0, 0, fsm.TransferKindInvalid, fmt.Errorf("%w: %w", protocol.ErrInvalidParams, readErr)
		}
	}
}

func (s *Server) writeOneUploadChunk(
	r *http.Request,
	binding tools.TransferBinding,
	offset uint64,
	chunk []byte,
	approval algebraic.Option[gate.ApprovalSubmission],
) (uint64, fsm.TransferStateKind, error) {
	if offset+uint64(len(chunk)) > binding.TotalBytes() {
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
		writeHTTPJSONError(w, http.StatusRequestEntityTooLarge, "transfer_size_exceeded", "上传流字节数超出已声明的 total_bytes 上限", false)
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
	s.registry.DropTransfer(binding.TransferID())
	if cErr != nil {
		return false, algebraic.None[security.Digest](), fsm.TransferKindInvalid, cErr
	}
	return true, cRes.ActualDigest, cRes.State.Kind(), nil
}

func (s *Server) handleHTTPStreamDownload(w http.ResponseWriter, r *http.Request, binding tools.TransferBinding) {
	if binding.Direction() != fsm.TransferDirectionDownload {
		writeHTTPJSONError(w, http.StatusBadRequest, "direction_mismatch", "当前传输会话方向不是 download", false)
		return
	}
	approvalOpt, err := parseApprovalHeader(r.Header.Get(headerApproval))
	if err != nil {
		writeHTTPJSONError(w, http.StatusBadRequest, "invalid_approval", err.Error(), false)
		return
	}
	scopedFS := s.registry.ScopedFS()
	localRoot, okRoot := binding.LocalRoot().Get()
	localDest, okDest := binding.LocalDest().Get()
	if scopedFS == nil || !okRoot || !okDest {
		writeHTTPJSONError(w, http.StatusServiceUnavailable, "scoped_fs_unavailable", "沙箱 ScopedRootFS 或目标绑定缺失", false)
		return
	}
	base := uctrans.CallBase{Plan: binding.Plan(), NodeID: binding.NodeID(), Approval: approvalOpt}
	if err := s.pullAllDownloadChunks(r, binding, base); err != nil {
		writeClassifiedHTTPError(w, err)
		return
	}
	commitRes, cErr := s.registry.TransferService().CommitTransfer(r.Context(), uctrans.CommitTransferRequest{
		CallBase: base,
		Handle:   binding.Handle(),
	})
	s.registry.DropTransfer(binding.TransferID())
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
		writeHTTPJSONError(w, http.StatusInternalServerError, "invalid_limits", lErr.Error(), false)
		return
	}
	buf := make([]byte, s.httpChunkSize)
	streamErr := scopedFS.WithRoot(localRoot, func(root ports.RootHandle) error {
		return root.WithReadRegular(localDest, limits, func(rd ports.BoundedReadHandle, size int64) error {
			w.Header().Set(headerContentType, "application/octet-stream")
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			w.Header().Set(headerTransferID, binding.TransferID().String())
			w.Header().Set(headerTransferState, commitRes.State.Kind().String())
			if dig, ok := commitRes.ActualDigest.Get(); ok {
				w.Header().Set(headerTransferHash, dig.String())
			}
			w.WriteHeader(http.StatusOK)
			_, cpErr := io.CopyBuffer(w, rd, buf)
			return cpErr
		})
	})
	if streamErr != nil {
		s.emitDiag(events.SeverityWarn, "mcp_http_download_stream_error", streamErr.Error(), map[string]string{
			"transfer_id": binding.TransferID().String(),
		})
	}
}

func parseStartOffsetHeader(raw string) (uint64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("无效的 %s 头 %q: %w", headerStartOffset, raw, err)
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
		return algebraic.None[gate.ApprovalSubmission](), fmt.Errorf("无效的 %s 头: %w", headerApproval, err)
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
