package ports

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// 本文件集中维护 core/ports 全部失败关闭枚举的单一事实源名称表、值接收者 TextCodec
// 与全部不透明值对象的 Go 1.27 encoding/json/v2 严格编解码器（拒绝 null、缺失必填字段与未知字段）。
const (
	nmLockMode  = "invalid,shared,exclusive"
	nmHostTrust = "invalid,trusted,unknown,mismatch,revoked"
	nmFwdDir    = "invalid,local,remote,dynamic,streamlocal,tun"
	nmMuxAct    = "invalid,check,forward,cancel,exit,stop,proxy"
	nmRemType   = "invalid,regular,dir,symlink,other"
	nmAudPhase  = "invalid,denied,authorized,finalized"
	nmAudOut    = "invalid,pending,denied,succeeded,failed,canceled,escalated,aborted_by_crash,outcome_unknown"
)

type portEnum interface {
	~uint8
	IsValid() bool
	String() string
}

func pEnumOk(idx uint8, csv string) bool { return idx >= 1 && int(idx) <= strings.Count(csv, ",") }
func pEnumStr(idx uint8, csv string) string {
	parts := strings.Split(csv, ",")
	if int(idx) < len(parts) {
		return parts[idx]
	}
	return parts[0]
}
func pEnumParse[T portEnum](raw string, baseErr error) (T, error) {
	for v := T(1); v < 255 && v.IsValid(); v++ {
		if v.String() == raw {
			return v, nil
		}
	}
	return 0, fmt.Errorf("%w: %q", baseErr, raw)
}
func pEnumAppend[T portEnum](b []byte, v T, err error) ([]byte, error) {
	if !v.IsValid() {
		return nil, err
	}
	return append(b, v.String()...), nil
}
func pEnumUnm[T portEnum](dst *T, t []byte, err error) error {
	return unmarshalTextWithReset(dst, 0, t, func(s string) (T, error) { return pEnumParse[T](s, err) })
}
func missingField(baseErr error, field string) error {
	return fmt.Errorf("%w: 缺少必需的 %s 字段", baseErr, field)
}
func optOrZero[T any](o algebraic.Option[T]) T { return o.OrElse(zeroVal[T]()) }

// 全部 7 个失败关闭端口枚举的 Parse / IsValid / IsZero / String 与 TextCodec 统一实现。
func ParseLockMode(s string) (LockMode, error)         { return pEnumParse[LockMode](s, ErrInvalidLockMode) }
func (m LockMode) IsValid() bool                       { return pEnumOk(uint8(m), nmLockMode) }
func (m LockMode) IsZero() bool                        { return m == LockModeInvalid }
func (m LockMode) String() string                      { return pEnumStr(uint8(m), nmLockMode) }
func (m LockMode) AppendText(b []byte) ([]byte, error) { return pEnumAppend(b, m, ErrInvalidLockMode) }
func (m LockMode) MarshalText() ([]byte, error)        { return m.AppendText(nil) }
func (m *LockMode) UnmarshalText(t []byte) error       { return pEnumUnm(m, t, ErrInvalidLockMode) }

func ParseHostTrustStatus(s string) (HostTrustStatus, error) {
	return pEnumParse[HostTrustStatus](s, ErrInvalidArgument)
}
func (s HostTrustStatus) IsValid() bool  { return pEnumOk(uint8(s), nmHostTrust) }
func (s HostTrustStatus) IsZero() bool   { return s == HostTrustStatusInvalid }
func (s HostTrustStatus) String() string { return pEnumStr(uint8(s), nmHostTrust) }
func (s HostTrustStatus) AppendText(b []byte) ([]byte, error) {
	return pEnumAppend(b, s, ErrInvalidArgument)
}
func (s HostTrustStatus) MarshalText() ([]byte, error)  { return s.AppendText(nil) }
func (s *HostTrustStatus) UnmarshalText(t []byte) error { return pEnumUnm(s, t, ErrInvalidArgument) }

func ParseForwardDirection(s string) (ForwardDirection, error) {
	return pEnumParse[ForwardDirection](s, ErrInvalidArgument)
}
func (d ForwardDirection) IsValid() bool  { return pEnumOk(uint8(d), nmFwdDir) }
func (d ForwardDirection) IsZero() bool   { return d == ForwardDirectionInvalid }
func (d ForwardDirection) String() string { return pEnumStr(uint8(d), nmFwdDir) }
func (d ForwardDirection) AppendText(b []byte) ([]byte, error) {
	return pEnumAppend(b, d, ErrInvalidArgument)
}
func (d ForwardDirection) MarshalText() ([]byte, error)  { return d.AppendText(nil) }
func (d *ForwardDirection) UnmarshalText(t []byte) error { return pEnumUnm(d, t, ErrInvalidArgument) }

func ParseMuxControlAction(s string) (MuxControlAction, error) {
	return pEnumParse[MuxControlAction](s, ErrInvalidArgument)
}
func (a MuxControlAction) IsValid() bool  { return pEnumOk(uint8(a), nmMuxAct) }
func (a MuxControlAction) IsZero() bool   { return a == MuxActionInvalid }
func (a MuxControlAction) String() string { return pEnumStr(uint8(a), nmMuxAct) }
func (a MuxControlAction) AppendText(b []byte) ([]byte, error) {
	return pEnumAppend(b, a, ErrInvalidArgument)
}
func (a MuxControlAction) MarshalText() ([]byte, error)  { return a.AppendText(nil) }
func (a *MuxControlAction) UnmarshalText(t []byte) error { return pEnumUnm(a, t, ErrInvalidArgument) }

func ParseRemoteFileType(s string) (RemoteFileType, error) {
	return pEnumParse[RemoteFileType](s, ErrInvalidArgument)
}
func (t RemoteFileType) IsValid() bool  { return pEnumOk(uint8(t), nmRemType) }
func (t RemoteFileType) IsZero() bool   { return t == RemoteFileTypeInvalid }
func (t RemoteFileType) String() string { return pEnumStr(uint8(t), nmRemType) }
func (t RemoteFileType) AppendText(b []byte) ([]byte, error) {
	return pEnumAppend(b, t, ErrInvalidArgument)
}
func (t RemoteFileType) MarshalText() ([]byte, error)  { return t.AppendText(nil) }
func (t *RemoteFileType) UnmarshalText(b []byte) error { return pEnumUnm(t, b, ErrInvalidArgument) }

func ParseAuditPhase(s string) (AuditPhase, error) {
	return pEnumParse[AuditPhase](s, ErrInvalidAuditEntry)
}
func (p AuditPhase) IsValid() bool  { return pEnumOk(uint8(p), nmAudPhase) }
func (p AuditPhase) IsZero() bool   { return p == AuditPhaseInvalid }
func (p AuditPhase) String() string { return pEnumStr(uint8(p), nmAudPhase) }
func (p AuditPhase) AppendText(b []byte) ([]byte, error) {
	return pEnumAppend(b, p, ErrInvalidAuditEntry)
}
func (p AuditPhase) MarshalText() ([]byte, error)  { return p.AppendText(nil) }
func (p *AuditPhase) UnmarshalText(t []byte) error { return pEnumUnm(p, t, ErrInvalidAuditEntry) }

func ParseAuditOutcome(s string) (AuditOutcome, error) {
	return pEnumParse[AuditOutcome](s, ErrInvalidAuditEntry)
}
func (o AuditOutcome) IsValid() bool  { return pEnumOk(uint8(o), nmAudOut) }
func (o AuditOutcome) IsZero() bool   { return o == AuditOutcomeInvalid }
func (o AuditOutcome) String() string { return pEnumStr(uint8(o), nmAudOut) }
func (o AuditOutcome) AppendText(b []byte) ([]byte, error) {
	return pEnumAppend(b, o, ErrInvalidAuditEntry)
}
func (o AuditOutcome) MarshalText() ([]byte, error)  { return o.AppendText(nil) }
func (o *AuditOutcome) UnmarshalText(t []byte) error { return pEnumUnm(o, t, ErrInvalidAuditEntry) }

// 严格区分「零值本身合法（须用 Option 检测缺失，如 size/mode/alive/count）」与
// 「零值已由领域构造器失败关闭拒绝（直接标量解码后过构造器校验）」的线缆 DTO。
type (
	durabilityOutcomeWire struct {
		Status   fsm.DurabilityStatus       `json:"status"`
		Revision algebraic.Option[Revision] `json:"revision,omitzero"`
		Detail   string                     `json:"detail,omitzero"`
	}
	proxyRouteWire         struct{ route option.ProxyRoute }
	openSSHVirtualHostWire struct {
		Alias      string                             `json:"alias"`
		SourceFile string                             `json:"source_file,omitzero"`
		Endpoint   algebraic.Option[netaddr.Endpoint] `json:"endpoint,omitzero"`
		User       algebraic.Option[option.Username]  `json:"user,omitzero"`
		Proxy      proxyRouteWire                     `json:"proxy,omitzero"`
		Layer      option.OptionLayer                 `json:"layer,omitzero"`
	}
	readLimitsWire struct {
		MaxBytes int64 `json:"max_bytes"`
	}
	publicKeyInfoWire struct {
		Algorithm   string                   `json:"algorithm"`
		Fingerprint inventory.KeyFingerprint `json:"fingerprint"`
		WireBlobB64 string                   `json:"wire_blob_b64"`
		Comment     string                   `json:"comment,omitzero"`
	}
	hostTrustCheckWire struct {
		Status               HostTrustStatus            `json:"status"`
		Endpoint             netaddr.Endpoint           `json:"endpoint"`
		Presented            PublicKeyInfo              `json:"presented"`
		ExpectedFingerprints []inventory.KeyFingerprint `json:"expected_fingerprints,omitzero"`
		Reason               string                     `json:"reason,omitzero"`
	}
	ptyRequestWire struct {
		Term string       `json:"term"`
		Size TerminalSize `json:"size"`
	}
	forwardSpecWire struct {
		Direction  ForwardDirection `json:"direction"`
		BindAddr   string           `json:"bind_addr"`
		TargetAddr string           `json:"target_addr,omitzero"`
	}
	muxControlResponseWire struct {
		Alive     algebraic.Option[bool] `json:"alive"`
		MasterPID uint32                 `json:"master_pid,omitzero"`
		Detail    string                 `json:"detail,omitzero"`
	}
	remoteFileAnchorWire struct {
		FileType  RemoteFileType `json:"file_type"`
		HasDevIno bool           `json:"has_dev_ino,omitzero"`
		Dev       uint64         `json:"dev,omitzero"`
		Ino       uint64         `json:"ino,omitzero"`
	}
	remoteFileStatWire struct {
		Path    pathalg.RemotePath          `json:"path"`
		Size    algebraic.Option[int64]     `json:"size"`
		Mode    algebraic.Option[uint32]    `json:"mode"`
		ModTime algebraic.Option[time.Time] `json:"mod_time,omitzero"`
		Anchor  RemoteFileAnchor            `json:"anchor"`
	}
	remoteDirEntryWire struct {
		Name     pathalg.RemoteName          `json:"name"`
		FileType RemoteFileType              `json:"file_type"`
		Size     algebraic.Option[int64]     `json:"size"`
		Mode     algebraic.Option[uint32]    `json:"mode"`
		ModTime  algebraic.Option[time.Time] `json:"mod_time,omitzero"`
	}
	remoteWriteSpecWire struct {
		Perm           uint32                             `json:"perm"`
		ExpectedAnchor algebraic.Option[RemoteFileAnchor] `json:"expected_anchor,omitzero"`
		NoClobber      bool                               `json:"no_clobber,omitzero"`
		AtomicRename   bool                               `json:"atomic_rename,omitzero"`
	}
	auditEntryWire struct {
		ProcessID   ProcessInstanceID                       `json:"process_id"`
		TraceID     security.TraceID                        `json:"trace_id"`
		OperationID security.OperationID                    `json:"operation_id"`
		Phase       AuditPhase                              `json:"phase"`
		Outcome     AuditOutcome                            `json:"outcome"`
		Risk        security.RiskLevel                      `json:"risk"`
		Decision    algebraic.Option[security.DecisionKind] `json:"decision"`
		Binding     security.OperationBinding               `json:"binding"`
		Timestamp   time.Time                               `json:"timestamp"`
		Duration    algebraic.Option[algebraic.Duration]    `json:"duration,omitzero"`
		ErrorCode   string                                  `json:"error_code,omitzero"`
		Reason      string                                  `json:"reason,omitzero"`
	}
	crashReconcileReportWire struct {
		ScannedLocks      algebraic.Option[int]  `json:"scanned_locks"`
		LiveLocksSkipped  algebraic.Option[int]  `json:"live_locks_skipped"`
		DeadLocksClaimed  algebraic.Option[int]  `json:"dead_locks_claimed"`
		AbortedOperations []security.OperationID `json:"aborted_operations,omitzero"`
	}
	terminalSizeWire struct {
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
	}
	processSpecWire struct {
		Command        string                               `json:"command"`
		Args           []string                             `json:"args,omitzero"`
		WorkDir        algebraic.Option[pathalg.LocalDir]   `json:"work_dir,omitzero"`
		Env            map[string]string                    `json:"env,omitzero"`
		Timeout        algebraic.Option[algebraic.Duration] `json:"timeout,omitzero"`
		MaxOutputBytes algebraic.Option[uint64]             `json:"max_output_bytes"`
	}
	promptRequestWire struct {
		Title      string `json:"title,omitzero"`
		Prompt     string `json:"prompt"`
		Subject    string `json:"subject,omitzero"`
		AllowEmpty bool   `json:"allow_empty,omitzero"`
	}
	confirmRequestWire struct {
		Title   string             `json:"title,omitzero"`
		Message string             `json:"message"`
		Subject string             `json:"subject,omitzero"`
		Risk    security.RiskLevel `json:"risk"`
	}
	approvalDecisionResponseWire struct {
		Verdict        algebraic.Option[security.Verdict] `json:"verdict"`
		EnvelopeDigest security.Digest                    `json:"envelope_digest"`
		Comment        string                             `json:"comment,omitzero"`
	}
)

func (p proxyRouteWire) IsZero() bool {
	return p.route == nil || option.EqualProxyRoute(p.route, option.NewProxyUnset())
}
func (p proxyRouteWire) MarshalJSONTo(enc *jsontext.Encoder) error {
	return option.MarshalProxyRouteTo(enc, p.route)
}
func (p *proxyRouteWire) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	r, err := option.UnmarshalProxyRouteFrom(dec)
	if err != nil {
		p.route = nil
		return err
	}
	p.route = r
	return nil
}
func optModTime(t time.Time) algebraic.Option[time.Time] {
	if t.IsZero() {
		return algebraic.None[time.Time]()
	}
	return algebraic.Some(t.UTC())
}

// MarshalJSONTo 与 UnmarshalJSONFrom 实现存储与本地 FS 端口值对象的严格 json/v2 编解码。
func (d DurabilityOutcome) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, d.IsValid(), ErrInvalidDurability, durabilityOutcomeWire{d.status, d.revision, d.detail})
}
func (d *DurabilityOutcome) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(d, dec, ErrInvalidDurability, decodeDurabilityOutcomeWire)
}
func decodeDurabilityOutcomeWire(w durabilityOutcomeWire) (DurabilityOutcome, error) {
	switch w.Status {
	case fsm.DurabilityCommitted:
		if rev, okR := w.Revision.Get(); okR && w.Detail == "" {
			return NewDurabilityCommitted(rev)
		}
		return DurabilityOutcome{}, fmt.Errorf("%w: committed 须携带有效 revision 且无 detail", ErrInvalidDurability)
	case fsm.DurabilityNotApplied, fsm.DurabilityOutcomeUnknown:
		if w.Revision.IsSome() {
			return DurabilityOutcome{}, fmt.Errorf("%w: %s 不得携带 revision", ErrInvalidDurability, w.Status)
		}
		if w.Status == fsm.DurabilityNotApplied {
			return NewDurabilityNotApplied(w.Detail)
		}
		return NewDurabilityOutcomeUnknown(w.Detail)
	case fsm.DurabilityAppliedNotDurable:
		return NewDurabilityAppliedNotDurable(w.Revision, w.Detail)
	default:
		return DurabilityOutcome{}, missingField(ErrInvalidDurability, "status")
	}
}
func (h OpenSSHVirtualHost) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, h.IsValid(), ErrInvalidArgument, openSSHVirtualHostWire{h.alias, h.sourceFile, h.endpoint, h.user, proxyRouteWire{h.proxy}, h.layer})
}
func (h *OpenSSHVirtualHost) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(h, dec, ErrInvalidArgument, func(w openSSHVirtualHostWire) (OpenSSHVirtualHost, error) {
		return NewOpenSSHVirtualHost(OpenSSHVirtualHostSpec{w.Alias, w.SourceFile, w.Endpoint, w.User, w.Proxy.route, w.Layer})
	})
}
func (l ReadLimits) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, l.IsValid(), ErrInvalidReadLimits, readLimitsWire{l.maxBytes})
}
func (l *ReadLimits) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(l, dec, ErrInvalidReadLimits, func(w readLimitsWire) (ReadLimits, error) {
		return NewReadLimits(w.MaxBytes)
	})
}

// MarshalJSONTo 与 UnmarshalJSONFrom 实现凭据、主机密钥、传输与远端 FS 值对象的严格 json/v2 编解码。
func (k PublicKeyInfo) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, k.IsValid(), ErrInvalidArgument, publicKeyInfoWire{k.algorithm, k.fingerprint, base64.StdEncoding.EncodeToString(k.wireBlob), k.comment})
}
func (k *PublicKeyInfo) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(k, dec, ErrInvalidArgument, func(w publicKeyInfoWire) (PublicKeyInfo, error) {
		blob, err := base64.StdEncoding.Strict().DecodeString(w.WireBlobB64)
		if err != nil {
			return PublicKeyInfo{}, fmt.Errorf("%w: 公钥 Base64 解码失败: %w", ErrInvalidArgument, err)
		}
		return NewPublicKeyInfo(PublicKeyInfoSpec{w.Algorithm, w.Fingerprint, blob, w.Comment})
	})
}
func (c HostTrustCheck) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, c.IsValid(), ErrInvalidArgument, hostTrustCheckWire{c.status, c.endpoint, c.presented, c.expectedFingerprints, c.reason})
}
func (c *HostTrustCheck) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(c, dec, ErrInvalidArgument, func(w hostTrustCheckWire) (HostTrustCheck, error) {
		return NewHostTrustCheck(HostTrustCheckSpec(w))
	})
}
func (p PTYRequest) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, p.IsValid(), ErrInvalidArgument, ptyRequestWire{p.term, p.size})
}
func (p *PTYRequest) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(p, dec, ErrInvalidArgument, func(w ptyRequestWire) (PTYRequest, error) {
		return NewPTYRequest(w.Term, w.Size)
	})
}
func (f ForwardSpec) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, f.IsValid(), ErrInvalidArgument, forwardSpecWire{f.direction, f.bindAddr, f.targetAddr})
}
func (f *ForwardSpec) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(f, dec, ErrInvalidArgument, func(w forwardSpecWire) (ForwardSpec, error) {
		return NewForwardSpec(w.Direction, w.BindAddr, w.TargetAddr)
	})
}
func (r MuxControlResponse) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, r.IsValid(), ErrInvalidArgument, muxControlResponseWire{algebraic.Some(r.alive), r.masterPID, r.detail})
}
func (r *MuxControlResponse) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(r, dec, ErrInvalidArgument, func(w muxControlResponseWire) (MuxControlResponse, error) {
		if w.Alive.IsNone() {
			return MuxControlResponse{}, missingField(ErrInvalidArgument, "alive")
		}
		return NewMuxControlResponse(optOrZero(w.Alive), w.MasterPID, w.Detail)
	})
}
func (a RemoteFileAnchor) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, a.IsValid(), ErrInvalidArgument, remoteFileAnchorWire{a.fileType, a.hasDevIno, a.dev, a.ino})
}
func (a *RemoteFileAnchor) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(a, dec, ErrInvalidArgument, func(w remoteFileAnchorWire) (RemoteFileAnchor, error) {
		return NewRemoteFileAnchor(w.FileType, w.HasDevIno, w.Dev, w.Ino)
	})
}
func (s RemoteFileStat) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, s.IsValid(), ErrInvalidArgument, remoteFileStatWire{s.path, algebraic.Some(s.size), algebraic.Some(uint32(s.mode)), optModTime(s.modTime), s.anchor})
}
func (s *RemoteFileStat) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(s, dec, ErrInvalidArgument, func(w remoteFileStatWire) (RemoteFileStat, error) {
		if w.Size.IsNone() || w.Mode.IsNone() {
			return RemoteFileStat{}, missingField(ErrInvalidArgument, "size/mode")
		}
		return NewRemoteFileStat(RemoteFileStatSpec{w.Path, optOrZero(w.Size), fs.FileMode(optOrZero(w.Mode)), optOrZero(w.ModTime), w.Anchor})
	})
}
func (e RemoteDirEntry) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, e.IsValid(), ErrInvalidArgument, remoteDirEntryWire{e.name, e.fileType, algebraic.Some(e.size), algebraic.Some(uint32(e.mode)), optModTime(e.modTime)})
}
func (e *RemoteDirEntry) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(e, dec, ErrInvalidArgument, func(w remoteDirEntryWire) (RemoteDirEntry, error) {
		if w.Size.IsNone() || w.Mode.IsNone() {
			return RemoteDirEntry{}, missingField(ErrInvalidArgument, "size/mode")
		}
		return NewRemoteDirEntry(RemoteDirEntrySpec{w.Name, w.FileType, optOrZero(w.Size), fs.FileMode(optOrZero(w.Mode)), optOrZero(w.ModTime)})
	})
}
func (s RemoteWriteSpec) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, s.IsValid(), ErrInvalidArgument, remoteWriteSpecWire{uint32(s.perm), s.expectedAnchor, s.noClobber, s.atomicRename})
}
func (s *RemoteWriteSpec) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(s, dec, ErrInvalidArgument, func(w remoteWriteSpecWire) (RemoteWriteSpec, error) {
		return NewRemoteWriteSpec(RemoteWriteSpecInput{fs.FileMode(w.Perm), w.ExpectedAnchor, w.NoClobber, w.AtomicRename})
	})
}

// MarshalJSONTo 与 UnmarshalJSONFrom 实现审计、系统与交互值对象的严格 json/v2 编解码。
func (e AuditEntry) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, e.IsValid(), ErrInvalidAuditEntry, auditEntryWire{e.processID, e.traceID, e.operationID, e.phase, e.outcome, e.risk, algebraic.Some(e.decision), e.binding, e.timestamp.UTC(), e.duration, e.errorCode, e.reason})
}
func (e *AuditEntry) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(e, dec, ErrInvalidAuditEntry, func(w auditEntryWire) (AuditEntry, error) {
		if w.Decision.IsNone() {
			return AuditEntry{}, missingField(ErrInvalidAuditEntry, "decision")
		}
		return NewAuditEntry(AuditEntrySpec{w.ProcessID, w.TraceID, w.OperationID, w.Phase, w.Outcome, w.Risk, optOrZero(w.Decision), w.Binding, w.Timestamp, w.Duration, w.ErrorCode, w.Reason})
	})
}
func (r CrashReconcileReport) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, r.IsValid(), ErrInvalidArgument, crashReconcileReportWire{algebraic.Some(r.scannedLocks), algebraic.Some(r.liveLocksSkipped), algebraic.Some(r.deadLocksClaimed), r.abortedOperations})
}
func (r *CrashReconcileReport) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(r, dec, ErrInvalidArgument, func(w crashReconcileReportWire) (CrashReconcileReport, error) {
		if w.ScannedLocks.IsNone() || w.LiveLocksSkipped.IsNone() || w.DeadLocksClaimed.IsNone() {
			return CrashReconcileReport{}, missingField(ErrInvalidArgument, "崩溃对账计数")
		}
		return NewCrashReconcileReport(CrashReconcileReportSpec{optOrZero(w.ScannedLocks), optOrZero(w.LiveLocksSkipped), optOrZero(w.DeadLocksClaimed), w.AbortedOperations})
	})
}
func (s TerminalSize) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, s.IsValid(), ErrInvalidTTYSize, terminalSizeWire{s.cols, s.rows})
}
func (s *TerminalSize) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(s, dec, ErrInvalidTTYSize, func(w terminalSizeWire) (TerminalSize, error) {
		return NewTerminalSize(w.Cols, w.Rows)
	})
}
func (p ProcessSpec) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, p.IsValid(), ErrInvalidArgument, processSpecWire{p.command, p.args, p.workDir, p.Env(), p.timeout, algebraic.Some(p.maxOutputBytes)})
}
func (p *ProcessSpec) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(p, dec, ErrInvalidArgument, func(w processSpecWire) (ProcessSpec, error) {
		if w.MaxOutputBytes.IsNone() {
			return ProcessSpec{}, missingField(ErrInvalidArgument, "max_output_bytes")
		}
		return NewProcessSpec(ProcessSpecInput(w))
	})
}
func (r SecretPromptRequest) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, r.IsValid(), ErrInvalidArgument, promptRequestWire{r.title, r.prompt, r.subject, r.allowEmpty})
}
func (r *SecretPromptRequest) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(r, dec, ErrInvalidArgument, func(w promptRequestWire) (SecretPromptRequest, error) {
		return NewSecretPromptRequest(SecretPromptRequestSpec(w))
	})
}
func (r ConfirmRequest) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, r.IsValid(), ErrInvalidArgument, confirmRequestWire{r.title, r.message, r.subject, r.risk})
}
func (r *ConfirmRequest) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(r, dec, ErrInvalidArgument, func(w confirmRequestWire) (ConfirmRequest, error) {
		return NewConfirmRequest(ConfirmRequestSpec(w))
	})
}
func (r TextPromptRequest) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, r.IsValid(), ErrInvalidArgument, promptRequestWire{r.title, r.prompt, r.subject, r.allowEmpty})
}
func (r *TextPromptRequest) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(r, dec, ErrInvalidArgument, func(w promptRequestWire) (TextPromptRequest, error) {
		return NewTextPromptRequest(TextPromptRequestSpec(w))
	})
}
func (r ApprovalDecisionResponse) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidJSON(enc, r.IsValid(), ErrInvalidArgument, approvalDecisionResponseWire{algebraic.Some(r.verdict), r.envelopeDigest, r.comment})
}
func (r *ApprovalDecisionResponse) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(r, dec, ErrInvalidArgument, func(w approvalDecisionResponseWire) (ApprovalDecisionResponse, error) {
		if w.Verdict.IsNone() {
			return ApprovalDecisionResponse{}, missingField(ErrInvalidArgument, "verdict")
		}
		return NewApprovalDecisionResponse(optOrZero(w.Verdict), w.EnvelopeDigest, w.Comment)
	})
}
