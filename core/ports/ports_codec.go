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

// 本文件集中维护 core/ports 全部失败关闭枚举的名称表/TextCodec 与不透明值对象的严格 json/v2 编解码器。
const (
	nmLockMode   = "invalid,shared,exclusive"
	nmHostTrust  = "invalid,trusted,unknown,mismatch,revoked"
	nmFwdDir     = "invalid,local,remote,dynamic,streamlocal,tun"
	nmMuxAct     = "invalid,check,forward,cancel,exit,stop,proxy"
	nmRemType    = "invalid,regular,dir,symlink,other"
	nmAudPhase   = "invalid,denied,authorized,finalized"
	nmAudOut     = "invalid,pending,denied,succeeded,failed,canceled,escalated,aborted_by_crash,outcome_unknown"
	nmVaultState = "invalid,uninitialized,locked,unlocked"
	nmTUNMode    = "invalid,point_to_point,ethernet"
	nmPrivMethod = "invalid,sudo,su,doas"
)

type portEnum interface {
	~uint8
	IsValid() bool
	String() string
}

func eOk(i uint8, csv string) bool { return i >= 1 && int(i) <= strings.Count(csv, ",") }
func eStr(i uint8, csv string) string {
	p := strings.Split(csv, ",")
	return pickIf(int(i) < len(p), p[min(int(i), len(p)-1)], p[0])
}
func epErr[T portEnum](raw string, err error) (T, error) {
	for v := T(1); v < 255 && v.IsValid(); v++ {
		if v.String() == raw {
			return v, nil
		}
	}
	return 0, fmt.Errorf("%w: %q", err, raw)
}
func eaErr[T portEnum](b []byte, v T, err error) ([]byte, error) {
	if !v.IsValid() {
		return nil, err
	}
	return append(b, v.String()...), nil
}
func euErr[T portEnum](dst *T, t []byte, err error) error {
	return unmarshalTextWithReset(dst, 0, t, func(s string) (T, error) { return epErr[T](s, err) })
}
func ep[T portEnum](s string) (T, error)           { return epErr[T](s, ErrInvalidArgument) }
func ea[T portEnum](b []byte, v T) ([]byte, error) { return eaErr(b, v, ErrInvalidArgument) }
func eu[T portEnum](dst *T, t []byte) error        { return euErr(dst, t, ErrInvalidArgument) }
func missingField(baseErr error, f string) error {
	return fmt.Errorf("%w: 缺少必需的 %s 字段", baseErr, f)
}
func optOrZero[T any](o algebraic.Option[T]) T { return o.OrElse(zeroVal[T]()) }
func optModTime(t time.Time) algebraic.Option[time.Time] {
	return pickIf(t.IsZero(), algebraic.None[time.Time](), algebraic.Some(t.UTC()))
}
func encArg[W any](e *jsontext.Encoder, ok bool, w W) error {
	return marshalValidJSON(e, ok, ErrInvalidArgument, w)
}
func decArg[T, W any](dst *T, d *jsontext.Decoder, fn func(W) (T, error)) error {
	return unmarshalJSONWithNullReject(dst, d, ErrInvalidArgument, fn)
}
func decodeB64Strict(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: Base64 解码失败: %w", ErrInvalidArgument, err)
	}
	return b, nil
}

// 全部 10 个失败关闭端口枚举的 Parse / IsValid / IsZero / String 与 TextCodec 统一实现。
func ParseLockMode(s string) (LockMode, error)                 { return epErr[LockMode](s, ErrInvalidLockMode) }
func (m LockMode) IsValid() bool                               { return eOk(uint8(m), nmLockMode) }
func (m LockMode) IsZero() bool                                { return m == LockModeInvalid }
func (m LockMode) String() string                              { return eStr(uint8(m), nmLockMode) }
func (m LockMode) AppendText(b []byte) ([]byte, error)         { return eaErr(b, m, ErrInvalidLockMode) }
func (m LockMode) MarshalText() ([]byte, error)                { return m.AppendText(nil) }
func (m *LockMode) UnmarshalText(t []byte) error               { return euErr(m, t, ErrInvalidLockMode) }
func ParseHostTrustStatus(s string) (HostTrustStatus, error)   { return ep[HostTrustStatus](s) }
func (s HostTrustStatus) IsValid() bool                        { return eOk(uint8(s), nmHostTrust) }
func (s HostTrustStatus) IsZero() bool                         { return s == HostTrustStatusInvalid }
func (s HostTrustStatus) String() string                       { return eStr(uint8(s), nmHostTrust) }
func (s HostTrustStatus) AppendText(b []byte) ([]byte, error)  { return ea(b, s) }
func (s HostTrustStatus) MarshalText() ([]byte, error)         { return s.AppendText(nil) }
func (s *HostTrustStatus) UnmarshalText(t []byte) error        { return eu(s, t) }
func ParseForwardDirection(s string) (ForwardDirection, error) { return ep[ForwardDirection](s) }
func (d ForwardDirection) IsValid() bool                       { return eOk(uint8(d), nmFwdDir) }
func (d ForwardDirection) IsZero() bool                        { return d == ForwardDirectionInvalid }
func (d ForwardDirection) String() string                      { return eStr(uint8(d), nmFwdDir) }
func (d ForwardDirection) AppendText(b []byte) ([]byte, error) { return ea(b, d) }
func (d ForwardDirection) MarshalText() ([]byte, error)        { return d.AppendText(nil) }
func (d *ForwardDirection) UnmarshalText(t []byte) error       { return eu(d, t) }
func ParseMuxControlAction(s string) (MuxControlAction, error) { return ep[MuxControlAction](s) }
func (a MuxControlAction) IsValid() bool                       { return eOk(uint8(a), nmMuxAct) }
func (a MuxControlAction) IsZero() bool                        { return a == MuxActionInvalid }
func (a MuxControlAction) String() string                      { return eStr(uint8(a), nmMuxAct) }
func (a MuxControlAction) AppendText(b []byte) ([]byte, error) { return ea(b, a) }
func (a MuxControlAction) MarshalText() ([]byte, error)        { return a.AppendText(nil) }
func (a *MuxControlAction) UnmarshalText(t []byte) error       { return eu(a, t) }
func ParseRemoteFileType(s string) (RemoteFileType, error)     { return ep[RemoteFileType](s) }
func (t RemoteFileType) IsValid() bool                         { return eOk(uint8(t), nmRemType) }
func (t RemoteFileType) IsZero() bool                          { return t == RemoteFileTypeInvalid }
func (t RemoteFileType) String() string                        { return eStr(uint8(t), nmRemType) }
func (t RemoteFileType) AppendText(b []byte) ([]byte, error)   { return ea(b, t) }
func (t RemoteFileType) MarshalText() ([]byte, error)          { return t.AppendText(nil) }
func (t *RemoteFileType) UnmarshalText(b []byte) error         { return eu(t, b) }
func ParseAuditPhase(s string) (AuditPhase, error)             { return epErr[AuditPhase](s, ErrInvalidAuditEntry) }
func (p AuditPhase) IsValid() bool                             { return eOk(uint8(p), nmAudPhase) }
func (p AuditPhase) IsZero() bool                              { return p == AuditPhaseInvalid }
func (p AuditPhase) String() string                            { return eStr(uint8(p), nmAudPhase) }
func (p AuditPhase) AppendText(b []byte) ([]byte, error)       { return eaErr(b, p, ErrInvalidAuditEntry) }
func (p AuditPhase) MarshalText() ([]byte, error)              { return p.AppendText(nil) }
func (p *AuditPhase) UnmarshalText(t []byte) error             { return euErr(p, t, ErrInvalidAuditEntry) }
func ParseAuditOutcome(s string) (AuditOutcome, error) {
	return epErr[AuditOutcome](s, ErrInvalidAuditEntry)
}
func (o AuditOutcome) IsValid() bool                          { return eOk(uint8(o), nmAudOut) }
func (o AuditOutcome) IsZero() bool                           { return o == AuditOutcomeInvalid }
func (o AuditOutcome) String() string                         { return eStr(uint8(o), nmAudOut) }
func (o AuditOutcome) AppendText(b []byte) ([]byte, error)    { return eaErr(b, o, ErrInvalidAuditEntry) }
func (o AuditOutcome) MarshalText() ([]byte, error)           { return o.AppendText(nil) }
func (o *AuditOutcome) UnmarshalText(t []byte) error          { return euErr(o, t, ErrInvalidAuditEntry) }
func ParseVaultState(s string) (VaultState, error)            { return ep[VaultState](s) }
func (s VaultState) IsValid() bool                            { return eOk(uint8(s), nmVaultState) }
func (s VaultState) IsZero() bool                             { return s == VaultStateInvalid }
func (s VaultState) String() string                           { return eStr(uint8(s), nmVaultState) }
func (s VaultState) AppendText(b []byte) ([]byte, error)      { return ea(b, s) }
func (s VaultState) MarshalText() ([]byte, error)             { return s.AppendText(nil) }
func (s *VaultState) UnmarshalText(t []byte) error            { return eu(s, t) }
func ParseTUNMode(s string) (TUNMode, error)                  { return ep[TUNMode](s) }
func (m TUNMode) IsValid() bool                               { return eOk(uint8(m), nmTUNMode) }
func (m TUNMode) IsZero() bool                                { return m == TUNModeInvalid }
func (m TUNMode) String() string                              { return eStr(uint8(m), nmTUNMode) }
func (m TUNMode) AppendText(b []byte) ([]byte, error)         { return ea(b, m) }
func (m TUNMode) MarshalText() ([]byte, error)                { return m.AppendText(nil) }
func (m *TUNMode) UnmarshalText(t []byte) error               { return eu(m, t) }
func ParsePrivilegeMethod(s string) (PrivilegeMethod, error)  { return ep[PrivilegeMethod](s) }
func (m PrivilegeMethod) IsValid() bool                       { return eOk(uint8(m), nmPrivMethod) }
func (m PrivilegeMethod) IsZero() bool                        { return m == PrivilegeMethodInvalid }
func (m PrivilegeMethod) String() string                      { return eStr(uint8(m), nmPrivMethod) }
func (m PrivilegeMethod) AppendText(b []byte) ([]byte, error) { return ea(b, m) }
func (m PrivilegeMethod) MarshalText() ([]byte, error)        { return m.AppendText(nil) }
func (m *PrivilegeMethod) UnmarshalText(t []byte) error       { return eu(m, t) }

type (
	durWire struct {
		Status   fsm.DurabilityStatus       `json:"status"`
		Revision algebraic.Option[Revision] `json:"revision,omitzero"`
		Detail   string                     `json:"detail,omitzero"`
	}
	proxyRouteWire struct{ route option.ProxyRoute }
	vhostWire      struct {
		Alias      string                             `json:"alias"`
		SourceFile string                             `json:"source_file,omitzero"`
		Endpoint   algebraic.Option[netaddr.Endpoint] `json:"endpoint,omitzero"`
		User       algebraic.Option[option.Username]  `json:"user,omitzero"`
		Proxy      proxyRouteWire                     `json:"proxy,omitzero"`
		Layer      option.OptionLayer                 `json:"layer,omitzero"`
	}
	limWire struct {
		MaxBytes int64 `json:"max_bytes"`
	}
	sshfpWire struct {
		Algorithm       uint8                  `json:"algorithm"`
		FingerprintType uint8                  `json:"fingerprint_type"`
		DigestB64       string                 `json:"digest_b64"`
		Authenticated   algebraic.Option[bool] `json:"authenticated"`
	}
	pubKeyWire struct {
		Algorithm   string                   `json:"algorithm"`
		Fingerprint inventory.KeyFingerprint `json:"fingerprint"`
		WireBlobB64 string                   `json:"wire_blob_b64"`
		Comment     string                   `json:"comment,omitzero"`
	}
	ptyWire struct {
		Term string       `json:"term"`
		Size TerminalSize `json:"size"`
	}
	fwdWire struct {
		Direction  ForwardDirection          `json:"direction"`
		BindAddr   string                    `json:"bind_addr,omitzero"`
		TargetAddr string                    `json:"target_addr,omitzero"`
		TUN        algebraic.Option[TUNSpec] `json:"tun,omitzero"`
	}
	tunWire struct {
		Mode       TUNMode                  `json:"mode"`
		LocalUnit  algebraic.Option[uint32] `json:"local_unit"`
		RemoteUnit algebraic.Option[uint32] `json:"remote_unit"`
	}
	muxRespWire struct {
		Alive     algebraic.Option[bool] `json:"alive"`
		MasterPID uint32                 `json:"master_pid,omitzero"`
		Detail    string                 `json:"detail,omitzero"`
	}
	anchorWire struct {
		FileType  RemoteFileType `json:"file_type"`
		HasDevIno bool           `json:"has_dev_ino,omitzero"`
		Dev       uint64         `json:"dev,omitzero"`
		Ino       uint64         `json:"ino,omitzero"`
	}
	remoteStatWire struct {
		Path    pathalg.RemotePath          `json:"path"`
		Size    algebraic.Option[int64]     `json:"size"`
		Mode    algebraic.Option[uint32]    `json:"mode"`
		ModTime algebraic.Option[time.Time] `json:"mod_time,omitzero"`
		Anchor  RemoteFileAnchor            `json:"anchor"`
	}
	remoteDirWire struct {
		Name     pathalg.RemoteName          `json:"name"`
		FileType RemoteFileType              `json:"file_type"`
		Size     algebraic.Option[int64]     `json:"size"`
		Mode     algebraic.Option[uint32]    `json:"mode"`
		ModTime  algebraic.Option[time.Time] `json:"mod_time,omitzero"`
	}
	remoteWriteWire struct {
		Perm           uint32                             `json:"perm"`
		ExpectedAnchor algebraic.Option[RemoteFileAnchor] `json:"expected_anchor,omitzero"`
		NoClobber      bool                               `json:"no_clobber,omitzero"`
		AtomicRename   bool                               `json:"atomic_rename,omitzero"`
	}
	auditWire struct {
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
	crashRepWire struct {
		ScannedLocks      algebraic.Option[int]  `json:"scanned_locks"`
		LiveLocksSkipped  algebraic.Option[int]  `json:"live_locks_skipped"`
		DeadLocksClaimed  algebraic.Option[int]  `json:"dead_locks_claimed"`
		AbortedOperations []security.OperationID `json:"aborted_operations,omitzero"`
	}
	termSizeWire struct {
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
	}
	approvalRespWire struct {
		Verdict        algebraic.Option[security.Verdict] `json:"verdict"`
		EnvelopeDigest security.Digest                    `json:"envelope_digest"`
		Comment        string                             `json:"comment,omitzero"`
	}
)

func (p proxyRouteWire) IsZero() bool {
	return p.route == nil || option.EqualProxyRoute(p.route, option.NewProxyUnset())
}
func (p proxyRouteWire) MarshalJSONTo(e *jsontext.Encoder) error {
	return option.MarshalProxyRouteTo(e, p.route)
}
func (p *proxyRouteWire) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	r, err := option.UnmarshalProxyRouteFrom(d)
	p.route = pickIf[option.ProxyRoute](err == nil, r, nil)
	return err
}
func decodeDurWire(w durWire) (DurabilityOutcome, error) {
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
		return pickIf(w.Status == fsm.DurabilityNotApplied, NewDurabilityNotApplied, NewDurabilityOutcomeUnknown)(w.Detail)
	case fsm.DurabilityAppliedNotDurable:
		return NewDurabilityAppliedNotDurable(w.Revision, w.Detail)
	default:
		return DurabilityOutcome{}, missingField(ErrInvalidDurability, "status")
	}
}
func decVHost(w vhostWire) (OpenSSHVirtualHost, error) {
	return NewOpenSSHVirtualHost(OpenSSHVirtualHostSpec{w.Alias, w.SourceFile, w.Endpoint, w.User, w.Proxy.route, w.Layer})
}
func decLim(w limWire) (ReadLimits, error) { return NewReadLimits(w.MaxBytes) }
func decPTY(w ptyWire) (PTYRequest, error) { return NewPTYRequest(w.Term, w.Size) }
func decFwd(w fwdWire) (ForwardSpec, error) {
	if w.Direction == ForwardTUN {
		tun, ok := w.TUN.Get()
		if !ok {
			return ForwardSpec{}, missingField(ErrInvalidArgument, "tun")
		}
		spec, err := NewForwardTUNSpec(tun)
		if err != nil {
			return ForwardSpec{}, err
		}
		if (w.BindAddr != "" && w.BindAddr != spec.BindAddr()) || (w.TargetAddr != "" && w.TargetAddr != spec.TargetAddr()) {
			return ForwardSpec{}, fmt.Errorf("%w: ForwardTUN bind_addr/target_addr 与 tun 规格冲突", ErrInvalidArgument)
		}
		return spec, nil
	}
	if w.TUN.IsSome() {
		return ForwardSpec{}, fmt.Errorf("%w: 非 ForwardTUN 方向不得携带 tun 字段", ErrInvalidArgument)
	}
	return NewForwardSpec(w.Direction, w.BindAddr, w.TargetAddr)
}
func decAnc(w anchorWire) (RemoteFileAnchor, error) {
	return NewRemoteFileAnchor(w.FileType, w.HasDevIno, w.Dev, w.Ino)
}
func decWrite(w remoteWriteWire) (RemoteWriteSpec, error) {
	return NewRemoteWriteSpec(RemoteWriteSpecInput{fs.FileMode(w.Perm), w.ExpectedAnchor, w.NoClobber, w.AtomicRename})
}
func decTermSz(w termSizeWire) (TerminalSize, error) { return NewTerminalSize(w.Cols, w.Rows) }
func decSSHFP(w sshfpWire) (SSHFPRecord, error) {
	if w.Authenticated.IsNone() {
		return SSHFPRecord{}, missingField(ErrInvalidArgument, "authenticated")
	}
	dig, err := decodeB64Strict(w.DigestB64)
	if err != nil {
		return SSHFPRecord{}, err
	}
	return NewSSHFPRecord(SSHFPRecordSpec{w.Algorithm, w.FingerprintType, dig, optOrZero(w.Authenticated)})
}
func decPubKey(w pubKeyWire) (PublicKeyInfo, error) {
	blob, err := decodeB64Strict(w.WireBlobB64)
	if err != nil {
		return PublicKeyInfo{}, err
	}
	return NewPublicKeyInfo(PublicKeyInfoSpec{w.Algorithm, w.Fingerprint, blob, w.Comment})
}
func decTUN(w tunWire) (TUNSpec, error) {
	if w.LocalUnit.IsNone() || w.RemoteUnit.IsNone() {
		return TUNSpec{}, missingField(ErrInvalidArgument, "local_unit/remote_unit")
	}
	return NewTUNSpec(w.Mode, optOrZero(w.LocalUnit), optOrZero(w.RemoteUnit))
}
func decMux(w muxRespWire) (MuxControlResponse, error) {
	if w.Alive.IsNone() {
		return MuxControlResponse{}, missingField(ErrInvalidArgument, "alive")
	}
	return NewMuxControlResponse(optOrZero(w.Alive), w.MasterPID, w.Detail)
}
func decStat(w remoteStatWire) (RemoteFileStat, error) {
	if w.Size.IsNone() || w.Mode.IsNone() {
		return RemoteFileStat{}, missingField(ErrInvalidArgument, "size/mode")
	}
	return NewRemoteFileStat(RemoteFileStatSpec{w.Path, optOrZero(w.Size), fs.FileMode(optOrZero(w.Mode)), optOrZero(w.ModTime), w.Anchor})
}
func decDir(w remoteDirWire) (RemoteDirEntry, error) {
	if w.Size.IsNone() || w.Mode.IsNone() {
		return RemoteDirEntry{}, missingField(ErrInvalidArgument, "size/mode")
	}
	return NewRemoteDirEntry(RemoteDirEntrySpec{w.Name, w.FileType, optOrZero(w.Size), fs.FileMode(optOrZero(w.Mode)), optOrZero(w.ModTime)})
}
func decAudit(w auditWire) (AuditEntry, error) {
	if w.Decision.IsNone() {
		return AuditEntry{}, missingField(ErrInvalidAuditEntry, "decision")
	}
	return NewAuditEntry(AuditEntrySpec{w.ProcessID, w.TraceID, w.OperationID, w.Phase, w.Outcome, w.Risk, optOrZero(w.Decision), w.Binding, w.Timestamp, w.Duration, w.ErrorCode, w.Reason})
}
func decCrash(w crashRepWire) (CrashReconcileReport, error) {
	if w.ScannedLocks.IsNone() || w.LiveLocksSkipped.IsNone() || w.DeadLocksClaimed.IsNone() {
		return CrashReconcileReport{}, missingField(ErrInvalidArgument, "崩溃对账计数")
	}
	return NewCrashReconcileReport(CrashReconcileReportSpec{optOrZero(w.ScannedLocks), optOrZero(w.LiveLocksSkipped), optOrZero(w.DeadLocksClaimed), w.AbortedOperations})
}
func decProc(w ProcessSpecInput) (ProcessSpec, error) {
	if w.MaxOutputBytes.IsNone() {
		return ProcessSpec{}, missingField(ErrInvalidArgument, "max_output_bytes")
	}
	return NewProcessSpec(w)
}
func decAppr(w approvalRespWire) (ApprovalDecisionResponse, error) {
	if w.Verdict.IsNone() {
		return ApprovalDecisionResponse{}, missingField(ErrInvalidArgument, "verdict")
	}
	return NewApprovalDecisionResponse(optOrZero(w.Verdict), w.EnvelopeDigest, w.Comment)
}

// MarshalJSONTo 与 UnmarshalJSONFrom 实现全包不可变值对象的严格 json/v2 编解码。
func (d DurabilityOutcome) MarshalJSONTo(e *jsontext.Encoder) error {
	return marshalValidJSON(e, d.IsValid(), ErrInvalidDurability, durWire{d.status, d.revision, d.detail})
}
func (d *DurabilityOutcome) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(d, c, ErrInvalidDurability, decodeDurWire)
}
func (h OpenSSHVirtualHost) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, h.IsValid(), vhostWire{h.alias, h.sourceFile, h.endpoint, h.user, proxyRouteWire{h.proxy}, h.layer})
}
func (h *OpenSSHVirtualHost) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return decArg(h, c, decVHost)
}
func (l ReadLimits) MarshalJSONTo(e *jsontext.Encoder) error {
	return marshalValidJSON(e, l.IsValid(), ErrInvalidReadLimits, limWire{l.maxBytes})
}
func (l *ReadLimits) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(l, c, ErrInvalidReadLimits, decLim)
}
func (s VaultStatus) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, s.IsValid(), VaultStatusSpec{s.state, s.knownStores, s.detail})
}
func (s *VaultStatus) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return decArg(s, c, NewVaultStatus)
}
func (r SSHFPRecord) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, r.IsValid(), sshfpWire{r.algorithm, r.fpType, base64.StdEncoding.EncodeToString(r.digest), algebraic.Some(r.authenticated)})
}
func (r *SSHFPRecord) UnmarshalJSONFrom(c *jsontext.Decoder) error { return decArg(r, c, decSSHFP) }
func (k PublicKeyInfo) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, k.IsValid(), pubKeyWire{k.algorithm, k.fingerprint, base64.StdEncoding.EncodeToString(k.wireBlob), k.comment})
}
func (k *PublicKeyInfo) UnmarshalJSONFrom(c *jsontext.Decoder) error { return decArg(k, c, decPubKey) }
func (c HostTrustCheck) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, c.IsValid(), HostTrustCheckSpec{c.status, c.endpoint, c.presented, c.expectedFingerprints, c.reason})
}
func (c *HostTrustCheck) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return decArg(c, d, NewHostTrustCheck)
}
func (p PTYRequest) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, p.IsValid(), ptyWire{p.term, p.size})
}
func (p *PTYRequest) UnmarshalJSONFrom(c *jsontext.Decoder) error { return decArg(p, c, decPTY) }
func (f ForwardSpec) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, f.IsValid(), fwdWire{f.direction, f.bindAddr, f.targetAddr, f.tun})
}
func (f *ForwardSpec) UnmarshalJSONFrom(c *jsontext.Decoder) error { return decArg(f, c, decFwd) }
func (s TUNSpec) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, s.IsValid(), tunWire{s.mode, algebraic.Some(s.localUnit), algebraic.Some(s.remoteUnit)})
}
func (s *TUNSpec) UnmarshalJSONFrom(c *jsontext.Decoder) error { return decArg(s, c, decTUN) }
func (r PrivilegeRequest) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, r.IsValid(), PrivilegeRequestSpec{r.method, r.command, r.targetUser, r.nonInteractive, r.timeout})
}
func (r *PrivilegeRequest) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return decArg(r, c, NewPrivilegeRequest)
}
func (r ShellProbeResult) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, r.IsValid(), ShellProbeResultSpec{r.dialect, r.profile.Interpreter(), r.osFamily, r.probeStage, r.rawBanner})
}
func (r *ShellProbeResult) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return decArg(r, c, NewShellProbeResult)
}
func (r MuxControlResponse) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, r.IsValid(), muxRespWire{algebraic.Some(r.alive), r.masterPID, r.detail})
}
func (r *MuxControlResponse) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return decArg(r, c, decMux)
}
func (a RemoteFileAnchor) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, a.IsValid(), anchorWire{a.fileType, a.hasDevIno, a.dev, a.ino})
}
func (a *RemoteFileAnchor) UnmarshalJSONFrom(c *jsontext.Decoder) error { return decArg(a, c, decAnc) }
func (s RemoteFileStat) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, s.IsValid(), remoteStatWire{s.path, algebraic.Some(s.size), algebraic.Some(uint32(s.mode)), optModTime(s.modTime), s.anchor})
}
func (s *RemoteFileStat) UnmarshalJSONFrom(c *jsontext.Decoder) error { return decArg(s, c, decStat) }
func (e RemoteDirEntry) MarshalJSONTo(x *jsontext.Encoder) error {
	return encArg(x, e.IsValid(), remoteDirWire{e.name, e.fileType, algebraic.Some(e.size), algebraic.Some(uint32(e.mode)), optModTime(e.modTime)})
}
func (e *RemoteDirEntry) UnmarshalJSONFrom(c *jsontext.Decoder) error { return decArg(e, c, decDir) }
func (s RemoteWriteSpec) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, s.IsValid(), remoteWriteWire{uint32(s.perm), s.expectedAnchor, s.noClobber, s.atomicRename})
}
func (s *RemoteWriteSpec) UnmarshalJSONFrom(c *jsontext.Decoder) error { return decArg(s, c, decWrite) }
func (e AuditEntry) MarshalJSONTo(x *jsontext.Encoder) error {
	return marshalValidJSON(x, e.IsValid(), ErrInvalidAuditEntry, auditWire{e.processID, e.traceID, e.operationID, e.phase, e.outcome, e.risk, algebraic.Some(e.decision), e.binding, e.timestamp.UTC(), e.duration, e.errorCode, e.reason})
}
func (e *AuditEntry) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(e, c, ErrInvalidAuditEntry, decAudit)
}
func (r CrashReconcileReport) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, r.IsValid(), crashRepWire{algebraic.Some(r.scannedLocks), algebraic.Some(r.liveLocksSkipped), algebraic.Some(r.deadLocksClaimed), r.abortedOperations})
}
func (r *CrashReconcileReport) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return decArg(r, c, decCrash)
}
func (i LocalIdentityInfo) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, i.IsValid(), LocalIdentityInfoSpec{i.localHost, i.localUser, i.localUID, i.homeDir})
}
func (i *LocalIdentityInfo) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return decArg(i, c, NewLocalIdentityInfo)
}
func (s TerminalSize) MarshalJSONTo(e *jsontext.Encoder) error {
	return marshalValidJSON(e, s.IsValid(), ErrInvalidTTYSize, termSizeWire{s.cols, s.rows})
}
func (s *TerminalSize) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(s, c, ErrInvalidTTYSize, decTermSz)
}
func (p ProcessSpec) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, p.IsValid(), ProcessSpecInput{p.command, p.args, p.workDir, p.Env(), p.timeout, algebraic.Some(p.maxOutputBytes)})
}
func (p *ProcessSpec) UnmarshalJSONFrom(c *jsontext.Decoder) error { return decArg(p, c, decProc) }
func (r SecretPromptRequest) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, r.IsValid(), SecretPromptRequestSpec{r.core.title, r.core.prompt, r.core.subject, r.core.allowEmpty})
}
func (r *SecretPromptRequest) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return decArg(r, c, NewSecretPromptRequest)
}
func (r ConfirmRequest) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, r.IsValid(), ConfirmRequestSpec{r.core.title, r.core.prompt, r.core.subject, r.risk})
}
func (r *ConfirmRequest) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return decArg(r, c, NewConfirmRequest)
}
func (r TextPromptRequest) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, r.IsValid(), TextPromptRequestSpec{r.core.title, r.core.prompt, r.core.subject, r.core.allowEmpty})
}
func (r *TextPromptRequest) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return decArg(r, c, NewTextPromptRequest)
}
func (r ApprovalDecisionResponse) MarshalJSONTo(e *jsontext.Encoder) error {
	return encArg(e, r.IsValid(), approvalRespWire{algebraic.Some(r.verdict), r.envelopeDigest, r.comment})
}
func (r *ApprovalDecisionResponse) UnmarshalJSONFrom(c *jsontext.Decoder) error {
	return decArg(r, c, decAppr)
}
