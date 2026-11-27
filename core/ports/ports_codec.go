package ports

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"io/fs"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
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
	nmFwdDir     = "invalid,local,remote,dynamic,tun"
	nmFwdEnd     = "invalid,tcp,unix"
	nmMuxAct     = "invalid,check,forward,cancel,exit,stop,proxy"
	nmRemType    = "invalid,regular,dir,symlink,other"
	nmAudPhase   = "invalid,denied,authorized,finalized"
	nmAudOut     = "invalid,pending,denied,succeeded,failed,canceled,escalated,aborted_by_crash,outcome_unknown"
	nmVaultState = "invalid,uninitialized,locked,unlocked"
	nmTUNMode    = "invalid,point_to_point,ethernet"
	nmPrivMethod = "invalid,sudo,su,doas"
)

type (
	jEnc     = *jsontext.Encoder
	jDec     = *jsontext.Decoder
	portEnum interface {
		~uint8
		IsValid() bool
		String() string
	}
)

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
	return 0, domi18n.EF(err, domi18n.KeyCommonValueInvalid, domi18n.BoundStr("value", raw))
}
func eaErr[T portEnum](b []byte, v T, err error) ([]byte, error) {
	return appendValidText(b, v.IsValid(), v.String(), err)
}
func euErr[T portEnum](dst *T, t []byte, err error) error {
	return unmarshalTextWithReset(dst, 0, t, func(s string) (T, error) { return epErr[T](s, err) })
}
func ep[T portEnum](s string) (T, error)           { return epErr[T](s, ErrInvalidArgument) }
func epA[T portEnum](s string) (T, error)          { return epErr[T](s, ErrInvalidAuditEntry) }
func ea[T portEnum](b []byte, v T) ([]byte, error) { return eaErr(b, v, ErrInvalidArgument) }
func eu[T portEnum](dst *T, t []byte) error        { return euErr(dst, t, ErrInvalidArgument) }
func missingField(e error, f string) error {
	return domi18n.EF(e, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", f))
}
func un[T any](o algebraic.Option[T]) T { return o.OrElse(zeroVal[T]()) }
func optModTime(t time.Time) algebraic.Option[time.Time] {
	return pickIf(t.IsZero(), algebraic.None[time.Time](), algebraic.Some(t.UTC()))
}
func enc[W any](e jEnc, ok bool, w W) error { return marshalValidJSON(e, ok, ErrInvalidArgument, w) }
func dec[T, W any](d *T, c jDec, fn func(W) (T, error)) error {
	return unmarshalJSONWithNullReject(d, c, ErrInvalidArgument, fn)
}
func encE[W any](e jEnc, ok bool, err error, w W) error { return marshalValidJSON(e, ok, err, w) }
func decE[T, W any](d *T, c jDec, err error, fn func(W) (T, error)) error {
	return unmarshalJSONWithNullReject(d, c, err, fn)
}
func decodeB64Strict(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, domi18n.WrapS(ErrInvalidArgument, err, domi18n.KeyCommonBase64DecodeFailed)
	}
	return b, nil
}

// 全部 11 个失败关闭端口枚举的 Parse / IsValid / IsZero / String 与 TextCodec 统一实现。
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
func ParseForwardEndpointKind(s string) (ForwardEndpointKind, error) {
	return ep[ForwardEndpointKind](s)
}
func (k ForwardEndpointKind) IsValid() bool                       { return eOk(uint8(k), nmFwdEnd) }
func (k ForwardEndpointKind) IsZero() bool                        { return k == ForwardEndpointInvalid }
func (k ForwardEndpointKind) String() string                      { return eStr(uint8(k), nmFwdEnd) }
func (k ForwardEndpointKind) AppendText(b []byte) ([]byte, error) { return ea(b, k) }
func (k ForwardEndpointKind) MarshalText() ([]byte, error)        { return k.AppendText(nil) }
func (k *ForwardEndpointKind) UnmarshalText(t []byte) error       { return eu(k, t) }
func ParseMuxControlAction(s string) (MuxControlAction, error)    { return ep[MuxControlAction](s) }
func (a MuxControlAction) IsValid() bool                          { return eOk(uint8(a), nmMuxAct) }
func (a MuxControlAction) IsZero() bool                           { return a == MuxActionInvalid }
func (a MuxControlAction) String() string                         { return eStr(uint8(a), nmMuxAct) }
func (a MuxControlAction) AppendText(b []byte) ([]byte, error)    { return ea(b, a) }
func (a MuxControlAction) MarshalText() ([]byte, error)           { return a.AppendText(nil) }
func (a *MuxControlAction) UnmarshalText(t []byte) error          { return eu(a, t) }
func ParseRemoteFileType(s string) (RemoteFileType, error)        { return ep[RemoteFileType](s) }
func (t RemoteFileType) IsValid() bool                            { return eOk(uint8(t), nmRemType) }
func (t RemoteFileType) IsZero() bool                             { return t == RemoteFileTypeInvalid }
func (t RemoteFileType) String() string                           { return eStr(uint8(t), nmRemType) }
func (t RemoteFileType) AppendText(b []byte) ([]byte, error)      { return ea(b, t) }
func (t RemoteFileType) MarshalText() ([]byte, error)             { return t.AppendText(nil) }
func (t *RemoteFileType) UnmarshalText(b []byte) error            { return eu(t, b) }
func ParseAuditPhase(s string) (AuditPhase, error)                { return epA[AuditPhase](s) }
func (p AuditPhase) IsValid() bool                                { return eOk(uint8(p), nmAudPhase) }
func (p AuditPhase) IsZero() bool                                 { return p == AuditPhaseInvalid }
func (p AuditPhase) String() string                               { return eStr(uint8(p), nmAudPhase) }
func (p AuditPhase) AppendText(b []byte) ([]byte, error)          { return eaErr(b, p, ErrInvalidAuditEntry) }
func (p AuditPhase) MarshalText() ([]byte, error)                 { return p.AppendText(nil) }
func (p *AuditPhase) UnmarshalText(t []byte) error                { return euErr(p, t, ErrInvalidAuditEntry) }
func ParseAuditOutcome(s string) (AuditOutcome, error)            { return epA[AuditOutcome](s) }
func (o AuditOutcome) IsValid() bool                              { return eOk(uint8(o), nmAudOut) }
func (o AuditOutcome) IsZero() bool                               { return o == AuditOutcomeInvalid }
func (o AuditOutcome) String() string                             { return eStr(uint8(o), nmAudOut) }
func (o AuditOutcome) AppendText(b []byte) ([]byte, error)        { return eaErr(b, o, ErrInvalidAuditEntry) }
func (o AuditOutcome) MarshalText() ([]byte, error)               { return o.AppendText(nil) }
func (o *AuditOutcome) UnmarshalText(t []byte) error              { return euErr(o, t, ErrInvalidAuditEntry) }
func ParseVaultState(s string) (VaultState, error)                { return ep[VaultState](s) }
func (s VaultState) IsValid() bool                                { return eOk(uint8(s), nmVaultState) }
func (s VaultState) IsZero() bool                                 { return s == VaultStateInvalid }
func (s VaultState) String() string                               { return eStr(uint8(s), nmVaultState) }
func (s VaultState) AppendText(b []byte) ([]byte, error)          { return ea(b, s) }
func (s VaultState) MarshalText() ([]byte, error)                 { return s.AppendText(nil) }
func (s *VaultState) UnmarshalText(t []byte) error                { return eu(s, t) }
func ParseTUNMode(s string) (TUNMode, error)                      { return ep[TUNMode](s) }
func (m TUNMode) IsValid() bool                                   { return eOk(uint8(m), nmTUNMode) }
func (m TUNMode) IsZero() bool                                    { return m == TUNModeInvalid }
func (m TUNMode) String() string                                  { return eStr(uint8(m), nmTUNMode) }
func (m TUNMode) AppendText(b []byte) ([]byte, error)             { return ea(b, m) }
func (m TUNMode) MarshalText() ([]byte, error)                    { return m.AppendText(nil) }
func (m *TUNMode) UnmarshalText(t []byte) error                   { return eu(m, t) }
func ParsePrivilegeMethod(s string) (PrivilegeMethod, error)      { return ep[PrivilegeMethod](s) }
func (m PrivilegeMethod) IsValid() bool                           { return eOk(uint8(m), nmPrivMethod) }
func (m PrivilegeMethod) IsZero() bool                            { return m == PrivilegeMethodInvalid }
func (m PrivilegeMethod) String() string                          { return eStr(uint8(m), nmPrivMethod) }
func (m PrivilegeMethod) AppendText(b []byte) ([]byte, error)     { return ea(b, m) }
func (m PrivilegeMethod) MarshalText() ([]byte, error)            { return m.AppendText(nil) }
func (m *PrivilegeMethod) UnmarshalText(t []byte) error           { return eu(m, t) }

type (
	durWire struct {
		Status   fsm.DurabilityStatus       `json:"status"`
		Revision algebraic.Option[Revision] `json:"revision,omitzero"`
		Detail   string                     `json:"detail,omitzero"`
	}
	proxyRouteWire struct{ r option.ProxyRoute }
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
		BindKind   ForwardEndpointKind       `json:"bind_kind,omitzero"`
		BindAddr   string                    `json:"bind_addr,omitzero"`
		TargetKind ForwardEndpointKind       `json:"target_kind,omitzero"`
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
	remoteRenameWire struct {
		ExpectedAnchor algebraic.Option[RemoteFileAnchor] `json:"expected_anchor,omitzero"`
		NoClobber      algebraic.Option[bool]             `json:"no_clobber"`
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
	return p.r == nil || option.EqualProxyRoute(p.r, option.NewProxyUnset())
}
func (p proxyRouteWire) MarshalJSONTo(e jEnc) error { return option.MarshalProxyRouteTo(e, p.r) }
func (p *proxyRouteWire) UnmarshalJSONFrom(d jDec) error {
	r, err := option.UnmarshalProxyRouteFrom(d)
	p.r = pickIf[option.ProxyRoute](err == nil, r, nil)
	return err
}
func decodeDurWire(w durWire) (DurabilityOutcome, error) {
	switch w.Status {
	case fsm.DurabilityCommitted:
		if rev, okR := w.Revision.Get(); okR && w.Detail == "" {
			return NewDurabilityCommitted(rev)
		}
		return DurabilityOutcome{}, domi18n.EF(ErrInvalidDurability, domi18n.KeyPortsDurabilitySpec, domi18n.Str("status", w.Status.String()))
	case fsm.DurabilityNotApplied, fsm.DurabilityOutcomeUnknown:
		if w.Revision.IsSome() {
			return DurabilityOutcome{}, domi18n.EF(ErrInvalidDurability, domi18n.KeyPortsDurabilitySpec, domi18n.Str("status", w.Status.String()))
		}
		return pickIf(w.Status == fsm.DurabilityNotApplied, NewDurabilityNotApplied, NewDurabilityOutcomeUnknown)(w.Detail)
	case fsm.DurabilityAppliedNotDurable:
		return NewDurabilityAppliedNotDurable(w.Revision, w.Detail)
	default:
		return DurabilityOutcome{}, missingField(ErrInvalidDurability, "status")
	}
}
func decFwd(w fwdWire) (ForwardSpec, error) {
	if w.Direction != ForwardTUN {
		return need(!w.TUN.IsSome(), ErrInvalidArgument, "direction", func() (ForwardSpec, error) {
			return NewTypedForwardSpec(w.Direction, w.BindKind, w.BindAddr, w.TargetKind, w.TargetAddr)
		})
	}
	tun, ok := w.TUN.Get()
	if !ok || w.BindKind != ForwardEndpointInvalid || w.TargetKind != ForwardEndpointInvalid {
		return ForwardSpec{}, domi18n.EF(ErrInvalidArgument, domi18n.KeyCommonJSONVariantInvalid, domi18n.Str("variant", "tun"))
	}
	spec, err := NewForwardTUNSpec(tun)
	if err == nil && ((w.BindAddr != "" && w.BindAddr != spec.BindAddr()) || (w.TargetAddr != "" && w.TargetAddr != spec.TargetAddr())) {
		return ForwardSpec{}, domi18n.EF(ErrInvalidArgument, domi18n.KeyPortsTUNSpecConflict)
	}
	return spec, err
}
func need[T any](ok bool, err error, field string, fn func() (T, error)) (T, error) {
	if !ok {
		return zeroVal[T](), missingField(err, field)
	}
	return fn()
}
func decSSHFP(w sshfpWire) (SSHFPRecord, error) {
	if !w.Authenticated.IsSome() {
		return SSHFPRecord{}, missingField(ErrInvalidArgument, "authenticated")
	}
	dig, err := decodeB64Strict(w.DigestB64)
	if err != nil {
		return SSHFPRecord{}, err
	}
	return NewSSHFPRecord(SSHFPRecordSpec{w.Algorithm, w.FingerprintType, dig, un(w.Authenticated)})
}
func decPubKey(w pubKeyWire) (PublicKeyInfo, error) {
	blob, err := decodeB64Strict(w.WireBlobB64)
	if err != nil {
		return PublicKeyInfo{}, err
	}
	return NewPublicKeyInfo(PublicKeyInfoSpec{w.Algorithm, w.Fingerprint, blob, w.Comment})
}
func decReq[T, W any](d *T, c jDec, err error, field string, ok func(W) bool, fn func(W) (T, error)) error {
	return decE(d, c, err, func(w W) (T, error) { return need(ok(w), err, field, func() (T, error) { return fn(w) }) })
}
func sOpt[T any](v T) algebraic.Option[T] { return algebraic.Some(v) }

// MarshalJSONTo 与 UnmarshalJSONFrom 实现全包不可变值对象的严格 json/v2 编解码。
func (d DurabilityOutcome) MarshalJSONTo(e jEnc) error {
	return encE(e, d.IsValid(), ErrInvalidDurability, durWire{d.status, d.revision, d.detail})
}
func (d *DurabilityOutcome) UnmarshalJSONFrom(c jDec) error {
	return decE(d, c, ErrInvalidDurability, decodeDurWire)
}
func (h OpenSSHVirtualHost) MarshalJSONTo(e jEnc) error {
	return enc(e, h.IsValid(), vhostWire{h.s.Alias, h.s.SourceFile, h.s.Endpoint, h.s.User, proxyRouteWire{h.s.Proxy}, h.s.Layer})
}
func (h *OpenSSHVirtualHost) UnmarshalJSONFrom(c jDec) error {
	return dec(h, c, func(w vhostWire) (OpenSSHVirtualHost, error) {
		return NewOpenSSHVirtualHost(OpenSSHVirtualHostSpec{w.Alias, w.SourceFile, w.Endpoint, w.User, w.Proxy.r, w.Layer})
	})
}
func (l ReadLimits) MarshalJSONTo(e jEnc) error {
	return encE(e, l.IsValid(), ErrInvalidReadLimits, limWire{l.maxBytes})
}
func (l *ReadLimits) UnmarshalJSONFrom(c jDec) error {
	return decE(l, c, ErrInvalidReadLimits, func(w limWire) (ReadLimits, error) { return NewReadLimits(w.MaxBytes) })
}
func (s VaultStatus) MarshalJSONTo(e jEnc) error      { return enc(e, s.IsValid(), s.s) }
func (s *VaultStatus) UnmarshalJSONFrom(c jDec) error { return dec(s, c, NewVaultStatus) }
func (r SSHFPRecord) MarshalJSONTo(e jEnc) error {
	return enc(e, r.IsValid(), sshfpWire{r.s.Algorithm, r.s.FingerprintType, base64.StdEncoding.EncodeToString(r.s.Digest), sOpt(r.s.Authenticated)})
}
func (r *SSHFPRecord) UnmarshalJSONFrom(c jDec) error { return dec(r, c, decSSHFP) }
func (k PublicKeyInfo) MarshalJSONTo(e jEnc) error {
	return enc(e, k.IsValid(), pubKeyWire{k.s.Algorithm, k.s.Fingerprint, base64.StdEncoding.EncodeToString(k.s.WireBlob), k.s.Comment})
}
func (k *PublicKeyInfo) UnmarshalJSONFrom(c jDec) error  { return dec(k, c, decPubKey) }
func (c HostTrustCheck) MarshalJSONTo(e jEnc) error      { return enc(e, c.IsValid(), c.s) }
func (c *HostTrustCheck) UnmarshalJSONFrom(d jDec) error { return dec(c, d, NewHostTrustCheck) }
func (p PTYRequest) MarshalJSONTo(e jEnc) error          { return enc(e, p.IsValid(), ptyWire{p.term, p.size}) }
func (p *PTYRequest) UnmarshalJSONFrom(c jDec) error {
	return dec(p, c, func(w ptyWire) (PTYRequest, error) { return NewPTYRequest(w.Term, w.Size) })
}
func (f ForwardSpec) MarshalJSONTo(e jEnc) error {
	return enc(e, f.IsValid(), fwdWire{f.direction, f.bindKind, f.bindAddr, f.targetKind, f.targetAddr, f.tun})
}
func (f *ForwardSpec) UnmarshalJSONFrom(c jDec) error { return dec(f, c, decFwd) }
func (s TUNSpec) MarshalJSONTo(e jEnc) error {
	return enc(e, s.IsValid(), tunWire{s.mode, sOpt(s.localUnit), sOpt(s.remoteUnit)})
}
func (s *TUNSpec) UnmarshalJSONFrom(c jDec) error {
	return decReq(s, c, ErrInvalidArgument, "local_unit/remote_unit", func(w tunWire) bool { return w.LocalUnit.IsSome() && w.RemoteUnit.IsSome() }, func(w tunWire) (TUNSpec, error) { return NewTUNSpec(w.Mode, un(w.LocalUnit), un(w.RemoteUnit)) })
}
func (r PrivilegeRequest) MarshalJSONTo(e jEnc) error      { return enc(e, r.IsValid(), r.s) }
func (r *PrivilegeRequest) UnmarshalJSONFrom(c jDec) error { return dec(r, c, NewPrivilegeRequest) }
func (r ShellProbeResult) MarshalJSONTo(e jEnc) error      { return enc(e, r.IsValid(), r.s) }
func (r *ShellProbeResult) UnmarshalJSONFrom(c jDec) error { return dec(r, c, NewShellProbeResult) }
func (r MuxControlResponse) MarshalJSONTo(e jEnc) error {
	return enc(e, r.IsValid(), muxRespWire{sOpt(r.alive), r.masterPID, r.detail})
}
func (r *MuxControlResponse) UnmarshalJSONFrom(c jDec) error {
	return decReq(r, c, ErrInvalidArgument, "alive", func(w muxRespWire) bool { return w.Alive.IsSome() }, func(w muxRespWire) (MuxControlResponse, error) {
		return NewMuxControlResponse(un(w.Alive), w.MasterPID, w.Detail)
	})
}
func (a RemoteFileAnchor) MarshalJSONTo(e jEnc) error {
	return enc(e, a.IsValid(), anchorWire{a.fileType, a.hasDevIno, a.dev, a.ino})
}
func (a *RemoteFileAnchor) UnmarshalJSONFrom(c jDec) error {
	return dec(a, c, func(w anchorWire) (RemoteFileAnchor, error) {
		return NewRemoteFileAnchor(w.FileType, w.HasDevIno, w.Dev, w.Ino)
	})
}
func (s RemoteFileStat) MarshalJSONTo(e jEnc) error {
	return enc(e, s.IsValid(), remoteStatWire{s.s.Path, sOpt(s.s.Size), sOpt(uint32(s.s.Mode)), optModTime(s.s.ModTime), s.s.Anchor})
}
func (s *RemoteFileStat) UnmarshalJSONFrom(c jDec) error {
	return decReq(s, c, ErrInvalidArgument, "size/mode", func(w remoteStatWire) bool { return w.Size.IsSome() && w.Mode.IsSome() }, func(w remoteStatWire) (RemoteFileStat, error) {
		return NewRemoteFileStat(RemoteFileStatSpec{w.Path, un(w.Size), fs.FileMode(un(w.Mode)), un(w.ModTime), w.Anchor})
	})
}
func (e RemoteDirEntry) MarshalJSONTo(x jEnc) error {
	return enc(x, e.IsValid(), remoteDirWire{e.s.Name, e.s.FileType, sOpt(e.s.Size), sOpt(uint32(e.s.Mode)), optModTime(e.s.ModTime)})
}
func (e *RemoteDirEntry) UnmarshalJSONFrom(c jDec) error {
	return decReq(e, c, ErrInvalidArgument, "size/mode", func(w remoteDirWire) bool { return w.Size.IsSome() && w.Mode.IsSome() }, func(w remoteDirWire) (RemoteDirEntry, error) {
		return NewRemoteDirEntry(RemoteDirEntrySpec{w.Name, w.FileType, un(w.Size), fs.FileMode(un(w.Mode)), un(w.ModTime)})
	})
}
func (s RemoteWriteSpec) MarshalJSONTo(e jEnc) error      { return enc(e, s.IsValid(), s.in) }
func (s *RemoteWriteSpec) UnmarshalJSONFrom(c jDec) error { return dec(s, c, NewRemoteWriteSpec) }
func (s RemoteRenameSpec) MarshalJSONTo(e jEnc) error {
	return enc(e, s.IsValid(), remoteRenameWire{s.in.ExpectedAnchor, sOpt(s.in.NoClobber)})
}
func (r *RemoteRenameSpec) UnmarshalJSONFrom(c jDec) error {
	return decReq(r, c, ErrInvalidArgument, "no_clobber", func(w remoteRenameWire) bool { return w.NoClobber.IsSome() }, func(w remoteRenameWire) (RemoteRenameSpec, error) {
		return NewRemoteRenameSpec(RemoteRenameSpecInput{w.ExpectedAnchor, un(w.NoClobber)})
	})
}
func (e AuditEntry) MarshalJSONTo(x jEnc) error {
	return encE(x, e.IsValid(), ErrInvalidAuditEntry, auditWire{e.s.ProcessID, e.s.TraceID, e.s.OperationID, e.s.Phase, e.s.Outcome, e.s.Risk, sOpt(e.s.Decision), e.s.Binding, e.s.Timestamp.UTC(), e.s.Duration, e.s.ErrorCode, e.s.Reason})
}
func (e *AuditEntry) UnmarshalJSONFrom(c jDec) error {
	return decReq(e, c, ErrInvalidAuditEntry, "decision", func(w auditWire) bool { return w.Decision.IsSome() }, func(w auditWire) (AuditEntry, error) {
		return NewAuditEntry(AuditEntrySpec{w.ProcessID, w.TraceID, w.OperationID, w.Phase, w.Outcome, w.Risk, un(w.Decision), w.Binding, w.Timestamp, w.Duration, w.ErrorCode, w.Reason})
	})
}
func (r CrashReconcileReport) MarshalJSONTo(e jEnc) error {
	return enc(e, r.IsValid(), crashRepWire{sOpt(r.s.ScannedLocks), sOpt(r.s.LiveLocksSkipped), sOpt(r.s.DeadLocksClaimed), r.s.AbortedOperations})
}
func (r *CrashReconcileReport) UnmarshalJSONFrom(c jDec) error {
	return decReq(r, c, ErrInvalidArgument, "scanned_locks/live_locks_skipped/dead_locks_claimed", func(w crashRepWire) bool {
		return w.ScannedLocks.IsSome() && w.LiveLocksSkipped.IsSome() && w.DeadLocksClaimed.IsSome()
	}, func(w crashRepWire) (CrashReconcileReport, error) {
		return NewCrashReconcileReport(CrashReconcileReportSpec{un(w.ScannedLocks), un(w.LiveLocksSkipped), un(w.DeadLocksClaimed), w.AbortedOperations})
	})
}
func (i LocalIdentityInfo) MarshalJSONTo(e jEnc) error      { return enc(e, i.IsValid(), i.s) }
func (i *LocalIdentityInfo) UnmarshalJSONFrom(c jDec) error { return dec(i, c, NewLocalIdentityInfo) }
func (s TerminalSize) MarshalJSONTo(e jEnc) error {
	return encE(e, s.IsValid(), ErrInvalidTTYSize, termSizeWire{s.cols, s.rows})
}
func (s *TerminalSize) UnmarshalJSONFrom(c jDec) error {
	return decE(s, c, ErrInvalidTTYSize, func(w termSizeWire) (TerminalSize, error) { return NewTerminalSize(w.Cols, w.Rows) })
}
func (p ProcessSpec) MarshalJSONTo(e jEnc) error {
	return enc(e, p.IsValid(), ProcessSpecInput{p.command, p.args, p.workDir, p.Env(), p.timeout, sOpt(p.maxOutputBytes)})
}
func (p *ProcessSpec) UnmarshalJSONFrom(c jDec) error {
	return decReq(p, c, ErrInvalidArgument, "max_output_bytes", func(w ProcessSpecInput) bool { return w.MaxOutputBytes.IsSome() }, NewProcessSpec)
}
func (r SecretPromptRequest) MarshalJSONTo(e jEnc) error {
	return enc(e, r.IsValid(), SecretPromptRequestSpec{Title: r.core.title, Prompt: r.core.prompt, Subject: r.core.subject, AllowEmpty: r.core.allowEmpty, TitleMessage: r.core.titleMsg, BodyMessage: r.core.bodyMsg})
}
func (r *SecretPromptRequest) UnmarshalJSONFrom(c jDec) error {
	return dec(r, c, NewSecretPromptRequest)
}
func (r ConfirmRequest) MarshalJSONTo(e jEnc) error {
	return enc(e, r.IsValid(), ConfirmRequestSpec{Title: r.core.title, Message: r.core.prompt, Subject: r.core.subject, Risk: r.risk, TitleMessage: r.core.titleMsg, BodyMessage: r.core.bodyMsg})
}
func (r *ConfirmRequest) UnmarshalJSONFrom(c jDec) error { return dec(r, c, NewConfirmRequest) }
func (r TextPromptRequest) MarshalJSONTo(e jEnc) error {
	return enc(e, r.IsValid(), TextPromptRequestSpec{Title: r.core.title, Prompt: r.core.prompt, Subject: r.core.subject, AllowEmpty: r.core.allowEmpty, TitleMessage: r.core.titleMsg, BodyMessage: r.core.bodyMsg})
}
func (r *TextPromptRequest) UnmarshalJSONFrom(c jDec) error { return dec(r, c, NewTextPromptRequest) }
func (r ApprovalDecisionResponse) MarshalJSONTo(e jEnc) error {
	return enc(e, r.IsValid(), approvalRespWire{sOpt(r.verdict), r.envelopeDigest, r.comment})
}
func (r *ApprovalDecisionResponse) UnmarshalJSONFrom(c jDec) error {
	return decReq(r, c, ErrInvalidArgument, "verdict", func(w approvalRespWire) bool { return w.Verdict.IsSome() }, func(w approvalRespWire) (ApprovalDecisionResponse, error) {
		return NewApprovalDecisionResponse(un(w.Verdict), w.EnvelopeDigest, w.Comment)
	})
}
