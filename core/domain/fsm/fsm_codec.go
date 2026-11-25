package fsm

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// 全包 20 个失败关闭状态机枚举的单一事实源名称表（索引 0 为零值名称，1..N 为合法规范小写名称），
// 统一驱动 IsValid、String 与 Parse*/TextCodec，杜绝有效范围与文本映射漂移。
const (
	nmDur  = "unknown,not_applied,committed,applied_not_durable,outcome_unknown"
	nmOut  = "invalid,succeeded,failed_not_applied,outcome_unknown"
	nmVSt  = "invalid,init,writing_new,verifying_readback,committing_config,checking_old_refs,deleting_old,compensating,completed,rolled_back,uncertain_durability,failed_uncertain"
	nmVEff = "invalid,write_new,verify_readback,commit_config_cas,check_old_refs,delete_old,compensate_delete_new"
	nmVEv  = "invalid,started,new_secret_written,readback_verified,readback_failed,config_committed,config_rejected,old_refs_zero,old_secret_gc_deferred,old_secret_deleted,compensated,completed,rolled_back,uncertain_durability,halted_uncertain"
	nmAPh  = "invalid,lexical_precheck,canonicalizing,evaluating_escalation,challenge_pending,challenge_issued,approved,token_invalidated,denied"
	nmAEff = "invalid,canonicalize,request_challenge,present_challenge,invalidate_token"
	nmAEv  = "invalid,canonicalize_requested,canonicalized,escalation_detected,challenge_requested,challenge_issued,approved,denied,token_invalidated"
	nmTDir = "invalid,upload,download"
	nmJVer = "invalid,v1,v2"
	nmJRec = "invalid,init,chunk,verified,commit_started,committed,aborted"
	nmTSt  = "invalid,initialized,streaming,verifying,committing,committed,aborted,uncertain_commit"
	nmTEff = "invalid,write_journal,verify_full_digest,atomic_commit,cleanup_staging"
	nmTEv  = "invalid,started,chunk_accepted,stream_completed,digest_verified,commit_started,committed,aborted,uncertain_commit,recovered"
	nmEPh  = "unknown,pending,checking,applying,post_checking,converged_unchanged,converged_changed,failed,uncertain_outcome"
	nmEEff = "invalid,run_check,run_apply,run_post_check"
	nmEEv  = "invalid,check_started,retrying_not_started,apply_started,post_check_started,converged_unchanged,converged_changed,failed,uncertain_outcome"
	nmPPh  = "invalid,idle,staged,probing,verified,committing,cleaning_up,enrolled,aborted,uncertain"
	nmPEff = "invalid,pin_secrets,probe_connection,commit_inventory_cas,cleanup_pending_secrets,release_pins"
	nmPEv  = "invalid,staged,probe_started,verified,probe_failed,commit_started,enrolled,commit_rejected,expired,cancelled,cleaning_up,aborted,uncertain"
)

type fsmEnum interface {
	~uint8
	IsValid() bool
	String() string
}

func eOk(idx uint8, csv string) bool { return idx >= 1 && int(idx) <= strings.Count(csv, ",") }
func eStr(idx uint8, csv string) string {
	parts := strings.Split(csv, ",")
	if int(idx) < len(parts) {
		return parts[idx]
	}
	return parts[0]
}
func eParse[T fsmEnum](raw string, _ T, baseErr error) (T, error) {
	if !hasForbiddenStrictText(raw) {
		norm := strings.ToLower(strings.TrimSpace(raw))
		for v := T(1); v < 255 && v.IsValid(); v++ {
			if v.String() == norm {
				return v, nil
			}
		}
	}
	return 0, fmt.Errorf("%w: %q", baseErr, raw)
}
func eAppend[T fsmEnum](b []byte, v T, baseErr error) ([]byte, error) {
	if !v.IsValid() {
		return nil, baseErr
	}
	return append(b, v.String()...), nil
}
func eUnm[T fsmEnum](dst *T, text []byte, baseErr error) error {
	if dst == nil {
		return ErrNilReceiver
	}
	parsed, err := eParse(string(text), *dst, baseErr)
	*dst = parsed
	return err
}

func pSt[T fsmEnum](s string, v T) (T, error)           { return eParse(s, v, ErrInvalidState) }
func aSt[T fsmEnum](b []byte, v T) ([]byte, error)      { return eAppend(b, v, ErrInvalidState) }
func uSt[T fsmEnum](d *T, t []byte) error               { return eUnm(d, t, ErrInvalidState) }
func pIn[T fsmEnum](s string, v T) (T, error)           { return eParse(s, v, ErrInvalidInput) }
func aIn[T fsmEnum](b []byte, v T) ([]byte, error)      { return eAppend(b, v, ErrInvalidInput) }
func uIn[T fsmEnum](d *T, t []byte) error               { return eUnm(d, t, ErrInvalidInput) }
func pJr[T fsmEnum](s string, v T) (T, error)           { return eParse(s, v, ErrInvalidJournal) }
func aJr[T fsmEnum](b []byte, v T) ([]byte, error)      { return eAppend(b, v, ErrInvalidJournal) }
func uJr[T fsmEnum](d *T, t []byte) error               { return eUnm(d, t, ErrInvalidJournal) }
func pDu(s string) (v DurabilityStatus, e error)        { return eParse(s, v, ErrInvalidDurability) }
func aDu(b []byte, v DurabilityStatus) ([]byte, error)  { return eAppend(b, v, ErrInvalidDurability) }
func pSo(s string) (v SideEffectOutcome, e error)       { return eParse(s, v, ErrInvalidOutcome) }
func aSo(b []byte, v SideEffectOutcome) ([]byte, error) { return eAppend(b, v, ErrInvalidOutcome) }
func pDr(s string) (v TransferDirection, e error)       { return eParse(s, v, ErrInvalidContext) }
func aDr(b []byte, v TransferDirection) ([]byte, error) { return eAppend(b, v, ErrInvalidContext) }
func unmJSON[T, W any](dst *T, dec *jsontext.Decoder, baseErr error, build func(W) (T, error)) error {
	if dst == nil || dec == nil {
		return ErrNilReceiver
	}
	*dst = zeroVal[T]()
	if dec.PeekKind() == 'n' {
		_, err := dec.ReadToken()
		return pickIf(err != nil, err, fmt.Errorf("%w: JSON null 不是有效值", baseErr))
	}
	var wire W
	if err := jsonv2.UnmarshalDecode(dec, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	parsed, err := build(wire)
	if err == nil {
		*dst = parsed
	}
	return err
}
func mJSON[W any](enc *jsontext.Encoder, valid bool, badErr error, wire W) error {
	if !valid {
		return badErr
	}
	return jsonv2.MarshalEncode(enc, wire)
}
func decKind[K interface{ IsValid() bool }](opt algebraic.Option[K], detail string) (K, error) {
	k, ok := opt.Get()
	if !ok || !k.IsValid() || len(detail) > maxReasonBytes || hasForbiddenStrictText(detail) {
		return k, fmt.Errorf("%w: 事件 kind 或 detail 非法", ErrInvalidInput)
	}
	return k, nil
}

// 全包 20 个失败关闭枚举的 IsValid/String/Parse/TextCodec 统一实现（uint8 枚举原生零值即 0）。
func (d DurabilityStatus) IsValid() bool                                         { return eOk(uint8(d), nmDur) }
func (d DurabilityStatus) String() string                                        { return eStr(uint8(d), nmDur) }
func ParseDurabilityStatus(s string) (DurabilityStatus, error)                   { return pDu(s) }
func (d DurabilityStatus) AppendText(b []byte) ([]byte, error)                   { return aDu(b, d) }
func (d DurabilityStatus) MarshalText() ([]byte, error)                          { return d.AppendText(nil) }
func (d *DurabilityStatus) UnmarshalText(t []byte) error                         { return eUnm(d, t, ErrInvalidDurability) }
func (o SideEffectOutcome) IsValid() bool                                        { return eOk(uint8(o), nmOut) }
func (o SideEffectOutcome) String() string                                       { return eStr(uint8(o), nmOut) }
func ParseSideEffectOutcome(s string) (SideEffectOutcome, error)                 { return pSo(s) }
func (o SideEffectOutcome) AppendText(b []byte) ([]byte, error)                  { return aSo(b, o) }
func (o SideEffectOutcome) MarshalText() ([]byte, error)                         { return o.AppendText(nil) }
func (o *SideEffectOutcome) UnmarshalText(t []byte) error                        { return eUnm(o, t, ErrInvalidOutcome) }
func (k VaultSagaStateKind) IsValid() bool                                       { return eOk(uint8(k), nmVSt) }
func (k VaultSagaStateKind) String() string                                      { return eStr(uint8(k), nmVSt) }
func ParseVaultSagaStateKind(s string) (v VaultSagaStateKind, e error)           { return pSt(s, v) }
func (k VaultSagaStateKind) AppendText(b []byte) ([]byte, error)                 { return aSt(b, k) }
func (k VaultSagaStateKind) MarshalText() ([]byte, error)                        { return k.AppendText(nil) }
func (k *VaultSagaStateKind) UnmarshalText(t []byte) error                       { return uSt(k, t) }
func (k VaultSagaEffectKind) IsValid() bool                                      { return eOk(uint8(k), nmVEff) }
func (k VaultSagaEffectKind) String() string                                     { return eStr(uint8(k), nmVEff) }
func ParseVaultSagaEffectKind(s string) (v VaultSagaEffectKind, e error)         { return pIn(s, v) }
func (k VaultSagaEffectKind) AppendText(b []byte) ([]byte, error)                { return aIn(b, k) }
func (k VaultSagaEffectKind) MarshalText() ([]byte, error)                       { return k.AppendText(nil) }
func (k *VaultSagaEffectKind) UnmarshalText(t []byte) error                      { return uIn(k, t) }
func (k VaultSagaEventKind) IsValid() bool                                       { return eOk(uint8(k), nmVEv) }
func (k VaultSagaEventKind) String() string                                      { return eStr(uint8(k), nmVEv) }
func ParseVaultSagaEventKind(s string) (v VaultSagaEventKind, e error)           { return pIn(s, v) }
func (k VaultSagaEventKind) AppendText(b []byte) ([]byte, error)                 { return aIn(b, k) }
func (k VaultSagaEventKind) MarshalText() ([]byte, error)                        { return k.AppendText(nil) }
func (k *VaultSagaEventKind) UnmarshalText(t []byte) error                       { return uIn(k, t) }
func (p ApprovalPhase) IsValid() bool                                            { return eOk(uint8(p), nmAPh) }
func (p ApprovalPhase) String() string                                           { return eStr(uint8(p), nmAPh) }
func ParseApprovalPhase(s string) (v ApprovalPhase, e error)                     { return pSt(s, v) }
func (p ApprovalPhase) AppendText(b []byte) ([]byte, error)                      { return aSt(b, p) }
func (p ApprovalPhase) MarshalText() ([]byte, error)                             { return p.AppendText(nil) }
func (p *ApprovalPhase) UnmarshalText(t []byte) error                            { return uSt(p, t) }
func (k ApprovalEffectKind) IsValid() bool                                       { return eOk(uint8(k), nmAEff) }
func (k ApprovalEffectKind) String() string                                      { return eStr(uint8(k), nmAEff) }
func ParseApprovalEffectKind(s string) (v ApprovalEffectKind, e error)           { return pIn(s, v) }
func (k ApprovalEffectKind) AppendText(b []byte) ([]byte, error)                 { return aIn(b, k) }
func (k ApprovalEffectKind) MarshalText() ([]byte, error)                        { return k.AppendText(nil) }
func (k *ApprovalEffectKind) UnmarshalText(t []byte) error                       { return uIn(k, t) }
func (k ApprovalEventKind) IsValid() bool                                        { return eOk(uint8(k), nmAEv) }
func (k ApprovalEventKind) String() string                                       { return eStr(uint8(k), nmAEv) }
func ParseApprovalEventKind(s string) (v ApprovalEventKind, e error)             { return pIn(s, v) }
func (k ApprovalEventKind) AppendText(b []byte) ([]byte, error)                  { return aIn(b, k) }
func (k ApprovalEventKind) MarshalText() ([]byte, error)                         { return k.AppendText(nil) }
func (k *ApprovalEventKind) UnmarshalText(t []byte) error                        { return uIn(k, t) }
func (d TransferDirection) IsValid() bool                                        { return eOk(uint8(d), nmTDir) }
func (d TransferDirection) String() string                                       { return eStr(uint8(d), nmTDir) }
func ParseTransferDirection(s string) (TransferDirection, error)                 { return pDr(s) }
func (d TransferDirection) AppendText(b []byte) ([]byte, error)                  { return aDr(b, d) }
func (d TransferDirection) MarshalText() ([]byte, error)                         { return d.AppendText(nil) }
func (d *TransferDirection) UnmarshalText(t []byte) error                        { return eUnm(d, t, ErrInvalidContext) }
func (v JournalVersion) IsValid() bool                                           { return eOk(uint8(v), nmJVer) }
func (v JournalVersion) String() string                                          { return eStr(uint8(v), nmJVer) }
func ParseJournalVersion(s string) (v JournalVersion, e error)                   { return pJr(s, v) }
func (v JournalVersion) AppendText(b []byte) ([]byte, error)                     { return aJr(b, v) }
func (v JournalVersion) MarshalText() ([]byte, error)                            { return v.AppendText(nil) }
func (v *JournalVersion) UnmarshalText(t []byte) error                           { return uJr(v, t) }
func (k JournalRecordKind) IsValid() bool                                        { return eOk(uint8(k), nmJRec) }
func (k JournalRecordKind) String() string                                       { return eStr(uint8(k), nmJRec) }
func ParseJournalRecordKind(s string) (v JournalRecordKind, e error)             { return pJr(s, v) }
func (k JournalRecordKind) AppendText(b []byte) ([]byte, error)                  { return aJr(b, k) }
func (k JournalRecordKind) MarshalText() ([]byte, error)                         { return k.AppendText(nil) }
func (k *JournalRecordKind) UnmarshalText(t []byte) error                        { return uJr(k, t) }
func (k TransferStateKind) IsValid() bool                                        { return eOk(uint8(k), nmTSt) }
func (k TransferStateKind) String() string                                       { return eStr(uint8(k), nmTSt) }
func ParseTransferStateKind(s string) (v TransferStateKind, e error)             { return pSt(s, v) }
func (k TransferStateKind) AppendText(b []byte) ([]byte, error)                  { return aSt(b, k) }
func (k TransferStateKind) MarshalText() ([]byte, error)                         { return k.AppendText(nil) }
func (k *TransferStateKind) UnmarshalText(t []byte) error                        { return uSt(k, t) }
func (k TransferEffectKind) IsValid() bool                                       { return eOk(uint8(k), nmTEff) }
func (k TransferEffectKind) String() string                                      { return eStr(uint8(k), nmTEff) }
func ParseTransferEffectKind(s string) (v TransferEffectKind, e error)           { return pIn(s, v) }
func (k TransferEffectKind) AppendText(b []byte) ([]byte, error)                 { return aIn(b, k) }
func (k TransferEffectKind) MarshalText() ([]byte, error)                        { return k.AppendText(nil) }
func (k *TransferEffectKind) UnmarshalText(t []byte) error                       { return uIn(k, t) }
func (k TransferEventKind) IsValid() bool                                        { return eOk(uint8(k), nmTEv) }
func (k TransferEventKind) String() string                                       { return eStr(uint8(k), nmTEv) }
func ParseTransferEventKind(s string) (v TransferEventKind, e error)             { return pIn(s, v) }
func (k TransferEventKind) AppendText(b []byte) ([]byte, error)                  { return aIn(b, k) }
func (k TransferEventKind) MarshalText() ([]byte, error)                         { return k.AppendText(nil) }
func (k *TransferEventKind) UnmarshalText(t []byte) error                        { return uIn(k, t) }
func (p EnsurePhase) IsValid() bool                                              { return eOk(uint8(p), nmEPh) }
func (p EnsurePhase) String() string                                             { return eStr(uint8(p), nmEPh) }
func ParseEnsurePhase(s string) (v EnsurePhase, e error)                         { return pSt(s, v) }
func (p EnsurePhase) AppendText(b []byte) ([]byte, error)                        { return aSt(b, p) }
func (p EnsurePhase) MarshalText() ([]byte, error)                               { return p.AppendText(nil) }
func (p *EnsurePhase) UnmarshalText(t []byte) error                              { return uSt(p, t) }
func (k EnsureEffectKind) IsValid() bool                                         { return eOk(uint8(k), nmEEff) }
func (k EnsureEffectKind) String() string                                        { return eStr(uint8(k), nmEEff) }
func ParseEnsureEffectKind(s string) (v EnsureEffectKind, e error)               { return pIn(s, v) }
func (k EnsureEffectKind) AppendText(b []byte) ([]byte, error)                   { return aIn(b, k) }
func (k EnsureEffectKind) MarshalText() ([]byte, error)                          { return k.AppendText(nil) }
func (k *EnsureEffectKind) UnmarshalText(t []byte) error                         { return uIn(k, t) }
func (k EnsureEventKind) IsValid() bool                                          { return eOk(uint8(k), nmEEv) }
func (k EnsureEventKind) String() string                                         { return eStr(uint8(k), nmEEv) }
func ParseEnsureEventKind(s string) (v EnsureEventKind, e error)                 { return pIn(s, v) }
func (k EnsureEventKind) AppendText(b []byte) ([]byte, error)                    { return aIn(b, k) }
func (k EnsureEventKind) MarshalText() ([]byte, error)                           { return k.AppendText(nil) }
func (k *EnsureEventKind) UnmarshalText(t []byte) error                          { return uIn(k, t) }
func (p PendingEnrollPhase) IsValid() bool                                       { return eOk(uint8(p), nmPPh) }
func (p PendingEnrollPhase) String() string                                      { return eStr(uint8(p), nmPPh) }
func ParsePendingEnrollPhase(s string) (v PendingEnrollPhase, e error)           { return pSt(s, v) }
func (p PendingEnrollPhase) AppendText(b []byte) ([]byte, error)                 { return aSt(b, p) }
func (p PendingEnrollPhase) MarshalText() ([]byte, error)                        { return p.AppendText(nil) }
func (p *PendingEnrollPhase) UnmarshalText(t []byte) error                       { return uSt(p, t) }
func (k PendingEnrollEffectKind) IsValid() bool                                  { return eOk(uint8(k), nmPEff) }
func (k PendingEnrollEffectKind) String() string                                 { return eStr(uint8(k), nmPEff) }
func ParsePendingEnrollEffectKind(s string) (v PendingEnrollEffectKind, e error) { return pIn(s, v) }
func (k PendingEnrollEffectKind) AppendText(b []byte) ([]byte, error)            { return aIn(b, k) }
func (k PendingEnrollEffectKind) MarshalText() ([]byte, error)                   { return k.AppendText(nil) }
func (k *PendingEnrollEffectKind) UnmarshalText(t []byte) error                  { return uIn(k, t) }
func (k PendingEnrollEventKind) IsValid() bool                                   { return eOk(uint8(k), nmPEv) }
func (k PendingEnrollEventKind) String() string                                  { return eStr(uint8(k), nmPEv) }
func ParsePendingEnrollEventKind(s string) (v PendingEnrollEventKind, e error)   { return pIn(s, v) }
func (k PendingEnrollEventKind) AppendText(b []byte) ([]byte, error)             { return aIn(b, k) }
func (k PendingEnrollEventKind) MarshalText() ([]byte, error)                    { return k.AppendText(nil) }
func (k *PendingEnrollEventKind) UnmarshalText(t []byte) error                   { return uIn(k, t) }

type (
	eventWire[K validKind] struct {
		Kind   algebraic.Option[K] `json:"kind"`
		Detail string              `json:"detail,omitzero"`
	}
	transferEventWire struct {
		Kind   algebraic.Option[TransferEventKind] `json:"kind"`
		Offset uint64                              `json:"offset,omitzero"`
		Detail string                              `json:"detail,omitzero"`
	}
	ensureEventWire struct {
		Kind   algebraic.Option[EnsureEventKind] `json:"kind"`
		Phase  algebraic.Option[EnsurePhase]     `json:"phase"`
		Detail string                            `json:"detail,omitzero"`
	}
	transferDestWire struct {
		Direction algebraic.Option[TransferDirection]       `json:"direction"`
		Remote    algebraic.Option[pathalg.RemotePath]      `json:"remote,omitzero"`
		Local     algebraic.Option[pathalg.LocalRootedDest] `json:"local,omitzero"`
	}
	transferJournalWire struct {
		Version      algebraic.Option[JournalVersion]       `json:"version"`
		Generation   algebraic.Option[uint64]               `json:"generation"`
		Seq          algebraic.Option[uint64]               `json:"seq"`
		Kind         algebraic.Option[JournalRecordKind]    `json:"kind"`
		TransferID   algebraic.Option[security.OperationID] `json:"transfer_id"`
		Dest         algebraic.Option[TransferDest]         `json:"dest,omitzero"`
		Offset       uint64                                 `json:"offset,omitzero"`
		Length       uint64                                 `json:"length,omitzero"`
		TotalBytes   uint64                                 `json:"total_bytes,omitzero"`
		Digest       algebraic.Option[security.Digest]      `json:"digest,omitzero"`
		PrevDigest   algebraic.Option[security.Digest]      `json:"prev_digest,omitzero"`
		RecordDigest algebraic.Option[security.Digest]      `json:"record_digest"`
	}
)

// MarshalJSONTo 与 UnmarshalJSONFrom 实现状态机事件、传输目标与 Journal 记录的 json/v2 严格编解码（拒绝 null 与未知字段）。
func uEv[T, W any](dst *T, d *jsontext.Decoder, fn func(W) (T, error)) error {
	return unmJSON(dst, d, ErrInvalidInput, fn)
}
func (e Event[K]) MarshalJSONTo(enc *jsontext.Encoder) error {
	return mJSON(enc, e.IsValid(), ErrInvalidInput, eventWire[K]{algebraic.Some(e.kind), e.detail})
}
func (e *Event[K]) UnmarshalJSONFrom(d *jsontext.Decoder) error { return uEv(e, d, decEv[K]) }
func (e TransferEvent) MarshalJSONTo(enc *jsontext.Encoder) error {
	return mJSON(enc, e.IsValid(), ErrInvalidInput, transferEventWire{algebraic.Some(e.kind), e.offset, e.detail})
}
func (e *TransferEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error { return uEv(e, d, decTEv) }
func (e EnsureEvent) MarshalJSONTo(enc *jsontext.Encoder) error {
	return mJSON(enc, e.IsValid(), ErrInvalidInput, ensureEventWire{algebraic.Some(e.kind), algebraic.Some(e.phase), e.detail})
}
func (e *EnsureEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error { return uEv(e, d, decEEv) }
func decEv[K validKind](w eventWire[K]) (Event[K], error) {
	k, err := decKind(w.Kind, w.Detail)
	return Event[K]{k, w.Detail, err == nil}, err
}
func decTEv(w transferEventWire) (TransferEvent, error) {
	k, err := decKind(w.Kind, w.Detail)
	return TransferEvent{k, w.Offset, w.Detail, err == nil}, err
}
func decEEv(w ensureEventWire) (EnsureEvent, error) {
	k, err := decKind(w.Kind, w.Detail)
	if p, okP := w.Phase.Get(); err == nil && okP && p.IsValid() {
		return EnsureEvent{k, p, w.Detail, true}, nil
	}
	return EnsureEvent{}, pickIf(err != nil, err, fmt.Errorf("%w: 缺少或无效的 EnsureEvent phase", ErrInvalidInput))
}
func (d TransferDest) MarshalJSONTo(enc *jsontext.Encoder) error {
	return mJSON(enc, d.IsValid(), ErrInvalidContext, transferDestWire{algebraic.Some(d.direction), d.Remote(), d.Local()})
}
func (d *TransferDest) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmJSON(d, dec, ErrInvalidContext, decTDst)
}
func decTDst(w transferDestWire) (TransferDest, error) {
	dir, okDir := w.Direction.Get()
	rem, hasRem := w.Remote.Get()
	loc, hasLoc := w.Local.Get()
	if okDir && dir == TransferDirectionUpload && hasRem && !hasLoc {
		return NewUploadDest(rem)
	}
	if okDir && dir == TransferDirectionDownload && hasLoc && !hasRem {
		return NewDownloadDest(loc)
	}
	return TransferDest{}, fmt.Errorf("%w: 非法 TransferDest 方向或字段组合", ErrInvalidContext)
}
func (r TransferJournalRecord) MarshalJSONTo(enc *jsontext.Encoder) error {
	return mJSON(enc, r.IsValid(), ErrInvalidJournal, transferJournalWire{
		algebraic.Some(r.version), algebraic.Some(r.generation), algebraic.Some(r.seq), algebraic.Some(r.kind),
		algebraic.Some(r.transferID), r.dest, r.offset, r.length, r.totalBytes, r.digest, r.prevDigest, algebraic.Some(r.recordDigest),
	})
}
func (r *TransferJournalRecord) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmJSON(r, d, ErrCorruptJournal, decJRec)
}
func decJRec(w transferJournalWire) (TransferJournalRecord, error) {
	tid, okT := w.TransferID.Get()
	rd, okRD := w.RecordDigest.Get()
	if !okT || !okRD || w.Version.IsNone() || w.Generation.IsNone() || w.Seq.IsNone() || w.Kind.IsNone() {
		return TransferJournalRecord{}, fmt.Errorf("%w: 缺少必需的 Journal 字段", ErrCorruptJournal)
	}
	rec, err := NewTransferJournalRecord(TransferJournalRecordSpec{w.Version.OrElse(0), w.Generation.OrElse(0), w.Seq.OrElse(0), w.Kind.OrElse(0), tid, w.Dest, w.Offset, w.Length, w.TotalBytes, w.Digest, w.PrevDigest})
	if err != nil {
		return TransferJournalRecord{}, fmt.Errorf("%w: %w", ErrCorruptJournal, err)
	}
	if !rd.Equal(rec.recordDigest) {
		return TransferJournalRecord{}, fmt.Errorf("%w: record_digest 校验失败", ErrCorruptJournal)
	}
	return rec, nil
}
