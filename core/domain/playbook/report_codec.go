package playbook

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/security"
)

type (
	outcomeFieldWire struct{ outcome execution.ExecutionOutcome }
	stepRecordWire   struct {
		NodeID   algebraic.Option[inventory.NodeID]   `json:"node_id"`
		StepID   algebraic.Option[StepID]             `json:"step_id"`
		Status   algebraic.Option[StepStatus]         `json:"status"`
		Outcome  algebraic.Option[outcomeFieldWire]   `json:"outcome,omitzero"`
		Duration algebraic.Option[algebraic.Duration] `json:"duration"`
		Message  string                               `json:"message,omitzero"`
	}
	nodeReportWire struct {
		NodeID            algebraic.Option[inventory.NodeID]   `json:"node_id"`
		Status            algebraic.Option[NodeStatus]         `json:"status"`
		Steps             []StepExecutionRecord                `json:"steps"`
		Counts            algebraic.Option[StepCounts]         `json:"counts"`
		TotalDuration     algebraic.Option[algebraic.Duration] `json:"total_duration"`
		HasUnknownOutcome algebraic.Option[bool]               `json:"has_unknown_outcome"`
	}
	playbookReportWire struct {
		PlaybookID        algebraic.Option[PlaybookID]      `json:"playbook_id"`
		PlaybookDigest    algebraic.Option[security.Digest] `json:"playbook_digest"`
		Status            algebraic.Option[NodeStatus]      `json:"status"`
		Nodes             []NodeReport                      `json:"nodes"`
		StepCounts        algebraic.Option[StepCounts]      `json:"step_counts"`
		HasUnknownOutcome algebraic.Option[bool]            `json:"has_unknown_outcome"`
	}
)

func (o outcomeFieldWire) MarshalJSONTo(enc *jsontext.Encoder) error {
	return execution.MarshalOutcomeTo(enc, o.outcome)
}

func (o *outcomeFieldWire) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	val, err := execution.UnmarshalOutcomeFrom(dec)
	if err != nil {
		o.outcome = nil
		return err
	}
	o.outcome = val
	return nil
}

// MarshalJSONTo 为 StepExecutionRecord、NodeReport 与 PlaybookReport 提供值接收者确定性 json/v2 编码。
func (r StepExecutionRecord) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !r.IsValid() {
		return ErrInvalidStepRecord
	}
	var ow algebraic.Option[outcomeFieldWire]
	if o, ok := r.outcome.Get(); ok {
		ow = algebraic.Some(outcomeFieldWire{o})
	}
	return jsonv2.MarshalEncode(enc, stepRecordWire{
		algebraic.Some(r.nodeID), algebraic.Some(r.stepID), algebraic.Some(r.status),
		ow, algebraic.Some(r.duration), r.message,
	})
}

// UnmarshalJSONFrom 实现 StepExecutionRecord 的严格失败关闭 json/v2 解码：
// 拒绝 JSON null、未知字段、缺失必填字段以及 ExecutionOutcome 与 StepStatus 冲突。
func (r *StepExecutionRecord) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONStrict(r, dec, ErrInvalidStepRecord, func(w stepRecordWire) (StepExecutionRecord, error) {
		nodeID, okN := w.NodeID.Get()
		stepID, okS := w.StepID.Get()
		status, okSt := w.Status.Get()
		dur, okD := w.Duration.Get()
		if !okN || !okS || !okSt || !okD {
			return StepExecutionRecord{}, domi18n.EF(ErrInvalidStepRecord, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "node_id/step_id/status/duration"))
		}
		var outOpt algebraic.Option[execution.ExecutionOutcome]
		if ow, ok := w.Outcome.Get(); ok {
			outOpt = algebraic.Some(ow.outcome)
		}
		return NewStepExecutionRecord(StepExecutionRecordSpec{
			NodeID: nodeID, StepID: stepID, Status: status, Outcome: outOpt, Duration: dur, Message: w.Message,
		})
	})
}

func (r NodeReport) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !r.IsValid() {
		return ErrEmptyReport
	}
	return jsonv2.MarshalEncode(enc, nodeReportWire{
		algebraic.Some(r.nodeID), algebraic.Some(r.status), r.steps,
		algebraic.Some(r.counts), algebraic.Some(r.totalDuration), algebraic.Some(r.hasUnknownOutcome),
	})
}

// UnmarshalJSONFrom 实现 NodeReport 的防篡改 json/v2 解码：
// 强制重算步骤计数、状态并半格、总耗时与 OutcomeUnknown 不降级不变量，不一致或含未知字段一律失败关闭。
func (r *NodeReport) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONStrict(r, dec, ErrEmptyReport, decodeNodeReportWire)
}

func decodeNodeReportWire(w nodeReportWire) (NodeReport, error) {
	nodeID, okN := w.NodeID.Get()
	status, okS := w.Status.Get()
	counts, okC := w.Counts.Get()
	totalDur, okD := w.TotalDuration.Get()
	hasUnknown, okU := w.HasUnknownOutcome.Get()
	if !okN || !okS || !okC || !okD || !okU || !nodeID.IsValid() || !status.IsValid() || len(w.Steps) == 0 {
		return NodeReport{}, domi18n.EF(ErrEmptyReport, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "node_report"))
	}
	reStatus, reDur, reUnknown := NodeStatusSucceeded, algebraic.ZeroDuration(), false
	var reCounts StepCounts
	seen := make(map[StepID]bool, len(w.Steps))
	for i, rec := range w.Steps {
		if !rec.IsValid() || !rec.nodeID.Equal(nodeID) || seen[rec.stepID] {
			return NodeReport{}, domi18n.EF(ErrInvalidStepRecord, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "steps"), domi18n.Int("index", i))
		}
		seen[rec.stepID] = true
		reStatus = JoinNodeStatus(reStatus, reCounts.addStatus(rec.status))
		if rec.IsOutcomeUnknown() {
			reStatus, reUnknown = NodeStatusOutcomeUnknown, true
		}
		nextDur, err := reDur.CheckedAdd(rec.duration)
		if err != nil {
			return NodeReport{}, domi18n.WrapS(ErrInvalidStepRecord, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "total_duration"))
		}
		reDur = nextDur
	}
	if reStatus != status || reCounts != counts || !reDur.Equal(totalDur) || reUnknown != hasUnknown {
		return NodeReport{}, domi18n.EF(ErrOutcomeStatusMismatch, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "node_report"))
	}
	return NodeReport{nodeID, status, slices.Clone(w.Steps), counts, totalDur, hasUnknown, true}, nil
}

func (r PlaybookReport) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !r.IsValid() {
		return ErrEmptyReport
	}
	return jsonv2.MarshalEncode(enc, playbookReportWire{
		algebraic.Some(r.playbookID), algebraic.Some(r.playbookDigest), algebraic.Some(r.status),
		r.nodes, algebraic.Some(r.stepCounts), algebraic.Some(r.hasUnknownOutcome),
	})
}

// UnmarshalJSONFrom 实现 PlaybookReport 的防篡改 json/v2 解码：
// 强制校验节点确定性全序与唯一性，并重算跨节点状态并半格、汇总计数与 OutcomeUnknown 吸收不变量。
func (r *PlaybookReport) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONStrict(r, dec, ErrEmptyReport, decodePlaybookReportWire)
}

func decodePlaybookReportWire(w playbookReportWire) (PlaybookReport, error) {
	pbID, okID := w.PlaybookID.Get()
	pbDig, okDig := w.PlaybookDigest.Get()
	status, okSt := w.Status.Get()
	counts, okC := w.StepCounts.Get()
	hasUnknown, okU := w.HasUnknownOutcome.Get()
	if !okID || !okDig || !okSt || !okC || !okU || !pbID.IsValid() || !pbDig.IsValid() || !status.IsValid() || len(w.Nodes) == 0 {
		return PlaybookReport{}, domi18n.EF(ErrEmptyReport, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "playbook_report"))
	}
	reStatus, reUnknown := NodeStatusSucceeded, false
	var reCounts StepCounts
	for i, nr := range w.Nodes {
		if !nr.IsValid() {
			return PlaybookReport{}, domi18n.EF(ErrEmptyReport, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "nodes"), domi18n.Int("index", i))
		}
		if i > 0 && w.Nodes[i-1].nodeID.Compare(nr.nodeID) >= 0 {
			return PlaybookReport{}, domi18n.EF(ErrDuplicateStepRecord, domi18n.KeyCommonDuplicateItem, domi18n.Str("kind", "node_id"), domi18n.BoundStr("value", nr.nodeID.String()))
		}
		reStatus = JoinNodeStatus(reStatus, nr.status)
		reCounts.merge(nr.counts)
		reUnknown = reUnknown || nr.hasUnknownOutcome
	}
	if reUnknown && reStatus != NodeStatusOutcomeUnknown {
		return PlaybookReport{}, domi18n.EF(ErrOutcomeStatusMismatch, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "has_unknown_outcome"))
	}
	if reStatus != status || reCounts != counts || reUnknown != hasUnknown {
		return PlaybookReport{}, domi18n.EF(ErrOutcomeStatusMismatch, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "playbook_report"))
	}
	return PlaybookReport{pbID, pbDig, status, slices.Clone(w.Nodes), counts, hasUnknown, true}, nil
}
