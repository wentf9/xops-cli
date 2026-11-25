package playbook

import (
	"cmp"
	jsonv2 "encoding/json/v2"
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// StepStatus 与 NodeStatus 分别表示单步骤终态与节点/报表折叠终态；零值恒失败关闭。
// NodeStatus 严苛度格序满足 OutcomeUnknown > Failed > Aborted > Changed > Succeeded，绝不降级 OutcomeUnknown。
//
//xops:opaque
//xops:failclosed
type StepStatus uint8

//xops:opaque
//xops:failclosed
type NodeStatus uint8

const (
	StepStatusInvalid        StepStatus = iota // 无效零值（失败关闭）
	StepStatusSucceeded                        // 成功且无变更
	StepStatusChanged                          // 成功且产生变更
	StepStatusSkipped                          // 条件跳过
	StepStatusFailed                           // 确定失败
	StepStatusOutcomeUnknown                   // 结果未知（严禁降级或重试）
	StepStatusAborted                          // 因 fail_fast/abort 中止
)

const (
	NodeStatusInvalid        NodeStatus = iota // 无效零值（失败关闭）
	NodeStatusSucceeded                        // 全部成功或跳过
	NodeStatusChanged                          // 全部成功/跳过且至少一步变更
	NodeStatusAborted                          // 存在中止且无失败与未知结果
	NodeStatusFailed                           // 存在确定失败且无未知结果
	NodeStatusOutcomeUnknown                   // 至少一步未知结果（最高吸收态）
)

// ParseStepStatus 与 ParseNodeStatus 严格解析规范小写状态文本。
func ParseStepStatus(raw string) (StepStatus, error) {
	return parseEnumByName(raw, StepStatusSucceeded, StepStatusAborted, StepStatusInvalid, StepStatus.String, ErrInvalidStepStatus)
}
func ParseNodeStatus(raw string) (NodeStatus, error) {
	return parseEnumByName(raw, NodeStatusSucceeded, NodeStatusOutcomeUnknown, NodeStatusInvalid, NodeStatus.String, ErrInvalidNodeStatus)
}

func (s StepStatus) IsValid() bool { return s >= StepStatusSucceeded && s <= StepStatusAborted }
func (s StepStatus) IsZero() bool  { return s == StepStatusInvalid }
func (s StepStatus) String() string {
	return enumName(uint8(s), "invalid", "invalid", "succeeded", "changed", "skipped", "failed", "outcome_unknown", "aborted")
}
func (s StepStatus) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, s.IsValid(), s.String(), ErrInvalidStepStatus)
}
func (s StepStatus) MarshalText() ([]byte, error) { return s.AppendText(nil) }
func (s *StepStatus) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(s, StepStatusInvalid, text, ParseStepStatus)
}

func (s NodeStatus) IsValid() bool { return s >= NodeStatusSucceeded && s <= NodeStatusOutcomeUnknown }
func (s NodeStatus) IsZero() bool  { return s == NodeStatusInvalid }
func (s NodeStatus) String() string {
	return enumName(uint8(s), "invalid", "invalid", "succeeded", "changed", "aborted", "failed", "outcome_unknown")
}
func (s NodeStatus) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, s.IsValid(), s.String(), ErrInvalidNodeStatus)
}
func (s NodeStatus) MarshalText() ([]byte, error) { return s.AppendText(nil) }
func (s *NodeStatus) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(s, NodeStatusInvalid, text, ParseNodeStatus)
}

// JoinNodeStatus 执行节点汇总状态的交换/结合/幂等并半格折叠（OutcomeUnknown 吸收一切）。
func JoinNodeStatus(a, b NodeStatus) NodeStatus {
	return pickIf(a.IsValid() && b.IsValid(), max(a, b), NodeStatusInvalid)
}

// StepExecutionRecordSpec 与 StepExecutionRecord 表示单节点单步骤的不可变执行结果；
// 构造器严格强制 ExecutionOutcome 与 StepStatus 一致性，禁止降级 *execution.OutcomeUnknown。
type StepExecutionRecordSpec struct {
	NodeID   inventory.NodeID
	StepID   StepID
	Status   StepStatus
	Outcome  algebraic.Option[execution.ExecutionOutcome]
	Duration algebraic.Duration
	Message  string
}

//xops:opaque
//xops:failclosed
type StepExecutionRecord struct {
	nodeID   inventory.NodeID
	stepID   StepID
	status   StepStatus
	outcome  algebraic.Option[execution.ExecutionOutcome]
	duration algebraic.Duration
	message  string
	valid    bool
}

// NewStepExecutionRecord 校验节点、步骤、状态、结果一致性与非负耗时并构造不可变记录。
func NewStepExecutionRecord(spec StepExecutionRecordSpec) (StepExecutionRecord, error) {
	if !spec.NodeID.IsValid() || !spec.StepID.IsValid() || !spec.Status.IsValid() || spec.Duration.IsNegative() {
		return StepExecutionRecord{}, fmt.Errorf("%w: node_id/step_id/status 须有效且 duration 不能为负", ErrInvalidStepRecord)
	}
	if err := validateOutcomeStatusConsistency(spec.Status, spec.Outcome); err != nil {
		return StepExecutionRecord{}, err
	}
	msg := truncateUTF8(security.SanitizePromptText(spec.Message), maxMessageBytes)
	return StepExecutionRecord{spec.NodeID, spec.StepID, spec.Status, spec.Outcome, spec.Duration, msg, true}, nil
}

func validateOutcomeStatusConsistency(status StepStatus, opt algebraic.Option[execution.ExecutionOutcome]) error {
	out, hasOut := opt.Get()
	if !hasOut {
		return nil
	}
	if out == nil || !out.IsValid() {
		return fmt.Errorf("%w: outcome 不可为 nil 或无效零值", ErrInvalidStepRecord)
	}
	switch v := out.(type) {
	case *execution.OutcomeUnknown:
		if status != StepStatusOutcomeUnknown {
			return fmt.Errorf("%w: OutcomeUnknown 仅允许对应 outcome_unknown（实际=%s）", ErrOutcomeStatusMismatch, status)
		}
	case *execution.OutcomeNotStarted:
		if status != StepStatusFailed && status != StepStatusAborted {
			return fmt.Errorf("%w: OutcomeNotStarted 仅允许对应 failed/aborted（实际=%s）", ErrOutcomeStatusMismatch, status)
		}
	case *execution.OutcomeCompleted:
		if (v.Succeeded() && status != StepStatusSucceeded && status != StepStatusChanged) ||
			(!v.Succeeded() && status != StepStatusFailed && status != StepStatusAborted) {
			return fmt.Errorf("%w: OutcomeCompleted 与状态 %s 冲突", ErrOutcomeStatusMismatch, status)
		}
	default:
		return ErrInvalidStepRecord
	}
	return nil
}

func (r StepExecutionRecord) IsValid() bool {
	return r.valid && r.nodeID.IsValid() && r.stepID.IsValid() && r.status.IsValid() && !r.duration.IsNegative()
}
func (r StepExecutionRecord) IsZero() bool                                          { return !r.IsValid() }
func (r StepExecutionRecord) NodeID() inventory.NodeID                              { return r.nodeID }
func (r StepExecutionRecord) StepID() StepID                                        { return r.stepID }
func (r StepExecutionRecord) Status() StepStatus                                    { return r.status }
func (r StepExecutionRecord) Outcome() algebraic.Option[execution.ExecutionOutcome] { return r.outcome }
func (r StepExecutionRecord) Duration() algebraic.Duration                          { return r.duration }
func (r StepExecutionRecord) Message() string                                       { return r.message }
func (r StepExecutionRecord) IsOutcomeUnknown() bool {
	out, ok := r.outcome.Get()
	return r.IsValid() && (r.status == StepStatusOutcomeUnknown || (ok && out != nil && out.Kind() == execution.OutcomeKindUnknown))
}
func (r StepExecutionRecord) Equal(o StepExecutionRecord) bool {
	return r.IsValid() && o.IsValid() && r.nodeID.Equal(o.nodeID) && r.stepID.Equal(o.stepID) &&
		r.status == o.status && equalOptionFunc(r.outcome, o.outcome, execution.EqualOutcome) &&
		r.duration.Equal(o.duration) && r.message == o.message
}

// StepCounts 汇总各步骤终态计数。
type StepCounts struct {
	Succeeded int `json:"succeeded"`
	Changed   int `json:"changed"`
	Skipped   int `json:"skipped"`
	Failed    int `json:"failed"`
	Unknown   int `json:"outcome_unknown"`
	Aborted   int `json:"aborted"`
}

func (c *StepCounts) addStatus(st StepStatus) NodeStatus {
	ptrs := [...]*int{nil, &c.Succeeded, &c.Changed, &c.Skipped, &c.Failed, &c.Unknown, &c.Aborted}
	mapped := [...]NodeStatus{NodeStatusInvalid, NodeStatusSucceeded, NodeStatusChanged, NodeStatusSucceeded, NodeStatusFailed, NodeStatusOutcomeUnknown, NodeStatusAborted}
	if !st.IsValid() {
		return NodeStatusInvalid
	}
	*ptrs[st]++
	return mapped[st]
}
func (c *StepCounts) merge(o StepCounts) {
	c.Succeeded += o.Succeeded
	c.Changed += o.Changed
	c.Skipped += o.Skipped
	c.Failed += o.Failed
	c.Unknown += o.Unknown
	c.Aborted += o.Aborted
}

// NodeReport 与 PlaybookReport 分别为单节点与跨节点确定性折叠后的不可变报表；零值恒无效。
//
//xops:opaque
//xops:failclosed
type NodeReport struct {
	nodeID            inventory.NodeID
	status            NodeStatus
	steps             []StepExecutionRecord
	counts            StepCounts
	totalDuration     algebraic.Duration
	hasUnknownOutcome bool
	valid             bool
}

//xops:opaque
//xops:failclosed
type PlaybookReport struct {
	playbookID        PlaybookID
	playbookDigest    security.Digest
	status            NodeStatus
	nodes             []NodeReport
	stepCounts        StepCounts
	hasUnknownOutcome bool
	valid             bool
}

func (r NodeReport) IsValid() bool {
	return r.valid && r.nodeID.IsValid() && r.status.IsValid() && len(r.steps) > 0
}
func (r NodeReport) IsZero() bool                      { return !r.IsValid() }
func (r NodeReport) NodeID() inventory.NodeID          { return r.nodeID }
func (r NodeReport) Status() NodeStatus                { return r.status }
func (r NodeReport) Steps() []StepExecutionRecord      { return slices.Clone(r.steps) }
func (r NodeReport) Counts() StepCounts                { return r.counts }
func (r NodeReport) TotalDuration() algebraic.Duration { return r.totalDuration }
func (r NodeReport) HasUnknownOutcome() bool           { return r.hasUnknownOutcome }
func (r NodeReport) Equal(o NodeReport) bool {
	return r.IsValid() && o.IsValid() && r.nodeID.Equal(o.nodeID) && r.status == o.status &&
		r.counts == o.counts && r.totalDuration.Equal(o.totalDuration) &&
		r.hasUnknownOutcome == o.hasUnknownOutcome && slices.EqualFunc(r.steps, o.steps, StepExecutionRecord.Equal)
}

func (r PlaybookReport) IsValid() bool {
	return r.valid && r.playbookID.IsValid() && r.playbookDigest.IsValid() && r.status.IsValid() && len(r.nodes) > 0
}
func (r PlaybookReport) IsZero() bool                    { return !r.IsValid() }
func (r PlaybookReport) PlaybookID() PlaybookID          { return r.playbookID }
func (r PlaybookReport) PlaybookDigest() security.Digest { return r.playbookDigest }
func (r PlaybookReport) Status() NodeStatus              { return r.status }
func (r PlaybookReport) StepCounts() StepCounts          { return r.stepCounts }
func (r PlaybookReport) HasUnknownOutcome() bool         { return r.hasUnknownOutcome }
func (r PlaybookReport) Nodes() []NodeReport {
	if !r.IsValid() {
		return nil
	}
	out := make([]NodeReport, len(r.nodes))
	for i, n := range r.nodes {
		out[i] = NodeReport{n.nodeID, n.status, slices.Clone(n.steps), n.counts, n.totalDuration, n.hasUnknownOutcome, true}
	}
	return out
}
func (r PlaybookReport) CanonicalJSON() ([]byte, error) {
	if !r.IsValid() {
		return nil, ErrEmptyReport
	}
	return jsonv2.Marshal(r, jsonv2.Deterministic(true))
}
func (r PlaybookReport) Equal(o PlaybookReport) bool {
	return r.IsValid() && o.IsValid() && r.playbookID.Equal(o.playbookID) &&
		r.playbookDigest.Equal(o.playbookDigest) && r.status == o.status &&
		r.stepCounts == o.stepCounts && r.hasUnknownOutcome == o.hasUnknownOutcome &&
		slices.EqualFunc(r.nodes, o.nodes, NodeReport.Equal)
}

// FoldPlaybookReport 以纯确定性方式折叠跨节点执行记录：
// 节点间按 NodeID 全序排序（输入顺序无关），节点内按 pb.Steps() 声明序排列，
// 严格拒绝无效/未知步骤/重复 (NodeID, StepID) 记录，并永不降级 OutcomeUnknown。
func FoldPlaybookReport(pb Playbook, records []StepExecutionRecord) (PlaybookReport, error) {
	if !pb.IsValid() {
		return PlaybookReport{}, ErrInvalidPlaybook
	}
	if len(records) == 0 {
		return PlaybookReport{}, ErrEmptyReport
	}
	stepOrder := make(map[StepID]int, pb.steps.Len())
	for i, st := range pb.steps.Slice() {
		stepOrder[st.id] = i
	}
	grouped, err := groupRecordsByNode(records, stepOrder)
	if err != nil {
		return PlaybookReport{}, err
	}
	nodeIDs := make([]inventory.NodeID, 0, len(grouped))
	for id := range grouped {
		nodeIDs = append(nodeIDs, id)
	}
	slices.SortFunc(nodeIDs, inventory.NodeID.Compare)
	nodes, overall, hasUnknown := make([]NodeReport, 0, len(nodeIDs)), NodeStatusSucceeded, false
	var totalCounts StepCounts
	for _, id := range nodeIDs {
		nr, err := foldNodeReport(id, grouped[id], stepOrder)
		if err != nil {
			return PlaybookReport{}, err
		}
		nodes = append(nodes, nr)
		overall = JoinNodeStatus(overall, nr.status)
		totalCounts.merge(nr.counts)
		hasUnknown = hasUnknown || nr.hasUnknownOutcome
	}
	return PlaybookReport{pb.id, pb.snapshotDigest, overall, nodes, totalCounts, hasUnknown, true}, nil
}

type nodeStepKey struct {
	node inventory.NodeID
	step StepID
}

func groupRecordsByNode(records []StepExecutionRecord, stepOrder map[StepID]int) (map[inventory.NodeID][]StepExecutionRecord, error) {
	grouped, seen := make(map[inventory.NodeID][]StepExecutionRecord), make(map[nodeStepKey]bool, len(records))
	for i, rec := range records {
		if !rec.IsValid() {
			return nil, fmt.Errorf("%w: records[%d] 无效", ErrInvalidStepRecord, i)
		}
		if _, ok := stepOrder[rec.stepID]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownStepID, rec.stepID)
		}
		k := nodeStepKey{rec.nodeID, rec.stepID}
		if seen[k] {
			return nil, fmt.Errorf("%w: node=%s step=%s", ErrDuplicateStepRecord, rec.nodeID, rec.stepID)
		}
		seen[k] = true
		grouped[rec.nodeID] = append(grouped[rec.nodeID], rec)
	}
	return grouped, nil
}

func foldNodeReport(nodeID inventory.NodeID, recs []StepExecutionRecord, stepOrder map[StepID]int) (NodeReport, error) {
	ordered := slices.Clone(recs)
	slices.SortFunc(ordered, func(a, b StepExecutionRecord) int { return cmp.Compare(stepOrder[a.stepID], stepOrder[b.stepID]) })
	status, totalDur, hasUnknown := NodeStatusSucceeded, algebraic.ZeroDuration(), false
	var counts StepCounts
	for _, rec := range ordered {
		status = JoinNodeStatus(status, counts.addStatus(rec.status))
		if rec.IsOutcomeUnknown() {
			status, hasUnknown = NodeStatusOutcomeUnknown, true
		}
		nextDur, err := totalDur.CheckedAdd(rec.duration)
		if err != nil {
			return NodeReport{}, fmt.Errorf("%w: 节点 %s 耗时累加溢出: %w", ErrInvalidStepRecord, nodeID, err)
		}
		totalDur = nextDur
	}
	return NodeReport{nodeID, status, ordered, counts, totalDur, hasUnknown, true}, nil
}
