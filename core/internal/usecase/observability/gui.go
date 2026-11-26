package observability

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

func isASCIIDigits(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isGUIKeyChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// ValidateX11Display 严格校验 X11 DISPLAY 格式（仅允许 ":N" 或 ":N.S"），阻断环境变量与命令注入。
func ValidateX11Display(raw string) error {
	if len(raw) < 2 || raw[0] != ':' {
		return fmt.Errorf("%w: 非法 X11 DISPLAY %q", ErrInvalidGUIInput, raw)
	}
	body := raw[1:]
	disp, screen, hasDot := strings.Cut(body, ".")
	if !isASCIIDigits(disp, 1, 4) || (hasDot && !isASCIIDigits(screen, 1, 3)) {
		return fmt.Errorf("%w: 非法 X11 DISPLAY %q", ErrInvalidGUIInput, raw)
	}
	return nil
}

// ValidateWaylandDisplay 严格校验 WAYLAND_DISPLAY 格式（仅允许 "wayland-N"）。
func ValidateWaylandDisplay(raw string) error {
	num, ok := strings.CutPrefix(raw, "wayland-")
	if !ok || !isASCIIDigits(num, 1, 4) {
		return fmt.Errorf("%w: 非法 WAYLAND_DISPLAY %q", ErrInvalidGUIInput, raw)
	}
	return nil
}

// ValidateGUIKeySpec 严格校验按键或组合和弦名称（如 "Return"、"ctrl+c"），拒绝前导 "-"、空白与 Shell 元字符。
func ValidateGUIKeySpec(raw string) error {
	if raw == "" || len(raw) > 64 {
		return fmt.Errorf("%w: 按键规格长度非法", ErrInvalidGUIInput)
	}
	parts := strings.Split(raw, "+")
	if len(parts) > 5 {
		return fmt.Errorf("%w: 组合键节数超限", ErrInvalidGUIInput)
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 24 {
			return fmt.Errorf("%w: 非法按键标识 %q", ErrInvalidGUIInput, raw)
		}
		for i := range len(p) {
			if !isGUIKeyChar(p[i]) {
				return fmt.Errorf("%w: 非法按键标识 %q", ErrInvalidGUIInput, raw)
			}
		}
	}
	return nil
}

// ValidateGUIAction 对 GUIActionSpec 执行全量失败关闭校验（归一化坐标 [0,1000]、Display、键位、滚轮与文本边界）。
func ValidateGUIAction(spec GUIActionSpec) error {
	if !spec.Action.IsValid() {
		return fmt.Errorf("%w: 未知 GUI 动作", ErrInvalidGUIInput)
	}
	if spec.Display != "" {
		if err := ValidateX11Display(spec.Display); err != nil {
			return err
		}
	}
	if spec.WaylandDisplay != "" {
		if err := ValidateWaylandDisplay(spec.WaylandDisplay); err != nil {
			return err
		}
	}
	return validateGUIActionArgs(spec)
}

func validateGUIActionArgs(spec GUIActionSpec) error {
	switch spec.Action {
	case GUIActionScreenshot:
		return nil
	case GUIActionClick, GUIActionDoubleClick, GUIActionRightClick, GUIActionMove:
		return validateNormCoord(spec.X, spec.Y)
	case GUIActionDrag:
		return firstErr(validateNormCoord(spec.StartX, spec.StartY), validateNormCoord(spec.EndX, spec.EndY))
	case GUIActionScroll:
		if err := validateNormCoord(spec.X, spec.Y); err != nil {
			return err
		}
		clicks := pickIf(spec.Clicks == 0, 3, spec.Clicks)
		if !spec.Direction.IsValid() || clicks < 1 || clicks > maxGUIClicks {
			return fmt.Errorf("%w: 滚轮方向或步数非法", ErrInvalidGUIInput)
		}
		return nil
	case GUIActionType:
		if spec.Text == "" || len(spec.Text) > maxGUITypeTextBytes || strings.ContainsRune(spec.Text, 0) {
			return fmt.Errorf("%w: type 文本为空、超长或含 NUL", ErrInvalidGUIInput)
		}
		return nil
	case GUIActionKey:
		return ValidateGUIKeySpec(spec.Key)
	default:
		return ErrInvalidGUIInput
	}
}

func validateNormCoord(x, y int) error {
	if x < 0 || x > 1000 || y < 0 || y > 1000 {
		return fmt.Errorf("%w: 归一化坐标 (%d,%d) 须落在 [0,1000]", ErrInvalidGUIInput, x, y)
	}
	return nil
}

// BuildGUIScript 为校验通过的 GUIActionSpec 生成硬化 POSIX Bourne 脚本（mktemp -d 0700 + trap + 全量 QuotePOSIX）。
func BuildGUIScript(spec GUIActionSpec) (string, error) {
	if err := ValidateGUIAction(spec); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("set -eu\nXOPS_TMP=$(mktemp -d)\nchmod 700 \"$XOPS_TMP\"\ntrap 'rm -rf \"$XOPS_TMP\"' EXIT\n")
	if err := writeGUIDisplayEnv(&b, spec); err != nil {
		return "", err
	}
	if err := writeGUIActionBody(&b, spec); err != nil {
		return "", err
	}
	if spec.Action == GUIActionScreenshot || spec.IncludeShot {
		if err := writeGUIScreenshotSnippet(&b); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func writeGUIDisplayEnv(b *strings.Builder, spec GUIActionSpec) error {
	if spec.Display != "" {
		q, err := execution.QuotePOSIX(spec.Display)
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "export DISPLAY=%s\n", q)
	} else {
		b.WriteString("export DISPLAY=\"${DISPLAY:-:0}\"\n")
	}
	if spec.WaylandDisplay != "" {
		q, err := execution.QuotePOSIX(spec.WaylandDisplay)
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "export WAYLAND_DISPLAY=%s\n", q)
	}
	return nil
}

func writeGUIActionBody(b *strings.Builder, spec GUIActionSpec) error {
	switch spec.Action {
	case GUIActionScreenshot:
		return nil
	case GUIActionClick, GUIActionDoubleClick, GUIActionRightClick, GUIActionMove:
		fmt.Fprintf(b, "xdotool mousemove --sync %d %d\n", spec.X, spec.Y)
		writePointerClick(b, spec.Action)
		return nil
	case GUIActionDrag:
		fmt.Fprintf(b, "xdotool mousemove --sync %d %d mousedown 1 mousemove --sync %d %d mouseup 1\n", spec.StartX, spec.StartY, spec.EndX, spec.EndY)
		return nil
	case GUIActionScroll:
		clicks := pickIf(spec.Clicks == 0, 3, spec.Clicks)
		fmt.Fprintf(b, "xdotool mousemove --sync %d %d click --repeat %d %d\n", spec.X, spec.Y, clicks, mapScrollButton(spec.Direction))
		return nil
	case GUIActionType:
		q, err := execution.QuotePOSIX(spec.Text)
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "xdotool type --clearmodifiers -- %s\n", q)
		return nil
	case GUIActionKey:
		q, err := execution.QuotePOSIX(spec.Key)
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "xdotool key --clearmodifiers -- %s\n", q)
		return nil
	default:
		return ErrInvalidGUIInput
	}
}

func writePointerClick(b *strings.Builder, act GUIActionKind) {
	switch act {
	case GUIActionClick:
		b.WriteString("xdotool click 1\n")
	case GUIActionDoubleClick:
		b.WriteString("xdotool click --repeat 2 1\n")
	case GUIActionRightClick:
		b.WriteString("xdotool click 3\n")
	}
}
func mapScrollButton(dir ScrollDirection) int {
	return pickIf(dir >= ScrollUp && dir <= ScrollRight, int(dir)+3, 5)
}
func writeGUIScreenshotSnippet(b *strings.Builder) error {
	qStart, e1 := execution.QuotePOSIX(screenshotStartMarker)
	qEnd, e2 := execution.QuotePOSIX(screenshotEndMarker)
	if err := firstErr(e1, e2); err != nil {
		return err
	}
	b.WriteString("SHOT=\"$XOPS_TMP/shot.png\"\nif [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v grim >/dev/null 2>&1; then grim \"$SHOT\"\nelif command -v maim >/dev/null 2>&1; then maim \"$SHOT\"\nelif command -v scrot >/dev/null 2>&1; then scrot -o \"$SHOT\"\nelif command -v import >/dev/null 2>&1; then import -window root \"$SHOT\"\nelse echo 'no screenshot tool available' >&2; exit 127; fi\n")
	fmt.Fprintf(b, "printf '%%s\\n' %s\nbase64 < \"$SHOT\" | tr -d '\\r\\n'\nprintf '\\n%%s\\n' %s\n", qStart, qEnd)
	return nil
}

// ExecuteGUI 执行经强 POSIX 校验与能力门控（CapExecute）的远端 GUI 动作，
// 支持纯 Go 截图压缩与可选 ScopedRootFS 产物落盘（物理 0 OperatorReadFS 依赖，供 MCP gui 安全复用）。
func (s *Service) ExecuteGUI(ctx context.Context, req GUIExecRequest) (GUIExecResult, error) {
	defer closeStream(req.OperationStream)
	targetHop, explicitProf, hasProf, script, err := s.validateGUIExecRequest(ctx, req)
	if err != nil {
		return GUIExecResult{}, err
	}
	nodeID := resolveNodeID(targetHop, req.NodeID)
	gateReq, err := buildGUIGateRequest(req, targetHop, nodeID, script)
	if err != nil {
		return GUIExecResult{}, err
	}
	startedAt := s.clock.Now().UTC().Round(0)
	var stdoutRaw, stderrRaw []byte
	var shotOpt algebraic.Option[ProcessedScreenshot]
	var savedArt algebraic.Option[pathalg.LocalRootedDest]

	out, gateErr := runAuthorized[security.CapExecute](ctx, s, req.Plan.PlanDigest(), nodeID, "gui_"+req.Spec.Action.String(), gateReq, req.OperationStream,
		func(authCtx context.Context, _ security.OperationBinding, emitter *obsEmitter) (execution.ExecutionOutcome, error) {
			runCtx, cancel := applyOptionalTimeout(authCtx, req.Timeout)
			defer cancel()
			outTee := &boundedOutputTee{ctx: runCtx, emitter: emitter, kind: events.OutputStreamStdout, limit: maxGUIScriptCaptureBytes}
			errTee := &boundedOutputTee{ctx: runCtx, emitter: emitter, kind: events.OutputStreamStderr, limit: defaultLogMaxBytes}
			buildCmd := func(prof execution.LaunchProfile) (execution.CommandPlan, error) {
				return execution.NewCommandPlan(execution.CommandPlanSpec{
					Kind: execution.PlanKindCommand, Profile: prof, Command: script,
					MaxOutputBytes: algebraic.Some(min(uint64(maxGUIScriptCaptureBytes), execution.MaxAllowedOutputBytes)),
				})
			}
			execOut, execErr := s.execPOSIXInLease(runCtx, req.Plan, targetHop, explicitProf, hasProf, nil, buildCmd, outTee, errTee)
			stdoutRaw, _ = outTee.snapshot()
			stderrRaw, _ = errTee.snapshot()
			if execErr != nil || !isOutcomeSucceeded(execOut) {
				return execOut, execErr
			}
			shotOpt, savedArt, execErr = s.maybeProcessGUIShot(req, stdoutRaw)
			return execOut, execErr
		})
	if gateErr != nil && (out == nil || !out.IsValid()) {
		return GUIExecResult{}, gateErr
	}
	return GUIExecResult{
		action: req.Spec.Action, outcome: out, screenshot: shotOpt, artifact: savedArt,
		stdout: string(stdoutRaw), stderr: string(stderrRaw),
		duration: algebraic.FromStdDuration(max(s.clock.Since(startedAt), 0)), valid: out != nil && out.IsValid(),
	}, gateErr
}

func (s *Service) maybeProcessGUIShot(req GUIExecRequest, stdoutRaw []byte) (algebraic.Option[ProcessedScreenshot], algebraic.Option[pathalg.LocalRootedDest], error) {
	noneShot, noneArt := algebraic.None[ProcessedScreenshot](), algebraic.None[pathalg.LocalRootedDest]()
	if req.Spec.Action != GUIActionScreenshot && !req.Spec.IncludeShot {
		return noneShot, noneArt, nil
	}
	shot, err := ExtractAndProcessScreenshot(stdoutRaw)
	if err != nil {
		return noneShot, noneArt, err
	}
	art, hasArt := req.Artifact.Get()
	if !hasArt {
		return algebraic.Some(shot), noneArt, nil
	}
	if wErr := s.saveGUIArtifact(art, shot.Data); wErr != nil {
		return algebraic.Some(shot), noneArt, wErr
	}
	return algebraic.Some(shot), algebraic.Some(art.File), nil
}

func (s *Service) validateGUIExecRequest(ctx context.Context, req GUIExecRequest) (plan.HopSpec, execution.LaunchProfile, bool, string, error) {
	hop, err := s.validatePlanCall(ctx, req.Plan, req.Risk)
	if err != nil {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, "", err
	}
	prof, hasProf, err := validateRequestedPOSIXProfile(req.Profile)
	if err != nil {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, "", err
	}
	if d, ok := req.Timeout.Get(); ok && !d.IsPositive() {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, "", fmt.Errorf("%w: Timeout 必须为正时长", ErrInvalidRequest)
	}
	if art, hasArt := req.Artifact.Get(); hasArt {
		if !art.RootDir.IsValid() || !art.File.IsValid() {
			return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, "", fmt.Errorf("%w: Artifact 路径无效", ErrInvalidRequest)
		}
		if s.scopedFS == nil {
			return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, "", ErrScopedFSUnavailable
		}
	}
	script, err := BuildGUIScript(req.Spec)
	if err != nil {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, "", err
	}
	return hop, prof, hasProf, script, nil
}

func defaultGUIRisk(spec GUIActionSpec) security.RiskLevel {
	switch spec.Action {
	case GUIActionScreenshot, GUIActionMove:
		return security.RiskSafe
	case GUIActionType, GUIActionKey:
		return security.RiskDangerous
	default:
		return security.RiskModerate
	}
}

func buildGUIGateRequest(req GUIExecRequest, hop plan.HopSpec, nodeID, script string) (gate.GateRequest[security.CapExecute], error) {
	cmdDigest := security.DigestFromSHA256(sha256.Sum256([]byte("xops.observability.gui_script.v1\x00" + script)))
	params := map[string]string{
		"action":       req.Spec.Action.String(),
		"display":      pickIf(req.Spec.Display != "", req.Spec.Display, ":0"),
		"include_shot": strconv.FormatBool(req.Spec.IncludeShot),
	}
	if req.Spec.WaylandDisplay != "" {
		params["wayland_display"] = req.Spec.WaylandDisplay
	}
	// type 与 key 动作明文纳入操作绑定与审批摘要，杜绝盲审注入按键或口令文本。
	if req.Spec.Action == GUIActionType {
		params["text"] = req.Spec.Text
	}
	if req.Spec.Action == GUIActionKey {
		params["key"] = req.Spec.Key
	}
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: toolObservability, Action: "gui_" + req.Spec.Action.String(),
		NodeID: nodeID, Endpoint: algebraic.Some(hop.Endpoint()),
		CommandDigest: algebraic.Some(cmdDigest), PlanDigest: algebraic.Some(req.Plan.PlanDigest().SecurityDigest()),
		Parameters: params,
	})
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapExecute]](), err
	}
	summary := fmt.Sprintf("gui %s on %s", req.Spec.Action, nodeID)
	switch req.Spec.Action {
	case GUIActionType:
		summary = fmt.Sprintf("gui type %q on %s", security.SanitizePromptText(req.Spec.Text), nodeID)
	case GUIActionKey:
		summary = fmt.Sprintf("gui key %s on %s", req.Spec.Key, nodeID)
	}
	return gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding: binding, Risk: req.Risk.OrElse(defaultGUIRisk(req.Spec)),
		ScopeSummary: summary, Approval: req.Approval, OperationStream: req.OperationStream,
	})
}

func (s *Service) saveGUIArtifact(art GUIArtifactDest, data []byte) error {
	if err := s.scopedFS.EnsureRoot(art.RootDir, defaultArtifactDirPerm); err != nil {
		return err
	}
	return s.scopedFS.WithRoot(art.RootDir, func(root ports.RootHandle) error {
		return root.AtomicReplace(art.File, defaultArtifactFilePerm, func(w io.Writer) error {
			_, err := w.Write(data)
			return err
		})
	})
}

func isOutcomeSucceeded(out execution.ExecutionOutcome) bool {
	c, ok := out.(*execution.OutcomeCompleted)
	return ok && c.Succeeded()
}
