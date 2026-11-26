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

func isGUIKeyChar(b byte) bool { return isAlnumASCII(b) || b == '_' }

// ValidateX11Display 严格校验 X11 DISPLAY 格式（仅允许 ":N" 或 ":N.S"），阻断环境变量与命令注入。
func ValidateX11Display(raw string) error {
	if len(raw) >= 2 && raw[0] == ':' {
		if disp, screen, hasDot := strings.Cut(raw[1:], "."); isASCIIDigits(disp, 1, 4) && (!hasDot || isASCIIDigits(screen, 1, 3)) {
			return nil
		}
	}
	return fmt.Errorf("%w: 非法 X11 DISPLAY %q", ErrInvalidGUIInput, raw)
}

// ValidateWaylandDisplay 严格校验 WAYLAND_DISPLAY 格式（仅允许 "wayland-N"）。
func ValidateWaylandDisplay(raw string) error {
	if num, ok := strings.CutPrefix(raw, "wayland-"); ok && isASCIIDigits(num, 1, 4) {
		return nil
	}
	return fmt.Errorf("%w: 非法 WAYLAND_DISPLAY %q", ErrInvalidGUIInput, raw)
}

// ValidateGUIKeySpec 严格校验按键或组合和弦名称（如 "Return"、"ctrl+c"），拒绝前导 "-"、空白与 Shell 元字符。
func ValidateGUIKeySpec(raw string) error {
	parts := strings.Split(raw, "+")
	if raw == "" || len(raw) > 64 || len(parts) > 5 {
		return fmt.Errorf("%w: 按键规格长度或节数非法 %q", ErrInvalidGUIInput, raw)
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
		if clicks := pickIf(spec.Clicks == 0, 3, spec.Clicks); !spec.Direction.IsValid() || clicks < 1 || clicks > maxGUIClicks {
			return fmt.Errorf("%w: 滚轮方向或步数非法", ErrInvalidGUIInput)
		}
		return nil
	case GUIActionType:
		if spec.Text == "" || len(spec.Text) > maxGUITypeTextBytes || strings.ContainsRune(spec.Text, 0) {
			return fmt.Errorf("%w: type 文本为空、超长或含 NUL", ErrInvalidGUIInput)
		}
		if _, err := execution.QuotePOSIX(spec.Text); err != nil {
			return fmt.Errorf("%w: type 文本含非法控制/Bidi/UTF-8 字符: %w", ErrInvalidGUIInput, err)
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

// BuildGUIScript 为校验通过的 GUIActionSpec 生成硬化 POSIX Bourne 脚本：
// mktemp -d 0700 + trap、分辨率感知归一化坐标换算 [0,1000]->像素、Wayland(ydotool)/X11(xdotool) 双分支与全量 QuotePOSIX。
func BuildGUIScript(spec GUIActionSpec) (string, error) {
	if err := ValidateGUIAction(spec); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("set -eu\nXOPS_TMP=$(mktemp -d)\nchmod 700 \"$XOPS_TMP\"\ntrap 'rm -rf \"$XOPS_TMP\"' EXIT\n")
	if err := writeGUIDisplayEnv(&b, spec); err != nil {
		return "", err
	}
	if guiActionNeedsGeometry(spec.Action) {
		writeGUIGeometryHelpers(&b)
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

func guiActionNeedsGeometry(act GUIActionKind) bool {
	return act >= GUIActionClick && act <= GUIActionScroll
}

const guiGeomHelpers = `xops_wh() { W=$(printf '%s' "$1" | awk -F"$2" 'NF>=2&&$1+0>0&&$2+0>0{print int($1);exit}'); H=$(printf '%s' "$1" | awk -F"$2" 'NF>=2&&$1+0>0&&$2+0>0{print int($2);exit}'); }
xops_geom() {
  W=''; H=''
  if [ -n "${WAYLAND_DISPLAY:-}" ] && command -v wlr-randr >/dev/null 2>&1; then xops_wh "$(wlr-randr 2>/dev/null | awk '/current/{print $1;exit}')" x; fi
  [ -z "$W" ] || [ -z "$H" ] && xops_wh "$(xdotool getdisplaygeometry 2>/dev/null || true)" ' '
  if [ -z "$W" ] || [ -z "$H" ]; then D=$(xdpyinfo 2>/dev/null | awk '/dimensions:/{print $2;exit}'); [ -z "$D" ] && D=$(xrandr --current 2>/dev/null | awk '/\*/{print $1;exit}'); xops_wh "$D" x; fi
  RES_W=${W:-1920}; RES_H=${H:-1080}
}
xops_px() { V=$(( $1 * $2 / 1000 )); [ "$V" -ge "$2" ] && V=$(( $2 - 1 )); [ "$V" -lt 0 ] && V=0; printf '%d' "$V"; }
xops_geom
`

func writeGUIGeometryHelpers(b *strings.Builder) { b.WriteString(guiGeomHelpers) }

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

func writeGUIInputDispatch(b *strings.Builder, waylandCmd, x11Cmd string) {
	fmt.Fprintf(b, "if [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v ydotool >/dev/null 2>&1; then\n  %s\nelif command -v xdotool >/dev/null 2>&1; then\n  %s\nelse\n  echo 'no gui input tool available' >&2; exit 127\nfi\n", waylandCmd, x11Cmd)
}

func writeGUIActionBody(b *strings.Builder, spec GUIActionSpec) error {
	switch spec.Action {
	case GUIActionScreenshot:
		return nil
	case GUIActionClick, GUIActionDoubleClick, GUIActionRightClick, GUIActionMove:
		fmt.Fprintf(b, "PX=$(xops_px %d \"$RES_W\"); PY=$(xops_px %d \"$RES_H\")\n", spec.X, spec.Y)
		wl, x11 := pointerActionCmds(spec.Action)
		writeGUIInputDispatch(b, wl, x11)
		return nil
	case GUIActionDrag:
		fmt.Fprintf(b, "SX=$(xops_px %d \"$RES_W\"); SY=$(xops_px %d \"$RES_H\"); EX=$(xops_px %d \"$RES_W\"); EY=$(xops_px %d \"$RES_H\")\n", spec.StartX, spec.StartY, spec.EndX, spec.EndY)
		writeGUIInputDispatch(b,
			`ydotool mousemove -a -x "$SX" -y "$SY" && ydotool click 0x40 && ydotool mousemove -a -x "$EX" -y "$EY" && ydotool click 0x80`,
			`xdotool mousemove --sync "$SX" "$SY" mousedown 1 mousemove --sync "$EX" "$EY" mouseup 1`)
		return nil
	case GUIActionScroll:
		clicks := pickIf(spec.Clicks == 0, 3, spec.Clicks)
		dx, dy, btn := scrollActionArgs(spec.Direction, clicks)
		fmt.Fprintf(b, "PX=$(xops_px %d \"$RES_W\"); PY=$(xops_px %d \"$RES_H\")\n", spec.X, spec.Y)
		writeGUIInputDispatch(b,
			fmt.Sprintf(`ydotool mousemove -a -x "$PX" -y "$PY" && ydotool mousemove -w -x %d -y %d`, dx, dy),
			fmt.Sprintf(`xdotool mousemove --sync "$PX" "$PY" click --repeat %d %d`, clicks, btn))
		return nil
	case GUIActionType:
		q, err := execution.QuotePOSIX(spec.Text)
		if err != nil {
			return err
		}
		writeGUIInputDispatch(b, "ydotool type -- "+q, "xdotool type --clearmodifiers -- "+q)
		return nil
	case GUIActionKey:
		q, err := execution.QuotePOSIX(spec.Key)
		if err != nil {
			return err
		}
		writeGUIInputDispatch(b, "ydotool key -- "+q, "xdotool key --clearmodifiers -- "+q)
		return nil
	default:
		return ErrInvalidGUIInput
	}
}

func pointerActionCmds(act GUIActionKind) (wl, x11 string) {
	switch act {
	case GUIActionClick:
		return `ydotool mousemove -a -x "$PX" -y "$PY" && ydotool click 0xC0`, `xdotool mousemove --sync "$PX" "$PY" click 1`
	case GUIActionDoubleClick:
		return `ydotool mousemove -a -x "$PX" -y "$PY" && ydotool click --repeat 2 0xC0`, `xdotool mousemove --sync "$PX" "$PY" click --repeat 2 1`
	case GUIActionRightClick:
		return `ydotool mousemove -a -x "$PX" -y "$PY" && ydotool click 0xC1`, `xdotool mousemove --sync "$PX" "$PY" click 3`
	default:
		return `ydotool mousemove -a -x "$PX" -y "$PY"`, `xdotool mousemove --sync "$PX" "$PY"`
	}
}

func scrollActionArgs(dir ScrollDirection, clicks int) (dx, dy, btn int) {
	switch dir {
	case ScrollUp:
		return 0, clicks, 4
	case ScrollDown:
		return 0, -clicks, 5
	case ScrollLeft:
		return -clicks, 0, 6
	default:
		return clicks, 0, 7
	}
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
	prep, err := s.validateGUIExecRequest(ctx, req)
	if err != nil {
		return GUIExecResult{}, err
	}
	nodeID := resolveNodeID(prep.hop, req.NodeID)
	gateReq, err := buildGUIGateRequest(req, prep.hop, nodeID, prep.script)
	if err != nil {
		return GUIExecResult{}, err
	}
	startedAt := s.clock.Now().UTC().Round(0)
	hasShot := req.Spec.Action == GUIActionScreenshot || req.Spec.IncludeShot
	var stdoutClean string
	var stderrRaw []byte
	var shotOpt algebraic.Option[ProcessedScreenshot]
	var savedArt algebraic.Option[pathalg.LocalRootedDest]

	out, gateErr := runAuthorized[security.CapExecute](ctx, s, req.Plan.PlanDigest(), nodeID, "gui_"+req.Spec.Action.String(), gateReq, req.OperationStream,
		func(authCtx context.Context, _ security.OperationBinding, emitter *obsEmitter) (execution.ExecutionOutcome, error) {
			runCtx, cancel := applyOptionalTimeout(authCtx, req.Timeout)
			defer cancel()
			// 含截图采集时静默 stdout 分片发射，避免数十 MB 原始 Base64 灌爆 OperationStream 通道。
			outTee := &boundedOutputTee{ctx: runCtx, emitter: pickIf[*obsEmitter](hasShot, nil, emitter), kind: events.OutputStreamStdout, limit: maxGUIScriptCaptureBytes}
			errTee := &boundedOutputTee{ctx: runCtx, emitter: emitter, kind: events.OutputStreamStderr, limit: defaultLogMaxBytes}
			buildCmd := func(prof execution.LaunchProfile) (execution.CommandPlan, error) {
				return execution.NewCommandPlan(execution.CommandPlanSpec{
					Kind: execution.PlanKindCommand, Profile: prof, Command: prep.script,
					MaxOutputBytes: algebraic.Some(min(uint64(maxGUIScriptCaptureBytes), execution.MaxAllowedOutputBytes)),
				})
			}
			execOut, execErr := s.execPOSIXInLease(runCtx, req.Plan, prep.hop, prep.prof, prep.hasProf, nil, buildCmd, outTee, errTee)
			stdoutRaw, _ := outTee.snapshot()
			stderrRaw, _ = errTee.snapshot()
			stdoutClean = pickIf(hasShot, stripMarkedPayload(string(stdoutRaw)), string(stdoutRaw))
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
		stdout: stdoutClean, stderr: string(stderrRaw), duration: s.elapsed(startedAt), valid: out != nil && out.IsValid(),
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
	if art, hasArt := req.Artifact.Get(); hasArt {
		if wErr := s.saveGUIArtifact(art, shot.Data); wErr != nil {
			return algebraic.Some(shot), noneArt, wErr
		}
		return algebraic.Some(shot), algebraic.Some(art.File), nil
	}
	return algebraic.Some(shot), noneArt, nil
}

type guiExecPrepared struct {
	posixCallBase
	script string
}

func (s *Service) validateGUIExecRequest(ctx context.Context, req GUIExecRequest) (guiExecPrepared, error) {
	base, err := s.validatePOSIXCall(ctx, req.Plan, req.Risk, req.Profile, req.Timeout)
	if err != nil {
		return guiExecPrepared{}, err
	}
	if art, hasArt := req.Artifact.Get(); hasArt {
		if !art.RootDir.IsValid() || !art.File.IsValid() {
			return guiExecPrepared{}, fmt.Errorf("%w: Artifact 路径无效", ErrInvalidRequest)
		}
		if s.scopedFS == nil {
			return guiExecPrepared{}, ErrScopedFSUnavailable
		}
	}
	script, err := BuildGUIScript(req.Spec)
	if err != nil {
		return guiExecPrepared{}, err
	}
	return guiExecPrepared{posixCallBase: base, script: script}, nil
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
	return newObsGateReq[security.CapExecute](security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: toolObservability, Action: "gui_" + req.Spec.Action.String(),
		NodeID: nodeID, Endpoint: algebraic.Some(hop.Endpoint()), CommandDigest: algebraic.Some(cmdDigest),
		PlanDigest: algebraic.Some(req.Plan.PlanDigest().SecurityDigest()), Parameters: buildGUIBindingParams(req),
	}, req.Risk.OrElse(defaultGUIRisk(req.Spec)), buildGUIScopeSummary(req, nodeID), nil, nil, req.Approval, req.OperationStream)
}
func buildGUIBindingParams(req GUIExecRequest) map[string]string {
	params := map[string]string{"action": req.Spec.Action.String(), "display": pickIf(req.Spec.Display != "", req.Spec.Display, ":0"), "include_shot": strconv.FormatBool(req.Spec.IncludeShot)}
	if req.Spec.WaylandDisplay != "" {
		params["wayland_display"] = req.Spec.WaylandDisplay
	}
	if art, ok := req.Artifact.Get(); ok {
		params["artifact_root"], params["artifact_file"] = art.RootDir.String(), art.File.String()
	}
	// 全部动作坐标、按键、文本与落盘目标均纳入操作绑定，彻底杜绝两步审批参数篡改。
	switch req.Spec.Action {
	case GUIActionClick, GUIActionDoubleClick, GUIActionRightClick, GUIActionMove:
		params["x"], params["y"] = strconv.Itoa(req.Spec.X), strconv.Itoa(req.Spec.Y)
	case GUIActionDrag:
		params["start_x"], params["start_y"], params["end_x"], params["end_y"] = strconv.Itoa(req.Spec.StartX), strconv.Itoa(req.Spec.StartY), strconv.Itoa(req.Spec.EndX), strconv.Itoa(req.Spec.EndY)
	case GUIActionScroll:
		params["x"], params["y"], params["direction"], params["clicks"] = strconv.Itoa(req.Spec.X), strconv.Itoa(req.Spec.Y), req.Spec.Direction.String(), strconv.Itoa(pickIf(req.Spec.Clicks == 0, 3, req.Spec.Clicks))
	case GUIActionType:
		params["text"] = req.Spec.Text
	case GUIActionKey:
		params["key"] = req.Spec.Key
	}
	return params
}
func buildGUIScopeSummary(req GUIExecRequest, nodeID string) string {
	summary := fmt.Sprintf("gui %s on %s", req.Spec.Action, nodeID)
	switch req.Spec.Action {
	case GUIActionType:
		summary = fmt.Sprintf("gui type %q on %s", security.SanitizePromptText(req.Spec.Text), nodeID)
	case GUIActionKey:
		summary = fmt.Sprintf("gui key %s on %s", req.Spec.Key, nodeID)
	}
	if art, ok := req.Artifact.Get(); ok {
		summary += " -> " + art.File.String()
	}
	return summary
}
func (s *Service) saveGUIArtifact(art GUIArtifactDest, data []byte) error {
	if err := s.scopedFS.EnsureRoot(art.RootDir, 0o700); err != nil {
		return err
	}
	return s.scopedFS.WithRoot(art.RootDir, func(root ports.RootHandle) error {
		return root.AtomicReplace(art.File, 0o600, func(w io.Writer) error { _, err := w.Write(data); return err })
	})
}
func isOutcomeSucceeded(out execution.ExecutionOutcome) bool {
	c, ok := out.(*execution.OutcomeCompleted)
	return ok && c.Succeeded()
}
