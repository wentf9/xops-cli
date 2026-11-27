package tools

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	ucobs "github.com/wentf9/xops-cli/core/internal/usecase/observability"
)

type guiArgs struct {
	Action               string                                                `json:"action"`
	Target               string                                                `json:"target,omitzero"`
	Handle               algebraic.Option[plan.ManagedHandle[plan.KindTunnel]] `json:"handle,omitzero"`
	HandleToken          string                                                `json:"handle_token,omitzero"`
	GUIAction            string                                                `json:"gui_action,omitzero"`
	Display              string                                                `json:"display,omitzero"`
	WaylandDisplay       string                                                `json:"wayland_display,omitzero"`
	X                    int                                                   `json:"x,omitzero"`
	Y                    int                                                   `json:"y,omitzero"`
	StartX               int                                                   `json:"start_x,omitzero"`
	StartY               int                                                   `json:"start_y,omitzero"`
	EndX                 int                                                   `json:"end_x,omitzero"`
	EndY                 int                                                   `json:"end_y,omitzero"`
	Clicks               int                                                   `json:"clicks,omitzero"`
	Direction            string                                                `json:"direction,omitzero"`
	Text                 string                                                `json:"text,omitzero"`
	Key                  string                                                `json:"key,omitzero"`
	IncludeShot          bool                                                  `json:"include_shot,omitzero"`
	ArtifactFile         string                                                `json:"artifact_file,omitzero"`
	Timeout              algebraic.Option[algebraic.Duration]                  `json:"timeout,omitzero"`
	SessionKind          string                                                `json:"session_kind,omitzero"`
	DisplayNum           int                                                   `json:"display_num,omitzero"`
	UseUnixSocket        bool                                                  `json:"use_unix_socket,omitzero"`
	AllowNonLoopbackBind bool                                                  `json:"allow_non_loopback_bind,omitzero"`
	LocalBindHost        string                                                `json:"local_bind_host,omitzero"`
	LocalBindPort        uint16                                                `json:"local_bind_port,omitzero"`
	Risk                 algebraic.Option[security.RiskLevel]                  `json:"risk,omitzero"`
	Approval             algebraic.Option[protocol.ApprovalSubmissionDTO]      `json:"approval,omitzero"`
}

func (r *Registry) callGUI(ctx context.Context, rawArgs jsontext.Value) (protocol.CallToolResult, error) {
	if r.observability == nil {
		return protocol.CallToolResult{}, domi18n.EF(ErrServiceUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "ObservabilityService"))
	}
	args, err := decodeToolArgs[guiArgs](rawArgs)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	risk, approval, err := validateApprovalAndRisk(args.Risk, args.Approval)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	switch args.Action {
	case "exec":
		return r.guiExec(ctx, args, risk, approval)
	case "open_session":
		return r.guiOpenSession(ctx, args, risk, approval)
	case "inspect_session", "close_session":
		return r.guiManageSession(ctx, args)
	default:
		return protocol.CallToolResult{}, domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "gui action"), domi18n.BoundStr("value", args.Action))
	}
}

func (r *Registry) resolveGUIArtifact(artifactFile string) (algebraic.Option[ucobs.GUIArtifactDest], error) {
	if strings.TrimSpace(artifactFile) == "" {
		return algebraic.None[ucobs.GUIArtifactDest](), nil
	}
	rootDir, okRoot := r.artifactRoot.Get()
	if !okRoot {
		rootDir, okRoot = r.transferRoot.Get()
	}
	if !okRoot || !rootDir.IsValid() {
		return algebraic.None[ucobs.GUIArtifactDest](), domi18n.EF(ucobs.ErrScopedFSUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "ArtifactRoot/TransferRoot"))
	}
	dest, err := pathalg.ParseLocalRootedDest(artifactFile)
	if err != nil {
		return algebraic.None[ucobs.GUIArtifactDest](), domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "artifact_file"))
	}
	return algebraic.Some(ucobs.GUIArtifactDest{RootDir: rootDir, File: dest}), nil
}

func parseOptionalScrollDir(raw string) (ucobs.ScrollDirection, error) {
	if raw == "" {
		return ucobs.ScrollDirectionInvalid, nil
	}
	dir, err := ucobs.ParseScrollDirection(raw)
	if err != nil {
		return ucobs.ScrollDirectionInvalid, domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "direction"))
	}
	return dir, nil
}

func (r *Registry) guiExec(
	ctx context.Context,
	args guiArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	resolved, err := r.resolveTarget(ctx, args.Target, option.UnsetOptionLayer())
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	actionKind, err := ucobs.ParseGUIActionKind(args.GUIAction)
	if err != nil {
		return protocol.CallToolResult{}, domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "gui_action"))
	}
	scrollDir, err := parseOptionalScrollDir(args.Direction)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	artOpt, err := r.resolveGUIArtifact(args.ArtifactFile)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	res, err := r.observability.ExecuteGUI(ctx, ucobs.GUIExecRequest{
		Plan:   resolved.Plan(),
		NodeID: resolved.NodeID(),
		Spec: ucobs.GUIActionSpec{
			Action:         actionKind,
			Display:        args.Display,
			WaylandDisplay: args.WaylandDisplay,
			X:              args.X,
			Y:              args.Y,
			StartX:         args.StartX,
			StartY:         args.StartY,
			EndX:           args.EndX,
			EndY:           args.EndY,
			Clicks:         args.Clicks,
			Direction:      scrollDir,
			Text:           args.Text,
			Key:            args.Key,
			IncludeShot:    args.IncludeShot,
		},
		Artifact: artOpt,
		Timeout:  args.Timeout,
		Risk:     risk,
		Approval: approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	var extra []protocol.ContentBlock
	if shot, hasShot := res.Screenshot().Get(); hasShot && len(shot.Data) > 0 {
		extra = append(extra, protocol.NewImageContent(shot.MIMEType, base64.StdEncoding.EncodeToString(shot.Data)))
	}
	return protocol.NewToolSuccessResult(struct {
		Action     ucobs.GUIActionKind                         `json:"gui_action"`
		Outcome    outcomeJSON                                 `json:"outcome"`
		Stdout     string                                      `json:"stdout,omitzero"`
		Stderr     string                                      `json:"stderr,omitzero"`
		Duration   algebraic.Duration                          `json:"duration"`
		Artifact   algebraic.Option[pathalg.LocalRootedDest]   `json:"artifact,omitzero"`
		Screenshot algebraic.Option[ucobs.ProcessedScreenshot] `json:"screenshot,omitzero"`
	}{
		Action:     res.Action(),
		Outcome:    outcomeJSON{outcome: res.Outcome()},
		Stdout:     res.Stdout(),
		Stderr:     res.Stderr(),
		Duration:   res.Duration(),
		Artifact:   res.Artifact(),
		Screenshot: res.Screenshot(),
	}, extra...)
}

func (r *Registry) guiOpenSession(
	ctx context.Context,
	args guiArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	resolved, err := r.resolveTarget(ctx, args.Target, option.UnsetOptionLayer())
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	kind, err := ucobs.ParseGUISessionKind(args.SessionKind)
	if err != nil {
		return protocol.CallToolResult{}, domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "session_kind"))
	}
	info, err := r.observability.OpenGUISession(ctx, ucobs.OpenGUISessionRequest{
		Plan:   resolved.Plan(),
		NodeID: resolved.NodeID(),
		Spec: ucobs.GUISessionSpec{
			Kind:                 kind,
			DisplayNum:           args.DisplayNum,
			UseUnixSocket:        args.UseUnixSocket,
			AllowNonLoopbackBind: args.AllowNonLoopbackBind,
			LocalBindHost:        args.LocalBindHost,
			LocalBindPort:        args.LocalBindPort,
		},
		Risk:     risk,
		Approval: approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	r.mu.Lock()
	tok := storeHandleMap(r.guiHandles, r.maxHandles, info.Handle())
	r.mu.Unlock()
	return protocol.NewToolSuccessResult(struct {
		Handle       plan.ManagedHandle[plan.KindTunnel] `json:"handle"`
		HandleToken  string                              `json:"handle_token"`
		Kind         ucobs.GUISessionKind                `json:"session_kind"`
		DisplayNum   int                                 `json:"display_num"`
		BoundAddr    string                              `json:"bound_addr"`
		RemoteTarget string                              `json:"remote_target"`
	}{info.Handle(), tok, info.Kind(), info.DisplayNum(), info.BoundAddr(), info.RemoteTarget()})
}

func (r *Registry) guiManageSession(ctx context.Context, args guiArgs) (protocol.CallToolResult, error) {
	h, err := resolveHandleArg(&r.mu, r.guiHandles, args.Handle, args.HandleToken)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	if args.Action == "close_session" {
		if err := r.observability.CloseGUISession(ctx, h); err != nil {
			return protocol.CallToolResult{}, err
		}
		r.mu.Lock()
		delete(r.guiHandles, h.String())
		r.mu.Unlock()
		return protocol.NewToolSuccessResult(struct {
			Closed      bool   `json:"closed"`
			HandleToken string `json:"handle_token"`
		}{true, h.String()})
	}
	st, err := r.observability.InspectGUISession(ctx, h)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		HandleToken  string               `json:"handle_token"`
		Active       bool                 `json:"active"`
		Kind         ucobs.GUISessionKind `json:"session_kind"`
		DisplayNum   int                  `json:"display_num"`
		BoundAddr    string               `json:"bound_addr"`
		RemoteTarget string               `json:"remote_target"`
	}{h.String(), st.Active(), st.Kind(), st.DisplayNum(), st.BoundAddr(), st.RemoteTarget()})
}
