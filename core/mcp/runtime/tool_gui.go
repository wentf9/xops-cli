package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/gui"
	"github.com/wentf9/xops-cli/core/mcp/ports"
)

type GUIInput struct {
	NodeID string `json:"nodeID" jsonschema:"Target SSH node ID or alias"`
	Action string `json:"action" jsonschema:"GUI action: shot, click, double_click, right_click, move, type, key, scroll, or drag"`
	Coord  []int  `json:"coord,omitempty" jsonschema:"Normalized 0-1000 coordinates: [x, y] for click/move/scroll, or [start_x, start_y, end_x, end_y] for drag"`
	Text   string `json:"text,omitempty" jsonschema:"Text to input for type, key combination for key (e.g. ctrl+c, Return), or direction for scroll (up, down, left, right)"`
}

type GUIOutput struct {
	Action   string `json:"action" jsonschema:"Executed GUI action"`
	MimeType string `json:"mimeType" jsonschema:"Screenshot image MIME type"`
	Status   string `json:"status" jsonschema:"Operation status"`
}

func (r *Runtime) guiHandler(ctx context.Context, _ *mcp.CallToolRequest, input GUIInput) (*mcp.CallToolResult, GUIOutput, error) {
	if input.NodeID == "" || input.Action == "" {
		return nil, GUIOutput{}, errors.New("nodeID and action are required")
	}
	script, err := gui.BuildScript(gui.Request{Action: input.Action, Coord: input.Coord, Text: input.Text})
	if err != nil {
		return nil, GUIOutput{}, err
	}
	op, err := currentOperation(ctx)
	if err != nil {
		return nil, GUIOutput{}, err
	}

	res, execErr := r.backend.Run(ctx, op.permit, input.NodeID, ports.Command{
		Text:         script,
		Execution:    op.execution.Clone(),
		RequirePOSIX: true,
		OutputLimit:  gui.CaptureOutputLimit,
	})
	if execErr != nil {
		return nil, GUIOutput{}, fmt.Errorf("gui action %q failed: %w", input.Action, FormatMCPError(execErr))
	}
	if res.Truncated {
		return nil, GUIOutput{}, fmt.Errorf("gui action %q: screenshot exceeds %d bytes of captured output", input.Action, gui.CaptureOutputLimit)
	}

	imgBytes, mimeType, err := gui.ExtractAndProcessImage(res.Output)
	if err != nil {
		return nil, GUIOutput{}, fmt.Errorf("process gui screenshot: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.ImageContent{Data: imgBytes, MIMEType: mimeType}},
	}, GUIOutput{
		Action:   input.Action,
		MimeType: mimeType,
		Status:   "success",
	}, nil
}

// guiRiskInput exposes typed text to the guardrail: typing into a terminal
// window is equivalent to running a command, so it is classified, matched
// against blocked patterns, shown in approvals, and recorded in audit details.
func guiRiskInput(in GUIInput) guardrail.RiskInput {
	ri := guardrail.RiskInput{Action: in.Action, NodeID: in.NodeID}
	switch in.Action {
	case gui.ActionType:
		ri.Text = in.Text
		ri.Details = fmt.Sprintf("text=%q", in.Text)
	case gui.ActionKey:
		ri.Text = in.Text
		ri.Details = fmt.Sprintf("key=%q", in.Text)
	}
	return ri
}

func (r *Runtime) registerGUI(server *mcp.Server, g *guardrail.Guardrail) {
	destructive := true
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "gui",
			Description: "Visual desktop automation (Computer Use) on a remote Linux SSH node (X11, or Wayland with ydotool/grim). Uses 0-1000 normalized coordinates and returns a compressed screenshot (longest edge <= 1280px) after every action. Keyboard actions ('type', 'key') are rated Dangerous and require approval under the default policy.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive},
		},
		withOperation(r, g, "gui", guiRiskInput, r.guiHandler),
	)
}
