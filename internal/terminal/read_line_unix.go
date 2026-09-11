//go:build !windows

package terminal

import "context"

func (p *stdPrompter) readPromptLine(ctx context.Context, input PromptInput) (string, error) {
	return p.readLineLoop(ctx, input)
}
