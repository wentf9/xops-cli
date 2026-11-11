//go:build !windows

package cmd

import (
	"context"
	"os/exec"
)

var defaultSystemAskpassCandidates = []string{
	"ssh-askpass",
	"/usr/libexec/openssh/ssh-askpass",
	"/usr/lib/openssh/ssh-askpass",
	"/usr/lib/ssh/ssh-askpass",
	"/usr/bin/ssh-askpass",
	"/usr/X11R6/bin/ssh-askpass",
}

func findSystemAskpass() string {
	for _, candidate := range defaultSystemAskpassCandidates {
		if path, err := exec.LookPath(candidate); err == nil && path != "" {
			return path
		}
	}
	return ""
}

func buildAskpassCommand(ctx context.Context, askpassProg, prompt string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, askpassProg, prompt), nil
}
