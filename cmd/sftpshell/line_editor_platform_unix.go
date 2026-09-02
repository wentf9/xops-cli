//go:build !windows

package sftpshell

import (
	"context"
	"io"
	"time"

	"github.com/chzyer/readline"
)

type lineEditorPlatform struct {
	ready chan struct{}
}

func newLineEditorPlatform(io.Reader) *lineEditorPlatform {
	return &lineEditorPlatform{ready: make(chan struct{})}
}

func (*lineEditorPlatform) configure(*readline.Config) {}

func (p *lineEditorPlatform) start(ctx context.Context, instance *readline.Instance) {
	go p.waitForTerminalReader(ctx, instance)
}

// waitForTerminalReader establishes that readline's internal terminal
// goroutine has registered itself before Close is allowed to call into it.
// readline v1.5.1 registers its WaitGroup inside that goroutine; closing any
// earlier races with Wait. Unix keeps the existing eager read because its
// cancellable prompt input does not alter terminal echo before Prompt.
func (p *lineEditorPlatform) waitForTerminalReader(ctx context.Context, instance *readline.Instance) {
	instance.Terminal.KickRead()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	ctxDone := ctx.Done()
	for !instance.Terminal.IsReading() {
		select {
		case <-ctxDone:
			// The owner calls Close after cancellation. Keep waiting until
			// readline has registered its WaitGroup so Close cannot race Add.
			ctxDone = nil
		case <-ticker.C:
		}
	}
	close(p.ready)
}

func (*lineEditorPlatform) preparePrompt() error {
	return nil
}

func (*lineEditorPlatform) finishPrompt(err error) error {
	return err
}

func (p *lineEditorPlatform) waitBeforeClose() {
	<-p.ready
}

func (*lineEditorPlatform) prepareInstanceClose(*readline.Instance, bool) {}
