package sftpshell

import (
	"context"
	"os"
	"sync"

	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"
)

type editorInputEnded struct{ err error }
type editorReceipt struct{ consumed, finished bool }
type editorDelivery struct {
	message tea.Msg
	receipt chan editorReceipt
}

// A send alone does not mean the model consumed an event: the program can quit
// between delivery and Update. Acknowledge only after Update changes the model.
func deliverEditorInput(message tea.Msg, send func(tea.Msg), stopped <-chan struct{}) editorReceipt {
	select {
	case <-stopped:
		return editorReceipt{}
	default:
	}
	delivery := editorDelivery{message: message, receipt: make(chan editorReceipt, 1)}
	send(delivery)
	select {
	case receipt := <-delivery.receipt:
		return receipt
	case <-stopped:
		// Run has returned, so an Update that accepted the event has finished.
		select {
		case receipt := <-delivery.receipt:
			return receipt
		default:
			return editorReceipt{}
		}
	}
}

func editorKeyMessage(event uv.Event) (tea.Msg, bool) {
	switch event := event.(type) {
	case uv.KeyPressEvent:
		return tea.KeyPressMsg(event), true
	case uv.KeyReleaseEvent:
		return tea.KeyReleaseMsg(event), true
	case uv.PasteEvent:
		return tea.PasteMsg(event), true
	case uv.PasteStartEvent:
		return tea.PasteStartMsg(event), true
	case uv.PasteEndEvent:
		return tea.PasteEndMsg(event), true
	default:
		return event, false
	}
}

// The session queues unconsumed input across prompts. Stop physical reads at
// submission, but drain the decoder to EOF: canceling its context immediately
// can discard a prefetched byte buffer before it becomes decoded events.
func startEditorEvents(ctx context.Context, input *editorInput, session *editorSession, send func(tea.Msg)) func() {
	stopped := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		pending := session.takeInput()
		for i, message := range pending {
			receipt := deliverEditorInput(message, send, stopped)
			if !receipt.consumed || receipt.finished {
				if receipt.consumed {
					i++
				}
				session.retainInput(pending[i:])
				return
			}
		}
		// Parent cancellation interrupts input through the runner. This context is
		// canceled after the joined decoder drains, rather than discarding bytes.
		decodeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		defer cancel()
		events := make(chan uv.Event)
		readDone := make(chan error, 1)
		go func() {
			reader := uv.NewTerminalReader(input, os.Getenv("TERM"))
			readDone <- reader.StreamEvents(decodeCtx, events)
			close(events)
		}()
		active := true
		for event := range events {
			message, keyboard := editorKeyMessage(event)
			if !keyboard {
				if active {
					send(event)
				}
				continue
			}
			var receipt editorReceipt
			if active {
				receipt = deliverEditorInput(message, send, stopped)
			}
			if !receipt.consumed {
				session.retainInput([]tea.Msg{message})
			}
			if !receipt.consumed || receipt.finished {
				active = false
				input.Interrupt()
			}
		}
		err := <-readDone
		if err == nil {
			err = input.EndError()
		}
		if err != nil {
			message := editorInputEnded{err: err}
			if !active || !deliverEditorInput(message, send, stopped).consumed {
				session.retainInput([]tea.Msg{message})
			}
		}
	}()
	return sync.OnceFunc(func() {
		close(stopped)
		input.Interrupt()
		<-done
		input.Wait()
	})
}
