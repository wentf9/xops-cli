package sftpshell

import (
	"bytes"
	"context"
	"sync"
	"time"
	"unicode/utf8"

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

// Capability reports must reach Bubble Tea's event loop directly. Only input
// consumed by the model needs a receipt and replay across prompt boundaries.
func deliverEditorEvent(event uv.Event, send func(tea.Msg), stopped <-chan struct{}) editorReceipt {
	message, keyboard := editorKeyMessage(event)
	if !keyboard {
		send(message)
		return editorReceipt{consumed: true}
	}
	return deliverEditorInput(message, send, stopped)
}

// editorDecoder belongs to the session, but is accessed only while session.prompt
// is held. Prompt shutdown preserves raw bytes instead of forcing decoder EOF.
// A paste stays opaque until its closing marker, including across terminal handoffs.
type editorDecoder struct {
	parser  uv.EventDecoder
	buffer  []byte
	paste   bool
	pending []uv.Event
	endErr  error
}

func (d *editorDecoder) next(expired bool) (uv.Event, bool) {
	if len(d.pending) > 0 {
		message := d.pending[0]
		d.pending = d.pending[1:]
		return message, true
	}
	for len(d.buffer) > 0 {
		if d.paste {
			const end = "\x1b[201~"
			index := bytes.Index(d.buffer, []byte(end))
			if index < 0 {
				return nil, false
			}
			message := uv.PasteEvent{Content: string(d.buffer[:index])}
			d.buffer = d.buffer[index+len(end):]
			d.paste = false
			return message, true
		}
		// Incomplete encodings remain buffered even after the Escape timeout.
		if !utf8.FullRune(d.buffer) {
			return nil, false
		}
		n, event := d.parser.Decode(d.buffer)
		if n == 0 {
			return nil, false
		}
		_, unknown := event.(uv.UnknownEvent)
		if (unknown || n <= 2) && incompleteEditorSequence(d.buffer) {
			return nil, false
		}
		if !expired && (unknown || (d.buffer[0] == '\x1b' && n <= 2)) {
			return nil, false
		}
		d.buffer = d.buffer[n:]
		if _, start := event.(uv.PasteStartEvent); start {
			d.paste = true
			continue
		}
		if events, multi := event.(uv.MultiEvent); multi {
			d.pending = append(d.pending, events...)
			return d.next(expired)
		}
		return event, true
	}
	return nil, false
}

// CSI and SS3 introducers identify structured input. Keep their parameter bytes
// until a final byte arrives; the Escape timeout must not discard a split paste
// opener or arrow key while the next prompt is still starting its renderer.
func incompleteEditorSequence(buffer []byte) bool {
	if len(buffer) < 2 || buffer[0] != '\x1b' || (buffer[1] != '[' && buffer[1] != 'O') {
		return false
	}
	for _, b := range buffer[2:] {
		if b < 0x20 || b > 0x3f {
			return false
		}
	}
	return true
}

// The physical reader is prompt-scoped and joined before releasing the terminal.
// On submission/cancellation, drain prefetched chunks into session state without
// decoding them. Only a real source EOF ends the logical input stream.
func startEditorEvents(ctx context.Context, input *editorInput, session *editorSession, send func(tea.Msg)) func() {
	stopped := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		chunks := make(chan []byte)
		go func() {
			defer close(chunks)
			for {
				buffer := make([]byte, 4096)
				n, err := input.Read(buffer)
				if n > 0 {
					chunks <- buffer[:n]
				}
				if err != nil {
					return
				}
			}
		}()
		decoder := &session.decoder
		defer func() {
			input.Interrupt()
			for chunk := range chunks {
				decoder.buffer = append(decoder.buffer, chunk...)
			}
			if err := input.EndError(); err != nil {
				decoder.endErr = err
			}
		}()
		timer := time.NewTimer(uv.DefaultEscTimeout)
		defer timer.Stop()
		expired := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopped:
				return
			default:
			}
			event, ok := decoder.next(expired)
			if ok {
				receipt := deliverEditorEvent(event, send, stopped)
				if !receipt.consumed {
					decoder.pending = append([]uv.Event{event}, decoder.pending...)
				}
				if !receipt.consumed || receipt.finished {
					return
				}
				continue
			}
			if decoder.endErr != nil {
				deliverEditorInput(editorInputEnded{err: decoder.endErr}, send, stopped)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-stopped:
				return
			case <-timer.C:
				expired = true
			case chunk, open := <-chunks:
				if !open {
					decoder.endErr = input.EndError()
					if decoder.endErr == nil {
						return
					}
					expired = true
					continue
				}
				decoder.buffer = append(decoder.buffer, chunk...)
				expired = false
				timer.Reset(uv.DefaultEscTimeout)
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
