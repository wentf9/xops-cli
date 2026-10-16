package sftp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	corelog "github.com/wentf9/xops-cli/core/log"
)

type protocolRecorder struct {
	mu     sync.Mutex
	events []corelog.Diagnostic
	level  int
}

func (r *protocolRecorder) DiagnosticLevel() int { return r.level }
func (r *protocolRecorder) ObserveDiagnostic(e corelog.Diagnostic) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}
func (r *protocolRecorder) snapshot() []corelog.Diagnostic {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]corelog.Diagnostic(nil), r.events...)
}

func diagnosticTestPacket(kind byte, id uint32, body []byte) []byte {
	p := make([]byte, 9+len(body))
	binary.BigEndian.PutUint32(p, uint32(5+len(body)))
	p[4] = kind
	binary.BigEndian.PutUint32(p[5:], id)
	copy(p[9:], body)
	return p
}
func diagnosticTestString(value string) []byte {
	p := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(p, uint32(len(value)))
	copy(p[4:], value)
	return p
}

func TestProtocolDiagnosticsFragmentedMetadata(t *testing.T) {
	for _, fragment := range []int{1, 2, 4, 7, 1024} {
		t.Run(fmt.Sprint(fragment), func(t *testing.T) {
			r := &protocolRecorder{level: 3}
			trace := newProtocolDiagnostics(r)
			d := packetDiagnostics{trace: trace, direction: "receive"}
			version := append(diagnosticTestString("custom-extension@fixture"), diagnosticTestString("v1")...)
			wire := append(diagnosticTestPacket(2, 3, version), diagnosticTestPacket(101, 47, []byte{0, 0, 0, 2})...)
			for len(wire) > 0 {
				n := min(fragment, len(wire))
				d.feed(wire[:n])
				wire = wire[n:]
			}
			events := r.snapshot()
			if len(events) != 4 {
				t.Fatalf("events: %+v", events)
			}
			if events[1].Kind != corelog.SFTPVersion || events[1].ProtocolVersion != 3 || events[2].Extension != "custom-extension@fixture" || events[2].ExtensionVersion != "v1" {
				t.Fatalf("version/extensions: %+v", events)
			}
			status := events[3]
			if status.PacketID != 47 || !status.HasStatus || status.StatusCode != 2 || status.StreamID != trace.streamID || status.Direction != "receive" {
				t.Fatalf("status: %+v", status)
			}
		})
	}
}

func TestProtocolDiagnosticsNeverCapturePayload(t *testing.T) {
	secret := "file-content-or-handle-MUST-NOT-LEAK"
	for _, kind := range []byte{4, 5, 6, 8, 10, 12, 101, 102, 103, 104, 105, 201, 255} {
		r := &protocolRecorder{level: 3}
		d := packetDiagnostics{trace: newProtocolDiagnostics(r), direction: "send"}
		body := diagnosticTestString(strings.Repeat(secret, 1000))
		d.feed(diagnosticTestPacket(kind, 7, body))
		if bytes.Contains(d.prefix[:], []byte(secret)) || strings.Contains(fmt.Sprint(r.snapshot()), secret) {
			t.Fatalf("type %d retained payload", kind)
		}
	}
	// Extension request arguments are opaque and may contain file data.
	r := &protocolRecorder{level: 3}
	d := packetDiagnostics{trace: newProtocolDiagnostics(r), direction: "send"}
	d.feed(diagnosticTestPacket(200, 9, append(diagnosticTestString("custom"), []byte(secret)...)))
	if bytes.Contains(d.prefix[:], []byte(secret)) || strings.Contains(fmt.Sprint(r.snapshot()), secret) {
		t.Fatal("extension payload retained")
	}
}

func TestProtocolDiagnosticsOnlyKnownRequestIDs(t *testing.T) {
	r := &protocolRecorder{level: 3}
	d := packetDiagnostics{trace: newProtocolDiagnostics(r), direction: "receive"}
	for _, kind := range []byte{1, 2, 255, 101} {
		d.feed(diagnosticTestPacket(kind, 99, []byte{0, 0, 0, 0}))
	}
	for _, event := range r.snapshot() {
		if event.Kind != corelog.SFTPPacket {
			continue
		}
		if event.HasPacketID != (event.PacketType == 101) {
			t.Fatalf("invented/missing request ID: %+v", event)
		}
		if event.PacketType == 255 && event.PacketID != 0 {
			t.Fatalf("unknown layout decoded: %+v", event)
		}
	}
}

func TestProtocolDiagnosticsLimitsAndLevels(t *testing.T) {
	if newProtocolDiagnostics(&protocolRecorder{level: 1}) != nil {
		t.Fatal("DEBUG1 installed a packet decoder")
	}
	r := &protocolRecorder{level: 2}
	d := packetDiagnostics{trace: newProtocolDiagnostics(r), direction: "send"}
	d.feed(diagnosticTestPacket(3, 8, diagnosticTestString(strings.Repeat("p", 100000))))
	events := r.snapshot()
	if len(events) != 1 || events[0].Kind != corelog.SFTPOperation || !events[0].Truncated || len(events[0].Path) != 512 {
		t.Fatalf("clipped operation: %+v", events)
	}
	if d.prefixN != 521 {
		t.Fatalf("capture size: %d", d.prefixN)
	}
	r = &protocolRecorder{level: 3}
	d = packetDiagnostics{trace: newProtocolDiagnostics(r), direction: "receive"}
	d.feed([]byte{0, 0, 0, 0, 0, 0, 0, 1, 101})
	if len(r.snapshot()) != 2 {
		t.Fatalf("zero/short packet handling: %+v", r.snapshot())
	}
	// An untrusted 4 GiB length must not allocate a matching buffer.
	d.feed([]byte{255, 255, 255, 255, 103, 0, 0, 0, 1})
	if d.prefixN != 5 || d.remaining != ^uint32(0)-5 {
		t.Fatal("oversized length corrupted decoder state")
	}
}

type diagnosticShortWriter struct {
	data   bytes.Buffer
	closed bool
}

func (w *diagnosticShortWriter) Write(p []byte) (int, error) {
	n := min(len(p), 3)
	_, _ = w.data.Write(p[:n])
	return n, io.ErrShortWrite
}
func (w *diagnosticShortWriter) Close() error { w.closed = true; return nil }

func TestDiagnosticPipesPreserveIOAndOwnership(t *testing.T) {
	r := &protocolRecorder{level: 3}
	trace := newProtocolDiagnostics(r)
	wire := diagnosticTestPacket(1, 3, nil)
	writer := &diagnosticShortWriter{}
	rd, wr := trace.pipes(bytes.NewReader(wire), writer)
	got, err := io.ReadAll(rd)
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("Read changed: %x %v", got, err)
	}
	n, err := wr.Write(wire)
	if n != 3 || !errors.Is(err, io.ErrShortWrite) || !bytes.Equal(writer.data.Bytes(), wire[:3]) {
		t.Fatalf("Write changed: %d %v", n, err)
	}
	if writer.closed {
		t.Fatal("observer closed the pipe")
	}
	if err := wr.Close(); err != nil || !writer.closed {
		t.Fatalf("Close not delegated: %v", err)
	}
	if len(r.snapshot()) != 2 {
		t.Fatalf("partially written packet reported complete: %+v", r.snapshot())
	}
}

func TestDiagnosticParallelStreams(t *testing.T) {
	r := &protocolRecorder{level: 3}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			d := packetDiagnostics{trace: newProtocolDiagnostics(r), direction: "send"}
			for i := range 100 {
				d.feed(diagnosticTestPacket(4, uint32(i), nil))
			}
		})
	}
	workers.Wait()
	streams := map[uint64]int{}
	for _, e := range r.snapshot() {
		streams[e.StreamID]++
	}
	if len(streams) != 8 {
		t.Fatalf("stream IDs collided: %v", streams)
	}
	for _, n := range streams {
		if n != 100 {
			t.Fatalf("packets missing: %v", streams)
		}
	}
}

type diagnosticBlockingWriter struct {
	io.WriteCloser
	started chan struct{}
}

func (w diagnosticBlockingWriter) Write(p []byte) (int, error) {
	close(w.started)
	return w.WriteCloser.Write(p)
}

func TestDiagnosticWriterCloseInterruptsBlockedWrite(t *testing.T) {
	reader, writer := io.Pipe()
	started := make(chan struct{})
	trace := newProtocolDiagnostics(&protocolRecorder{level: 3})
	_, wrapped := trace.pipes(reader, diagnosticBlockingWriter{writer, started})
	written := make(chan error, 1)
	closed := make(chan error, 1)
	go func() { _, err := wrapped.Write(diagnosticTestPacket(1, 3, nil)); written <- err }()
	<-started
	go func() { closed <- wrapped.Close() }()
	// Cleanup closes the owned reader before joining either worker, even if
	// Close incorrectly waited on the observer's in-flight Write mutex.
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
		<-written
		<-closed
	}()
	select {
	case err := <-closed:
		closed <- err
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited for blocked observed Write")
	}
	select {
	case err := <-written:
		written <- err
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("write error lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write outlived pipe closure")
	}
}

type protocolFuzzObserver struct{}

func (protocolFuzzObserver) ObserveDiagnostic(corelog.Diagnostic) {}

func FuzzProtocolDiagnostics(f *testing.F) {
	f.Add(diagnosticTestPacket(2, 3, append(diagnosticTestString("ext"), diagnosticTestString("1")...)))
	f.Add([]byte{0, 0, 0, 0, 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, p []byte) {
		d := packetDiagnostics{trace: newProtocolDiagnostics(protocolFuzzObserver{}), direction: "receive"}
		for len(p) > 0 {
			n := min(7, len(p))
			d.feed(p[:n])
			p = p[n:]
		}
		if d.prefixN > diagnosticPrefixLimit {
			t.Fatal("unbounded capture")
		}
	})
}
