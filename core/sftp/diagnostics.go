package sftp

import (
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"

	corelog "github.com/wentf9/xops-cli/core/log"
)

// Diagnostics observe the existing protocol pipes; they never implement,
// validate, retry or modify protocol operations. Memory is fixed per stream.
const (
	diagnosticPrefixLimit     = 16 * 1024
	diagnosticPathLimit       = 512
	diagnosticPathPrefixLimit = 9 + diagnosticPathLimit
)

var diagnosticStreamID atomic.Uint64

type protocolDiagnostics struct {
	observer corelog.DiagnosticObserver
	streamID uint64
}

func newProtocolDiagnostics(observer corelog.DiagnosticObserver) *protocolDiagnostics {
	if !corelog.DiagnosticEnabled(observer, 2) {
		return nil
	}
	return &protocolDiagnostics{observer: observer, streamID: diagnosticStreamID.Add(1)}
}

func (d *protocolDiagnostics) emit(event corelog.Diagnostic) {
	event.StreamID = d.streamID
	corelog.EmitDiagnostic(d.observer, event)
}

func (d *protocolDiagnostics) pipes(rd io.Reader, wr io.WriteCloser) (io.Reader, io.WriteCloser) {
	if d == nil {
		return rd, wr
	}
	return &diagnosticReader{reader: rd, decoder: packetDiagnostics{trace: d, direction: "receive"}},
		&diagnosticWriter{WriteCloser: wr, decoder: packetDiagnostics{trace: d, direction: "send"}}
}

// Each side serializes I/O and observation in the same order. Close deliberately
// delegates directly to the owned pipe, so it can interrupt a blocked Write.
type diagnosticReader struct {
	mu      sync.Mutex
	reader  io.Reader
	decoder packetDiagnostics
}

func (r *diagnosticReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.reader.Read(p)
	r.decoder.feed(p[:n])
	return n, err
}

type diagnosticWriter struct {
	mu sync.Mutex
	io.WriteCloser
	decoder packetDiagnostics
}

func (w *diagnosticWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.WriteCloser.Write(p)
	w.decoder.feed(p[:n])
	return n, err
}

type packetDiagnostics struct {
	trace             *protocolDiagnostics
	direction         string
	header            [4]byte
	headerN           int
	length, remaining uint32
	prefix            [diagnosticPrefixLimit]byte
	prefixN           int
}

func (d *packetDiagnostics) feed(p []byte) {
	for len(p) > 0 {
		if d.headerN < 4 {
			n := copy(d.header[d.headerN:], p)
			d.headerN += n
			p = p[n:]
			if d.headerN < 4 {
				return
			}
			d.length = binary.BigEndian.Uint32(d.header[:])
			d.remaining = d.length
			d.prefixN = 0
			if d.length == 0 {
				d.report()
				d.headerN = 0
				continue
			}
			if len(p) == 0 {
				return
			}
		}
		n := int(min(uint64(len(p)), uint64(d.remaining)))
		// Read the type first, then capture only public metadata. File DATA,
		// WRITE payloads, handles and server error text never enter the prefix.
		if d.prefixN == 0 {
			d.prefix[0] = p[0]
			d.prefixN = 1
			d.remaining--
			p = p[1:]
			n--
		}
		limit := diagnosticCaptureLimit(d.prefix[0])
		d.capture(p[:n], limit)
		d.remaining -= uint32(n)
		p = p[n:]
		if d.remaining == 0 {
			d.report()
			d.headerN = 0
		}
	}
}

func (d *packetDiagnostics) capture(p []byte, limit int) {
	if limit == diagnosticPathPrefixLimit {
		// Capture the string length first, then only the first path or
		// extension name. Do not retain trailing attributes/extension data.
		if d.prefixN < 9 {
			n := copy(d.prefix[d.prefixN:9], p)
			d.prefixN += n
			p = p[n:]
		}
		if d.prefixN < 9 {
			return
		}
		limit = 9 + int(min(binary.BigEndian.Uint32(d.prefix[5:9]), diagnosticPathLimit))
	}
	if d.prefixN < limit {
		d.prefixN += copy(d.prefix[d.prefixN:limit], p)
	}
}

func diagnosticCaptureLimit(kind byte) int {
	switch kind {
	case 2:
		return diagnosticPrefixLimit // VERSION extension metadata
	case 3, 7, 9, 11, 13, 14, 15, 16, 17, 18, 19, 20, 200:
		return diagnosticPathPrefixLimit // request ID and first path/extension name only
	case 101, 103:
		return 9 // STATUS code or DATA length; no message/content
	case 1, 4, 5, 6, 8, 10, 12, 102, 104, 105, 201:
		return 5 // type and request ID (or INIT version)
	default:
		return 1 // unknown types have no assumed request ID or payload layout
	}
}

func (d *packetDiagnostics) report() {
	e := corelog.Diagnostic{Kind: corelog.SFTPPacket, Level: 3, Direction: d.direction, PacketLength: d.length}
	p := d.prefix[:d.prefixN]
	if len(p) == 0 {
		e.Kind = corelog.SFTPMalformed
		d.trace.emit(e)
		return
	}
	e.PacketType = p[0]
	if diagnosticCaptureLimit(p[0]) == 1 {
		d.trace.emit(e)
		return
	}
	if len(p) < 5 {
		e.Kind = corelog.SFTPMalformed
		d.trace.emit(e)
		return
	}
	e.HasPacketID = true
	e.PacketID = binary.BigEndian.Uint32(p[1:5])
	if p[0] == 1 || p[0] == 2 {
		e.ProtocolVersion = e.PacketID
		e.PacketID = 0
		e.HasPacketID = false
	}
	if p[0] == 101 && len(p) >= 9 {
		e.HasStatus = true
		e.StatusCode = binary.BigEndian.Uint32(p[5:9])
	}
	d.trace.emit(e)
	if p[0] == 1 || p[0] == 2 {
		d.version(e, p)
		return
	}
	if d.direction != "send" {
		return
	}
	if diagnosticCaptureLimit(p[0]) != diagnosticPathPrefixLimit {
		return
	}
	value, _, ok := diagnosticString(p[5:])
	if !ok && len(p) < 9 {
		return
	}
	e.Kind, e.Level = corelog.SFTPOperation, 2
	e.Truncated = !ok
	if p[0] == 200 {
		e.Extension = value
	} else {
		e.Path = value
	}
	d.trace.emit(e)
}

// diagnosticString never allocates based on an untrusted wire length. A clipped
// value remains diagnostic metadata; protocol validation stays in the dependency.
func diagnosticString(p []byte) (string, []byte, bool) {
	if len(p) < 4 {
		return "", nil, false
	}
	n := uint64(binary.BigEndian.Uint32(p[:4]))
	p = p[4:]
	if n > uint64(len(p)) {
		return string(p), nil, false
	}
	return string(p[:int(n)]), p[int(n):], true
}

func (d *packetDiagnostics) version(e corelog.Diagnostic, p []byte) {
	e.Kind, e.Level = corelog.SFTPVersion, 2
	e.Truncated = d.length > uint32(len(p))
	d.trace.emit(e)
	if e.PacketType != 2 {
		return
	}
	p = p[5:]
	for len(p) > 0 {
		name, rest, ok := diagnosticString(p)
		if !ok {
			break
		}
		version, rest, ok := diagnosticString(rest)
		if !ok {
			break
		}
		e.Kind = corelog.SFTPExtension
		e.Extension = name
		e.ExtensionVersion = version
		d.trace.emit(e)
		p = rest
	}
}

// stderr is drained by the existing worker. Report its byte count only: server
// text is untrusted and may contain file contents or credentials.
func (d *protocolDiagnostics) stderr(n int64) {
	if d != nil && n > 0 {
		d.emit(corelog.Diagnostic{Kind: corelog.SubsystemStderr, Level: 2, Size: n})
	}
}

func (c *Client) observeFileTransfer(operation, source, destination string, size int64) func(error) {
	e := corelog.Diagnostic{Kind: corelog.FileTransfer, Level: 2, StreamID: c.diagnosticStreamID, Operation: operation, Source: source, Destination: destination, Size: size, Outcome: "starting"}
	corelog.EmitDiagnostic(c.diagnostics, e)
	return func(err error) {
		e.Outcome = "completed"
		if err != nil {
			e.Outcome = "failed"
		}
		corelog.EmitDiagnostic(c.diagnostics, e)
	}
}
