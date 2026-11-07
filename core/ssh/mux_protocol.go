package ssh

import (
	"encoding/binary"
	"fmt"
	"io"
	"slices"
)

// OpenSSH PROTOCOL.mux version 4.
const (
	MuxProtoVersion    uint32 = 4
	MuxProtocolVersion uint32 = 4
)

// Client -> Master request message types.
const (
	MUX_MSG_HELLO        uint32 = 0x00000001
	MUX_C_NEW_SESSION    uint32 = 0x10000002
	MUX_C_ALIVE_CHECK    uint32 = 0x10000004
	MUX_C_TERMINATE      uint32 = 0x10000005
	MUX_C_OPEN_FWD       uint32 = 0x10000006
	MUX_C_CLOSE_FWD      uint32 = 0x10000007
	MUX_C_NEW_STDIO_FWD  uint32 = 0x10000008
	MUX_C_STOP_LISTENING uint32 = 0x10000009
	MUX_C_PROXY          uint32 = 0x1000000f
	MUX_C_EXT_INFO       uint32 = 0x20000001
)

// Master -> Client response message types.
const (
	MUX_S_OK                uint32 = 0x80000001
	MUX_S_PERMISSION_DENIED uint32 = 0x80000002
	MUX_S_FAILURE           uint32 = 0x80000003
	MUX_S_EXIT_MESSAGE      uint32 = 0x80000004
	MUX_S_ALIVE             uint32 = 0x80000005
	MUX_S_SESSION_OPENED    uint32 = 0x80000006
	MUX_S_REMOTE_PORT       uint32 = 0x80000007
	MUX_S_TTY_ALLOC_FAIL    uint32 = 0x80000008
	MUX_S_PROXY             uint32 = 0x8000000f
	MUX_S_EXT_INFO          uint32 = 0x90000001
)

// Forwarding types.
const (
	MUX_FWD_LOCAL   uint32 = 1
	MUX_FWD_REMOTE  uint32 = 2
	MUX_FWD_DYNAMIC uint32 = 3
)

// MUX_SPECIAL_PORT_UNIX indicates a Unix domain socket path rather than a TCP port.
const MUX_SPECIAL_PORT_UNIX uint32 = 0xfffffffe

// Packet limits to defend against resource exhaustion DOS.
const (
	MaxMuxPacketLength = 256 * 1024 // 256 KB
	MaxMuxStringLength = 64 * 1024  // 64 KB
)

// ReadMuxPacket reads a single framed MUX packet from r.
// Wire format:
//
//	uint32 packet_length (big-endian: 4 bytes type + payload length)
//	uint32 packet_type   (big-endian opcode)
//	bytes  payload
func ReadMuxPacket(r io.Reader) (packetType uint32, payload []byte, err error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	pktLen := binary.BigEndian.Uint32(header[0:4])
	if pktLen < 4 {
		return 0, nil, fmt.Errorf("invalid mux packet length %d (must be >= 4)", pktLen)
	}
	if pktLen > MaxMuxPacketLength {
		return 0, nil, fmt.Errorf("mux packet length %d exceeds maximum %d", pktLen, MaxMuxPacketLength)
	}

	packetType = binary.BigEndian.Uint32(header[4:8])
	payloadLen := pktLen - 4
	if payloadLen == 0 {
		return packetType, nil, nil
	}

	payload = make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("failed to read mux packet payload: %w", err)
	}
	return packetType, payload, nil
}

// WriteMuxPacket writes a single framed MUX packet to w in a single atomic Write call.
func WriteMuxPacket(w io.Writer, packetType uint32, payload []byte) error {
	totalLen := 4 + len(payload)
	if totalLen > MaxMuxPacketLength {
		return fmt.Errorf("mux packet length %d exceeds maximum %d", totalLen, MaxMuxPacketLength)
	}
	buf := make([]byte, 4+totalLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.BigEndian.PutUint32(buf[4:8], packetType)
	copy(buf[8:], payload)
	_, err := w.Write(buf)
	return err
}

type muxWriter struct {
	buf []byte
}

func newMuxWriter() *muxWriter {
	return &muxWriter{buf: make([]byte, 0, 128)}
}

func (w *muxWriter) WriteUint32(v uint32) {
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *muxWriter) WriteBool(b bool) {
	if b {
		w.buf = append(w.buf, 1)
	} else {
		w.buf = append(w.buf, 0)
	}
}

func (w *muxWriter) WriteString(s string) {
	w.WriteUint32(uint32(len(s)))
	w.buf = append(w.buf, s...)
}

func (w *muxWriter) WriteBytes(p []byte) {
	w.WriteUint32(uint32(len(p)))
	w.buf = append(w.buf, p...)
}

func (w *muxWriter) Bytes() []byte {
	return w.buf
}

type muxReader struct {
	data []byte
	off  int
}

func newMuxReader(data []byte) *muxReader {
	return &muxReader{data: data, off: 0}
}

func (r *muxReader) Remaining() int {
	return len(r.data) - r.off
}

func (r *muxReader) ReadUint32() (uint32, error) {
	if r.Remaining() < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.BigEndian.Uint32(r.data[r.off : r.off+4])
	r.off += 4
	return v, nil
}

func (r *muxReader) ReadBool() (bool, error) {
	if r.Remaining() < 1 {
		return false, io.ErrUnexpectedEOF
	}
	b := r.data[r.off] != 0
	r.off += 1
	return b, nil
}

func (r *muxReader) ReadString() (string, error) {
	n, err := r.ReadUint32()
	if err != nil {
		return "", err
	}
	if n > MaxMuxStringLength {
		return "", fmt.Errorf("string length %d exceeds maximum %d", n, MaxMuxStringLength)
	}
	if r.Remaining() < int(n) {
		return "", io.ErrUnexpectedEOF
	}
	s := string(r.data[r.off : r.off+int(n)])
	r.off += int(n)
	return s, nil
}

func (r *muxReader) ReadBytes() ([]byte, error) {
	n, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	if n > MaxMuxPacketLength {
		return nil, fmt.Errorf("byte slice length %d exceeds maximum %d", n, MaxMuxPacketLength)
	}
	if r.Remaining() < int(n) {
		return nil, io.ErrUnexpectedEOF
	}
	b := slices.Clone(r.data[r.off : r.off+int(n)])
	r.off += int(n)
	return b, nil
}

// MuxExtension represents an extension name/value pair in MUX_MSG_HELLO.
type MuxExtension struct {
	Name  string
	Value string
}

// MuxFwdRequest represents port forwarding parameters for OPEN_FWD and CLOSE_FWD.
type MuxFwdRequest struct {
	RequestID   uint32
	FwdType     uint32
	ListenHost  string
	ListenPort  uint32
	ConnectHost string
	ConnectPort uint32
}

// MuxNewSessionRequest represents passenger session creation parameters.
type MuxNewSessionRequest struct {
	RequestID  uint32
	Reserved   string
	WantTTY    bool
	WantX11    bool
	WantAgent  bool
	Subsystem  bool
	EscapeChar uint32
	TermType   string
	Command    string
	Env        []string
}

// MuxNewStdioFwdRequest represents stdio forwarding parameters.
type MuxNewStdioFwdRequest struct {
	RequestID   uint32
	Reserved    string
	ConnectHost string
	ConnectPort uint32
}

// 1. MUX_MSG_HELLO (0x00000001)
func EncodeMuxHello(version uint32, extensions []MuxExtension) []byte {
	w := newMuxWriter()
	w.WriteUint32(version)
	for _, ext := range extensions {
		w.WriteString(ext.Name)
		w.WriteString(ext.Value)
	}
	return w.Bytes()
}

func DecodeMuxHello(payload []byte) (version uint32, extensions []MuxExtension, err error) {
	r := newMuxReader(payload)
	version, err = r.ReadUint32()
	if err != nil {
		return 0, nil, fmt.Errorf("decode hello version: %w", err)
	}
	for r.Remaining() > 0 {
		name, err := r.ReadString()
		if err != nil {
			return 0, nil, fmt.Errorf("decode hello ext name: %w", err)
		}
		val, err := r.ReadString()
		if err != nil {
			return 0, nil, fmt.Errorf("decode hello ext value: %w", err)
		}
		extensions = append(extensions, MuxExtension{Name: name, Value: val})
	}
	return version, extensions, nil
}

// 2. Simple Request ID requests (ALIVE_CHECK, TERMINATE, STOP_LISTENING, PROXY)
func EncodeMuxRequestID(requestID uint32) []byte {
	w := newMuxWriter()
	w.WriteUint32(requestID)
	return w.Bytes()
}

func DecodeMuxRequestID(payload []byte) (requestID uint32, err error) {
	r := newMuxReader(payload)
	requestID, err = r.ReadUint32()
	if err != nil {
		return 0, fmt.Errorf("decode request id: %w", err)
	}
	if r.Remaining() != 0 {
		return 0, fmt.Errorf("trailing %d bytes after request id", r.Remaining())
	}
	return requestID, nil
}

// 3. MUX_S_ALIVE (0x80000005)
func EncodeMuxAlive(requestID uint32, pid uint32) []byte {
	w := newMuxWriter()
	w.WriteUint32(requestID)
	w.WriteUint32(pid)
	return w.Bytes()
}

func DecodeMuxAlive(payload []byte) (requestID uint32, pid uint32, err error) {
	r := newMuxReader(payload)
	if requestID, err = r.ReadUint32(); err != nil {
		return 0, 0, err
	}
	if pid, err = r.ReadUint32(); err != nil {
		return 0, 0, err
	}
	if r.Remaining() != 0 {
		return 0, 0, fmt.Errorf("trailing %d bytes in alive packet", r.Remaining())
	}
	return requestID, pid, nil
}

// 4. MUX_S_OK (0x80000001) & MUX_S_PROXY (0x8000000f)
func EncodeMuxClientRequestID(clientRequestID uint32) []byte {
	return EncodeMuxRequestID(clientRequestID)
}

func DecodeMuxClientRequestID(payload []byte) (clientRequestID uint32, err error) {
	return DecodeMuxRequestID(payload)
}

// 5. MUX_S_FAILURE (0x80000003) & MUX_S_PERMISSION_DENIED (0x80000002)
func EncodeMuxError(clientRequestID uint32, reason string) []byte {
	w := newMuxWriter()
	w.WriteUint32(clientRequestID)
	w.WriteString(reason)
	return w.Bytes()
}

func DecodeMuxError(payload []byte) (clientRequestID uint32, reason string, err error) {
	r := newMuxReader(payload)
	if clientRequestID, err = r.ReadUint32(); err != nil {
		return 0, "", err
	}
	if reason, err = r.ReadString(); err != nil {
		return 0, "", err
	}
	if r.Remaining() != 0 {
		return 0, "", fmt.Errorf("trailing %d bytes in error packet", r.Remaining())
	}
	return clientRequestID, reason, nil
}

// 6. MUX_C_OPEN_FWD (0x10000006) & MUX_C_CLOSE_FWD (0x10000007)
func EncodeMuxFwdRequest(req MuxFwdRequest) []byte {
	w := newMuxWriter()
	w.WriteUint32(req.RequestID)
	w.WriteUint32(req.FwdType)
	w.WriteString(req.ListenHost)
	w.WriteUint32(req.ListenPort)
	w.WriteString(req.ConnectHost)
	w.WriteUint32(req.ConnectPort)
	return w.Bytes()
}

func DecodeMuxFwdRequest(payload []byte) (req MuxFwdRequest, err error) {
	r := newMuxReader(payload)
	if req.RequestID, err = r.ReadUint32(); err != nil {
		return req, err
	}
	if req.FwdType, err = r.ReadUint32(); err != nil {
		return req, err
	}
	if req.ListenHost, err = r.ReadString(); err != nil {
		return req, err
	}
	if req.ListenPort, err = r.ReadUint32(); err != nil {
		return req, err
	}
	if req.ConnectHost, err = r.ReadString(); err != nil {
		return req, err
	}
	if req.ConnectPort, err = r.ReadUint32(); err != nil {
		return req, err
	}
	if r.Remaining() != 0 {
		return req, fmt.Errorf("trailing %d bytes in fwd request", r.Remaining())
	}
	return req, nil
}

// 7. MUX_S_REMOTE_PORT (0x80000007)
func EncodeMuxRemotePort(clientRequestID uint32, allocatedPort uint32) []byte {
	w := newMuxWriter()
	w.WriteUint32(clientRequestID)
	w.WriteUint32(allocatedPort)
	return w.Bytes()
}

func DecodeMuxRemotePort(payload []byte) (clientRequestID uint32, allocatedPort uint32, err error) {
	r := newMuxReader(payload)
	if clientRequestID, err = r.ReadUint32(); err != nil {
		return 0, 0, err
	}
	if allocatedPort, err = r.ReadUint32(); err != nil {
		return 0, 0, err
	}
	if r.Remaining() != 0 {
		return 0, 0, fmt.Errorf("trailing %d bytes in remote port packet", r.Remaining())
	}
	return clientRequestID, allocatedPort, nil
}

// 8. MUX_C_NEW_SESSION (0x10000002)
func EncodeMuxNewSession(req MuxNewSessionRequest) []byte {
	w := newMuxWriter()
	w.WriteUint32(req.RequestID)
	w.WriteString(req.Reserved)
	w.WriteUint32(boolToUint32(req.WantTTY))
	w.WriteUint32(boolToUint32(req.WantX11))
	w.WriteUint32(boolToUint32(req.WantAgent))
	w.WriteUint32(boolToUint32(req.Subsystem))
	w.WriteUint32(req.EscapeChar)
	w.WriteString(req.TermType)
	w.WriteString(req.Command)
	for _, env := range req.Env {
		w.WriteString(env)
	}
	return w.Bytes()
}

func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func DecodeMuxNewSession(payload []byte) (req MuxNewSessionRequest, err error) {
	r := newMuxReader(payload)
	if req.RequestID, err = r.ReadUint32(); err != nil {
		return req, err
	}
	if req.Reserved, err = r.ReadString(); err != nil {
		return req, err
	}
	var wantTTY, wantX11, wantAgent, subsystem uint32
	if wantTTY, err = r.ReadUint32(); err != nil {
		return req, err
	}
	if wantX11, err = r.ReadUint32(); err != nil {
		return req, err
	}
	if wantAgent, err = r.ReadUint32(); err != nil {
		return req, err
	}
	if subsystem, err = r.ReadUint32(); err != nil {
		return req, err
	}
	req.WantTTY = wantTTY != 0
	req.WantX11 = wantX11 != 0
	req.WantAgent = wantAgent != 0
	req.Subsystem = subsystem != 0
	if req.EscapeChar, err = r.ReadUint32(); err != nil {
		return req, err
	}
	if req.TermType, err = r.ReadString(); err != nil {
		return req, err
	}
	if req.Command, err = r.ReadString(); err != nil {
		return req, err
	}
	for r.Remaining() > 0 {
		envItem, err := r.ReadString()
		if err != nil {
			return req, err
		}
		req.Env = append(req.Env, envItem)
	}
	return req, nil
}

// 9. MUX_S_SESSION_OPENED (0x80000006)
func EncodeMuxSessionOpened(clientRequestID uint32, sessionID uint32) []byte {
	w := newMuxWriter()
	w.WriteUint32(clientRequestID)
	w.WriteUint32(sessionID)
	return w.Bytes()
}

func DecodeMuxSessionOpened(payload []byte) (clientRequestID uint32, sessionID uint32, err error) {
	r := newMuxReader(payload)
	if clientRequestID, err = r.ReadUint32(); err != nil {
		return 0, 0, err
	}
	if sessionID, err = r.ReadUint32(); err != nil {
		return 0, 0, err
	}
	if r.Remaining() != 0 {
		return 0, 0, fmt.Errorf("trailing %d bytes in session opened packet", r.Remaining())
	}
	return clientRequestID, sessionID, nil
}

// 10. MUX_S_EXIT_MESSAGE (0x80000004)
func EncodeMuxExitMessage(sessionID uint32, exitValue uint32) []byte {
	w := newMuxWriter()
	w.WriteUint32(sessionID)
	w.WriteUint32(exitValue)
	return w.Bytes()
}

func DecodeMuxExitMessage(payload []byte) (sessionID uint32, exitValue uint32, err error) {
	r := newMuxReader(payload)
	if sessionID, err = r.ReadUint32(); err != nil {
		return 0, 0, err
	}
	if exitValue, err = r.ReadUint32(); err != nil {
		return 0, 0, err
	}
	if r.Remaining() != 0 {
		return 0, 0, fmt.Errorf("trailing %d bytes in exit message", r.Remaining())
	}
	return sessionID, exitValue, nil
}

// 11. MUX_S_TTY_ALLOC_FAIL (0x80000008)
func EncodeMuxTTYAllocFail(sessionID uint32) []byte {
	w := newMuxWriter()
	w.WriteUint32(sessionID)
	return w.Bytes()
}

func DecodeMuxTTYAllocFail(payload []byte) (sessionID uint32, err error) {
	r := newMuxReader(payload)
	if sessionID, err = r.ReadUint32(); err != nil {
		return 0, err
	}
	if r.Remaining() != 0 {
		return 0, fmt.Errorf("trailing %d bytes in tty alloc fail", r.Remaining())
	}
	return sessionID, nil
}

// 12. MUX_C_NEW_STDIO_FWD (0x10000008)
func EncodeMuxNewStdioFwd(req MuxNewStdioFwdRequest) []byte {
	w := newMuxWriter()
	w.WriteUint32(req.RequestID)
	w.WriteString(req.Reserved)
	w.WriteString(req.ConnectHost)
	w.WriteUint32(req.ConnectPort)
	return w.Bytes()
}

func DecodeMuxNewStdioFwd(payload []byte) (req MuxNewStdioFwdRequest, err error) {
	r := newMuxReader(payload)
	if req.RequestID, err = r.ReadUint32(); err != nil {
		return req, err
	}
	if req.Reserved, err = r.ReadString(); err != nil {
		return req, err
	}
	if req.ConnectHost, err = r.ReadString(); err != nil {
		return req, err
	}
	if req.ConnectPort, err = r.ReadUint32(); err != nil {
		return req, err
	}
	if r.Remaining() != 0 {
		return req, fmt.Errorf("trailing %d bytes in stdio fwd request", r.Remaining())
	}
	return req, nil
}

// 13. MUX_C_EXT_INFO (0x20000001)
func EncodeMuxExtInfo(requestID uint32, name string) []byte {
	w := newMuxWriter()
	w.WriteUint32(requestID)
	w.WriteString(name)
	return w.Bytes()
}

func DecodeMuxExtInfo(payload []byte) (requestID uint32, name string, err error) {
	r := newMuxReader(payload)
	if requestID, err = r.ReadUint32(); err != nil {
		return 0, "", err
	}
	if name, err = r.ReadString(); err != nil {
		return 0, "", err
	}
	if r.Remaining() != 0 {
		return 0, "", fmt.Errorf("trailing %d bytes in ext info request", r.Remaining())
	}
	return requestID, name, nil
}

// 14. MUX_S_EXT_INFO (0x90000001)
func EncodeMuxExtInfoResponse(clientRequestID uint32, status uint32, msg string) []byte {
	w := newMuxWriter()
	w.WriteUint32(clientRequestID)
	w.WriteUint32(status)
	w.WriteString(msg)
	return w.Bytes()
}

func DecodeMuxExtInfoResponse(payload []byte) (clientRequestID uint32, status uint32, msg string, err error) {
	r := newMuxReader(payload)
	if clientRequestID, err = r.ReadUint32(); err != nil {
		return 0, 0, "", err
	}
	if status, err = r.ReadUint32(); err != nil {
		return 0, 0, "", err
	}
	if msg, err = r.ReadString(); err != nil {
		return 0, 0, "", err
	}
	if r.Remaining() != 0 {
		return 0, 0, "", fmt.Errorf("trailing %d bytes in ext info response", r.Remaining())
	}
	return clientRequestID, status, msg, nil
}
