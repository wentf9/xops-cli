package ssh

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestMuxPacket_FramingRoundtrip(t *testing.T) {
	buf := new(bytes.Buffer)
	payload := []byte("hello multiplex world 12345")

	if err := WriteMuxPacket(buf, MUX_C_ALIVE_CHECK, payload); err != nil {
		t.Fatalf("WriteMuxPacket failed: %v", err)
	}

	pktType, readPayload, err := ReadMuxPacket(buf)
	if err != nil {
		t.Fatalf("ReadMuxPacket failed: %v", err)
	}
	if pktType != MUX_C_ALIVE_CHECK {
		t.Fatalf("expected packet type 0x%08x, got 0x%08x", MUX_C_ALIVE_CHECK, pktType)
	}
	if !bytes.Equal(readPayload, payload) {
		t.Fatalf("expected payload %q, got %q", payload, readPayload)
	}
}

func TestMuxPacket_InvalidLengthBounds(t *testing.T) {
	// 1. Length < 4
	shortPkt := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01}
	r := bytes.NewReader(shortPkt)
	_, _, err := ReadMuxPacket(r)
	if err == nil || !strings.Contains(err.Error(), "invalid mux packet length") {
		t.Fatalf("expected length error, got: %v", err)
	}

	// 2. Length > MaxMuxPacketLength
	hugePkt := []byte{0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01} // 512KB > 256KB
	r = bytes.NewReader(hugePkt)
	_, _, err = ReadMuxPacket(r)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected max length error, got: %v", err)
	}
}

func TestMuxPacket_TruncatedPayload(t *testing.T) {
	// Length header says 14 bytes (4 type + 10 payload), but only 4 bytes payload provided
	truncated := []byte{
		0x00, 0x00, 0x00, 0x0e, // len = 14
		0x10, 0x00, 0x00, 0x04, // MUX_C_ALIVE_CHECK
		0x01, 0x02, 0x03, 0x04, // only 4 bytes of payload
	}
	r := bytes.NewReader(truncated)
	_, _, err := ReadMuxPacket(r)
	if err == nil || !strings.Contains(err.Error(), "failed to read mux packet payload") {
		t.Fatalf("expected truncated payload error, got: %v", err)
	}
}

func TestMuxCodec_Primitives(t *testing.T) {
	w := newMuxWriter()
	w.WriteUint32(0x12345678)
	w.WriteBool(true)
	w.WriteBool(false)
	w.WriteString("test string")
	w.WriteBytes([]byte{0xaa, 0xbb, 0xcc})

	r := newMuxReader(w.Bytes())

	u, err := r.ReadUint32()
	if err != nil || u != 0x12345678 {
		t.Fatalf("ReadUint32: got %x, err: %v", u, err)
	}

	b1, err := r.ReadBool()
	if err != nil || !b1 {
		t.Fatalf("ReadBool(1): got %v, err: %v", b1, err)
	}

	b2, err := r.ReadBool()
	if err != nil || b2 {
		t.Fatalf("ReadBool(2): got %v, err: %v", b2, err)
	}

	s, err := r.ReadString()
	if err != nil || s != "test string" {
		t.Fatalf("ReadString: got %q, err: %v", s, err)
	}

	bs, err := r.ReadBytes()
	if err != nil || !bytes.Equal(bs, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("ReadBytes: got %v, err: %v", bs, err)
	}

	if r.Remaining() != 0 {
		t.Fatalf("expected 0 remaining bytes, got %d", r.Remaining())
	}

	// Unexpected EOF on empty reader
	emptyR := newMuxReader(nil)
	if _, err := emptyR.ReadUint32(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}
	if _, err := emptyR.ReadBool(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestMuxMsg_Hello(t *testing.T) {
	exts := []MuxExtension{
		{Name: "ext1@openssh.com", Value: "val1"},
		{Name: "ext2@xops.internal", Value: "val2"},
	}
	payload := EncodeMuxHello(MuxProtoVersion, exts)

	version, decodedExts, err := DecodeMuxHello(payload)
	if err != nil {
		t.Fatalf("DecodeMuxHello failed: %v", err)
	}
	if version != MuxProtoVersion {
		t.Fatalf("expected version %d, got %d", MuxProtoVersion, version)
	}
	if !reflect.DeepEqual(decodedExts, exts) {
		t.Fatalf("extensions mismatch: expected %+v, got %+v", exts, decodedExts)
	}
}

func TestMuxMsg_AliveCheck_And_Alive(t *testing.T) {
	// Request
	reqPayload := EncodeMuxRequestID(42)
	reqID, err := DecodeMuxRequestID(reqPayload)
	if err != nil || reqID != 42 {
		t.Fatalf("DecodeMuxRequestID: got %d, err: %v", reqID, err)
	}

	// Response
	alivePayload := EncodeMuxAlive(42, 9999)
	respID, pid, err := DecodeMuxAlive(alivePayload)
	if err != nil || respID != 42 || pid != 9999 {
		t.Fatalf("DecodeMuxAlive: got req=%d pid=%d, err: %v", respID, pid, err)
	}
}

func TestMuxMsg_Terminate_Stop_Proxy(t *testing.T) {
	for _, id := range []uint32{1, 100, 999999} {
		payload := EncodeMuxClientRequestID(id)
		decID, err := DecodeMuxClientRequestID(payload)
		if err != nil || decID != id {
			t.Fatalf("DecodeMuxClientRequestID(%d): got %d, err: %v", id, decID, err)
		}
	}
}

func TestMuxMsg_ErrorResponses(t *testing.T) {
	payload := EncodeMuxError(123, "permission denied for client")
	id, reason, err := DecodeMuxError(payload)
	if err != nil {
		t.Fatalf("DecodeMuxError failed: %v", err)
	}
	if id != 123 || reason != "permission denied for client" {
		t.Fatalf("got id=%d reason=%q", id, reason)
	}
}

func TestMuxMsg_PortForwarding(t *testing.T) {
	req := MuxFwdRequest{
		RequestID:   55,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "0.0.0.0",
		ListenPort:  0, // dynamically allocate
		ConnectHost: "127.0.0.1",
		ConnectPort: 8080,
	}
	payload := EncodeMuxFwdRequest(req)
	decoded, err := DecodeMuxFwdRequest(payload)
	if err != nil {
		t.Fatalf("DecodeMuxFwdRequest failed: %v", err)
	}
	if !reflect.DeepEqual(decoded, req) {
		t.Fatalf("fwd request mismatch: expected %+v, got %+v", req, decoded)
	}

	// Remote port allocation response
	respPayload := EncodeMuxRemotePort(55, 34567)
	reqID, allocPort, err := DecodeMuxRemotePort(respPayload)
	if err != nil || reqID != 55 || allocPort != 34567 {
		t.Fatalf("DecodeMuxRemotePort: got req=%d port=%d, err: %v", reqID, allocPort, err)
	}
}

func TestMuxMsg_NewSession(t *testing.T) {
	req := MuxNewSessionRequest{
		RequestID:  77,
		Reserved:   "",
		WantTTY:    true,
		WantX11:    false,
		WantAgent:  true,
		Subsystem:  false,
		EscapeChar: 0x1e,
		TermType:   "xterm-256color",
		Command:    "/bin/bash -l",
		Env:        []string{"LANG=en_US.UTF-8", "TERM=xterm-256color"},
	}
	payload := EncodeMuxNewSession(req)
	decoded, err := DecodeMuxNewSession(payload)
	if err != nil {
		t.Fatalf("DecodeMuxNewSession failed: %v", err)
	}
	if !reflect.DeepEqual(decoded, req) {
		t.Fatalf("new session request mismatch: expected %+v, got %+v", req, decoded)
	}

	// Session opened response
	openPayload := EncodeMuxSessionOpened(77, 1)
	reqID, sessID, err := DecodeMuxSessionOpened(openPayload)
	if err != nil || reqID != 77 || sessID != 1 {
		t.Fatalf("DecodeMuxSessionOpened: got req=%d sess=%d, err: %v", reqID, sessID, err)
	}

	// Exit message
	exitPayload := EncodeMuxExitMessage(1, 0)
	sID, exitVal, err := DecodeMuxExitMessage(exitPayload)
	if err != nil || sID != 1 || exitVal != 0 {
		t.Fatalf("DecodeMuxExitMessage: got sess=%d exit=%d, err: %v", sID, exitVal, err)
	}

	// TTY Alloc Fail
	failPayload := EncodeMuxTTYAllocFail(1)
	sID, err = DecodeMuxTTYAllocFail(failPayload)
	if err != nil || sID != 1 {
		t.Fatalf("DecodeMuxTTYAllocFail: got sess=%d, err: %v", sID, err)
	}
}

func TestMuxMsg_NewStdioFwd(t *testing.T) {
	req := MuxNewStdioFwdRequest{
		RequestID:   88,
		Reserved:    "",
		ConnectHost: "internal.database",
		ConnectPort: 5432,
	}
	payload := EncodeMuxNewStdioFwd(req)
	decoded, err := DecodeMuxNewStdioFwd(payload)
	if err != nil {
		t.Fatalf("DecodeMuxNewStdioFwd failed: %v", err)
	}
	if !reflect.DeepEqual(decoded, req) {
		t.Fatalf("stdio fwd request mismatch: expected %+v, got %+v", req, decoded)
	}
}

func TestMuxMsg_NewSession_OpenSSHWireFixture(t *testing.T) {
	// Exact OpenSSH PROTOCOL.mux v4 wire layout for MUX_C_NEW_SESSION:
	// uint32 request_id (1)
	// string reserved ("")
	// uint32 want_tty (1)
	// uint32 want_x11 (0)
	// uint32 want_agent (1)
	// uint32 subsystem (0)
	// uint32 escape_char (0xffffffff)
	// string term ("xterm")
	// string command ("echo hi")
	// string env[0] ("LC_ALL=C")
	wire := []byte{
		0x00, 0x00, 0x00, 0x01, // request_id = 1
		0x00, 0x00, 0x00, 0x00, // reserved = ""
		0x00, 0x00, 0x00, 0x01, // want_tty = 1 (uint32)
		0x00, 0x00, 0x00, 0x00, // want_x11 = 0 (uint32)
		0x00, 0x00, 0x00, 0x01, // want_agent = 1 (uint32)
		0x00, 0x00, 0x00, 0x00, // subsystem = 0 (uint32)
		0xff, 0xff, 0xff, 0xff, // escape_char = 0xffffffff
		0x00, 0x00, 0x00, 0x05, 'x', 't', 'e', 'r', 'm', // term = "xterm"
		0x00, 0x00, 0x00, 0x07, 'e', 'c', 'h', 'o', ' ', 'h', 'i', // command = "echo hi"
		0x00, 0x00, 0x00, 0x08, 'L', 'C', '_', 'A', 'L', 'L', '=', 'C', // env[0] = "LC_ALL=C"
	}

	decoded, err := DecodeMuxNewSession(wire)
	if err != nil {
		t.Fatalf("DecodeMuxNewSession on OpenSSH wire fixture failed: %v", err)
	}
	want := MuxNewSessionRequest{
		RequestID:  1,
		Reserved:   "",
		WantTTY:    true,
		WantX11:    false,
		WantAgent:  true,
		Subsystem:  false,
		EscapeChar: 0xffffffff,
		TermType:   "xterm",
		Command:    "echo hi",
		Env:        []string{"LC_ALL=C"},
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("decoded mismatch:\ngot:  %+v\nwant: %+v", decoded, want)
	}
	reencoded := EncodeMuxNewSession(want)
	if !bytes.Equal(reencoded, wire) {
		t.Fatalf("reencoded bytes do not match OpenSSH wire layout:\ngot:  %x\nwant: %x", reencoded, wire)
	}
}

func TestMuxMsg_NewStdioFwd_OpenSSHWireFixture(t *testing.T) {
	// Exact OpenSSH PROTOCOL.mux v4 wire layout for MUX_C_NEW_STDIO_FWD:
	// uint32 request_id (1)
	// string reserved ("")
	// string connect_host ("127.0.0.1")
	// uint32 connect_port (22)
	wire := []byte{
		0x00, 0x00, 0x00, 0x01, // request_id = 1
		0x00, 0x00, 0x00, 0x00, // reserved = ""
		0x00, 0x00, 0x00, 0x09, '1', '2', '7', '.', '0', '.', '0', '.', '1', // connect_host
		0x00, 0x00, 0x00, 0x16, // connect_port = 22 (uint32)
	}

	decoded, err := DecodeMuxNewStdioFwd(wire)
	if err != nil {
		t.Fatalf("DecodeMuxNewStdioFwd on OpenSSH wire fixture failed: %v", err)
	}
	want := MuxNewStdioFwdRequest{
		RequestID:   1,
		Reserved:    "",
		ConnectHost: "127.0.0.1",
		ConnectPort: 22,
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("decoded mismatch:\ngot:  %+v\nwant: %+v", decoded, want)
	}
	reencoded := EncodeMuxNewStdioFwd(want)
	if !bytes.Equal(reencoded, wire) {
		t.Fatalf("reencoded bytes do not match OpenSSH wire layout:\ngot:  %x\nwant: %x", reencoded, wire)
	}
}

func TestMuxMsg_MalformedPayloads(t *testing.T) {
	// Truncated payload for DecodeMuxAlive
	if _, _, err := DecodeMuxAlive([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected error on truncated alive payload, got nil")
	}

	// Truncated payload for DecodeMuxError
	if _, _, err := DecodeMuxError([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected error on truncated error payload, got nil")
	}

	// Truncated payload for DecodeMuxFwdRequest
	if _, err := DecodeMuxFwdRequest([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected error on truncated fwd payload, got nil")
	}

	// Truncated payload for DecodeMuxNewSession
	if _, err := DecodeMuxNewSession([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected error on truncated new session payload, got nil")
	}
}

func TestMuxMsg_ExtInfo(t *testing.T) {
	// Request encoding/decoding
	reqEncoded := EncodeMuxExtInfo(101, "connection")
	reqID, name, err := DecodeMuxExtInfo(reqEncoded)
	if err != nil {
		t.Fatalf("DecodeMuxExtInfo failed: %v", err)
	}
	if reqID != 101 || name != "connection" {
		t.Fatalf("ext info request mismatch: reqID=%d, name=%q", reqID, name)
	}

	// Response encoding/decoding
	respEncoded := EncodeMuxExtInfoResponse(101, 1, "Master running ok")
	clientReqID, status, msg, err := DecodeMuxExtInfoResponse(respEncoded)
	if err != nil {
		t.Fatalf("DecodeMuxExtInfoResponse failed: %v", err)
	}
	if clientReqID != 101 || status != 1 || msg != "Master running ok" {
		t.Fatalf("ext info response mismatch: clientReqID=%d, status=%d, msg=%q", clientReqID, status, msg)
	}

	// Truncated payloads
	if _, _, err := DecodeMuxExtInfo([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected error on truncated ext info request")
	}
	if _, _, _, err := DecodeMuxExtInfoResponse([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected error on truncated ext info response")
	}
}
