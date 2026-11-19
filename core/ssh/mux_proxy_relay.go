package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// discardAbortedChannelRequests drains incoming channel requests on an early
// error/shutdown exit while bounding goroutine lifetime by serverCtx and
// sessionShutdownTimeout so unclosed mock channels cannot leak goroutines.
func discardAbortedChannelRequests(serverCtx context.Context, reqs <-chan *cryptoSSH.Request) {
	if reqs == nil {
		return
	}
	var serverDone <-chan struct{}
	if serverCtx != nil {
		serverDone = serverCtx.Done()
	}
	timer := time.NewTimer(sessionShutdownTimeout)
	defer timer.Stop()
	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				return
			}
			if req != nil && req.WantReply {
				_ = req.Reply(false, nil)
			}
		case <-serverDone:
			for {
				select {
				case req, ok := <-reqs:
					if !ok {
						return
					}
					if req != nil && req.WantReply {
						_ = req.Reply(false, nil)
					}
				default:
					return
				}
			}
		case <-timer.C:
			return
		}
	}
}

func (ps *proxySessionState) serverBaseContext() context.Context {
	if ps != nil && ps.server != nil {
		return ps.server.baseContext()
	}
	return nil
}

// RFC 4254 Connection Protocol packet type opcodes.
const (
	msgGlobalRequest           byte = 80
	msgRequestSuccess          byte = 81
	msgRequestFailure          byte = 82
	msgChannelOpen             byte = 90
	msgChannelOpenConfirmation byte = 91
	msgChannelOpenFailure      byte = 92
	msgChannelWindowAdjust     byte = 93
	msgChannelData             byte = 94
	msgChannelExtendedData     byte = 95
	msgChannelEOF              byte = 96
	msgChannelClose            byte = 97
	msgChannelRequest          byte = 98
	msgChannelSuccess          byte = 99
	msgChannelFailure          byte = 100
	msgPing                    byte = 192
	msgPong                    byte = 193
)

// extendedDataStderr is RFC 4254 section 5.2 SSH_EXTENDED_DATA_STDERR.
const extendedDataStderr uint32 = 1

const (
	// proxyAdvertisedWindow is the per-channel receive window this master offers
	// a proxy client. Credit is returned only after data reached the remote
	// channel, so unrelayed client input stays bounded by this window.
	proxyAdvertisedWindow uint32 = 2 * 1024 * 1024
	// proxyAdvertisedMaxPacket bounds one client-to-master data chunk.
	proxyAdvertisedMaxPacket uint32 = 32 * 1024
	// maxProxyQueuedInput bounds client input that was accepted but not yet
	// forwarded. The window above normally caps it; this limit stops a peer that
	// ignores the window from growing the relay queue without bound.
	maxProxyQueuedInput = int64(2) * int64(proxyAdvertisedWindow)
	// minProxyChannelPacket is the smallest maximum packet size a peer may
	// advertise (4-byte length, 1-byte padding length, message type).
	minProxyChannelPacket uint32 = 9
	// maxFlowWindow is the largest representable SSH channel window (2^31).
	maxFlowWindow = int64(1) << 31
)

type proxyChan struct {
	remoteCh cryptoSSH.Channel
	clientCh uint32
	serverCh uint32
	// clientWindow tracks the proxy client's receive window for the
	// master-to-client direction, and clientMaxPacket bounds one data packet.
	// Both come from the client's channel open; ignoring them makes the client's
	// SSH mux abort the whole multiplexed connection once its window overruns.
	clientWindow    *clientFlowWindow
	clientMaxPacket int
	// reqsDone closes when the remote side stops sending channel requests.
	reqsDone chan struct{}
	// requests serializes client-to-server channel requests. RFC 4254 channel
	// responses carry no request ID, so requests and their replies must stay in
	// wire order instead of running one goroutine per request.
	requests *orderedQueue[proxyChannelRequest]
	// requestsDone closes once the request worker has drained every queued
	// request and written its reply.
	requestsDone chan struct{}
	// input relays client-to-master data in wire order. Writing it inline would
	// let one channel whose remote window is exhausted stall the shared proxy
	// read loop, and with it every other channel on the session.
	input    *orderedQueue[proxyChannelInput]
	queuedIn atomic.Int64
	// pendingRemoteReqs holds remote-initiated channel requests that asked for a
	// reply and are waiting for the proxy client's answer. RFC 4254 pairs replies
	// positionally, so they are answered in arrival order.
	pendingRemoteReqs *remoteRequestQueue
	// closeSent is guarded by proxySessionState.writeMu. It records that the one
	// SSH_MSG_CHANNEL_CLOSE for this channel has been written, so no later packet
	// can follow it.
	closeSent bool

	leaseMu         sync.Mutex
	leaseReleased   bool
	agentProxyLease *agentForwardLease
}

func (pc *proxyChan) attachAgentProxyLease(lease *agentForwardLease) bool {
	if lease == nil {
		return false
	}
	pc.leaseMu.Lock()
	if pc.leaseReleased {
		pc.leaseMu.Unlock()
		lease.Release()
		return false
	}
	prev := pc.agentProxyLease
	pc.agentProxyLease = lease
	pc.leaseMu.Unlock()
	if prev != nil {
		prev.Release()
	}
	return true
}

func (pc *proxyChan) releaseAgentProxyLease() {
	pc.leaseMu.Lock()
	pc.leaseReleased = true
	lease := pc.agentProxyLease
	pc.agentProxyLease = nil
	pc.leaseMu.Unlock()
	if lease != nil {
		lease.Release()
	}
}

// proxyChannelInput is one ordered client-to-master channel event.
type proxyChannelInput struct {
	kind         byte
	extendedType uint32
	payload      []byte
}

// clientFlowWindow tracks the credit granted by the proxy client for data this
// master writes to it. Credit starts at the window advertised in the client's
// channel open and is replenished by SSH_MSG_CHANNEL_WINDOW_ADJUST.
type clientFlowWindow struct {
	mu     sync.Mutex
	cond   *sync.Cond
	credit int64
	closed bool
}

func newClientFlowWindow(size uint32) *clientFlowWindow {
	window := &clientFlowWindow{credit: int64(size)}
	window.cond = sync.NewCond(&window.mu)
	return window
}

// add applies a window-adjust delta. RFC 4254 forbids growing a channel window
// beyond 2^31, so an overflow is treated as a protocol violation.
func (w *clientFlowWindow) add(delta uint32) error {
	if delta == 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	if w.credit+int64(delta) > maxFlowWindow {
		return fmt.Errorf("channel window overflow: %d + %d", w.credit, delta)
	}
	w.credit += int64(delta)
	w.cond.Broadcast()
	return nil
}

// reserve blocks until the client has granted exactly n bytes and consumes that
// credit. n must not exceed the client's advertised maximum packet size, so the
// reservation is always written by one data packet and never over-reserves the
// window shared with the other remote stream. io.EOF reports that the channel
// ended while waiting for credit.
func (w *clientFlowWindow) reserve(n int) error {
	if n == 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for int64(n) > w.credit {
		if w.closed {
			return io.EOF
		}
		w.cond.Wait()
	}
	w.credit -= int64(n)
	return nil
}

// close releases every sender blocked in reserve.
func (w *clientFlowWindow) close() {
	w.mu.Lock()
	w.closed = true
	w.cond.Broadcast()
	w.mu.Unlock()
}

// remoteRequestQueue is a FIFO of remote-initiated want-reply channel requests.
// The proxy client answers them in order, and unanswered requests are rejected
// when the channel ends so the remote side never blocks.
type remoteRequestQueue struct {
	mu    sync.Mutex
	items []*cryptoSSH.Request
}

func newRemoteRequestQueue() *remoteRequestQueue {
	return &remoteRequestQueue{}
}

func (q *remoteRequestQueue) push(req *cryptoSSH.Request) {
	q.mu.Lock()
	q.items = append(q.items, req)
	q.mu.Unlock()
}

func (q *remoteRequestQueue) pop() (*cryptoSSH.Request, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil, false
	}
	req := q.items[0]
	q.items[0] = nil
	q.items = q.items[1:]
	return req, true
}

// drain replies false to every request still waiting, releasing the remote side.
func (q *remoteRequestQueue) drain() {
	for {
		req, ok := q.pop()
		if !ok {
			return
		}
		_ = req.Reply(false, nil)
	}
}

// proxyChannelRequest is one client-to-server channel request awaiting ordered
// forwarding to the master's SSH transport.
type proxyChannelRequest struct {
	requestType string
	wantReply   bool
	payload     []byte
}

// proxyGlobalRequest is one client-to-server global request awaiting ordered
// forwarding to the master's SSH transport.
type proxyGlobalRequest struct {
	requestType string
	wantReply   bool
	payload     []byte
}

// orderedQueue is an unbounded FIFO drained by a single worker. Push never
// blocks the proxy read loop, so data needed by the remote side of an in-flight
// request is still forwarded, while the worker keeps wire order for messages
// whose replies carry no request identifier.
type orderedQueue[T any] struct {
	mu     sync.Mutex
	items  []T
	closed bool
	wake   chan struct{}
}

func newOrderedQueue[T any]() *orderedQueue[T] {
	return &orderedQueue[T]{wake: make(chan struct{}, 1)}
}

func (q *orderedQueue[T]) push(item T) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.items = append(q.items, item)
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// close stops accepting new items; the worker drains queued items first.
func (q *orderedQueue[T]) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *orderedQueue[T]) pop() (T, bool) {
	var zero T
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			item := q.items[0]
			q.items[0] = zero
			q.items = q.items[1:]
			q.mu.Unlock()
			return item, true
		}
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return zero, false
		}
		<-q.wake
	}
}

type proxySessionState struct {
	server   *MuxServer
	conn     net.Conn
	writeMu  sync.Mutex
	channels sync.Map // serverChID (uint32) -> *proxyChan
	// byClientCh indexes the same records by the proxy client's channel ID, which
	// is what channel responses carry back.
	byClientCh sync.Map // clientChID (uint32) -> *proxyChan
	nextChID   atomic.Uint32
	// global serializes client-to-server global requests. RFC 4254 global
	// replies carry no request ID, so they can only be answered in wire order.
	global   *orderedQueue[proxyGlobalRequest]
	closed   atomic.Bool
	closedMu sync.Mutex
	closedCh chan struct{}
}

func (ps *proxySessionState) closedSignal() <-chan struct{} {
	ps.closedMu.Lock()
	defer ps.closedMu.Unlock()
	if ps.closedCh == nil {
		ps.closedCh = make(chan struct{})
		if ps.closed.Load() {
			close(ps.closedCh)
		}
	}
	return ps.closedCh
}

func (ps *proxySessionState) closeAll() {
	if ps.closed.Swap(true) {
		return
	}
	ps.closedMu.Lock()
	if ps.closedCh == nil {
		ps.closedCh = make(chan struct{})
	}
	close(ps.closedCh)
	ps.closedMu.Unlock()
	if ps.global != nil {
		ps.global.close()
	}
	ps.channels.Range(func(key, val any) bool {
		if pc, ok := val.(*proxyChan); ok {
			ps.byClientCh.CompareAndDelete(pc.clientCh, pc)
			pc.clientWindow.close()
			pc.input.close()
			pc.requests.close()
			pc.pendingRemoteReqs.drain()
			_ = pc.remoteCh.Close()
			pc.releaseAgentProxyLease()
		}
		return true
	})
}

// writeChannelPacket writes one channel-scoped packet unless the session ended or
// this channel's close was already written. The client's SSH mux fails the whole
// multiplexed connection on any packet for a channel it has closed, and RFC 4254
// forbids sending anything after SSH_MSG_CHANNEL_CLOSE, so io.EOF reports
// "closed".
func (ps *proxySessionState) writeChannelPacket(pc *proxyChan, payload []byte) error {
	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()
	if ps.closed.Load() || pc == nil || pc.closeSent {
		return io.EOF
	}
	return writeUnpaddedPacket(ps.conn, payload)
}

// closeChannel writes the single SSH_MSG_CHANNEL_CLOSE for pc. RFC 4254 requires
// answering a close this side did not initiate, and the client only releases its
// channel (unblocking its readers) after receiving that answer. The closeSent
// gate also makes every later channel packet a no-op.
func (ps *proxySessionState) closeChannel(pc *proxyChan) {
	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()
	if ps.closed.Load() || pc == nil || pc.closeSent {
		return
	}
	pc.closeSent = true
	w := newMuxWriter()
	w.buf = append(w.buf, msgChannelClose)
	w.WriteUint32(pc.clientCh)
	_ = writeUnpaddedPacket(ps.conn, w.Bytes())
}

func (ps *proxySessionState) writePacket(payload []byte) error {
	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()
	if ps.closed.Load() {
		return net.ErrClosed
	}
	return writeUnpaddedPacket(ps.conn, payload)
}

// serveProxyConn routes unpadded SSH transport packets between proxy client and sshClient.
func (s *MuxServer) serveProxyConn(conn net.Conn) error {
	ps := &proxySessionState{
		server: s,
		conn:   conn,
		global: newOrderedQueue[proxyGlobalRequest](),
	}
	defer ps.closeAll()

	// Send an initial want-reply=false SSH_MSG_GLOBAL_REQUEST ("hostkeys-00@openssh.com")
	// on entering proxy mode, matching OpenSSH mux_InitialProxyPacket behavior so that
	// `-O proxy` callers immediately observe the server's initial connection-protocol
	// packet while golang.org/x/crypto/ssh's NewControlClientConn discards it cleanly.
	initPkt := newMuxWriter()
	initPkt.buf = append(initPkt.buf, msgGlobalRequest)
	initPkt.WriteString("hostkeys-00@openssh.com")
	initPkt.buf = append(initPkt.buf, 0) // want_reply = false
	if err := ps.writePacket(initPkt.Bytes()); err != nil {
		return err
	}

	go ps.serveGlobalRequests()

	for {
		packet, err := readUnpaddedPacket(conn)
		if err != nil {
			return err
		}
		if len(packet) == 0 {
			continue
		}

		ps.dispatch(packet)
	}
}

func (ps *proxySessionState) dispatch(packet []byte) {
	switch packet[0] {
	case msgChannelOpen:
		ps.handleOpen(packet[1:])
	case msgChannelData:
		ps.handleData(packet[1:])
	case msgChannelEOF:
		ps.handleEOF(packet[1:])
	case msgChannelClose:
		ps.handleClose(packet[1:])
	case msgChannelExtendedData:
		ps.handleExtendedData(packet[1:])
	case msgChannelRequest:
		ps.handleRequest(packet[1:])
	case msgGlobalRequest:
		ps.handleGlobalRequest(packet[1:])
	case msgChannelWindowAdjust:
		ps.handleWindowAdjust(packet[1:])
	case msgChannelSuccess:
		ps.handleRemoteRequestReply(packet[1:], true)
	case msgChannelFailure:
		ps.handleRemoteRequestReply(packet[1:], false)
	case msgPing:
		pong := make([]byte, len(packet))
		pong[0] = msgPong
		copy(pong[1:], packet[1:])
		_ = ps.writePacket(pong)
	}
}

// handleRemoteRequestReply relays the proxy client's answer to a remote-initiated
// channel request. Without it a server waiting on a want-reply request (for
// example exit-status handling or a forwarding confirmation) blocks forever.
func (ps *proxySessionState) handleRemoteRequestReply(payload []byte, accepted bool) {
	r := newMuxReader(payload)
	clientChID, err := r.ReadUint32()
	if err != nil {
		return
	}
	pcVal, ok := ps.byClientCh.Load(clientChID)
	if !ok {
		return
	}
	pc := pcVal.(*proxyChan)
	req, ok := pc.pendingRemoteReqs.pop()
	if !ok {
		return
	}
	var replyPayload []byte
	if accepted && r.Remaining() > 0 {
		replyPayload = slices.Clone(r.data[r.off:])
	}
	_ = req.Reply(accepted, replyPayload)
}

func (ps *proxySessionState) handleOpen(payload []byte) {
	r := newMuxReader(payload)
	chType, err := r.ReadString()
	if err != nil {
		return
	}
	clientChID, err := r.ReadUint32()
	if err != nil {
		return
	}
	clientWindow, err := r.ReadUint32()
	if err != nil {
		return
	}
	clientMaxPacket, err := r.ReadUint32()
	if err != nil {
		return
	}
	var extra []byte
	if r.Remaining() > 0 {
		extra = r.data[r.off:]
	}

	// The client's window and maximum packet size bound every packet this master
	// sends it. Reject values SSH cannot represent instead of trusting them.
	if clientMaxPacket < minProxyChannelPacket || int64(clientMaxPacket) > maxFlowWindow || int64(clientWindow) > maxFlowWindow {
		w := newMuxWriter()
		w.buf = append(w.buf, msgChannelOpenFailure)
		w.WriteUint32(clientChID)
		w.WriteUint32(2) // SSH_OPEN_CONNECT_FAILED
		w.WriteString("invalid channel window or maximum packet size")
		w.WriteString("en")
		_ = ps.writePacket(w.Bytes())
		return
	}

	pc := &proxyChan{
		clientCh:          clientChID,
		clientWindow:      newClientFlowWindow(clientWindow),
		clientMaxPacket:   int(clientMaxPacket),
		reqsDone:          make(chan struct{}),
		requests:          newOrderedQueue[proxyChannelRequest](),
		requestsDone:      make(chan struct{}),
		input:             newOrderedQueue[proxyChannelInput](),
		pendingRemoteReqs: newRemoteRequestQueue(),
	}

	go ps.openRemoteChannel(pc, chType, extra)
}

func (ps *proxySessionState) openRemoteChannel(pc *proxyChan, chType string, extra []byte) {
	remoteCh, reqs, err := ps.server.sshClient.OpenChannel(chType, extra)
	if err != nil {
		pc.clientWindow.close()
		reason := uint32(2) // SSH_OPEN_CONNECT_FAILED
		msg := err.Error()
		var openErr *cryptoSSH.OpenChannelError
		if errors.As(err, &openErr) {
			reason = uint32(openErr.Reason)
			msg = openErr.Message
		}
		if chType == "session" && strings.TrimSpace(msg) == "open failed" {
			msg = "open failed (remote sshd MaxSessions limit may be reached)"
		}
		w := newMuxWriter()
		w.buf = append(w.buf, msgChannelOpenFailure)
		w.WriteUint32(pc.clientCh)
		w.WriteUint32(reason)
		w.WriteString(msg)
		w.WriteString("en")
		_ = ps.writePacket(w.Bytes())
		return
	}

	pc.remoteCh = remoteCh
	pc.serverCh = ps.nextChID.Add(1)
	ps.channels.Store(pc.serverCh, pc)
	ps.byClientCh.Store(pc.clientCh, pc)
	if ps.closed.Load() {
		// Shutdown may have taken its snapshot before this channel was published.
		ps.channels.CompareAndDelete(pc.serverCh, pc)
		ps.byClientCh.CompareAndDelete(pc.clientCh, pc)
		pc.clientWindow.close()
		pc.input.close()
		go discardAbortedChannelRequests(ps.serverBaseContext(), reqs)
		_ = remoteCh.Close()
		return
	}

	w := newMuxWriter()
	w.buf = append(w.buf, msgChannelOpenConfirmation)
	w.WriteUint32(pc.clientCh)
	w.WriteUint32(pc.serverCh)
	w.WriteUint32(proxyAdvertisedWindow)
	w.WriteUint32(proxyAdvertisedMaxPacket)
	_ = ps.writePacket(w.Bytes())

	go ps.forwardRequests(pc, reqs)
	go ps.serveChannelRequests(pc)
	go ps.relayChannelInput(pc)
	go ps.streamChannelData(pc)
}

func (ps *proxySessionState) forwardRequests(pc *proxyChan, reqs <-chan *cryptoSSH.Request) {
	defer close(pc.reqsDone)
	writeFailed := false
	for req := range reqs {
		if writeFailed {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		if req.WantReply {
			pc.pendingRemoteReqs.push(req)
		}
		rw := newMuxWriter()
		rw.buf = append(rw.buf, msgChannelRequest)
		rw.WriteUint32(pc.clientCh)
		rw.WriteString(req.Type)
		rw.WriteBool(req.WantReply)
		rw.buf = append(rw.buf, req.Payload...)
		if err := ps.writeChannelPacket(pc, rw.Bytes()); err != nil {
			writeFailed = true
			pc.pendingRemoteReqs.drain()
		}
	}
	// The remote request stream ended (or the client closed the channel). Any
	// request still awaiting an answer can no longer be satisfied, so release the
	// remote side instead of leaving it blocked on a reply that will never arrive.
	pc.pendingRemoteReqs.drain()
}

// streamRemoteStdout forwards SSH channel data (stdout) to the proxy client.
func (ps *proxySessionState) streamRemoteStdout(pc *proxyChan) {
	buf := make([]byte, proxyAdvertisedMaxPacket)
	for {
		n, err := pc.remoteCh.Read(buf)
		if n > 0 {
			if werr := ps.sendChannelData(pc, false, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// streamRemoteStderr forwards SSH extended channel data (stderr) to the proxy
// client. Dropping it would lose all remote stderr and, once the remote process
// fills the channel window, block it permanently.
func (ps *proxySessionState) streamRemoteStderr(pc *proxyChan) {
	stderr := pc.remoteCh.Stderr()
	if stderr == nil {
		return
	}
	buf := make([]byte, proxyAdvertisedMaxPacket)
	for {
		n, err := stderr.Read(buf)
		if n > 0 {
			if werr := ps.sendChannelData(pc, true, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// sendChannelData writes data to the proxy client within the credit it granted.
// Every packet reserves its exact size from the client's window first and stays
// within the client's maximum packet size; a larger packet makes the client's
// SSH mux abort the whole multiplexed connection.
func (ps *proxySessionState) sendChannelData(pc *proxyChan, extended bool, data []byte) error {
	for len(data) > 0 {
		chunk := min(len(data), pc.clientMaxPacket)
		if err := pc.clientWindow.reserve(chunk); err != nil {
			return err
		}

		w := newMuxWriter()
		if extended {
			w.buf = append(w.buf, msgChannelExtendedData)
			w.WriteUint32(pc.clientCh)
			w.WriteUint32(extendedDataStderr)
		} else {
			w.buf = append(w.buf, msgChannelData)
			w.WriteUint32(pc.clientCh)
		}
		w.WriteBytes(data[:chunk])
		if err := ps.writeChannelPacket(pc, w.Bytes()); err != nil {
			if errors.Is(err, io.EOF) {
				// The channel closed while data was in flight; nothing may follow its
				// close packet.
				return err
			}
			// The client will not drain any more data; end the session so the read
			// loop and every relay worker stop instead of waiting for a dead peer.
			_ = ps.conn.Close()
			return err
		}
		data = data[chunk:]
	}
	return nil
}

// streamChannelData drains both remote streams, then reports EOF and close to
// the proxy client once pending replies have settled.
func (ps *proxySessionState) streamChannelData(pc *proxyChan) {
	defer pc.releaseAgentProxyLease()
	var streams sync.WaitGroup
	streams.Add(2)
	go func() {
		defer streams.Done()
		ps.streamRemoteStdout(pc)
	}()
	go func() {
		defer streams.Done()
		ps.streamRemoteStderr(pc)
	}()
	streams.Wait()

	if ps.closed.Load() {
		// The session is gone: the peer will never answer and no packet may be
		// written, so report nothing and skip the drain waits below.
		return
	}

	// Report EOF to the proxy client once remote stdout and stderr reach EOF.
	// Do NOT close the channel on a 1s timer here: the remote process may have
	// closed its stdout/stderr while still reading large stdin from the client
	// (e.g. `cat > file 2>/dev/null < big`). Wait until the remote channel itself
	// closes (which closes reqs and therefore pc.reqsDone) before sending
	// SSH_MSG_CHANNEL_CLOSE.
	ew := newMuxWriter()
	ew.buf = append(ew.buf, msgChannelEOF)
	ew.WriteUint32(pc.clientCh)
	_ = ps.writeChannelPacket(pc, ew.Bytes())

	// Wait for the remote channel to close (or the proxy session to tear down),
	// which closes reqs and finishes forwarding exit-status / exit-signal.
	<-pc.reqsDone

	// Drain every queued client-to-server request before reporting close. A
	// close sent while a want-reply request (exec/shell) is still in flight
	// makes the proxy client fail that request with io.EOF.
	pc.requests.close()
	select {
	case <-pc.requestsDone:
	case <-time.After(5 * time.Second):
	}

	ps.closeChannel(pc)
	ps.channels.CompareAndDelete(pc.serverCh, pc)
	ps.byClientCh.CompareAndDelete(pc.clientCh, pc)
	pc.clientWindow.close()
	pc.input.close()
	_ = pc.remoteCh.Close()
	pc.releaseAgentProxyLease()
}

func (ps *proxySessionState) handleData(payload []byte) {
	r := newMuxReader(payload)
	serverChID, err := r.ReadUint32()
	if err != nil {
		return
	}
	data, err := r.ReadBytes()
	if err != nil || len(data) == 0 {
		return
	}
	ps.enqueueInput(serverChID, proxyChannelInput{kind: msgChannelData, payload: data})
}

func (ps *proxySessionState) handleExtendedData(payload []byte) {
	r := newMuxReader(payload)
	serverChID, err := r.ReadUint32()
	if err != nil {
		return
	}
	extendedType, err := r.ReadUint32()
	if err != nil || extendedType != extendedDataStderr {
		return
	}
	data, err := r.ReadBytes()
	if err != nil || len(data) == 0 {
		return
	}
	ps.enqueueInput(serverChID, proxyChannelInput{kind: msgChannelExtendedData, extendedType: extendedType, payload: data})
}

// enqueueInput hands client data to the channel's ordered relay worker. The
// read loop must never wait for a remote channel's window: one channel nobody
// reads would otherwise stall every other channel on the shared session.
func (ps *proxySessionState) enqueueInput(serverChID uint32, item proxyChannelInput) {
	pcVal, ok := ps.channels.Load(serverChID)
	if !ok {
		return
	}
	pc := pcVal.(*proxyChan)
	if pc.input == nil {
		return
	}
	if pc.queuedIn.Add(int64(len(item.payload))) > maxProxyQueuedInput {
		// The peer ignored the window it was given; fail the session instead of
		// buffering its input without bound.
		_ = ps.conn.Close()
		return
	}
	pc.input.push(item)
}

// relayChannelInput forwards queued client data in wire order and credits the
// client's window only afterwards, so accepted-but-unforwarded input stays
// bounded by the window this master advertised.
func (ps *proxySessionState) relayChannelInput(pc *proxyChan) {
	for {
		item, ok := pc.input.pop()
		if !ok {
			return
		}
		pc.queuedIn.Add(-int64(len(item.payload)))

		switch item.kind {
		case msgChannelData:
			_, _ = pc.remoteCh.Write(item.payload)
		case msgChannelExtendedData:
			if stderr := pc.remoteCh.Stderr(); stderr != nil {
				_, _ = stderr.Write(item.payload)
			}
		case msgChannelEOF:
			_ = pc.remoteCh.CloseWrite()
			continue
		default:
			continue
		}

		if len(item.payload) == 0 {
			continue
		}
		w := newMuxWriter()
		w.buf = append(w.buf, msgChannelWindowAdjust)
		w.WriteUint32(pc.clientCh)
		w.WriteUint32(uint32(len(item.payload)))
		_ = ps.writeChannelPacket(pc, w.Bytes())
	}
}

// handleWindowAdjust credits data this master may send to the proxy client.
func (ps *proxySessionState) handleWindowAdjust(payload []byte) {
	r := newMuxReader(payload)
	serverChID, err := r.ReadUint32()
	if err != nil {
		return
	}
	delta, err := r.ReadUint32()
	if err != nil {
		return
	}
	pcVal, ok := ps.channels.Load(serverChID)
	if !ok {
		return
	}
	_ = pcVal.(*proxyChan).clientWindow.add(delta)
}

func (ps *proxySessionState) handleEOF(payload []byte) {
	r := newMuxReader(payload)
	serverChID, err := r.ReadUint32()
	if err != nil {
		return
	}
	if pcVal, ok := ps.channels.Load(serverChID); ok {
		// The relay worker preserves order, so EOF reaches the remote channel only
		// after the data the client sent before it.
		pc := pcVal.(*proxyChan)
		if pc.input != nil {
			pc.input.push(proxyChannelInput{kind: msgChannelEOF})
		}
	}
}

func (ps *proxySessionState) handleClose(payload []byte) {
	r := newMuxReader(payload)
	serverChID, err := r.ReadUint32()
	if err != nil {
		return
	}
	if pcVal, ok := ps.channels.LoadAndDelete(serverChID); ok {
		pc := pcVal.(*proxyChan)
		ps.byClientCh.CompareAndDelete(pc.clientCh, pc)
		pc.clientWindow.close()
		pc.input.close()
		pc.requests.close()
		pc.pendingRemoteReqs.drain()
		_ = pc.remoteCh.Close()
		pc.releaseAgentProxyLease()
		// RFC 4254 requires answering a close this side did not initiate, and the
		// client only frees its channel (and unblocks its readers) after receiving
		// that answer. closeChannel also blocks every later packet for the channel.
		ps.closeChannel(pc)
	}
}

// handleRequest queues a client-to-server channel request. The queue preserves
// wire order for both requests and their replies.
func (ps *proxySessionState) handleRequest(payload []byte) {
	r := newMuxReader(payload)
	serverChID, err := r.ReadUint32()
	if err != nil {
		return
	}
	reqType, err := r.ReadString()
	if err != nil {
		return
	}
	wantReply, err := r.ReadBool()
	if err != nil {
		return
	}
	var reqPayload []byte
	if r.Remaining() > 0 {
		reqPayload = r.data[r.off:]
	}

	pcVal, ok := ps.channels.Load(serverChID)
	if !ok {
		return
	}
	pc := pcVal.(*proxyChan)
	if pc.requests == nil {
		return
	}
	pc.requests.push(proxyChannelRequest{requestType: reqType, wantReply: wantReply, payload: reqPayload})
}

func (ps *proxySessionState) acquireChannelAgentLease() (*agentForwardLease, bool) {
	if ps == nil || ps.server == nil || ps.server.sshClient == nil ||
		!ps.server.allowAgentForward || ps.server.agentSocket == "" || ps.server.dialAgent == nil {
		if ps != nil && ps.server != nil {
			ps.server.getLogger().Debugf(
				"mux: rejecting MUX_C_PROXY %s because master AllowAgentForward is disabled or master agent is unavailable",
				agentForwardRequestType,
			)
		}
		return nil, false
	}
	router, rErr := getOrCreateAgentRouter(ps.server.sshClient)
	if rErr != nil {
		ps.server.getLogger().Debugf("mux: failed to initialize agent router for MUX_C_PROXY session: %v", rErr)
		return nil, false
	}
	lease, lErr := router.acquireLocalLease(
		ps.server.baseContext(),
		ps.server.agentSocket,
		ps.server.dialAgent,
		ps.server.getLogger(),
	)
	if lErr != nil || lease == nil {
		return nil, false
	}
	return lease, true
}

func (ps *proxySessionState) writeChannelReply(pc *proxyChan, success bool) error {
	w := newMuxWriter()
	if success {
		w.buf = append(w.buf, msgChannelSuccess)
	} else {
		w.buf = append(w.buf, msgChannelFailure)
	}
	w.WriteUint32(pc.clientCh)
	return ps.writeChannelPacket(pc, w.Bytes())
}

func (ps *proxySessionState) sendBoundedProxyChannelRequest(
	pc *proxyChan,
	reqType string,
	wantReply bool,
	payload []byte,
) (bool, error) {
	if ps == nil || pc == nil || pc.remoteCh == nil || ps.closed.Load() {
		return false, net.ErrClosed
	}
	parentCtx := context.Background()
	var timeout time.Duration
	if ps.server != nil {
		parentCtx = ps.server.baseContext()
		timeout = ps.server.requestTimeout
	}
	work, cancel := withTimeoutOrDefault(parentCtx, timeout, defaultSSHHandshakeTimeout)
	defer cancel()

	done := make(chan channelRequestReply, 1)
	go func() {
		ok, err := pc.remoteCh.SendRequest(reqType, wantReply, payload)
		done <- channelRequestReply{accepted: ok, err: err}
	}()

	var cause error
	select {
	case r := <-done:
		return r.accepted, r.err
	case <-ps.closedSignal():
		cause = net.ErrClosed
	case <-work.Done():
		cause = work.Err()
	}

	shutdownDone := make(chan error, 1)
	go func() {
		closeErr := closeResource(pc.remoteCh, "canceled SSH proxy channel")
		reply := <-done
		shutdownDone <- errors.Join(closeErr, reply.err)
	}()

	timer := time.NewTimer(sessionShutdownTimeout)
	defer timer.Stop()
	select {
	case shutdownErr := <-shutdownDone:
		return false, errors.Join(cause, shutdownErr)
	case <-timer.C:
		var interruptErr error
		if ps.server != nil {
			interruptErr = interruptSSHTransport(ps.server.rootConn, ps.server.sshClient)
			_ = ps.server.Shutdown()
		}
		shutdownErr := <-shutdownDone
		return false, errors.Join(
			cause,
			fmt.Errorf("ssh proxy channel request shutdown timed out after %s", sessionShutdownTimeout),
			interruptErr,
			shutdownErr,
		)
	}
}

// serveChannelRequests forwards queued channel requests in wire order and
// answers want-reply requests in the same order.
func (ps *proxySessionState) serveChannelRequests(pc *proxyChan) {
	if pc.requests == nil {
		return
	}
	defer close(pc.requestsDone)
	for {
		req, ok := pc.requests.pop()
		if !ok {
			return
		}
		var newAgentLease *agentForwardLease
		if req.requestType == agentForwardRequestType {
			var allowed bool
			newAgentLease, allowed = ps.acquireChannelAgentLease()
			if !allowed {
				if req.wantReply && ps.writeChannelReply(pc, false) != nil {
					return
				}
				continue
			}
		}
		accepted, err := ps.sendBoundedProxyChannelRequest(pc, req.requestType, req.wantReply, req.payload)
		if newAgentLease != nil {
			if err == nil && (!req.wantReply || accepted) && !ps.closed.Load() {
				pc.attachAgentProxyLease(newAgentLease)
			} else {
				newAgentLease.Release()
			}
		}
		if !req.wantReply {
			continue
		}
		if ps.writeChannelReply(pc, err == nil && accepted) != nil {
			return
		}
	}
}

// handleGlobalRequest queues a client-to-server global request instead of
// answering it from a free-running goroutine. RFC 4254 global replies carry no
// request ID, so one ordered worker is required to keep request/reply pairing
// intact; concurrent goroutines would pair replies with the wrong request.
func (ps *proxySessionState) handleGlobalRequest(payload []byte) {
	r := newMuxReader(payload)
	reqType, err := r.ReadString()
	if err != nil {
		return
	}
	wantReply, err := r.ReadBool()
	if err != nil {
		return
	}
	var reqPayload []byte
	if r.Remaining() > 0 {
		reqPayload = slices.Clone(r.data[r.off:])
	}

	if ps.server.sshClient == nil || ps.global == nil {
		return
	}
	ps.global.push(proxyGlobalRequest{requestType: reqType, wantReply: wantReply, payload: reqPayload})
}

// isAllowedProxyGlobalRequest restricts which global requests a proxy client
// may forward to the shared SSH transport. Session-mutating global requests
// such as no-more-sessions@openssh.com or cancel-tcpip-forward would affect
// other users of the master.
func isAllowedProxyGlobalRequest(reqType string) bool {
	switch reqType {
	case "keepalive@openssh.com", "hostkeys-prove-00@openssh.com":
		return true
	default:
		return false
	}
}

// serveGlobalRequests forwards allowed queued global requests in wire order.
func (ps *proxySessionState) serveGlobalRequests() {
	for {
		req, ok := ps.global.pop()
		if !ok {
			return
		}
		var (
			accepted     bool
			replyPayload []byte
			err          error
		)
		if isAllowedProxyGlobalRequest(req.requestType) {
			accepted, replyPayload, err = ps.server.sshClient.SendRequest(req.requestType, req.wantReply, req.payload)
		}
		if !req.wantReply {
			continue
		}
		w := newMuxWriter()
		if err != nil || !accepted {
			w.buf = append(w.buf, msgRequestFailure)
		} else {
			w.buf = append(w.buf, msgRequestSuccess)
			if len(replyPayload) > 0 {
				w.buf = append(w.buf, replyPayload...)
			}
		}
		if werr := ps.writePacket(w.Bytes()); werr != nil {
			return
		}
	}
}

func readUnpaddedPacket(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen == 0 || pktLen > MaxMuxPacketLength {
		return nil, fmt.Errorf("invalid unpadded packet length: %d", pktLen)
	}

	buf := make([]byte, pktLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	// buf[0] is padding length (must be 0)
	if buf[0] != 0 {
		return nil, fmt.Errorf("unexpected padding length %d in unpadded packet", buf[0])
	}
	return buf[1:], nil
}

func writeUnpaddedPacket(w io.Writer, payload []byte) error {
	totalLen := uint32(1 + len(payload))
	buf := make([]byte, 4+totalLen)
	binary.BigEndian.PutUint32(buf[0:4], totalLen)
	buf[4] = 0 // padding length = 0
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}
