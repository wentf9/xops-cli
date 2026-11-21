package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type fakeTunnelDevice struct {
	name       string
	mode       TunnelMode
	inbound    chan []byte
	outbound   chan []byte
	closed     chan struct{}
	closeOnce  sync.Once
	closeErr   error
	closeCalls atomic.Int32
}

func newFakeTunnelDevice(name string, mode TunnelMode) *fakeTunnelDevice {
	return &fakeTunnelDevice{
		name:     name,
		mode:     mode,
		inbound:  make(chan []byte, 128),
		outbound: make(chan []byte, 128),
		closed:   make(chan struct{}),
	}
}

func (d *fakeTunnelDevice) Name() string     { return d.name }
func (d *fakeTunnelDevice) Mode() TunnelMode { return d.mode }

func (d *fakeTunnelDevice) ReadPacket(buf []byte) ([]byte, error) {
	select {
	case <-d.closed:
		return nil, os.ErrClosed
	case pkt, ok := <-d.outbound:
		if !ok {
			return nil, os.ErrClosed
		}
		n := copy(buf, pkt)
		return buf[:n], nil
	}
}

func (d *fakeTunnelDevice) WritePacket(pkt []byte) error {
	select {
	case <-d.closed:
		return os.ErrClosed
	default:
	}
	pktCopy := make([]byte, len(pkt))
	copy(pktCopy, pkt)
	select {
	case <-d.closed:
		return os.ErrClosed
	case d.inbound <- pktCopy:
		return nil
	}
}

func (d *fakeTunnelDevice) Close() error {
	d.closeCalls.Add(1)
	d.closeOnce.Do(func() {
		close(d.closed)
	})
	return d.closeErr
}

type fakeTunnelOpener struct {
	mu      sync.Mutex
	devices map[string]*fakeTunnelDevice
	lastDev *fakeTunnelDevice
	openErr error
}

func newFakeTunnelOpener() *fakeTunnelOpener {
	return &fakeTunnelOpener{
		devices: make(map[string]*fakeTunnelDevice),
	}
}

func (o *fakeTunnelOpener) OpenTunnelDevice(mode TunnelMode, localUnit int) (TunnelDevice, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.openErr != nil {
		return nil, o.openErr
	}
	name := fmt.Sprintf("fake%d", localUnit)
	if localUnit == TunnelIDAny {
		name = "fake0"
	}
	dev := newFakeTunnelDevice(name, mode)
	o.devices[name] = dev
	o.lastDev = dev
	return dev, nil
}

func startMockOpenSSHTunnelServer(t *testing.T, onChannel func(newChan cryptoSSH.NewChannel)) (net.Listener, *Client, *fakeTunnelOpener, func()) {
	t.Helper()
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	serverWg := &sync.WaitGroup{}
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			serverWg.Add(1)
			go func(c net.Conn) {
				defer serverWg.Done()
				sConn, chans, reqs, sErr := cryptoSSH.NewServerConn(c, serverConfig)
				if sErr != nil {
					_ = c.Close()
					return
				}
				defer func() { _ = sConn.Close() }()
				go cryptoSSH.DiscardRequests(reqs)
				for newChan := range chans {
					if onChannel != nil {
						onChannel(newChan)
					} else {
						_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unhandled")
					}
				}
			}(conn)
		}
	}()

	rawClient := dialKeepAliveTestClient(t, listener.Addr().String())
	opener := newFakeTunnelOpener()
	teardown := func() {
		_ = rawClient.Close()
		_ = listener.Close()
		serverWg.Wait()
	}

	client := &Client{
		sshClient: rawClient,
		environment: Environment{
			TunnelOpener: opener,
		},
	}
	return listener, client, opener, teardown
}

func makeTestIPv4Packet(payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[4] = 0x00
	pkt[5] = 0x01
	pkt[6] = 0x40
	pkt[7] = 0x00
	pkt[8] = 0x40
	pkt[9] = 0x11 // UDP
	copy(pkt[12:16], []byte{192, 0, 2, 1})
	copy(pkt[16:20], []byte{192, 0, 2, 2})
	if len(payload) > 0 {
		copy(pkt[20:], payload)
	}
	return pkt
}

func makeTestIPv6Packet(payload []byte) []byte {
	payloadLen := len(payload)
	pkt := make([]byte, 40+payloadLen)
	pkt[0] = 0x60
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payloadLen))
	pkt[6] = 0x11 // UDP
	pkt[7] = 0x40 // Hop limit
	pkt[8] = 0x20
	pkt[9] = 0x01
	pkt[10] = 0x0d
	pkt[11] = 0xb8
	pkt[23] = 0x01
	pkt[24] = 0x20
	pkt[25] = 0x01
	pkt[26] = 0x0d
	pkt[27] = 0xb8
	pkt[39] = 0x02
	if payloadLen > 0 {
		copy(pkt[40:], payload)
	}
	return pkt
}

func expectFakeDeviceInboundPacket(t *testing.T, fakeDev *fakeTunnelDevice, want []byte, desc string) {
	t.Helper()
	select {
	case pkt := <-fakeDev.inbound:
		if !bytes.Equal(pkt, want) {
			t.Fatalf("received %s mismatch: got %x, want %x", desc, pkt, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for inbound %s", desc)
	}
}

func TestEncodeDecodeTunnelFrame_PointToPoint(t *testing.T) {
	// 1. IPv4 Frame
	ipv4Pkt := makeTestIPv4Packet([]byte{0x01, 0x02, 0x03, 0x04})
	frame4, err := encodeTunnelFrame(nil, TunnelModePointToPoint, ipv4Pkt)
	if err != nil {
		t.Fatalf("encode IPv4 frame failed: %v", err)
	}
	if len(frame4) != 4+len(ipv4Pkt) {
		t.Fatalf("frame4 length = %d, want %d", len(frame4), 4+len(ipv4Pkt))
	}
	af4 := binary.BigEndian.Uint32(frame4[0:4])
	if af4 != openSSHAFInet {
		t.Errorf("wire AF = %d, want %d (openSSHAFInet)", af4, openSSHAFInet)
	}

	decoded4, err := decodeTunnelPayload(TunnelModePointToPoint, frame4)
	if err != nil {
		t.Fatalf("decode IPv4 frame failed: %v", err)
	}
	if !bytes.Equal(decoded4, ipv4Pkt) {
		t.Errorf("decoded IPv4 mismatch: got %x, want %x", decoded4, ipv4Pkt)
	}

	// 2. IPv6 Frame (OpenBSD AF_INET6 = 24)
	ipv6Pkt := makeTestIPv6Packet([]byte{0xaa, 0xbb, 0xcc, 0xdd})
	frame6, err := encodeTunnelFrame(nil, TunnelModePointToPoint, ipv6Pkt)
	if err != nil {
		t.Fatalf("encode IPv6 frame failed: %v", err)
	}
	if len(frame6) != 4+len(ipv6Pkt) {
		t.Fatalf("frame6 length = %d, want %d", len(frame6), 4+len(ipv6Pkt))
	}
	af6 := binary.BigEndian.Uint32(frame6[0:4])
	if af6 != openSSHAFInet6 {
		t.Errorf("wire AF = %d, want %d (openSSHAFInet6)", af6, openSSHAFInet6)
	}
	decoded6, err := decodeTunnelPayload(TunnelModePointToPoint, frame6)
	if err != nil {
		t.Fatalf("decode IPv6 frame failed: %v", err)
	}
	if !bytes.Equal(decoded6, ipv6Pkt) {
		t.Errorf("decoded IPv6 mismatch: got %x, want %x", decoded6, ipv6Pkt)
	}
}

func TestEncodeDecodeTunnelFrame_EthernetUnsupported(t *testing.T) {
	ethPkt := bytes.Repeat([]byte{0xfe}, 14)
	if _, err := encodeTunnelFrame(nil, TunnelModeEthernet, ethPkt); !errors.Is(err, ErrTunnelDeviceUnsupported) {
		t.Fatalf("encodeTunnelFrame(TunnelModeEthernet) = %v, want ErrTunnelDeviceUnsupported", err)
	}
	if _, err := decodeTunnelPayload(TunnelModeEthernet, ethPkt); !errors.Is(err, ErrTunnelDeviceUnsupported) {
		t.Fatalf("decodeTunnelPayload(TunnelModeEthernet) = %v, want ErrTunnelDeviceUnsupported", err)
	}
}

func TestEncodeDecodeTunnelFrame_BoundaryAndErrors(t *testing.T) {
	t.Run("EncodeErrors", testEncodeTunnelFrameErrors)
	t.Run("DecodeErrors", testDecodeTunnelPayloadErrors)
}

func testEncodeTunnelFrameErrors(t *testing.T) {
	// Empty IP packet on point-to-point
	if _, err := encodeTunnelFrame(nil, TunnelModePointToPoint, nil); err == nil {
		t.Error("expected error encoding empty IP packet")
	}

	// Short IPv4 packet (< 20 bytes)
	if _, err := encodeTunnelFrame(nil, TunnelModePointToPoint, []byte{0x45, 0x00, 0x00, 0x13}); err == nil {
		t.Error("expected error encoding short IPv4 packet")
	}

	// Invalid IPv4 header length (ihl < 20)
	badIHL := makeTestIPv4Packet(nil)
	badIHL[0] = 0x44 // ihl = 16
	if _, err := encodeTunnelFrame(nil, TunnelModePointToPoint, badIHL); err == nil {
		t.Error("expected error encoding IPv4 packet with invalid IHL")
	}

	// IPv4 total length mismatch
	badTotalLen := makeTestIPv4Packet(nil)
	binary.BigEndian.PutUint16(badTotalLen[2:4], 50)
	if _, err := encodeTunnelFrame(nil, TunnelModePointToPoint, badTotalLen); err == nil {
		t.Error("expected error encoding IPv4 packet with total length mismatch")
	}

	// Short IPv6 packet (< 40 bytes)
	shortV6 := make([]byte, 39)
	shortV6[0] = 0x60
	if _, err := encodeTunnelFrame(nil, TunnelModePointToPoint, shortV6); err == nil {
		t.Error("expected error encoding short IPv6 packet")
	}

	// IPv6 payload length mismatch
	badPayloadLen := makeTestIPv6Packet(nil)
	binary.BigEndian.PutUint16(badPayloadLen[4:6], 10)
	if _, err := encodeTunnelFrame(nil, TunnelModePointToPoint, badPayloadLen); err == nil {
		t.Error("expected error encoding IPv6 packet with payload length mismatch")
	}

	// Unsupported IP version (0x30 -> version 3)
	if _, err := encodeTunnelFrame(nil, TunnelModePointToPoint, []byte{0x30}); err == nil {
		t.Error("expected error encoding IP version 3")
	}

	// Ethernet mode explicitly unsupported
	if _, err := encodeTunnelFrame(nil, TunnelModeEthernet, make([]byte, 14)); !errors.Is(err, ErrTunnelDeviceUnsupported) {
		t.Errorf("encodeTunnelFrame(TunnelModeEthernet) = %v, want ErrTunnelDeviceUnsupported", err)
	}

	// Payload exceeding maxTunnelWirePayloadBytes
	hugePkt := makeTestIPv4Packet(make([]byte, maxTunnelWirePayloadBytes))
	if _, err := encodeTunnelFrame(nil, TunnelModePointToPoint, hugePkt); err == nil {
		t.Error("expected error encoding oversized IP packet")
	}

	// Unsupported tunnel mode
	if _, err := encodeTunnelFrame(nil, TunnelModeNo, []byte{0x45}); err == nil {
		t.Error("expected error encoding with TunnelModeNo")
	}
}

func testDecodeTunnelPayloadErrors(t *testing.T) {
	// Decode short frame (< 4 bytes for P2P)
	if _, err := decodeTunnelPayload(TunnelModePointToPoint, []byte{0x00, 0x00, 0x02}); err == nil {
		t.Error("expected error decoding short P2P frame")
	}

	// Decode AF_INET mismatch with IP version (AF=2, but IP=6)
	mismatchV6 := append([]byte{0x00, 0x00, 0x00, 0x02}, makeTestIPv6Packet(nil)...)
	if _, err := decodeTunnelPayload(TunnelModePointToPoint, mismatchV6); err == nil {
		t.Error("expected error decoding AF_INET with IPv6 packet")
	}

	// Decode AF_INET6 mismatch with IP version (AF=24, but IP=4)
	mismatchV4 := append([]byte{0x00, 0x00, 0x00, 0x18}, makeTestIPv4Packet(nil)...)
	if _, err := decodeTunnelPayload(TunnelModePointToPoint, mismatchV4); err == nil {
		t.Error("expected error decoding AF_INET6 with IPv4 packet")
	}

	// Decode unknown AF
	unknownAF := append([]byte{0x00, 0x00, 0x00, 0x99}, makeTestIPv4Packet(nil)...)
	if _, err := decodeTunnelPayload(TunnelModePointToPoint, unknownAF); err == nil {
		t.Error("expected error decoding unknown address family")
	}

	// Ethernet mode explicitly unsupported
	if _, err := decodeTunnelPayload(TunnelModeEthernet, make([]byte, 14)); !errors.Is(err, ErrTunnelDeviceUnsupported) {
		t.Errorf("decodeTunnelPayload(TunnelModeEthernet) = %v, want ErrTunnelDeviceUnsupported", err)
	}

	// Unsupported tunnel mode
	if _, err := decodeTunnelPayload(TunnelModeNo, []byte{0x45}); err == nil {
		t.Error("expected error decoding with TunnelModeNo")
	}
}

func servePointToPointBidirectionalChannel(t *testing.T, ch cryptoSSH.Channel, send4, send6 []byte) {
	defer func() { _ = ch.Close() }()

	wantWire4 := append([]byte{0x00, 0x00, 0x00, 0x02}, send4...)
	gotWire4 := make([]byte, len(wantWire4))
	if _, rErr := io.ReadFull(ch, gotWire4); rErr != nil {
		t.Errorf("server read IPv4 wire err: %v", rErr)
		return
	}
	if !bytes.Equal(gotWire4, wantWire4) {
		t.Errorf("server received IPv4 wire mismatch: got %x, want %x", gotWire4, wantWire4)
		return
	}

	wantWire6 := append([]byte{0x00, 0x00, 0x00, 0x18}, send6...)
	gotWire6 := make([]byte, len(wantWire6))
	if _, rErr := io.ReadFull(ch, gotWire6); rErr != nil {
		t.Errorf("server read IPv6 wire err: %v", rErr)
		return
	}
	if !bytes.Equal(gotWire6, wantWire6) {
		t.Errorf("server received IPv6 wire mismatch: got %x, want %x", gotWire6, wantWire6)
		return
	}

	resp4 := makeTestIPv4Packet([]byte{0xaa, 0xbb, 0xcc, 0xdd})
	wire4 := append([]byte{0x00, 0x00, 0x00, 0x02}, resp4...)
	if _, wErr := ch.Write(wire4); wErr != nil {
		t.Errorf("server write IPv4 wire err: %v", wErr)
		return
	}

	resp6 := makeTestIPv6Packet([]byte{0x10, 0x11, 0x22})
	wire6 := append([]byte{0x00, 0x00, 0x00, 0x18}, resp6...)
	if _, wErr := ch.Write(wire6); wErr != nil {
		t.Errorf("server write IPv6 wire err: %v", wErr)
		return
	}

	buf := make([]byte, 1024)
	for {
		if _, rErr := ch.Read(buf); rErr != nil {
			break
		}
	}
}

func TestTunnelDeviceForward_PointToPoint_Bidirectional(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	var (
		openMode       uint32
		openRemoteUnit uint32
	)
	channelReady := make(chan struct{})

	send4 := makeTestIPv4Packet([]byte{0x01, 0x02, 0x03, 0x04})
	send6 := makeTestIPv6Packet([]byte{0x05, 0x06, 0x07, 0x08})

	_, client, opener, teardown := startMockOpenSSHTunnelServer(t, func(newChan cryptoSSH.NewChannel) {
		if newChan.ChannelType() != "tun@openssh.com" {
			_ = newChan.Reject(cryptoSSH.UnknownChannelType, "not tun@openssh.com")
			return
		}
		var msg tunnelChannelOpenMsg
		if err := cryptoSSH.Unmarshal(newChan.ExtraData(), &msg); err != nil {
			_ = newChan.Reject(cryptoSSH.ConnectionFailed, "bad open msg")
			return
		}
		openMode = msg.Mode
		openRemoteUnit = msg.RemoteUnit

		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go cryptoSSH.DiscardRequests(reqs)
		close(channelReady)
		servePointToPointBidirectionalChannel(t, ch, send4, send6)
	})
	defer teardown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	spec := TunnelDeviceSpec{LocalUnit: 0, RemoteUnit: TunnelIDAny}
	forward, err := client.TunnelDeviceForward(ctx, TunnelModePointToPoint, spec)
	if err != nil {
		t.Fatalf("TunnelDeviceForward failed: %v", err)
	}

	select {
	case <-channelReady:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel channel was not opened")
	}

	if openMode != openSSHTunModePointToPoint {
		t.Errorf("openMode = %d, want %d", openMode, openSSHTunModePointToPoint)
	}
	if openRemoteUnit != uint32(math.MaxInt32) {
		t.Errorf("openRemoteUnit = %d, want %d", openRemoteUnit, math.MaxInt32)
	}

	fakeDev := opener.lastDev
	if fakeDev == nil {
		t.Fatal("fake tunnel device was not created")
	}

	fakeDev.outbound <- send4
	fakeDev.outbound <- send6

	want4 := makeTestIPv4Packet([]byte{0xaa, 0xbb, 0xcc, 0xdd})
	expectFakeDeviceInboundPacket(t, fakeDev, want4, "IPv4 response packet")

	want6 := makeTestIPv6Packet([]byte{0x10, 0x11, 0x22})
	expectFakeDeviceInboundPacket(t, fakeDev, want6, "IPv6 response packet")

	cancel()
	if wErr := forward.Wait(); wErr != nil {
		t.Errorf("forward.Wait() on canceled context error = %v, want nil", wErr)
	}
}

func TestTunnelDeviceForward_Ethernet_UnsupportedFailsClosed(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	channelOpened := false
	_, client, opener, teardown := startMockOpenSSHTunnelServer(t, func(newChan cryptoSSH.NewChannel) {
		channelOpened = true
		_ = newChan.Reject(cryptoSSH.Prohibited, "should not be called")
	})
	defer teardown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	spec := TunnelDeviceSpec{LocalUnit: 1, RemoteUnit: 2}
	forward, err := client.TunnelDeviceForward(ctx, TunnelModeEthernet, spec)
	if !errors.Is(err, ErrTunnelDeviceUnsupported) {
		t.Fatalf("TunnelDeviceForward(TunnelModeEthernet) = (%v, %v), want ErrTunnelDeviceUnsupported", forward, err)
	}
	if forward != nil {
		t.Fatalf("expected nil forward on unsupported ethernet mode, got %v", forward)
	}
	if opener.lastDev != nil {
		t.Fatal("local tunnel device should not be opened when ethernet mode is unsupported")
	}
	if channelOpened {
		t.Fatal("remote tun@openssh.com channel should not be opened when ethernet mode is unsupported")
	}
}

func TestTunnelDeviceForward_ServerRejectRollsBackDevice(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	_, client, opener, teardown := startMockOpenSSHTunnelServer(t, func(newChan cryptoSSH.NewChannel) {
		if newChan.ChannelType() != "tun@openssh.com" {
			_ = newChan.Reject(cryptoSSH.UnknownChannelType, "not tun@openssh.com")
			return
		}
		_ = newChan.Reject(cryptoSSH.Prohibited, "administratively prohibited by administrator")
	})
	defer teardown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	spec := TunnelDeviceSpec{LocalUnit: 0, RemoteUnit: 0}
	forward, err := client.TunnelDeviceForward(ctx, TunnelModePointToPoint, spec)
	if err == nil {
		_ = forward.Wait()
		t.Fatal("TunnelDeviceForward() error = nil, want channel rejection error")
	}

	dev := opener.lastDev
	if dev == nil {
		t.Fatal("expected local device to be opened before channel open attempt")
	}
	if dev.closeCalls.Load() < 1 {
		t.Errorf("expected local device to be closed after channel open failure, closeCalls = %d", dev.closeCalls.Load())
	}
}

func TestTunnelDeviceForward_RemoteDisconnectReturnsError(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	channelReady := make(chan struct{})
	var serverCh cryptoSSH.Channel

	_, client, _, teardown := startMockOpenSSHTunnelServer(t, func(newChan cryptoSSH.NewChannel) {
		if newChan.ChannelType() != "tun@openssh.com" {
			_ = newChan.Reject(cryptoSSH.UnknownChannelType, "not tun@openssh.com")
			return
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go cryptoSSH.DiscardRequests(reqs)
		serverCh = ch
		close(channelReady)
	})
	defer teardown()

	ctx := context.Background()
	spec := TunnelDeviceSpec{LocalUnit: 0, RemoteUnit: 0}
	forward, err := client.TunnelDeviceForward(ctx, TunnelModePointToPoint, spec)
	if err != nil {
		t.Fatalf("TunnelDeviceForward failed: %v", err)
	}

	select {
	case <-channelReady:
	case <-time.After(3 * time.Second):
		t.Fatal("channel not opened")
	}

	_ = serverCh.Close()

	waitErr := forward.Wait()
	if waitErr == nil {
		t.Fatal("forward.Wait() error = nil, want connection lost error on remote disconnect")
	}
}

func verifyCoalescedPointToPointReads(t *testing.T, serverCh cryptoSSH.Channel, fakeDev *fakeTunnelDevice) {
	t.Helper()
	pkt1 := makeTestIPv4Packet([]byte("coalesced-1"))
	wire1 := append([]byte{0x00, 0x00, 0x00, 0x02}, pkt1...)

	pkt2 := makeTestIPv6Packet([]byte("coalesced-2"))
	wire2 := append([]byte{0x00, 0x00, 0x00, 0x18}, pkt2...)

	pkt3 := makeTestIPv4Packet([]byte("coalesced-3"))
	wire3 := append([]byte{0x00, 0x00, 0x00, 0x02}, pkt3...)

	combined := make([]byte, 0, len(wire1)+len(wire2)+len(wire3))
	combined = append(combined, wire1...)
	combined = append(combined, wire2...)
	combined = append(combined, wire3...)

	if _, wErr := serverCh.Write(combined); wErr != nil {
		t.Fatalf("server write coalesced frames err: %v", wErr)
	}

	expectFakeDeviceInboundPacket(t, fakeDev, pkt1, "coalesced packet 1")
	expectFakeDeviceInboundPacket(t, fakeDev, pkt2, "coalesced packet 2")
	expectFakeDeviceInboundPacket(t, fakeDev, pkt3, "coalesced packet 3")
}

func verifySplitPointToPointReads(t *testing.T, serverCh cryptoSSH.Channel, fakeDev *fakeTunnelDevice) {
	t.Helper()
	splitPkt := makeTestIPv4Packet([]byte("split-packet-payload-test"))
	wireSplit := append([]byte{0x00, 0x00, 0x00, 0x02}, splitPkt...)
	if len(wireSplit) <= 6 {
		t.Fatalf("wireSplit too short: %d", len(wireSplit))
	}

	if _, wErr := serverCh.Write(wireSplit[:6]); wErr != nil {
		t.Fatalf("server write split head err: %v", wErr)
	}
	time.Sleep(20 * time.Millisecond)
	if _, wErr := serverCh.Write(wireSplit[6:]); wErr != nil {
		t.Fatalf("server write split tail err: %v", wErr)
	}

	expectFakeDeviceInboundPacket(t, fakeDev, splitPkt, "split packet")
}

func TestTunnelDeviceForward_PointToPoint_CoalescedAndSplitReads(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	channelReady := make(chan struct{})
	var serverCh cryptoSSH.Channel

	_, client, opener, teardown := startMockOpenSSHTunnelServer(t, func(newChan cryptoSSH.NewChannel) {
		if newChan.ChannelType() != "tun@openssh.com" {
			_ = newChan.Reject(cryptoSSH.UnknownChannelType, "not tun@openssh.com")
			return
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go cryptoSSH.DiscardRequests(reqs)
		serverCh = ch
		close(channelReady)
	})
	defer teardown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	spec := TunnelDeviceSpec{LocalUnit: 0, RemoteUnit: 0}
	forward, err := client.TunnelDeviceForward(ctx, TunnelModePointToPoint, spec)
	if err != nil {
		t.Fatalf("TunnelDeviceForward failed: %v", err)
	}

	select {
	case <-channelReady:
	case <-time.After(3 * time.Second):
		t.Fatal("channel not opened")
	}

	fakeDev := opener.lastDev
	if fakeDev == nil {
		t.Fatal("fake tunnel device was not created")
	}

	verifyCoalescedPointToPointReads(t, serverCh, fakeDev)
	verifySplitPointToPointReads(t, serverCh, fakeDev)

	cancel()
	if wErr := forward.Wait(); wErr != nil {
		t.Errorf("forward.Wait() on cancel err = %v, want nil", wErr)
	}
}

func TestTunnelDeviceForward_MalformedRemotePacketNonFatal(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	channelReady := make(chan struct{})
	var serverCh cryptoSSH.Channel

	_, client, opener, teardown := startMockOpenSSHTunnelServer(t, func(newChan cryptoSSH.NewChannel) {
		if newChan.ChannelType() != "tun@openssh.com" {
			_ = newChan.Reject(cryptoSSH.UnknownChannelType, "not tun@openssh.com")
			return
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go cryptoSSH.DiscardRequests(reqs)
		serverCh = ch
		close(channelReady)
	})
	defer teardown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 10)
	spec := TunnelDeviceSpec{LocalUnit: 0, RemoteUnit: 0}
	forward, err := client.TunnelDeviceForward(ctx, TunnelModePointToPoint, spec,
		WithForwardErrorHandler(func(e error) {
			select {
			case errChan <- e:
			default:
			}
		}),
	)
	if err != nil {
		t.Fatalf("TunnelDeviceForward failed: %v", err)
	}

	select {
	case <-channelReady:
	case <-time.After(3 * time.Second):
		t.Fatal("channel not opened")
	}

	fakeDev := opener.lastDev
	if fakeDev == nil {
		t.Fatal("fake tunnel device was not created")
	}

	// 1. Server writes a bogus AF frame ([0x00, 0x00, 0x00, 0x99, ...])
	bogusFrame := []byte{0x00, 0x00, 0x00, 0x99, 0x45, 0x00, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04}
	if _, wErr := serverCh.Write(bogusFrame); wErr != nil {
		t.Fatalf("server write bogus frame err: %v", wErr)
	}

	// Wait for non-fatal packet error callback to fire
	select {
	case pktErr := <-errChan:
		if pktErr == nil {
			t.Fatal("expected non-nil packet error from handler")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for error handler to receive malformed packet error")
	}

	// 2. Server writes a valid IPv4 frame
	validPkt := makeTestIPv4Packet([]byte("after-malformed-recovery"))
	validWire := append([]byte{0x00, 0x00, 0x00, 0x02}, validPkt...)
	if _, wErr := serverCh.Write(validWire); wErr != nil {
		t.Fatalf("server write valid wire err: %v", wErr)
	}

	expectFakeDeviceInboundPacket(t, fakeDev, validPkt, "valid packet after malformed frame")

	cancel()
	if wErr := forward.Wait(); wErr != nil {
		t.Errorf("forward.Wait() on cancel err = %v, want nil", wErr)
	}
}

type stalledCloseTunnelChannel struct {
	reqs      chan *cryptoSSH.Request
	closed    chan struct{}
	closeOnce sync.Once
	connDone  <-chan struct{}
}

func (c *stalledCloseTunnelChannel) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *stalledCloseTunnelChannel) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *stalledCloseTunnelChannel) CloseWrite() error { return nil }

func (c *stalledCloseTunnelChannel) Stderr() io.ReadWriter { return nil }

func (c *stalledCloseTunnelChannel) SendRequest(string, bool, []byte) (bool, error) {
	return true, nil
}

func (c *stalledCloseTunnelChannel) Close() error {
	// Stall channel close until transport Interrupt (conn.Close) closes connDone.
	<-c.connDone
	c.closeOnce.Do(func() {
		close(c.closed)
		close(c.reqs)
	})
	return nil
}

type stalledCloseTunnelConn struct {
	*dummySSHConn
	chOpened chan struct{}
}

func (s *stalledCloseTunnelConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	reqs := make(chan *cryptoSSH.Request)
	ch := &stalledCloseTunnelChannel{
		reqs:     reqs,
		closed:   make(chan struct{}),
		connDone: s.closedChan(),
	}
	select {
	case <-s.chOpened:
	default:
		close(s.chOpened)
	}
	return ch, reqs, nil
}

func TestTunnelDeviceForward_StalledCloseCancelTriggersInterruptBounded(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	conn := &stalledCloseTunnelConn{
		dummySSHConn: &dummySSHConn{chans: chans, reqs: reqs},
		chOpened:     make(chan struct{}),
	}
	sshClient := cryptoSSH.NewClient(conn, chans, reqs)
	defer func() { _ = sshClient.Close() }()

	client := &Client{
		sshClient: sshClient,
		environment: Environment{
			TunnelOpener: newFakeTunnelOpener(),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	forward, err := client.TunnelDeviceForward(ctx, TunnelModePointToPoint, TunnelDeviceSpec{LocalUnit: 0, RemoteUnit: 0})
	if err != nil {
		cancel()
		t.Fatalf("TunnelDeviceForward failed: %v", err)
	}
	<-conn.chOpened

	start := time.Now()
	cancel()
	waitErr := forward.Wait()
	elapsed := time.Since(start)
	if waitErr != nil {
		t.Fatalf("forward.Wait() error = %v, want nil on ctx cancel", waitErr)
	}
	if elapsed > sessionShutdownTimeout+1500*time.Millisecond {
		t.Fatalf("forward.Wait() took %v, expected bounded exit after sessionShutdownTimeout", elapsed)
	}
	select {
	case <-conn.closedChan():
	default:
		t.Fatal("expected stalled ch.Close() after ctx cancel to trigger c.Interrupt() (conn.Close)")
	}
}

type asyncReqsCloseTunnelChannel struct {
	reqs       chan *cryptoSSH.Request
	closed     chan struct{}
	closeOnce  sync.Once
	reqsClosed atomic.Bool
}

func (c *asyncReqsCloseTunnelChannel) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *asyncReqsCloseTunnelChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *asyncReqsCloseTunnelChannel) CloseWrite() error           { return nil }
func (c *asyncReqsCloseTunnelChannel) Stderr() io.ReadWriter       { return nil }
func (c *asyncReqsCloseTunnelChannel) SendRequest(string, bool, []byte) (bool, error) {
	return true, nil
}
func (c *asyncReqsCloseTunnelChannel) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		time.AfterFunc(80*time.Millisecond, func() {
			c.reqsClosed.Store(true)
			close(c.reqs)
		})
	})
	return nil
}

type asyncReqsCloseTunnelConn struct {
	*dummySSHConn
	lastCh *asyncReqsCloseTunnelChannel
}

func (s *asyncReqsCloseTunnelConn) OpenChannel(string, []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	reqs := make(chan *cryptoSSH.Request)
	ch := &asyncReqsCloseTunnelChannel{
		reqs:   reqs,
		closed: make(chan struct{}),
	}
	s.lastCh = ch
	return ch, reqs, nil
}

func TestTunnelDeviceForward_RemoteEOFJoinsDiscardRequests(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	conn := &asyncReqsCloseTunnelConn{dummySSHConn: &dummySSHConn{chans: chans, reqs: reqs}}
	sshClient := cryptoSSH.NewClient(conn, chans, reqs)
	defer func() { _ = sshClient.Close() }()

	client := &Client{
		sshClient: sshClient,
		environment: Environment{
			TunnelOpener: newFakeTunnelOpener(),
		},
	}

	forward, err := client.TunnelDeviceForward(t.Context(), TunnelModePointToPoint, TunnelDeviceSpec{LocalUnit: 0, RemoteUnit: 0})
	if err != nil {
		t.Fatalf("TunnelDeviceForward failed: %v", err)
	}

	_ = forward.Wait()
	if conn.lastCh == nil || !conn.lastCh.reqsClosed.Load() {
		t.Fatal("forward.Wait() returned before DiscardRequests(reqs) completed")
	}
}
