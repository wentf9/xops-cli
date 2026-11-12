package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// ErrTunnelDeviceUnsupported indicates that local kernel tun/tap forwarding is
// unavailable on the current operating system or requested TunnelMode.
var ErrTunnelDeviceUnsupported = errors.New("tunnel device forwarding is not supported on this platform")

const (
	openSSHTunnelChannelType = "tun@openssh.com"

	openSSHTunModePointToPoint uint32 = 1
	openSSHTunModeEthernet     uint32 = 2

	// OpenSSH wire address family constants (OpenBSD AF_INET=2, AF_INET6=24).
	openSSHAFInet  uint32 = 2
	openSSHAFInet6 uint32 = 24

	// OpenSSH wire payload limits.
	maxTunnelWirePayloadBytes = 32768
	maxTunnelDeviceReadBytes  = 65536
	maxTunnelRxFrameBytes     = 4 + 40 + 65535 // 65579
)

// TunnelDevice abstracts a local OS Layer-3 (tun/utun) or Layer-2 (tap) virtual interface.
//
// Packet framing contract:
//   - In TunnelModePointToPoint, ReadPacket and WritePacket exchange raw IPv4/IPv6
//     packets WITHOUT OS-specific PI or BSD loopback headers.
//   - In TunnelModeEthernet, ReadPacket and WritePacket exchange raw IEEE 802.3
//     Ethernet frames.
//   - Close must be idempotent and immediately unblock any concurrent ReadPacket/WritePacket.
type TunnelDevice interface {
	Name() string
	Mode() TunnelMode
	ReadPacket(buf []byte) ([]byte, error)
	WritePacket(pkt []byte) error
	Close() error
}

// TunnelDeviceOpener creates or attaches to a local OS tunnel interface.
type TunnelDeviceOpener interface {
	OpenTunnelDevice(mode TunnelMode, localUnit int) (TunnelDevice, error)
}

type platformTunnelDeviceOpener struct{}

func (platformTunnelDeviceOpener) OpenTunnelDevice(mode TunnelMode, localUnit int) (TunnelDevice, error) {
	return openPlatformTunnelDevice(mode, localUnit)
}

type tunnelChannelOpenMsg struct {
	Mode       uint32
	RemoteUnit uint32
}

type tunnelNetAddr struct {
	network string
	name    string
}

func (a tunnelNetAddr) Network() string { return a.network }
func (a tunnelNetAddr) String() string  { return a.name }

// TunnelDeviceForward opens a local tun/tap device and bridges packets with the
// remote SSH server over an OpenSSH "tun@openssh.com" channel.
//
// Ownership contract: On startup error, any opened local TunnelDevice is closed
// before returning. Once started, the returned *Forward owns both the local
// TunnelDevice and the SSH channel until ctx is canceled or either endpoint closes.
func (c *Client) TunnelDeviceForward(ctx context.Context, mode TunnelMode, spec TunnelDeviceSpec, opts ...ForwardOption) (*Forward, error) {
	if ctx == nil {
		return nil, fmt.Errorf("tunnel device forward context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("tunnel device forward canceled: %w", err)
	}
	if c == nil || c.sshClient == nil {
		return nil, fmt.Errorf("SSH client is not connected")
	}
	var wireMode uint32
	var networkName string
	switch mode {
	case TunnelModeYes, TunnelModePointToPoint:
		mode = TunnelModePointToPoint
		wireMode = openSSHTunModePointToPoint
		networkName = "tun"
	case TunnelModeEthernet:
		wireMode = openSSHTunModeEthernet
		networkName = "tap"
	default:
		return nil, fmt.Errorf("invalid tunnel mode %q for tunnel device forwarding", mode)
	}
	if spec.LocalUnit < 0 || spec.LocalUnit > TunnelIDAny || spec.RemoteUnit < 0 || spec.RemoteUnit > TunnelIDAny {
		return nil, fmt.Errorf("invalid tunnel device unit specification %+v", spec)
	}

	opener := c.environment.TunnelOpener
	if nilCapability(opener) {
		opener = platformTunnelDeviceOpener{}
	}

	dev, err := opener.OpenTunnelDevice(mode, spec.LocalUnit)
	if err != nil {
		return nil, fmt.Errorf("open local tunnel device (%s, unit=%s) failed: %w", mode, formatTunnelUnit(spec.LocalUnit), err)
	}

	openPayload := cryptoSSH.Marshal(&tunnelChannelOpenMsg{
		Mode:       wireMode,
		RemoteUnit: uint32(spec.RemoteUnit),
	})
	ch, reqs, err := c.openChannelContext(ctx, openSSHTunnelChannelType, openPayload)
	if err != nil {
		closeDevErr := closeTunnelDevice(dev)
		return nil, errors.Join(
			fmt.Errorf("open remote %s channel (%s, remote=%s) failed: %w", openSSHTunnelChannelType, mode, formatTunnelUnit(spec.RemoteUnit), err),
			closeDevErr,
		)
	}
	go cryptoSSH.DiscardRequests(reqs)

	options := c.forwardOptions(opts...)
	addr := tunnelNetAddr{network: networkName, name: dev.Name()}
	forward := &Forward{done: make(chan struct{}), addr: addr}

	runCtx, runCancel := context.WithCancel(ctx)
	closeEndpoints := sync.OnceValue(func() error {
		return errors.Join(closeTunnelDevice(dev), closeSSHChannel(ch))
	})

	stopOnCancel := context.AfterFunc(runCtx, func() {
		_ = closeEndpoints()
	})

	go func() {
		defer close(forward.done)
		defer runCancel()

		errCh := make(chan error, 2)
		var wg sync.WaitGroup

		// tx: local tunnel device -> SSH tun@openssh.com channel
		wg.Go(func() {
			errCh <- pumpDeviceToChannel(runCtx, dev, ch, mode, options.onConnectionError)
		})

		// rx: SSH tun@openssh.com channel -> local tunnel device
		wg.Go(func() {
			errCh <- pumpChannelToDevice(runCtx, ch, dev, mode, options.onConnectionError)
		})

		firstErr := <-errCh
		runCancel()
		_ = stopOnCancel()
		closeErr := closeEndpoints()
		wg.Wait()
		secondErr := <-errCh

		if ctx.Err() == nil {
			forward.err = errors.Join(firstErr, secondErr, closeErr)
		}
	}()

	return forward, nil
}

func closeTunnelDevice(dev TunnelDevice) error {
	if dev == nil {
		return nil
	}
	if err := dev.Close(); err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func pumpDeviceToChannel(ctx context.Context, dev TunnelDevice, ch io.Writer, mode TunnelMode, onPacketErr func(error)) error {
	readBuf := make([]byte, maxTunnelDeviceReadBytes)
	var frameBuf []byte
	for {
		pkt, err := dev.ReadPacket(readBuf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read local tunnel device %s failed: %w", dev.Name(), err)
		}
		if len(pkt) == 0 {
			continue
		}
		var encErr error
		frameBuf, encErr = encodeTunnelFrame(frameBuf[:0], mode, pkt)
		if encErr != nil {
			if onPacketErr != nil && ctx.Err() == nil {
				onPacketErr(encErr)
			}
			continue
		}
		if _, writeErr := ch.Write(frameBuf); writeErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("SSH connection lost on tunnel %s write: %w", dev.Name(), writeErr)
		}
	}
}

func pumpChannelToDevice(ctx context.Context, ch io.Reader, dev TunnelDevice, mode TunnelMode, onPacketErr func(error)) error {
	switch mode {
	case TunnelModePointToPoint:
		return pumpPointToPointToDevice(ctx, ch, dev, onPacketErr)
	case TunnelModeEthernet:
		return pumpEthernetToDevice(ctx, ch, dev, onPacketErr)
	default:
		return fmt.Errorf("unsupported tunnel mode %q", mode)
	}
}

func pumpPointToPointToDevice(ctx context.Context, ch io.Reader, dev TunnelDevice, onPacketErr func(error)) error {
	buf := make([]byte, maxTunnelRxFrameBytes*2)
	buffered := 0
	for {
		if buffered == len(buf) {
			if onPacketErr != nil && ctx.Err() == nil {
				onPacketErr(fmt.Errorf("point-to-point tunnel receive buffer full (%d bytes)", buffered))
			}
			buffered = 0
		}
		n, rErr := ch.Read(buf[buffered:])
		if n > 0 {
			var procErr error
			buffered, procErr = processBufferedPointToPoint(ctx, dev, buf, buffered+n, onPacketErr)
			if procErr != nil {
				return procErr
			}
		}
		if rErr != nil {
			if buffered > 0 && onPacketErr != nil && ctx.Err() == nil {
				onPacketErr(fmt.Errorf("truncated point-to-point tunnel frame (%d trailing bytes)", buffered))
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("SSH connection lost on tunnel %s read: %w", dev.Name(), rErr)
		}
	}
}

func processBufferedPointToPoint(ctx context.Context, dev TunnelDevice, buf []byte, buffered int, onPacketErr func(error)) (int, error) {
	offset := 0
	for offset < buffered {
		pkt, consumed, needMore, err := extractNextPointToPointPacket(buf[offset:buffered])
		if err != nil {
			if onPacketErr != nil && ctx.Err() == nil {
				onPacketErr(err)
			}
			offset = buffered
			break
		}
		if needMore {
			break
		}
		if writeErr := dev.WritePacket(pkt); writeErr != nil {
			if ctx.Err() != nil || errors.Is(writeErr, os.ErrClosed) || errors.Is(writeErr, net.ErrClosed) {
				return 0, nil
			}
			return 0, fmt.Errorf("write local tunnel device %s failed: %w", dev.Name(), writeErr)
		}
		offset += consumed
	}
	if offset > 0 {
		return copy(buf, buf[offset:buffered]), nil
	}
	return buffered, nil
}

func extractNextPointToPointPacket(data []byte) (pkt []byte, consumed int, needMore bool, err error) {
	if len(data) < 4 {
		return nil, 0, true, nil
	}
	af := binary.BigEndian.Uint32(data[0:4])
	switch af {
	case openSSHAFInet:
		if len(data) >= 5 && (data[4]>>4) != 4 {
			return nil, 0, false, fmt.Errorf("tunnel AF_INET header mismatch with IP version %d", data[4]>>4)
		}
		if len(data) < 24 {
			return nil, 0, true, nil
		}
		ihl := int(data[4]&0x0f) * 4
		if ihl < 20 {
			return nil, 0, false, fmt.Errorf("invalid IPv4 header length %d", ihl)
		}
		totalLen := int(binary.BigEndian.Uint16(data[6:8]))
		if totalLen < ihl {
			return nil, 0, false, fmt.Errorf("invalid IPv4 total length %d", totalLen)
		}
		frameLen := 4 + totalLen
		if len(data) < frameLen {
			return nil, 0, true, nil
		}
		return data[4:frameLen], frameLen, false, nil

	case openSSHAFInet6:
		if len(data) >= 5 && (data[4]>>4) != 6 {
			return nil, 0, false, fmt.Errorf("tunnel AF_INET6 header mismatch with IP version %d", data[4]>>4)
		}
		if len(data) < 44 {
			return nil, 0, true, nil
		}
		payloadLen := int(binary.BigEndian.Uint16(data[8:10]))
		frameLen := 44 + payloadLen
		if len(data) < frameLen {
			return nil, 0, true, nil
		}
		return data[4:frameLen], frameLen, false, nil

	default:
		return nil, 0, false, fmt.Errorf("unsupported OpenSSH tunnel address family %d", af)
	}
}

// pumpEthernetToDevice pumps L2 Ethernet frames from the SSH channel to the local TAP device.
// Unlike L3 point-to-point tunnels where IP headers define exact packet lengths, Ethernet II
// frames lack a universal L2 frame length field (EtherType indicates payload protocol, not frame
// length, and frames may contain trailing hardware padding). OpenSSH tun@openssh.com in ethernet
// mode relies on 1:1 SSH_MSG_CHANNEL_DATA message framing per Ethernet frame, with no extra
// inner header.
func pumpEthernetToDevice(ctx context.Context, ch io.Reader, dev TunnelDevice, onPacketErr func(error)) error {
	readBuf := make([]byte, maxTunnelDeviceReadBytes)
	for {
		n, rErr := ch.Read(readBuf)
		if n > 0 {
			pkt, decErr := decodeTunnelPayload(TunnelModeEthernet, readBuf[:n])
			if decErr != nil {
				if onPacketErr != nil && ctx.Err() == nil {
					onPacketErr(decErr)
				}
			} else {
				if writeErr := dev.WritePacket(pkt); writeErr != nil {
					if ctx.Err() != nil || errors.Is(writeErr, os.ErrClosed) || errors.Is(writeErr, net.ErrClosed) {
						return nil
					}
					return fmt.Errorf("write local tunnel device %s failed: %w", dev.Name(), writeErr)
				}
			}
		}
		if rErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("SSH connection lost on tunnel %s read: %w", dev.Name(), rErr)
		}
	}
}

// encodeTunnelFrame encodes a raw L3 IP packet or L2 Ethernet frame into an
// OpenSSH tun@openssh.com wire frame ([uint32 AF][pkt] for point-to-point, [pkt] for ethernet).
func encodeTunnelFrame(dst []byte, mode TunnelMode, pkt []byte) ([]byte, error) {
	switch mode {
	case TunnelModePointToPoint:
		af, err := validatePointToPointPacket(pkt)
		if err != nil {
			return dst, err
		}
		if 4+len(pkt) > maxTunnelWirePayloadBytes {
			return dst, fmt.Errorf("IP packet size %d exceeds maximum tunnel wire payload (%d)", len(pkt), maxTunnelWirePayloadBytes)
		}
		total := 4 + len(pkt)
		if cap(dst) < total {
			dst = make([]byte, total)
		} else {
			dst = dst[:total]
		}
		binary.BigEndian.PutUint32(dst[0:4], af)
		copy(dst[4:], pkt)
		return dst, nil

	case TunnelModeEthernet:
		if len(pkt) < 14 {
			return dst, fmt.Errorf("ethernet frame too short (%d bytes)", len(pkt))
		}
		if len(pkt) > maxTunnelWirePayloadBytes {
			return dst, fmt.Errorf("ethernet frame size %d exceeds maximum tunnel wire payload (%d)", len(pkt), maxTunnelWirePayloadBytes)
		}
		total := len(pkt)
		if cap(dst) < total {
			dst = make([]byte, total)
		} else {
			dst = dst[:total]
		}
		copy(dst, pkt)
		return dst, nil

	default:
		return dst, fmt.Errorf("unsupported tunnel mode %q", mode)
	}
}

func validatePointToPointPacket(pkt []byte) (uint32, error) {
	if len(pkt) < 1 {
		return 0, errors.New("empty IP packet on point-to-point tunnel")
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return 0, fmt.Errorf("IPv4 packet too short (%d bytes)", len(pkt))
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return 0, fmt.Errorf("invalid IPv4 header length %d", ihl)
		}
		totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
		if totalLen != len(pkt) {
			return 0, fmt.Errorf("IPv4 total length %d does not match packet size %d", totalLen, len(pkt))
		}
		return openSSHAFInet, nil
	case 6:
		if len(pkt) < 40 {
			return 0, fmt.Errorf("IPv6 packet too short (%d bytes)", len(pkt))
		}
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if 40+payloadLen != len(pkt) {
			return 0, fmt.Errorf("IPv6 payload length %d does not match packet size %d", payloadLen, len(pkt))
		}
		return openSSHAFInet6, nil
	default:
		return 0, fmt.Errorf("unsupported IP version %d on point-to-point tunnel", pkt[0]>>4)
	}
}

// decodeTunnelPayload validates and strips the OpenSSH wire header from a single
// complete tun@openssh.com frame.
func decodeTunnelPayload(mode TunnelMode, frame []byte) ([]byte, error) {
	switch mode {
	case TunnelModePointToPoint:
		return decodePointToPointTunnelPayload(frame)
	case TunnelModeEthernet:
		if len(frame) < 14 {
			return nil, fmt.Errorf("ethernet tunnel frame too short (%d bytes)", len(frame))
		}
		return frame, nil
	default:
		return nil, fmt.Errorf("unsupported tunnel mode %q", mode)
	}
}

func decodePointToPointTunnelPayload(frame []byte) ([]byte, error) {
	if len(frame) < 4 {
		return nil, fmt.Errorf("point-to-point tunnel frame too short (%d bytes)", len(frame))
	}
	af := binary.BigEndian.Uint32(frame[0:4])
	switch af {
	case openSSHAFInet:
		if len(frame) >= 5 && (frame[4]>>4) != 4 {
			return nil, fmt.Errorf("tunnel AF_INET header mismatch with IP version %d", frame[4]>>4)
		}
		if len(frame) < 24 {
			return nil, fmt.Errorf("point-to-point IPv4 tunnel frame too short (%d bytes)", len(frame))
		}
		pkt := frame[4:]
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return nil, fmt.Errorf("invalid IPv4 header length %d", ihl)
		}
		totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
		if totalLen != len(pkt) {
			return nil, fmt.Errorf("IPv4 total length %d does not match packet size %d", totalLen, len(pkt))
		}
		return pkt, nil

	case openSSHAFInet6:
		if len(frame) >= 5 && (frame[4]>>4) != 6 {
			return nil, fmt.Errorf("tunnel AF_INET6 header mismatch with IP version %d", frame[4]>>4)
		}
		if len(frame) < 44 {
			return nil, fmt.Errorf("point-to-point IPv6 tunnel frame too short (%d bytes)", len(frame))
		}
		pkt := frame[4:]
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if 40+payloadLen != len(pkt) {
			return nil, fmt.Errorf("IPv6 payload length %d does not match packet size %d", payloadLen, len(pkt))
		}
		return pkt, nil

	default:
		return nil, fmt.Errorf("unsupported OpenSSH tunnel address family %d", af)
	}
}
