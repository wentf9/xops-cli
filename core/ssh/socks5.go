package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Socks5Forward starts a SOCKS5 proxy server on listenAddr, forwarding traffic via SSH.
func (c *Client) Socks5Forward(ctx context.Context, listenAddr string, opts ...ForwardOption) (*Forward, error) {
	if ctx == nil {
		return nil, fmt.Errorf("socks5 forward context is nil")
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on local SOCKS5 address %s failed: %w", listenAddr, err)
	}
	return runForwardListener(ctx, listener, c.forwardOptions(opts...), func(runCtx context.Context, conn net.Conn) error {
		return c.handleSocks5(runCtx, conn)
	}), nil
}

func (c *Client) handleSocks5(ctx context.Context, conn net.Conn) (retErr error) {
	defer joinResourceCloseError(&retErr, conn, "SOCKS5 client connection")
	destAddr, err := handshakeAndParseRequest(conn)
	if err != nil {
		return fmt.Errorf("socks5 handshake failed: %w", err)
	}

	// 3. Dial remote via SSH client
	remoteConn, err := c.dialSSH(ctx, "tcp", destAddr)
	if err != nil {
		// Send reply: host unreachable / network unreachable (0x03 / 0x04)
		writeErr := writeSocks5Reply(conn, []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return errors.Join(fmt.Errorf("dial SOCKS5 destination %s failed: %w", destAddr, err), writeErr)
	}
	defer joinResourceCloseError(&retErr, remoteConn, "SOCKS5 remote connection")

	// Remove deadline for TCP data copy phase after successful dial
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear SOCKS5 connection deadline failed: %w", err)
	}

	// Send reply: success
	// SOCKS5 success reply: VER (0x05), REP (0x00), RSV (0x00), ATYP (0x01), BND.ADDR (0.0.0.0), BND.PORT (0)
	if err := writeSocks5Reply(conn, []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}

	// 4. Data transfer
	return c.copyStream(ctx, conn, remoteConn)
}

func writeSocks5Reply(conn net.Conn, reply []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return fmt.Errorf("set SOCKS5 reply deadline failed: %w", err)
	}
	for len(reply) > 0 {
		n, err := conn.Write(reply)
		if err != nil {
			return fmt.Errorf("write SOCKS5 reply failed: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("write SOCKS5 reply failed: %w", io.ErrShortWrite)
		}
		reply = reply[n:]
	}
	return nil
}

func handshakeAndParseRequest(conn net.Conn) (string, error) {
	// Set deadline for greeting and request phases to avoid leakage
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return "", fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// 1. Negotiation (Greeting)
	if err := handleGreeting(conn); err != nil {
		return "", fmt.Errorf("negotiation failed: %w", err)
	}

	// 2. Request phase
	var buf [4]byte
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", fmt.Errorf("failed to read request header: %w", err)
	}
	if buf[0] != 0x05 {
		return "", fmt.Errorf("unsupported request version: 0x%02x", buf[0])
	}
	if buf[1] != 0x01 { // CMD: CONNECT only
		// Send reply: command not supported (0x07)
		var responseErrs []error
		if _, err := conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			responseErrs = append(responseErrs, fmt.Errorf("write unsupported command reply failed: %w", err))
		}
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			if err := cw.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
				responseErrs = append(responseErrs, fmt.Errorf("close SOCKS5 response writer failed: %w", err))
			}
			// Wait a bit for client to read the response and close its end (up to 2 seconds)
			if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				responseErrs = append(responseErrs, fmt.Errorf("set SOCKS5 response drain deadline failed: %w", err))
			}
			var temp [1]byte
			if _, err := conn.Read(temp[:]); err != nil {
				var netErr net.Error
				if !errors.Is(err, io.EOF) && (!errors.As(err, &netErr) || !netErr.Timeout()) {
					responseErrs = append(responseErrs, fmt.Errorf("drain SOCKS5 response failed: %w", err))
				}
			}
		}
		return "", errors.Join(
			fmt.Errorf("unsupported command: 0x%02x (only CONNECT is supported)", buf[1]),
			errors.Join(responseErrs...),
		)
	}

	atyp := buf[3]
	destAddr, err := readSocks5Address(conn, atyp)
	if err != nil {
		if atyp != 0x01 && atyp != 0x03 && atyp != 0x04 {
			// Send reply: address type not supported (0x08)
			if _, writeErr := conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); writeErr != nil {
				err = errors.Join(err, fmt.Errorf("write unsupported address reply failed: %w", writeErr))
			}
		}
		return "", fmt.Errorf("failed to read destination address: %w", err)
	}

	return destAddr, nil
}

func handleGreeting(conn net.Conn) error {
	var buf [257]byte
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return fmt.Errorf("failed to read greeting header: %w", err)
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("unsupported version: 0x%02x", buf[0])
	}
	numMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:numMethods]); err != nil {
		return fmt.Errorf("failed to read methods: %w", err)
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return fmt.Errorf("failed to write greeting reply: %w", err)
	}
	return nil
}

func readSocks5Address(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		var ipBuf [4]byte
		if _, err := io.ReadFull(conn, ipBuf[:]); err != nil {
			return "", fmt.Errorf("failed to read IPv4 body: %w", err)
		}
		var portBuf [2]byte
		if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
			return "", fmt.Errorf("failed to read IPv4 port: %w", err)
		}
		port := binary.BigEndian.Uint16(portBuf[:])
		return fmt.Sprintf("%d.%d.%d.%d:%d", ipBuf[0], ipBuf[1], ipBuf[2], ipBuf[3], port), nil

	case 0x03: // Domain name
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return "", fmt.Errorf("failed to read domain length: %w", err)
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", fmt.Errorf("failed to read domain body: %w", err)
		}
		var portBuf [2]byte
		if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
			return "", fmt.Errorf("failed to read domain port: %w", err)
		}
		port := binary.BigEndian.Uint16(portBuf[:])
		return net.JoinHostPort(string(domainBuf), fmt.Sprintf("%d", port)), nil

	case 0x04: // IPv6
		var ipBuf [16]byte
		if _, err := io.ReadFull(conn, ipBuf[:]); err != nil {
			return "", fmt.Errorf("failed to read IPv6 body: %w", err)
		}
		var portBuf [2]byte
		if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
			return "", fmt.Errorf("failed to read IPv6 port: %w", err)
		}
		port := binary.BigEndian.Uint16(portBuf[:])
		return net.JoinHostPort(net.IP(ipBuf[:]).String(), fmt.Sprintf("%d", port)), nil

	default:
		return "", fmt.Errorf("unsupported address type: 0x%02x", atyp)
	}
}
