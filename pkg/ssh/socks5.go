package ssh

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
)

// Socks5Forward starts a SOCKS5 proxy server on listenAddr, forwarding traffic via SSH.
func (c *Client) Socks5Forward(ctx context.Context, listenAddr string) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on local SOCKS5 addr %s: %w", listenAddr, err)
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	go func() {
		defer func() { _ = listener.Close() }()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Context canceled or listener closed
			}
			go c.handleSocks5(ctx, conn)
		}
	}()

	return nil
}

func (c *Client) handleSocks5(ctx context.Context, conn net.Conn) {
	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	defer func() { _ = conn.Close() }()

	destAddr, err := handshakeAndParseRequest(conn)
	if err != nil {
		logger.Warnf("socks5: handshake failed: %v", err)
		return
	}

	// 3. Dial remote via SSH client
	// Note: We keep the 15-second deadline active during Dial to prevent routine hang if Dial blocks forever.
	remoteConn, err := c.sshClient.Dial("tcp", destAddr)
	if err != nil {
		logger.Warnf("socks5: failed to dial remote %s via SSH: %v", destAddr, err)
		// Send reply: host unreachable / network unreachable (0x03 / 0x04)
		_, _ = conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = remoteConn.Close() }()

	// Remove deadline for TCP data copy phase after successful dial
	if err := conn.SetDeadline(time.Time{}); err != nil {
		logger.Warnf("socks5: failed to clear deadline: %v", err)
		return
	}

	// Send reply: success
	// SOCKS5 success reply: VER (0x05), REP (0x00), RSV (0x00), ATYP (0x01), BND.ADDR (0.0.0.0), BND.PORT (0)
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		logger.Warnf("socks5: failed to write success reply: %v", err)
		return
	}

	// 4. Data transfer
	c.copyStream(conn, remoteConn)
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
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			// Wait a bit for client to read the response and close its end (up to 2 seconds)
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			var temp [1]byte
			_, _ = conn.Read(temp[:])
		}
		return "", fmt.Errorf("unsupported command: 0x%02x (only CONNECT is supported)", buf[1])
	}

	atyp := buf[3]
	destAddr, err := readSocks5Address(conn, atyp)
	if err != nil {
		if atyp != 0x01 && atyp != 0x03 && atyp != 0x04 {
			// Send reply: address type not supported (0x08)
			_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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
