package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Socks5Forward starts a SOCKS5 proxy server on listenAddr, forwarding traffic via SSH.
func (c *Client) Socks5Forward(ctx context.Context, listenAddr string, opts ...ForwardOption) (*Forward, error) {
	if ctx == nil {
		return nil, fmt.Errorf("socks5 forward context is nil")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddr)
	if err != nil {
		c.observeForward("dynamic", "listen failed", listenAddr, "")
		return nil, fmt.Errorf("listen on local SOCKS5 address %s failed: %w", listenAddr, err)
	}
	fopts := c.forwardOptions(opts...)
	return runForwardListener(ctx, listener, c.forwardDiagnostics(fopts, "dynamic", listener, ""), func(runCtx context.Context, conn net.Conn) error {
		return c.observedForwardHandler("dynamic", listener.Addr().String(), "", func() error {
			return c.handleSocks5(runCtx, conn)
		})
	}), nil
}

// DynamicForwardEndpoint starts a dynamic SOCKS4/4a/5 forwarder on the given endpoint.
func (c *Client) DynamicForwardEndpoint(ctx context.Context, bind ForwardEndpoint, gatewayPorts bool, opts ...ForwardOption) (*Forward, error) {
	if ctx == nil {
		return nil, fmt.Errorf("dynamic forward context is nil")
	}
	fopts := c.forwardOptions(opts...)
	listenNet, listenAddr := bind.LocalListenAddress(gatewayPorts)
	var listener net.Listener
	var err error
	if listenNet == "unix" {
		listener, err = listenLocalStreamLocal(ctx, listenAddr, fopts.streamLocalBindMask, fopts.streamLocalBindUnlink)
	} else {
		listener, err = (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddr)
	}
	if err != nil {
		c.observeForward("dynamic", "listen failed", listenAddr, "")
		return nil, fmt.Errorf("listen on dynamic forward address %s failed: %w", listenAddr, err)
	}
	return runForwardListener(ctx, listener, c.forwardDiagnostics(fopts, "dynamic", listener, ""), func(runCtx context.Context, conn net.Conn) error {
		return c.observedForwardHandler("dynamic", listener.Addr().String(), "", func() error {
			return c.handleSocks5(runCtx, conn)
		})
	}), nil
}

func (c *Client) handleSocks5(ctx context.Context, conn net.Conn) error {
	return serveSocksConn(ctx, conn, func(dCtx context.Context, destAddr string) (net.Conn, error) {
		return c.dialSSH(dCtx, "tcp", destAddr)
	}, c.copyStream)
}

func serveSocksConn(
	ctx context.Context,
	conn net.Conn,
	dialFn func(ctx context.Context, destAddr string) (net.Conn, error),
	pipeFn func(ctx context.Context, c1, c2 net.Conn) error,
) (retErr error) {
	defer joinResourceCloseError(&retErr, conn, "SOCKS client connection")
	stopHandshake := startHandshakeDeadline(conn, 15*time.Second)
	defer func() {
		if stopHandshake != nil {
			_ = stopHandshake()
		}
	}()

	var verBuf [1]byte
	if _, err := io.ReadFull(conn, verBuf[:]); err != nil {
		return fmt.Errorf("failed to read SOCKS version: %w", err)
	}
	ver := verBuf[0]

	var destAddr string
	var err error
	switch ver {
	case 0x05:
		destAddr, err = handleSocks5Handshake(conn)
	case 0x04:
		destAddr, err = handleSocks4Handshake(conn)
	default:
		return fmt.Errorf("unsupported SOCKS version: 0x%02x", ver)
	}
	if err != nil {
		return fmt.Errorf("socks handshake failed: %w", err)
	}

	remoteConn, dialErr := dialFn(ctx, destAddr)
	if dialErr != nil {
		var rejectErr error
		if ver == 0x05 {
			rejectErr = writeSocksReply(conn, []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		} else {
			rejectErr = writeSocksReply(conn, []byte{0x00, 0x5B, 0, 0, 0, 0, 0, 0})
		}
		return errors.Join(fmt.Errorf("dial SOCKS destination %s failed: %w", destAddr, dialErr), rejectErr)
	}
	defer joinResourceCloseError(&retErr, remoteConn, "SOCKS remote connection")

	if err := stopHandshake(); err != nil {
		return err
	}
	stopHandshake = nil

	if ver == 0x05 {
		if err := writeSocksReply(conn, []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return err
		}
	} else {
		if err := writeSocksReply(conn, []byte{0x00, 0x5A, 0, 0, 0, 0, 0, 0}); err != nil {
			return err
		}
	}

	return pipeFn(ctx, conn, remoteConn)
}

func startHandshakeDeadline(conn net.Conn, d time.Duration) func() error {
	if err := conn.SetDeadline(time.Now().Add(d)); err == nil {
		return func() error {
			return conn.SetDeadline(time.Time{})
		}
	}
	timedOut := make(chan struct{})
	var closeErr error
	var once sync.Once
	timer := time.AfterFunc(d, func() {
		once.Do(func() {
			closeErr = conn.Close()
			close(timedOut)
		})
	})
	return func() error {
		if timer.Stop() {
			return nil
		}
		<-timedOut
		return errors.Join(fmt.Errorf("socks handshake timed out after %s", d), closeErr)
	}
}

func writeSocksReply(conn net.Conn, reply []byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	for len(reply) > 0 {
		n, err := conn.Write(reply)
		if err != nil {
			return fmt.Errorf("write SOCKS reply failed: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("write SOCKS reply failed: %w", io.ErrShortWrite)
		}
		reply = reply[n:]
	}
	return nil
}

func drainSocksResponse(conn net.Conn) error {
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return nil
	}
	var errs []error
	if err := cw.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
		errs = append(errs, fmt.Errorf("close SOCKS response writer failed: %w", err))
	}
	stop := startHandshakeDeadline(conn, 2*time.Second)
	defer func() { _ = stop() }()
	var temp [1]byte
	if _, err := conn.Read(temp[:]); err != nil {
		var netErr net.Error
		if !errors.Is(err, io.EOF) && (!errors.As(err, &netErr) || !netErr.Timeout()) {
			errs = append(errs, fmt.Errorf("drain SOCKS response failed: %w", err))
		}
	}
	return errors.Join(errs...)
}

func readNulTerminatedString(r io.Reader, maxBytes int) (string, error) {
	var buf []byte
	var b [1]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == 0 {
			return string(buf), nil
		}
		if len(buf) >= maxBytes {
			return "", fmt.Errorf("string exceeded maximum length of %d bytes", maxBytes)
		}
		buf = append(buf, b[0])
	}
}

func handleSocks5Handshake(conn net.Conn) (string, error) {
	var nmethodsBuf [1]byte
	if _, err := io.ReadFull(conn, nmethodsBuf[:]); err != nil {
		return "", fmt.Errorf("failed to read SOCKS5 methods count: %w", err)
	}
	numMethods := int(nmethodsBuf[0])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("failed to read SOCKS5 methods: %w", err)
	}
	if err := writeSocksReply(conn, []byte{0x05, 0x00}); err != nil {
		return "", fmt.Errorf("failed to write greeting reply: %w", err)
	}

	var buf [4]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return "", fmt.Errorf("failed to read request header: %w", err)
	}
	if buf[0] != 0x05 {
		return "", fmt.Errorf("unsupported request version: 0x%02x", buf[0])
	}
	if buf[1] != 0x01 { // CMD: CONNECT only
		writeErr := writeSocksReply(conn, []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		drainErr := drainSocksResponse(conn)
		return "", errors.Join(fmt.Errorf("unsupported command: 0x%02x (only CONNECT is supported)", buf[1]), writeErr, drainErr)
	}

	atyp := buf[3]
	destAddr, err := readSocks5Address(conn, atyp)
	if err != nil {
		if atyp != 0x01 && atyp != 0x03 && atyp != 0x04 {
			_ = writeSocksReply(conn, []byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		}
		return "", fmt.Errorf("failed to read destination address: %w", err)
	}
	return destAddr, nil
}

func handleSocks4Handshake(conn net.Conn) (string, error) {
	var header [7]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", fmt.Errorf("failed to read SOCKS4 header: %w", err)
	}
	cmd := header[0]
	port := binary.BigEndian.Uint16(header[1:3])
	ipBuf := header[3:7]

	_, userErr := readNulTerminatedString(conn, 1024)
	if userErr != nil {
		return "", fmt.Errorf("failed to read SOCKS4 userid: %w", userErr)
	}

	if cmd != 0x01 {
		writeErr := writeSocksReply(conn, []byte{0x00, 0x5B, 0, 0, 0, 0, 0, 0})
		drainErr := drainSocksResponse(conn)
		return "", errors.Join(fmt.Errorf("unsupported SOCKS4 command: 0x%02x (only CONNECT is supported)", cmd), writeErr, drainErr)
	}

	if port == 0 {
		writeErr := writeSocksReply(conn, []byte{0x00, 0x5B, 0, 0, 0, 0, 0, 0})
		return "", errors.Join(errors.New("invalid SOCKS4 destination port 0"), writeErr)
	}

	if ipBuf[0] == 0 && ipBuf[1] == 0 && ipBuf[2] == 0 && ipBuf[3] != 0 {
		hostname, hostErr := readNulTerminatedString(conn, 255)
		if hostErr != nil || hostname == "" {
			writeErr := writeSocksReply(conn, []byte{0x00, 0x5B, 0, 0, 0, 0, 0, 0})
			if hostErr == nil {
				hostErr = errors.New("empty SOCKS4a hostname")
			}
			return "", errors.Join(fmt.Errorf("failed to read SOCKS4a hostname: %w", hostErr), writeErr)
		}
		return net.JoinHostPort(hostname, strconv.Itoa(int(port))), nil
	}

	return fmt.Sprintf("%d.%d.%d.%d:%d", ipBuf[0], ipBuf[1], ipBuf[2], ipBuf[3], port), nil
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
