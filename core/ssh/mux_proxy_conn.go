package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	logger "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// muxProxySSHConn implements golang.org/x/crypto/ssh.Conn over an OpenSSH
// ControlMaster socket in proxy mode.
type muxProxySSHConn struct {
	cryptoSSH.Conn
	rawConn    net.Conn
	target     TargetContext
	remoteAddr net.Addr
	localAddr  net.Addr
	user       string
	closed     atomic.Bool
	closeOnce  sync.Once
	closeErr   error
}

type targetTCPAddr struct {
	network string
	address string
}

func (a *targetTCPAddr) Network() string { return a.network }
func (a *targetTCPAddr) String() string  { return a.address }

func newMuxProxySSHConn(underlying cryptoSSH.Conn, raw net.Conn, target TargetContext) *muxProxySSHConn {
	port := target.Port
	if port <= 0 {
		port = 22
	}
	remoteStr := fmt.Sprintf("%s:%d", target.Host, port)
	remoteAddr := &targetTCPAddr{network: "tcp", address: remoteStr}

	localAddr := raw.LocalAddr()
	if localAddr == nil {
		localAddr = &targetTCPAddr{network: "unix", address: "local-controlmaster"}
	}

	return &muxProxySSHConn{
		Conn:       underlying,
		rawConn:    raw,
		target:     target,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
		user:       target.User,
	}
}

func (m *muxProxySSHConn) User() string {
	if m.user != "" {
		return m.user
	}
	if m.Conn != nil {
		return m.Conn.User()
	}
	return ""
}

func (m *muxProxySSHConn) RemoteAddr() net.Addr {
	if m.remoteAddr != nil {
		return m.remoteAddr
	}
	if m.Conn != nil {
		return m.Conn.RemoteAddr()
	}
	return &targetTCPAddr{network: "tcp", address: "unknown"}
}

func (m *muxProxySSHConn) LocalAddr() net.Addr {
	if m.localAddr != nil {
		return m.localAddr
	}
	if m.Conn != nil {
		return m.Conn.LocalAddr()
	}
	return &targetTCPAddr{network: "unix", address: "local-controlmaster"}
}

func (m *muxProxySSHConn) RawConn() net.Conn {
	return m.rawConn
}

func (m *muxProxySSHConn) Target() TargetContext {
	return m.target
}

func (m *muxProxySSHConn) Close() error {
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		var errs []error
		if m.Conn != nil {
			if err := m.Conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		if m.rawConn != nil {
			if err := m.rawConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		m.closeErr = errors.Join(errs...)
	})
	return m.closeErr
}

// muxHandshakeInspectorConn wraps a control socket connection during the initial
// NewControlClientConn handshake so target identity (advertised in the server's
// MUX_MSG_HELLO) and proxy rejection packets are inspected on the exact same
// socket connection without a separate TOCTOU probe connection.
type muxHandshakeInspectorConn struct {
	net.Conn
	socketPath  string
	target      TargetContext
	inspecting  atomic.Bool
	readBuf     bytes.Buffer
	packetsSeen int
	mismatchErr error
	rejectedErr error
}

func (c *muxHandshakeInspectorConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.inspecting.Load() {
		if c.readBuf.Len()+n <= 2*MaxMuxPacketLength {
			_, _ = c.readBuf.Write(p[:n])
			c.inspectBufferedPackets()
		} else {
			c.mismatchErr = fmt.Errorf("control proxy handshake on %q failed: handshake buffer exceeded %d bytes", c.socketPath, 2*MaxMuxPacketLength)
			c.inspecting.Store(false)
		}
		if c.mismatchErr != nil {
			return 0, c.mismatchErr
		}
	}
	return n, err
}

func (c *muxHandshakeInspectorConn) inspectBufferedPackets() {
	for c.packetsSeen < 2 && c.readBuf.Len() >= 4 {
		raw := c.readBuf.Bytes()
		pktLen := binary.BigEndian.Uint32(raw[:4])
		if pktLen < 4 || pktLen > MaxMuxPacketLength {
			c.mismatchErr = fmt.Errorf("control proxy handshake on %q failed: invalid mux packet length %d", c.socketPath, pktLen)
			c.inspecting.Store(false)
			return
		}
		if len(raw) < 8 {
			return
		}
		totalLen := 4 + int(pktLen)
		if len(raw) < totalLen {
			return
		}
		msgType := binary.BigEndian.Uint32(raw[4:8])
		payload := raw[8:totalLen]
		c.packetsSeen++
		_ = c.readBuf.Next(totalLen)

		switch c.packetsSeen {
		case 1:
			if c.target.CanonicalTargetIdentity() != "" {
				if msgType != MUX_MSG_HELLO {
					c.mismatchErr = fmt.Errorf("control proxy handshake on %q failed: expected MUX_MSG_HELLO, got 0x%08x", c.socketPath, msgType)
					c.inspecting.Store(false)
					return
				}
				_, exts, err := DecodeMuxHello(payload)
				if err != nil {
					c.mismatchErr = fmt.Errorf("control proxy handshake on %q failed: %w", c.socketPath, err)
					c.inspecting.Store(false)
					return
				}
				for _, ext := range exts {
					if ext.Name == muxTargetExtensionName && !c.target.MatchesMasterTarget(ext.Value) {
						c.mismatchErr = fmt.Errorf(
							"control socket %q is bound to target %s, cannot reuse for %s: %w",
							c.socketPath,
							FormatTargetIdentity(ext.Value),
							FormatTargetIdentity(c.target.CanonicalTargetIdentity()),
							ErrControlTargetMismatch,
						)
						c.inspecting.Store(false)
						return
					}
				}
			}
		case 2:
			if msgType == MUX_S_PERMISSION_DENIED || msgType == MUX_S_FAILURE {
				_, reason, _ := DecodeMuxError(payload)
				c.rejectedErr = fmt.Errorf("control proxy handshake failed on %q: %w: %s (0x%08x)", c.socketPath, ErrControlProxyRejected, reason, msgType)
			}
			c.inspecting.Store(false)
		}
	}
}

// DialControlProxy connects to an OpenSSH ControlMaster socket in proxy mode,
// wraps the resulting connection in muxProxySSHConn, and returns a standard *cryptoSSH.Client.
// The endpoint must belong to the effective local user (or root); see
// DialMuxClient.
func DialControlProxy(ctx context.Context, socketPath string, target TargetContext, opts ...MuxClientOption) (*cryptoSSH.Client, *muxProxySSHConn, error) {
	options := muxClientOptions{expectedUID: localPeerUID()}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("dial control socket %q: %w", socketPath, err)
	}

	unbind := bindConnContext(ctx, rawConn, DefaultInteractionTimeout)
	defer unbind()

	if err := checkPeerUID(rawConn, options.expectedUID); err != nil {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("control socket %q rejected: %w", socketPath, err)
	}

	inspector := &muxHandshakeInspectorConn{
		Conn:       rawConn,
		socketPath: socketPath,
		target:     target,
	}
	inspector.inspecting.Store(true)

	// Standard library proxy handshake (sends HELLO + PROXY, receives HELLO + PROXY)
	sshConn, chans, reqs, err := cryptoSSH.NewControlClientConn(inspector)
	inspector.inspecting.Store(false)
	inspector.readBuf.Reset()
	if err != nil {
		_ = rawConn.Close()
		if inspector.mismatchErr != nil {
			return nil, nil, inspector.mismatchErr
		}
		if inspector.rejectedErr != nil {
			return nil, nil, inspector.rejectedErr
		}
		errMsg := err.Error()
		if strings.Contains(errMsg, "2147483650") || strings.Contains(errMsg, "2147483651") ||
			strings.Contains(strings.ToLower(errMsg), "permission denied") {
			return nil, nil, fmt.Errorf("control proxy handshake failed on %q: %w: %w", socketPath, ErrControlProxyRejected, err)
		}
		return nil, nil, fmt.Errorf("control proxy handshake failed on %q: %w", socketPath, err)
	}
	if inspector.mismatchErr != nil {
		_ = sshConn.Close()
		_ = rawConn.Close()
		return nil, nil, inspector.mismatchErr
	}

	proxyConn := newMuxProxySSHConn(sshConn, rawConn, target)
	sshClient := cryptoSSH.NewClient(proxyConn, chans, reqs)

	return sshClient, proxyConn, nil
}

// DialControlProxyClient connects to an OpenSSH ControlMaster socket in
// MUX_C_PROXY mode, verifies target identity if target.Host is specified, and
// returns a wrapped *Client ready to execute SSH sessions over the multiplexed
// connection without falling back to direct TCP. The caller owns the returned
// *Client and must Close it when done.
func DialControlProxyClient(
	ctx context.Context,
	socketPath string,
	target TargetContext,
	env Environment,
	cfg *ClientConfig,
	l logger.DebugLogger,
	opts ...MuxClientOption,
) (*Client, error) {
	options := muxClientOptions{expectedUID: expectedPeerUIDFromEnvironment(env)}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	dialOpts := append([]MuxClientOption{WithExpectedPeerUID(options.expectedUID)}, opts...)
	rawClient, proxyConn, err := DialControlProxy(ctx, socketPath, target, dialOpts...)
	if err != nil {
		return nil, err
	}

	effectiveCfg := cfg
	if effectiveCfg == nil {
		port := target.Port
		if port <= 0 {
			port = 22
		}
		effectiveCfg = &ClientConfig{
			Address: target.Host,
			Port:    port,
			User:    target.User,
		}
	} else if effectiveCfg.Port <= 0 || effectiveCfg.User == "" {
		cloned := *effectiveCfg
		if cloned.Port <= 0 {
			if target.Port > 0 {
				cloned.Port = target.Port
			} else {
				cloned.Port = 22
			}
		}
		if cloned.User == "" {
			cloned.User = target.User
		}
		effectiveCfg = &cloned
	}

	client := newClientWithComponents(
		rawClient,
		proxyConn.RawConn(),
		effectiveCfg,
		options.provider,
		options.resolver,
		options.prompter,
		nil,
		options.passwordPromptPattern,
		0,
		0,
		l,
	)
	client.environment = env
	return client, nil
}
