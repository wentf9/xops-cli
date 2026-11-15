package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// DefaultMuxHandshakeTimeout bounds control-socket handshakes and RPCs when the
// caller's context carries no deadline of its own.
const DefaultMuxHandshakeTimeout = 10 * time.Second

// bindConnContext bounds I/O on conn by ctx.Deadline() (or defaultTimeout when
// ctx has no deadline), and interrupts in-flight reads/writes immediately if ctx
// is canceled even when ctx has no deadline. Calling the returned unbind function
// synchronizes against context.AfterFunc so an already-unbound connection can
// never have a stale cancellation deadline applied asynchronously later.
func bindConnContext(ctx context.Context, conn net.Conn, defaultTimeout time.Duration) func() {
	if ctx == nil {
		ctx = context.Background()
	}
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline && defaultTimeout > 0 {
		deadline = time.Now().Add(defaultTimeout)
		hasDeadline = true
	}

	var (
		mu       sync.Mutex
		unbound  bool
		canceled bool
	)
	mu.Lock()
	if ctx.Err() != nil {
		canceled = true
		_ = conn.SetDeadline(time.Now())
	} else if hasDeadline {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Time{})
	}
	mu.Unlock()

	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if unbound || canceled {
			return
		}
		canceled = true
		_ = conn.SetDeadline(time.Now())
	})
	return func() {
		stop()
		mu.Lock()
		defer mu.Unlock()
		if unbound {
			return
		}
		unbound = true
		if !canceled && ctx.Err() == nil {
			_ = conn.SetDeadline(time.Time{})
		}
	}
}

// ForwardType defines the port forwarding direction in OpenSSH PROTOCOL.mux.
type ForwardType uint32

const (
	ForwardLocal   ForwardType = ForwardType(MUX_FWD_LOCAL)
	ForwardRemote  ForwardType = ForwardType(MUX_FWD_REMOTE)
	ForwardDynamic ForwardType = ForwardType(MUX_FWD_DYNAMIC)
)

// ForwardRequest represents a dynamic, local, or remote forwarding request.
type ForwardRequest struct {
	Type        ForwardType
	ListenHost  string
	ListenPort  uint32
	ConnectHost string
	ConnectPort uint32
}

// MuxClientOption configures a control-socket client connection.
type MuxClientOption func(*muxClientOptions)

type muxClientOptions struct {
	expectedUID           uint32
	provider              ConnectionProvider
	resolver              SecretResolver
	prompter              SecretPrompter
	passwordPromptPattern string
}

// WithExpectedPeerUID overrides the local user identity that the master endpoint
// must run as. Zero means "expect root" on platforms that expose peer
// credentials; it never disables the check, because a client running as root
// would otherwise accept a socket planted by any other local user. Platforms
// without peer credentials already treat the check as a no-op.
func WithExpectedPeerUID(uid uint32) MuxClientOption {
	return func(options *muxClientOptions) { options.expectedUID = uid }
}

// WithMuxConnectionProvider configures the connection provider used by a
// control-proxy client to inspect node configuration without persisting edits.
func WithMuxConnectionProvider(provider ConnectionProvider) MuxClientOption {
	return func(options *muxClientOptions) { options.provider = provider }
}

// WithMuxSecretResolver configures the secret resolver used by a control-proxy
// client for privilege elevation over the multiplexed connection.
func WithMuxSecretResolver(resolver SecretResolver) MuxClientOption {
	return func(options *muxClientOptions) { options.resolver = resolver }
}

// WithMuxSecretPrompter configures the interactive secret prompter used by a
// control-proxy client when privilege elevation requires user input.
func WithMuxSecretPrompter(prompter SecretPrompter) MuxClientOption {
	return func(options *muxClientOptions) { options.prompter = prompter }
}

// WithMuxPasswordPromptPattern configures the fallback password prompt regex
// used by a control-proxy client when node configuration does not specify one.
func WithMuxPasswordPromptPattern(pattern string) MuxClientOption {
	return func(options *muxClientOptions) { options.passwordPromptPattern = pattern }
}

// MuxClient manages communication with an OpenSSH multiplexing master process.
type MuxClient struct {
	socketPath  string
	expectedUID uint32
	conn        net.Conn
	reqID       atomic.Uint32
	serverVer   uint32
	extensions  map[string]string
	closed      atomic.Bool
	closeMu     sync.Mutex
	ioMu        sync.Mutex
}

// DialMuxClient connects to the control socket and exchanges MUX_MSG_HELLO.
// The endpoint must belong to the effective local user (or root); a socket
// planted by another user in a shared directory is rejected before any request
// is sent.
func DialMuxClient(ctx context.Context, socketPath string, opts ...MuxClientOption) (*MuxClient, error) {
	options := muxClientOptions{expectedUID: localPeerUID()}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		if runtime.GOOS == "windows" && isConnectionRefused(err) {
			if _, statErr := os.Lstat(socketPath); errors.Is(statErr, os.ErrNotExist) {
				return nil, fmt.Errorf("dial mux socket %q: %w", socketPath, statErr)
			}
		}
		return nil, fmt.Errorf("dial mux socket %q: %w", socketPath, err)
	}

	unbind := bindConnContext(ctx, conn, DefaultMuxHandshakeTimeout)
	defer unbind()

	if err := checkPeerUID(conn, options.expectedUID); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("control socket %q rejected: %w", socketPath, err)
	}

	client := &MuxClient{
		socketPath:  socketPath,
		expectedUID: options.expectedUID,
		conn:        conn,
		extensions:  make(map[string]string),
	}

	if err := client.handshake(); err != nil {
		unbind()
		_ = conn.Close()
		if ctxErr := contextErrForConnIO(ctx, err); ctxErr != nil {
			return nil, fmt.Errorf("mux handshake failed on %q: %w", socketPath, ctxErr)
		}
		return nil, fmt.Errorf("mux handshake failed on %q: %w", socketPath, err)
	}

	unbind()
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mux handshake failed on %q: %w", socketPath, err)
	}

	return client, nil
}

func (m *MuxClient) nextID() uint32 {
	return m.reqID.Add(1)
}

// Close closes the underlying socket connection.
func (m *MuxClient) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	if m.conn != nil {
		return m.conn.Close()
	}
	return nil
}

// Extension returns the value of an extension advertised by the master in MUX_MSG_HELLO.
func (m *MuxClient) Extension(name string) (string, bool) {
	if m == nil || m.extensions == nil {
		return "", false
	}
	val, ok := m.extensions[name]
	return val, ok
}

func (m *MuxClient) handshake() error {
	// Client sends HELLO
	if err := WriteMuxPacket(m.conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil)); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	// Client reads HELLO
	msgType, payload, err := ReadMuxPacket(m.conn)
	if err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	if msgType != MUX_MSG_HELLO {
		return fmt.Errorf("expected MUX_MSG_HELLO (0x01), got 0x%08x", msgType)
	}

	serverVer, extensions, err := DecodeMuxHello(payload)
	if err != nil {
		return fmt.Errorf("decode hello response: %w", err)
	}
	m.serverVer = serverVer
	if m.serverVer != MuxProtoVersion {
		return fmt.Errorf("unsupported mux server version %d (expected %d)", m.serverVer, MuxProtoVersion)
	}
	for _, ext := range extensions {
		m.extensions[ext.Name] = ext.Value
	}
	return nil
}

func contextErrForConnIO(ctx context.Context, err error) error {
	if ctx == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
	}
	return nil
}

func wrapMuxRPCContextErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := contextErrForConnIO(ctx, err); ctxErr != nil && !errors.Is(err, ctxErr) {
		return errors.Join(ctxErr, err)
	}
	return err
}

func verifyMuxReplyReqID(reqID, respID uint32) error {
	if respID != reqID {
		return fmt.Errorf("request id mismatch: expected %d, got %d", reqID, respID)
	}
	return nil
}

func expectMuxOKPayload(reqID uint32, payload []byte) error {
	respID, err := DecodeMuxClientRequestID(payload)
	if err != nil {
		return fmt.Errorf("decode ok response: %w", err)
	}
	return verifyMuxReplyReqID(reqID, respID)
}

func decodeMuxRejectionPayload(opName string, reqID uint32, payload []byte) (string, error) {
	respID, reason, err := DecodeMuxError(payload)
	if err != nil {
		return "", fmt.Errorf("decode %s error response: %w", opName, err)
	}
	if err := verifyMuxReplyReqID(reqID, respID); err != nil {
		return "", err
	}
	return reason, nil
}

// roundTripMuxRPCLocked executes one request/response exchange on m.conn while
// m.ioMu is held. Any transport I/O failure, frame decode error, unexpected
// opcode, or requestID mismatch closes m.conn so subsequent callers cannot
// observe a desynchronized control stream; clean server rejections matching
// reqID leave m.conn open. If ctx is canceled or timed out on failure, ctx.Err()
// is joined into the returned error.
func (m *MuxClient) roundTripMuxRPCLocked(
	ctx context.Context,
	timeout time.Duration,
	opName string,
	reqType uint32,
	buildPayload func(reqID uint32) []byte,
	formatReject func(msgType uint32, reason string) error,
	handle func(reqID, msgType uint32, payload []byte) (poison bool, err error),
) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s canceled: %w", opName, err)
		}
	}
	if m.conn == nil {
		return wrapMuxRPCContextErr(ctx, fmt.Errorf("%s failed: %w", opName, net.ErrClosed))
	}

	unbind := bindConnContext(ctx, m.conn, timeout)
	defer unbind()

	reqID := m.nextID()
	if err := WriteMuxPacket(m.conn, reqType, buildPayload(reqID)); err != nil {
		unbind()
		_ = m.Close()
		return wrapMuxRPCContextErr(ctx, fmt.Errorf("send %s: %w", opName, err))
	}

	msgType, payload, err := ReadMuxPacket(m.conn)
	if err != nil {
		unbind()
		_ = m.Close()
		return wrapMuxRPCContextErr(ctx, fmt.Errorf("read %s response: %w", opName, err))
	}

	if msgType == MUX_S_FAILURE || msgType == MUX_S_PERMISSION_DENIED {
		reason, decErr := decodeMuxRejectionPayload(opName, reqID, payload)
		if decErr != nil {
			unbind()
			_ = m.Close()
			return wrapMuxRPCContextErr(ctx, decErr)
		}
		return wrapMuxRPCContextErr(ctx, formatReject(msgType, reason))
	}

	poison, handleErr := handle(reqID, msgType, payload)
	if handleErr != nil {
		if poison {
			unbind()
			_ = m.Close()
		}
		return wrapMuxRPCContextErr(ctx, handleErr)
	}
	return nil
}

// AliveCheck queries the master process alive status and returns the server PID.
func (m *MuxClient) AliveCheck(ctx context.Context) (uint32, error) {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()

	var pid uint32
	err := m.roundTripMuxRPCLocked(
		ctx,
		DefaultMuxHandshakeTimeout,
		"alive check",
		MUX_C_ALIVE_CHECK,
		EncodeMuxRequestID,
		func(msgType uint32, reason string) error {
			return fmt.Errorf("alive check rejected (0x%08x): %s", msgType, reason)
		},
		func(reqID, msgType uint32, payload []byte) (bool, error) {
			if msgType != MUX_S_ALIVE {
				return true, fmt.Errorf("unexpected alive check response type: 0x%08x", msgType)
			}
			respID, parsedPID, err := DecodeMuxAlive(payload)
			if err != nil {
				return true, fmt.Errorf("decode alive response: %w", err)
			}
			if err := verifyMuxReplyReqID(reqID, respID); err != nil {
				return true, err
			}
			pid = parsedPID
			return false, nil
		},
	)
	if err != nil {
		return 0, err
	}
	return pid, nil
}

// Terminate requests the master process to terminate and disconnect the session.
func (m *MuxClient) Terminate(ctx context.Context) error {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()

	return m.roundTripMuxRPCLocked(
		ctx,
		DefaultMuxHandshakeTimeout,
		"terminate",
		MUX_C_TERMINATE,
		EncodeMuxRequestID,
		func(msgType uint32, reason string) error {
			if msgType == MUX_S_PERMISSION_DENIED {
				return fmt.Errorf("master refused termination request: %s", reason)
			}
			return fmt.Errorf("termination failed: %s", reason)
		},
		func(reqID, msgType uint32, payload []byte) (bool, error) {
			if msgType != MUX_S_OK {
				return true, fmt.Errorf("unexpected terminate response type: 0x%08x", msgType)
			}
			if err := expectMuxOKPayload(reqID, payload); err != nil {
				return true, err
			}
			return false, nil
		},
	)
}

// StopListening requests the master to unlink the control socket and stop accepting new clients.
func (m *MuxClient) StopListening(ctx context.Context) error {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()

	return m.roundTripMuxRPCLocked(
		ctx,
		DefaultMuxHandshakeTimeout,
		"stop listening",
		MUX_C_STOP_LISTENING,
		EncodeMuxRequestID,
		func(_ uint32, reason string) error {
			return fmt.Errorf("master refused stop listening request: %s", reason)
		},
		func(reqID, msgType uint32, payload []byte) (bool, error) {
			if msgType != MUX_S_OK {
				return true, fmt.Errorf("unexpected stop listening response type: 0x%08x", msgType)
			}
			if err := expectMuxOKPayload(reqID, payload); err != nil {
				return true, err
			}
			return false, nil
		},
	)
}

func encodeMuxClientForwardReq(req ForwardRequest) func(uint32) []byte {
	return func(reqID uint32) []byte {
		return EncodeMuxFwdRequest(MuxFwdRequest{
			RequestID:   reqID,
			FwdType:     uint32(req.Type),
			ListenHost:  req.ListenHost,
			ListenPort:  req.ListenPort,
			ConnectHost: req.ConnectHost,
			ConnectPort: req.ConnectPort,
		})
	}
}

// OpenForward requests port forwarding on the master. Returns dynamically allocated remote port if requested.
func (m *MuxClient) OpenForward(ctx context.Context, req ForwardRequest) (uint32, error) {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()

	var allocatedPort uint32
	err := m.roundTripMuxRPCLocked(
		ctx,
		DefaultInteractionTimeout,
		"open forward",
		MUX_C_OPEN_FWD,
		encodeMuxClientForwardReq(req),
		func(_ uint32, reason string) error {
			return fmt.Errorf("forwarding request failed: %s", reason)
		},
		func(reqID, msgType uint32, payload []byte) (bool, error) {
			switch msgType {
			case MUX_S_OK:
				if err := expectMuxOKPayload(reqID, payload); err != nil {
					return true, err
				}
				return false, nil
			case MUX_S_REMOTE_PORT:
				respID, port, err := DecodeMuxRemotePort(payload)
				if err != nil {
					return true, fmt.Errorf("decode remote port: %w", err)
				}
				if err := verifyMuxReplyReqID(reqID, respID); err != nil {
					return true, err
				}
				allocatedPort = port
				return false, nil
			default:
				return true, fmt.Errorf("unexpected open forward response: 0x%08x", msgType)
			}
		},
	)
	if err != nil {
		return 0, err
	}
	return allocatedPort, nil
}

// CloseForward cancels an active port forwarding on the master.
func (m *MuxClient) CloseForward(ctx context.Context, req ForwardRequest) error {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()

	return m.roundTripMuxRPCLocked(
		ctx,
		DefaultMuxHandshakeTimeout,
		"close forward",
		MUX_C_CLOSE_FWD,
		encodeMuxClientForwardReq(req),
		func(_ uint32, reason string) error {
			return fmt.Errorf("cancel forward failed: %s", reason)
		},
		func(reqID, msgType uint32, payload []byte) (bool, error) {
			if msgType != MUX_S_OK {
				return true, fmt.Errorf("unexpected close forward response: 0x%08x", msgType)
			}
			if err := expectMuxOKPayload(reqID, payload); err != nil {
				return true, err
			}
			return false, nil
		},
	)
}

// HasExtension returns true if the master server advertised the specified extension.
func (m *MuxClient) HasExtension(name string) bool {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	_, ok := m.extensions[name]
	return ok
}

// RequestInfo sends a MUX_C_EXT_INFO query to the master process ("connection" or "channels").
func (m *MuxClient) RequestInfo(ctx context.Context, name string) (string, error) {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()

	if !m.HasExtension("info") {
		return "", wrapMuxRPCContextErr(ctx, fmt.Errorf("mux server does not support info request"))
	}

	var info string
	err := m.roundTripMuxRPCLocked(
		ctx,
		DefaultMuxHandshakeTimeout,
		"ext info",
		MUX_C_EXT_INFO,
		func(reqID uint32) []byte {
			return EncodeMuxExtInfo(reqID, name)
		},
		func(_ uint32, reason string) error {
			return fmt.Errorf("ext info rejected: %s", reason)
		},
		func(reqID, msgType uint32, payload []byte) (bool, error) {
			if msgType != MUX_S_EXT_INFO {
				return true, fmt.Errorf("unexpected ext info response type: 0x%08x", msgType)
			}
			respID, status, msg, err := DecodeMuxExtInfoResponse(payload)
			if err != nil {
				return true, fmt.Errorf("decode ext info response: %w", err)
			}
			if err := verifyMuxReplyReqID(reqID, respID); err != nil {
				return true, err
			}
			if status == 0 {
				return false, fmt.Errorf("master returned error: %s", msg)
			}
			info = msg
			return false, nil
		},
	)
	if err != nil {
		return "", err
	}
	return info, nil
}

// ErrControlProxyRejected reports that the master refused a MUX_C_PROXY request.
var ErrControlProxyRejected = errors.New("control master rejected proxy mode")

// DialMuxProxyStream connects to the control socket, verifies the endpoint's peer
// user, completes the HELLO handshake, and switches to MUX_C_PROXY transport
// mode. The returned connection carries raw SSH transport bytes and is owned by
// the caller. It is the caller-facing equivalent of DialControlProxy for cases
// that need the socket itself rather than a cryptoSSH.Client.
func DialMuxProxyStream(ctx context.Context, socketPath string, opts ...MuxClientOption) (net.Conn, error) {
	options := muxClientOptions{expectedUID: localPeerUID()}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial control socket %q: %w", socketPath, err)
	}

	unbind := bindConnContext(ctx, conn, DefaultInteractionTimeout)
	defer unbind()
	fail := func(err error) (net.Conn, error) {
		unbind()
		_ = conn.Close()
		return nil, err
	}
	failIO := func(op string, err error) (net.Conn, error) {
		unbind()
		_ = conn.Close()
		if ctxErr := contextErrForConnIO(ctx, err); ctxErr != nil {
			return nil, fmt.Errorf("%s on %q: %w", op, socketPath, ctxErr)
		}
		return nil, fmt.Errorf("%s on %q: %w", op, socketPath, err)
	}

	if err := checkPeerUID(conn, options.expectedUID); err != nil {
		return fail(fmt.Errorf("control socket %q rejected: %w", socketPath, err))
	}

	const requestID uint32 = 1
	if err := WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil)); err != nil {
		return failIO("send hello", err)
	}
	msgType, payload, err := ReadMuxPacket(conn)
	if err != nil {
		return failIO("read hello", err)
	}
	if msgType != MUX_MSG_HELLO {
		return fail(fmt.Errorf("unexpected hello response 0x%08x on %q", msgType, socketPath))
	}
	version, _, err := DecodeMuxHello(payload)
	if err != nil {
		return fail(fmt.Errorf("decode hello on %q: %w", socketPath, err))
	}
	if version != MuxProtoVersion {
		return fail(fmt.Errorf("unsupported mux server version %d on %q", version, socketPath))
	}

	if err := WriteMuxPacket(conn, MUX_C_PROXY, EncodeMuxRequestID(requestID)); err != nil {
		return failIO("send proxy request", err)
	}
	msgType, payload, err = ReadMuxPacket(conn)
	if err != nil {
		return failIO("read proxy response", err)
	}
	switch msgType {
	case MUX_S_PROXY:
		respID, err := DecodeMuxClientRequestID(payload)
		if err != nil {
			return fail(fmt.Errorf("decode proxy response on %q: %w", socketPath, err))
		}
		if respID != requestID {
			return fail(fmt.Errorf("proxy response request id mismatch on %q: expected %d, got %d", socketPath, requestID, respID))
		}
	case MUX_S_PERMISSION_DENIED, MUX_S_FAILURE:
		_, reason, _ := DecodeMuxError(payload)
		return fail(fmt.Errorf("%w on %q: %s", ErrControlProxyRejected, socketPath, reason))
	default:
		return fail(fmt.Errorf("%w on %q: unexpected response 0x%08x", ErrControlProxyRejected, socketPath, msgType))
	}

	unbind()
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return conn, nil
}

// Proxy switches the multiplexed connection into SSH transport proxy mode,
// returning an authenticated *cryptoSSH.Client wrapping muxProxySSHConn.
func (m *MuxClient) Proxy(ctx context.Context, target TargetContext) (*cryptoSSH.Client, *muxProxySSHConn, error) {
	return DialControlProxy(ctx, m.socketPath, target, WithExpectedPeerUID(m.expectedUID))
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) && (sysErr == syscall.ECONNREFUSED || (runtime.GOOS == "windows" && sysErr == syscall.Errno(10061))) {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "wsaeconnrefused") ||
		strings.Contains(errStr, "actively refused")
}

// isControlSocketFileInfo reports whether fi describes a valid control socket
// entry on the current platform. Only actual socket inodes/reparse points
// qualify so a regular file at ControlPath is never mistaken for a stale socket
// and unlinked.
func isControlSocketFileInfo(fi os.FileInfo) bool {
	if fi == nil {
		return false
	}
	return fi.Mode()&os.ModeSocket != 0
}

func socketPathExists(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return isControlSocketFileInfo(fi)
}
