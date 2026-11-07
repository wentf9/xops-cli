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

// bindConnContext bounds I/O on conn by the earlier of ctx.Deadline() and
// defaultTimeout, and interrupts in-flight reads/writes immediately if ctx is
// canceled even when ctx has no deadline.
func bindConnContext(ctx context.Context, conn net.Conn, defaultTimeout time.Duration) func() {
	if ctx == nil {
		ctx = context.Background()
	}
	deadline, hasDeadline := ctx.Deadline()
	if defaultTimeout > 0 {
		fallback := time.Now().Add(defaultTimeout)
		if !hasDeadline || fallback.Before(deadline) {
			deadline = fallback
			hasDeadline = true
		}
	}
	if hasDeadline {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	return func() {
		stop()
		if ctx.Err() == nil {
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

// AliveCheck queries the master process alive status and returns the server PID.
func (m *MuxClient) AliveCheck(ctx context.Context) (uint32, error) {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()

	unbind := bindConnContext(ctx, m.conn, DefaultMuxHandshakeTimeout)
	defer unbind()

	reqID := m.nextID()
	if err := WriteMuxPacket(m.conn, MUX_C_ALIVE_CHECK, EncodeMuxRequestID(reqID)); err != nil {
		return 0, fmt.Errorf("send alive check: %w", err)
	}

	msgType, payload, err := ReadMuxPacket(m.conn)
	if err != nil {
		return 0, fmt.Errorf("read alive check response: %w", err)
	}

	switch msgType {
	case MUX_S_ALIVE:
		respID, pid, err := DecodeMuxAlive(payload)
		if err != nil {
			return 0, fmt.Errorf("decode alive response: %w", err)
		}
		if respID != reqID {
			return 0, fmt.Errorf("request id mismatch: expected %d, got %d", reqID, respID)
		}
		return pid, nil

	case MUX_S_PERMISSION_DENIED, MUX_S_FAILURE:
		_, reason, _ := DecodeMuxError(payload)
		return 0, fmt.Errorf("alive check rejected (0x%08x): %s", msgType, reason)

	default:
		return 0, fmt.Errorf("unexpected alive check response type: 0x%08x", msgType)
	}
}

// Terminate requests the master process to terminate and disconnect the session.
func (m *MuxClient) Terminate(ctx context.Context) error {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()

	unbind := bindConnContext(ctx, m.conn, DefaultMuxHandshakeTimeout)
	defer unbind()

	reqID := m.nextID()
	if err := WriteMuxPacket(m.conn, MUX_C_TERMINATE, EncodeMuxRequestID(reqID)); err != nil {
		return fmt.Errorf("send terminate: %w", err)
	}

	msgType, payload, err := ReadMuxPacket(m.conn)
	if err != nil {
		return fmt.Errorf("read terminate response: %w", err)
	}

	switch msgType {
	case MUX_S_OK:
		return nil
	case MUX_S_PERMISSION_DENIED:
		_, reason, _ := DecodeMuxError(payload)
		return fmt.Errorf("master refused termination request: %s", reason)
	case MUX_S_FAILURE:
		_, reason, _ := DecodeMuxError(payload)
		return fmt.Errorf("termination failed: %s", reason)
	default:
		return fmt.Errorf("unexpected terminate response type: 0x%08x", msgType)
	}
}

// StopListening requests the master to unlink the control socket and stop accepting new clients.
func (m *MuxClient) StopListening(ctx context.Context) error {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()

	unbind := bindConnContext(ctx, m.conn, DefaultMuxHandshakeTimeout)
	defer unbind()

	reqID := m.nextID()
	if err := WriteMuxPacket(m.conn, MUX_C_STOP_LISTENING, EncodeMuxRequestID(reqID)); err != nil {
		return fmt.Errorf("send stop listening: %w", err)
	}

	msgType, payload, err := ReadMuxPacket(m.conn)
	if err != nil {
		return fmt.Errorf("read stop listening response: %w", err)
	}

	switch msgType {
	case MUX_S_OK:
		return nil
	case MUX_S_FAILURE:
		_, reason, _ := DecodeMuxError(payload)
		return fmt.Errorf("master refused stop listening request: %s", reason)
	default:
		return fmt.Errorf("unexpected stop listening response type: 0x%08x", msgType)
	}
}

// OpenForward requests port forwarding on the master. Returns dynamically allocated remote port if requested.
func (m *MuxClient) OpenForward(ctx context.Context, req ForwardRequest) (uint32, error) {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()

	unbind := bindConnContext(ctx, m.conn, DefaultMuxHandshakeTimeout)
	defer unbind()

	reqID := m.nextID()
	fwdReq := MuxFwdRequest{
		RequestID:   reqID,
		FwdType:     uint32(req.Type),
		ListenHost:  req.ListenHost,
		ListenPort:  req.ListenPort,
		ConnectHost: req.ConnectHost,
		ConnectPort: req.ConnectPort,
	}

	if err := WriteMuxPacket(m.conn, MUX_C_OPEN_FWD, EncodeMuxFwdRequest(fwdReq)); err != nil {
		return 0, fmt.Errorf("send open forward: %w", err)
	}

	msgType, respPayload, err := ReadMuxPacket(m.conn)
	if err != nil {
		return 0, fmt.Errorf("read open forward response: %w", err)
	}

	switch msgType {
	case MUX_S_OK:
		return 0, nil
	case MUX_S_REMOTE_PORT:
		_, allocatedPort, err := DecodeMuxRemotePort(respPayload)
		if err != nil {
			return 0, fmt.Errorf("decode remote port: %w", err)
		}
		return allocatedPort, nil
	case MUX_S_FAILURE, MUX_S_PERMISSION_DENIED:
		_, reason, _ := DecodeMuxError(respPayload)
		return 0, fmt.Errorf("forwarding request failed: %s", reason)
	default:
		return 0, fmt.Errorf("unexpected open forward response: 0x%08x", msgType)
	}
}

// CloseForward cancels an active port forwarding on the master.
func (m *MuxClient) CloseForward(ctx context.Context, req ForwardRequest) error {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()

	unbind := bindConnContext(ctx, m.conn, DefaultMuxHandshakeTimeout)
	defer unbind()

	reqID := m.nextID()
	fwdReq := MuxFwdRequest{
		RequestID:   reqID,
		FwdType:     uint32(req.Type),
		ListenHost:  req.ListenHost,
		ListenPort:  req.ListenPort,
		ConnectHost: req.ConnectHost,
		ConnectPort: req.ConnectPort,
	}

	if err := WriteMuxPacket(m.conn, MUX_C_CLOSE_FWD, EncodeMuxFwdRequest(fwdReq)); err != nil {
		return fmt.Errorf("send close forward: %w", err)
	}

	msgType, respPayload, err := ReadMuxPacket(m.conn)
	if err != nil {
		return fmt.Errorf("read close forward response: %w", err)
	}

	switch msgType {
	case MUX_S_OK:
		return nil
	case MUX_S_FAILURE:
		_, reason, _ := DecodeMuxError(respPayload)
		return fmt.Errorf("cancel forward failed: %s", reason)
	default:
		return fmt.Errorf("unexpected close forward response: 0x%08x", msgType)
	}
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
		return "", fmt.Errorf("mux server does not support info request")
	}

	unbind := bindConnContext(ctx, m.conn, DefaultMuxHandshakeTimeout)
	defer unbind()

	reqID := m.nextID()
	if err := WriteMuxPacket(m.conn, MUX_C_EXT_INFO, EncodeMuxExtInfo(reqID, name)); err != nil {
		return "", fmt.Errorf("send ext info: %w", err)
	}

	msgType, payload, err := ReadMuxPacket(m.conn)
	if err != nil {
		return "", fmt.Errorf("read ext info response: %w", err)
	}

	switch msgType {
	case MUX_S_EXT_INFO:
		respID, status, msg, err := DecodeMuxExtInfoResponse(payload)
		if err != nil {
			return "", fmt.Errorf("decode ext info response: %w", err)
		}
		if respID != reqID {
			return "", fmt.Errorf("request id mismatch: expected %d, got %d", reqID, respID)
		}
		if status == 0 {
			return "", fmt.Errorf("master returned error: %s", msg)
		}
		return msg, nil

	case MUX_S_FAILURE, MUX_S_PERMISSION_DENIED:
		_, reason, _ := DecodeMuxError(payload)
		return "", fmt.Errorf("ext info rejected: %s", reason)

	default:
		return "", fmt.Errorf("unexpected ext info response type: 0x%08x", msgType)
	}
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

	unbind := bindConnContext(ctx, conn, DefaultMuxHandshakeTimeout)
	defer unbind()
	fail := func(err error) (net.Conn, error) {
		_ = conn.Close()
		return nil, err
	}

	if err := checkPeerUID(conn, options.expectedUID); err != nil {
		return fail(fmt.Errorf("control socket %q rejected: %w", socketPath, err))
	}

	const requestID uint32 = 1
	if err := WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil)); err != nil {
		return fail(fmt.Errorf("send hello on %q: %w", socketPath, err))
	}
	msgType, payload, err := ReadMuxPacket(conn)
	if err != nil {
		return fail(fmt.Errorf("read hello on %q: %w", socketPath, err))
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
		return fail(fmt.Errorf("send proxy request on %q: %w", socketPath, err))
	}
	msgType, payload, err = ReadMuxPacket(conn)
	if err != nil {
		return fail(fmt.Errorf("read proxy response on %q: %w", socketPath, err))
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
// entry on the current platform. On Unix only actual socket inodes qualify so a
// regular file at ControlPath is never mistaken for a stale socket and unlinked.
func isControlSocketFileInfo(fi os.FileInfo) bool {
	if fi == nil {
		return false
	}
	if fi.Mode()&os.ModeSocket != 0 {
		return true
	}
	return runtime.GOOS == "windows" && fi.Mode().IsRegular()
}

func socketPathExists(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return isControlSocketFileInfo(fi)
}
