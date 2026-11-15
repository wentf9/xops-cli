package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
)

var (
	// ErrMasterAlreadyExists indicates a master is already listening on the socket path.
	ErrMasterAlreadyExists = errors.New("mux master already exists on control path")
	// ErrServerClosed indicates the multiplex server has shut down.
	ErrServerClosed = errors.New("mux server closed")
	// ErrUnauthorizedPeer indicates the peer UID check failed.
	ErrUnauthorizedPeer = errors.New("unauthorized peer UID")
	// ErrUnsupportedMuxPlatform indicates multiplex control sockets lack verified peer credentials on this OS.
	ErrUnsupportedMuxPlatform = errors.New("multiplex control socket peer credentials are not supported on this platform")
)

func unsupportedUnixBindControlSocket(targetPath, goos string) (net.Listener, error) {
	if strings.TrimSpace(targetPath) == "" {
		return nil, fmt.Errorf("control path cannot be empty")
	}
	return nil, fmt.Errorf("%w: refusing to bind unauthenticated Unix control socket %q on %s", ErrUnsupportedMuxPlatform, targetPath, goos)
}

func unsupportedUnixCheckPeerUID(goos string) error {
	return fmt.Errorf("%w: %w on %s", ErrUnauthorizedPeer, ErrUnsupportedMuxPlatform, goos)
}

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

// MuxServerOptions configures the multiplex master server.
type MuxServerOptions struct {
	ControlPath       string
	ExpectedUID       uint32
	CheckPeerUID      bool
	PersistEnabled    bool
	PersistDuration   time.Duration
	PersistIndefinite bool
	// ConfirmSession authorizes a proxy session, passenger session, or forwarding
	// request on an ask/autoask master. Nil rejects every such request.
	ConfirmSession         func(action string) bool
	AskConfirmation        bool
	SSHClient              *cryptoSSH.Client
	RootConn               net.Conn      // Optional underlying conn to close on Shutdown
	InitialActiveSessions  int32         // Initial active session count (e.g. 1 for foreground master)
	Target                 TargetContext // Optional target identity advertised via target@xops hello extension
	GatewayPorts           bool
	GatewayPortsMode       string
	DialNetwork            string
	StreamLocalBindUnlink  bool
	StreamLocalBindMask    uint32
	HasStreamLocalBindMask bool
	AllowAgentForward      bool
	AgentSocket            string
	DialAgent              func(ctx context.Context, socket string) (net.Conn, error)
	Logger                 logger.DebugLogger
}

const (
	muxExtGatewayPorts = "gateway-ports@xops-cli"
	muxExtDialNetwork  = "dial-network@xops-cli"
)

// MuxServer implements the OpenSSH PROTOCOL.mux v4 server engine.
type MuxServer struct {
	controlPath       string
	expectedUID       uint32
	checkPeerUID      bool
	persistEnabled    bool
	persistDuration   time.Duration
	persistIndefinite bool
	sshClient         *cryptoSSH.Client
	rootConn          net.Conn

	gatewayPorts          bool
	gatewayPortsMode      string
	dialNetwork           string
	streamLocalBindUnlink bool
	streamLocalBindMask   uint32
	allowAgentForward     bool
	agentSocket           string
	dialAgent             func(ctx context.Context, socket string) (net.Conn, error)
	requestTimeout        time.Duration
	logger                logger.DebugLogger

	listener             net.Listener
	activeSessions       atomic.Int32
	activeForwardStreams atomic.Int32
	idleTimer            *time.Timer
	idleGen              uint64        // generation counter for idle timer, protected by idleMu
	shuttingDown         bool          // true when server committed to shutdown, protected by idleMu
	handoffReserved      bool          // true while PrepareHandoff holds a reservation, protected by idleMu
	hadActiveSession     bool          // true once an initial or dynamic session was admitted, protected by idleMu
	stopRepliesInFlight  int           // count of in-flight -O stop replies, protected by idleMu
	openFwdsInFlight     int           // count of in-flight MUX_C_OPEN_FWD requests, protected by idleMu
	closeFwdsInFlight    int           // count of in-flight MUX_C_CLOSE_FWD requests, protected by idleMu
	idleNotify           chan struct{} // closed and replaced under idleMu when session/forward/stop state changes
	idleMu               sync.Mutex
	target               TargetContext

	closed                   atomic.Bool
	stoppedListening         atomic.Bool
	terminated               bool // protected by idleMu
	releaseForegroundOnStop  bool // protected by idleMu
	foregroundReleasedByStop bool // protected by idleMu
	shutdownOnce             sync.Once
	shutdownChan             chan struct{}
	origFi                   os.FileInfo
	askConfirmation          bool
	confirmSession           func(action string) bool

	serverCtx    context.Context
	serverCancel context.CancelFunc

	forwards        sync.Map                                      // string -> *muxForwardEntry
	listenEndpoints map[forwardListenKey]*muxForwardEndpointState // protected by idleMu
	// liveStreams holds every accepted connection the master is currently piping:
	// proxy sockets and forwarded client connections. Shutdown closes them so
	// idle readers unblock instead of outliving the master.
	liveStreams sync.Map // net.Conn -> struct{}
}

// NewMuxServer creates and binds a new OpenSSH multiplex master server.
func NewMuxServer(opts MuxServerOptions) (*MuxServer, error) {
	if strings.TrimSpace(opts.ControlPath) == "" {
		return nil, fmt.Errorf("control path cannot be empty")
	}
	if opts.SSHClient == nil {
		return nil, fmt.Errorf("ssh client cannot be nil")
	}

	listener, err := bindAndLinkSocket(opts.ControlPath)
	if err != nil {
		return nil, err
	}

	origFi, _ := os.Lstat(opts.ControlPath)

	mask := DefaultStreamLocalBindMask
	if opts.HasStreamLocalBindMask {
		mask = opts.StreamLocalBindMask
	}

	var normAgentSocket string
	if rawAgentSock := strings.TrimSpace(opts.AgentSocket); rawAgentSock != "" {
		normAgentSocket = normalizeExpandedAgentSocketPath(rawAgentSock, Environment{})
	}

	serverCtx, serverCancel := context.WithCancel(context.Background())

	server := &MuxServer{
		serverCtx:             serverCtx,
		serverCancel:          serverCancel,
		controlPath:           opts.ControlPath,
		expectedUID:           opts.ExpectedUID,
		checkPeerUID:          opts.CheckPeerUID,
		persistEnabled:        opts.PersistEnabled,
		persistDuration:       opts.PersistDuration,
		persistIndefinite:     opts.PersistIndefinite,
		sshClient:             opts.SSHClient,
		rootConn:              opts.RootConn,
		listener:              listener,
		shutdownChan:          make(chan struct{}),
		idleNotify:            make(chan struct{}),
		origFi:                origFi,
		askConfirmation:       opts.AskConfirmation,
		confirmSession:        opts.ConfirmSession,
		target:                opts.Target,
		gatewayPorts:          opts.GatewayPorts,
		gatewayPortsMode:      opts.GatewayPortsMode,
		dialNetwork:           normalizeTCPDialNetwork(opts.DialNetwork),
		streamLocalBindUnlink: opts.StreamLocalBindUnlink,
		streamLocalBindMask:   mask,
		allowAgentForward:     opts.AllowAgentForward,
		agentSocket:           normAgentSocket,
		dialAgent:             opts.DialAgent,
		logger:                opts.Logger,
	}

	if opts.InitialActiveSessions > 0 {
		server.activeSessions.Store(opts.InitialActiveSessions)
		server.hadActiveSession = true
	}

	if server.persistEnabled && !server.persistIndefinite && server.persistDuration > 0 && server.activeSessions.Load() == 0 {
		server.idleMu.Lock()
		server.idleGen++
		gen := server.idleGen
		server.idleTimer = time.AfterFunc(server.persistDuration, func() {
			server.onIdleTimeout(gen)
		})
		server.idleMu.Unlock()
	}

	if server.sshClient != nil && server.sshClient.Conn != nil {
		go server.monitorSSHTransport()
	}

	return server, nil
}

func (s *MuxServer) monitorSSHTransport() {
	if s == nil || s.sshClient == nil || s.sshClient.Conn == nil {
		return
	}
	waitDone := make(chan struct{})
	go func() {
		defer close(waitDone)
		_ = s.sshClient.Wait()
	}()
	select {
	case <-waitDone:
		_ = s.Shutdown()
	case <-s.shutdownChan:
	}
}

var activeMuxServers sync.Map // string (controlPath) -> *MuxServer

// GetActiveMuxServer returns the active MuxServer listening on the given control path, if any.
func GetActiveMuxServer(controlPath string) *MuxServer {
	if val, ok := activeMuxServers.Load(controlPath); ok {
		return val.(*MuxServer)
	}
	return nil
}

// MuxMasterOptions carries the master configuration a Connector applies for one
// resolved control path.
type MuxMasterOptions struct {
	Path        string
	Target      TargetContext
	Environment Environment
	RootConn    net.Conn
	// InitialActiveSessions is the number of sessions the caller already holds
	// on the new master. A connector passes 1 for its own transport: the master
	// exists to serve it, so an idle timer must not tear it down while the
	// caller keeps using it.
	InitialActiveSessions int32
	// ConfirmSession authorizes proxy sessions, passenger sessions, and
	// forwarding requests on an ask/autoask master. Nil rejects them.
	ConfirmSession         func(action string) bool
	GatewayPorts           bool
	GatewayPortsMode       string
	DialNetwork            string
	StreamLocalBindUnlink  bool
	StreamLocalBindMask    uint32
	HasStreamLocalBindMask bool
	AllowAgentForward      bool
	AgentSocket            string
	DialAgent              func(ctx context.Context, socket string) (net.Conn, error)
	Logger                 logger.DebugLogger
}

// StartMuxServer starts the master for opts.Path and returns it. The caller owns
// the returned server and must shut it down; nothing else releases the control
// socket or the SSH transport it references.
func StartMuxServer(ctx context.Context, sshClient *cryptoSSH.Client, opts MuxMasterOptions) (*MuxServer, error) {
	target := opts.Target
	env := opts.Environment

	expectedUID := expectedPeerUIDFromEnvironment(env)
	checkUID := true

	var persistEnabled, persistIndefinite bool
	var persistDuration time.Duration
	if target.Control != nil && target.Control.Persist != "" {
		en, ind, dur, err := ParseControlPersist(target.Control.Persist)
		if err == nil {
			persistEnabled = en
			persistIndefinite = ind
			persistDuration = dur
		}
	}

	masterMode := ControlMasterNo
	if target.Control != nil {
		masterMode = target.Control.Master
	}
	askConfirmation := masterMode == ControlMasterAsk || masterMode == ControlMasterAutoAsk

	dialAgent := opts.DialAgent
	if dialAgent == nil {
		dialAgent = env.DialAgent
	}
	agentSocket := strings.TrimSpace(opts.AgentSocket)
	if agentSocket == "" && opts.AllowAgentForward {
		agentSocket = strings.TrimSpace(env.AgentSocket)
	}
	if agentSocket != "" {
		agentSocket = normalizeExpandedAgentSocketPath(agentSocket, env)
	}

	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:            opts.Path,
		ExpectedUID:            expectedUID,
		CheckPeerUID:           checkUID,
		PersistEnabled:         persistEnabled,
		PersistDuration:        persistDuration,
		PersistIndefinite:      persistIndefinite,
		SSHClient:              sshClient,
		RootConn:               opts.RootConn,
		InitialActiveSessions:  opts.InitialActiveSessions,
		AskConfirmation:        askConfirmation,
		ConfirmSession:         opts.ConfirmSession,
		GatewayPorts:           opts.GatewayPorts,
		GatewayPortsMode:       opts.GatewayPortsMode,
		DialNetwork:            opts.DialNetwork,
		StreamLocalBindUnlink:  opts.StreamLocalBindUnlink,
		StreamLocalBindMask:    opts.StreamLocalBindMask,
		HasStreamLocalBindMask: opts.HasStreamLocalBindMask,
		AllowAgentForward:      opts.AllowAgentForward,
		AgentSocket:            agentSocket,
		DialAgent:              dialAgent,
		Logger:                 opts.Logger,
	})
	if err != nil {
		return nil, err
	}
	server.target = target

	activeMuxServers.Store(opts.Path, server)

	go func() {
		if err := server.Serve(); err != nil {
			// A fatal accept failure (EMFILE, ENOBUFS) leaves a socket nobody
			// accepts on and no other path to s.Wait(). Retire the master instead
			// of leaving -N and the ControlPersist daemon blocked forever. A nil
			// return means Shutdown or -O stop already owns the teardown, so the
			// draining sessions must not be cut off here.
			_ = server.Shutdown()
		}
	}()

	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = server.Shutdown()
			case <-server.Wait():
			}
		}()
	}

	return server, nil
}

// expectedPeerUIDFromEnvironment derives the UID a control socket endpoint must
// run as. The check defaults to the effective local user so a host that omits
// LocalUID cannot silently disable it. An explicit LocalUID still wins, and a
// malformed value falls back to the effective UID instead of dropping the check.
// Platforms without peer credentials treat the check as a no-op.
func expectedPeerUIDFromEnvironment(env Environment) uint32 {
	expectedUID := localPeerUID()
	if env.LocalUID != "" {
		if uid, err := strconv.ParseUint(env.LocalUID, 10, 32); err == nil {
			expectedUID = uint32(uid)
		}
	}
	return expectedUID
}

// PersistEnabled reports whether this master survives the end of the foreground
// session (`ControlPersist` other than "no").
func (s *MuxServer) PersistEnabled() bool {
	if s == nil {
		return false
	}
	return s.persistEnabled
}

// PersistIndefinite reports whether the master keeps running until an explicit
// stop (-O exit/stop) instead of an idle timeout.
func (s *MuxServer) PersistIndefinite() bool {
	if s == nil {
		return false
	}
	return s.persistIndefinite
}

// isShuttingDown reports whether this master already committed to shutting down.
func (s *MuxServer) isShuttingDown() bool {
	if s == nil {
		return true
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	return s.shuttingDown
}

func (s *MuxServer) hasInFlightEndpointsLocked() bool {
	for _, ep := range s.listenEndpoints {
		if ep != nil && (ep.inFlight || ep.closingWait != nil) {
			return true
		}
	}
	return false
}

func (s *MuxServer) hasInFlightControlOrForwardLocked() bool {
	return s.stopRepliesInFlight > 0 ||
		s.openFwdsInFlight > 0 ||
		s.closeFwdsInFlight > 0 ||
		s.hasInFlightEndpointsLocked()
}

// PrepareHandoff reserves the master for a ControlPersist handoff. It succeeds
// only when no other session or forward depends on this process: shutting the
// master down would otherwise cut those users off. On success the server is
// marked as shutting down so no new session or forward is admitted before the
// caller releases it.
func (s *MuxServer) PrepareHandoff() bool {
	return s.PrepareHandoffWithSessions(0)
}

// PrepareHandoffWithSessions atomically reserves the master for handoff when
// activeSessions is at most maxSessions and no forwards or in-flight endpoint
// operations remain. Callers keeping a single foreground reference (maxSessions=1)
// still prevent concurrent mux clients from being admitted until ReleaseMaster
// + Shutdown or CancelHandoff runs.
func (s *MuxServer) PrepareHandoffWithSessions(maxSessions int32) bool {
	if s == nil {
		return false
	}
	if maxSessions < 0 {
		maxSessions = 0
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.shuttingDown || s.closed.Load() || s.stoppedListening.Load() || s.hasInFlightControlOrForwardLocked() || s.activeSessions.Load() > maxSessions {
		return false
	}
	if s.forwardCount() > 0 || len(s.listenEndpoints) > 0 || s.activeForwardStreams.Load() > 0 {
		return false
	}
	s.shuttingDown = true
	s.handoffReserved = true
	s.idleGen++
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	return true
}

// CommitHandoffReady reports whether a reservation created by PrepareHandoff*
// is still intact and has not been invalidated by -O stop, -O exit, or shutdown.
func (s *MuxServer) CommitHandoffReady() bool {
	if s == nil {
		return false
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	return s.handoffReserved && !s.stoppedListening.Load() && !s.terminated && !s.closed.Load()
}

// CancelHandoff releases a reservation made by PrepareHandoff when a multi-hop
// handoff could not reserve every master in the chain.
func (s *MuxServer) CancelHandoff() {
	if s == nil {
		return
	}
	s.idleMu.Lock()
	if !s.handoffReserved || s.closed.Load() {
		s.idleMu.Unlock()
		return
	}
	s.handoffReserved = false
	if s.stoppedListening.Load() || s.terminated {
		shouldShutdown := s.terminated ||
			(!s.hasInFlightControlOrForwardLocked() &&
				s.activeSessions.Load() <= 0 &&
				s.activeForwardStreams.Load() <= 0)
		if shouldShutdown {
			s.shuttingDown = true
			s.idleGen++
			if s.idleTimer != nil {
				s.idleTimer.Stop()
				s.idleTimer = nil
			}
		} else {
			s.shuttingDown = false
		}
		s.notifyIdleLocked()
		s.idleMu.Unlock()
		if shouldShutdown {
			go func() { _ = s.Shutdown() }()
		}
		return
	}
	s.shuttingDown = false
	s.notifyIdleLocked()
	if !s.hasInFlightControlOrForwardLocked() &&
		s.activeSessions.Load() <= 0 && s.activeForwardStreams.Load() <= 0 {
		s.scheduleIdleOrShutdownLocked()
	}
	s.idleMu.Unlock()
}

// StoppedListening reports whether -O stop has unlinked the control socket.
func (s *MuxServer) StoppedListening() bool {
	if s == nil {
		return false
	}
	return s.stoppedListening.Load()
}

// Target returns the resolved connection target metadata for this master.
func (s *MuxServer) Target() TargetContext {
	if s == nil {
		return TargetContext{}
	}
	return s.target
}

// WaitForDrain blocks until activeSessions <= maxSessions and no active
// forwards remain on the master, or until the master stops listening, shuts
// down, or ctx is canceled.
func (s *MuxServer) WaitForDrain(ctx context.Context, maxSessions int32) error {
	if s == nil {
		return nil
	}
	for {
		s.idleMu.Lock()
		ready := s.shuttingDown || s.closed.Load() || s.stoppedListening.Load() ||
			(s.activeSessions.Load() <= maxSessions &&
				!s.hasInFlightControlOrForwardLocked() &&
				s.forwardCount() == 0 &&
				len(s.listenEndpoints) == 0 &&
				s.activeForwardStreams.Load() == 0)
		notify := s.idleNotify
		s.idleMu.Unlock()
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.shutdownChan:
			return nil
		case <-notify:
		}
	}
}

func (s *MuxServer) notifyIdleLocked() {
	if s.idleNotify != nil {
		close(s.idleNotify)
		s.idleNotify = make(chan struct{})
	}
}

func (s *MuxServer) forwardCount() int {
	count := 0
	s.forwards.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// Serve enters the client connection accept loop.
func (s *MuxServer) Serve() error {
	type deadliner interface {
		SetDeadline(t time.Time) error
	}
	dl, hasDeadline := s.listener.(deadliner)

	for {
		if hasDeadline && !s.closed.Load() && !s.stoppedListening.Load() {
			_ = dl.SetDeadline(time.Now().Add(50 * time.Millisecond))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() || s.stoppedListening.Load() {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Socket accept timed out; check whether the control socket still exists on disk
				currFi, statErr := os.Lstat(s.controlPath)
				if statErr != nil {
					if os.IsNotExist(statErr) || errors.Is(statErr, os.ErrNotExist) || errors.Is(statErr, syscall.ENOENT) {
						// Control socket was unlinked from filesystem: stop listening and
						// retire only once active sessions finish draining (never kill an
						// in-use foreground or proxy session).
						s.retireUnlinkedOrReplacedListener()
						return nil
					}
				} else if s.origFi != nil && !os.SameFile(s.origFi, currFi) {
					// Control socket was replaced on disk
					s.retireUnlinkedOrReplacedListener()
					return nil
				}
				continue
			}
			return fmt.Errorf("accept control connection failed: %w", err)
		}

		go s.handleClient(conn)
	}
}

// retireUnlinkedOrReplacedListener stops accepting new connections when the
// control socket entry on disk was unlinked or replaced externally, while
// letting any active foreground or proxy sessions drain cleanly before Shutdown.
func (s *MuxServer) retireUnlinkedOrReplacedListener() {
	if s.stoppedListening.CompareAndSwap(false, true) {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		activeMuxServers.CompareAndDelete(s.controlPath, s)
		s.idleMu.Lock()
		s.notifyIdleLocked()
		s.idleMu.Unlock()
	}
	if s.releaseForegroundOnStopIfArmed() {
		return
	}
	s.shutdownWhenIdle()
}

func (s *MuxServer) handleClient(conn net.Conn) {
	s.trackStream(conn)
	defer func() {
		_ = conn.Close()
		s.untrackStream(conn)
	}()

	if s.checkPeerUID {
		if err := checkPeerUID(conn, s.expectedUID); err != nil {
			_ = sendPermissionDenied(conn, 0, fmt.Sprintf("peer UID check failed: %v", err))
			return
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := s.handshakeHello(conn); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	for {
		msgType, reqPayload, err := ReadMuxPacket(conn)
		if err != nil {
			return
		}
		if !s.dispatchRequest(conn, msgType, reqPayload) {
			return
		}
	}
}

func (s *MuxServer) handshakeHello(conn net.Conn) error {
	pktType, payload, err := ReadMuxPacket(conn)
	if err != nil {
		return err
	}
	if pktType != MUX_MSG_HELLO {
		_ = sendFailure(conn, 0, fmt.Sprintf("expected MUX_MSG_HELLO (0x01), got 0x%08x", pktType))
		return errors.New("expected hello")
	}
	clientVer, _, err := DecodeMuxHello(payload)
	if err != nil || clientVer != MuxProtoVersion {
		_ = sendFailure(conn, 0, fmt.Sprintf("unsupported client protocol version %d", clientVer))
		return errors.New("unsupported version")
	}
	exts := []MuxExtension{{Name: "info", Value: "1"}}
	if targetID := s.target.CanonicalTargetIdentity(); targetID != "" {
		exts = append(exts, MuxExtension{Name: muxTargetExtensionName, Value: targetID})
	}
	if gwMode := s.effectiveGatewayPortsMode(); gwMode != "" {
		exts = append(exts, MuxExtension{Name: muxExtGatewayPorts, Value: gwMode})
	}
	if dialNet := s.effectiveDialNetwork(); dialNet != "" {
		exts = append(exts, MuxExtension{Name: muxExtDialNetwork, Value: dialNet})
	}
	return WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, exts))
}

func peekMuxRequestID(reqPayload []byte) uint32 {
	if len(reqPayload) >= 4 {
		return binary.BigEndian.Uint32(reqPayload[:4])
	}
	return 0
}

func (s *MuxServer) dispatchRequest(conn net.Conn, msgType uint32, reqPayload []byte) bool {
	switch msgType {
	case MUX_C_ALIVE_CHECK:
		reqID, err := DecodeMuxRequestID(reqPayload)
		if err != nil {
			_ = sendFailure(conn, peekMuxRequestID(reqPayload), "malformed alive check request")
			return false
		}
		return s.handleAliveCheck(conn, reqID) == nil

	case MUX_C_TERMINATE:
		reqID, err := DecodeMuxRequestID(reqPayload)
		if err != nil {
			_ = sendFailure(conn, peekMuxRequestID(reqPayload), "malformed terminate request")
			return false
		}
		_ = s.handleTerminate(conn, reqID)
		return false

	case MUX_C_STOP_LISTENING:
		reqID, err := DecodeMuxRequestID(reqPayload)
		if err != nil {
			_ = sendFailure(conn, peekMuxRequestID(reqPayload), "malformed stop listening request")
			return false
		}
		return s.handleStopListening(conn, reqID) == nil

	case MUX_C_PROXY:
		reqID, err := DecodeMuxRequestID(reqPayload)
		if err != nil {
			_ = sendFailure(conn, peekMuxRequestID(reqPayload), "malformed proxy request")
			return false
		}
		_ = s.handleProxy(conn, reqID)
		return false

	case MUX_C_OPEN_FWD:
		req, err := DecodeMuxFwdRequest(reqPayload)
		if err != nil {
			_ = sendFailure(conn, peekMuxRequestID(reqPayload), "malformed open forward request")
			return false
		}
		return s.handleOpenFwd(conn, req) == nil

	case MUX_C_CLOSE_FWD:
		req, err := DecodeMuxFwdRequest(reqPayload)
		if err != nil {
			_ = sendFailure(conn, peekMuxRequestID(reqPayload), "malformed close forward request")
			return false
		}
		return s.handleCloseFwd(conn, req) == nil

	case MUX_C_NEW_SESSION:
		req, err := DecodeMuxNewSession(reqPayload)
		if err != nil {
			_ = sendFailure(conn, peekMuxRequestID(reqPayload), "malformed new session request")
			return false
		}
		_ = handlePassengerSession(s, conn, req.RequestID, reqPayload)
		return false

	case MUX_C_NEW_STDIO_FWD:
		req, err := DecodeMuxNewStdioFwd(reqPayload)
		if err != nil {
			_ = sendFailure(conn, peekMuxRequestID(reqPayload), "malformed new stdio fwd request")
			return false
		}
		_ = handlePassengerStdioFwd(s, conn, req.RequestID, reqPayload)
		return false

	case MUX_C_EXT_INFO:
		reqID, name, err := DecodeMuxExtInfo(reqPayload)
		if err != nil {
			_ = sendFailure(conn, peekMuxRequestID(reqPayload), "malformed ext info request")
			return false
		}
		return s.handleExtInfo(conn, reqID, name) == nil

	default:
		_ = sendFailure(conn, peekMuxRequestID(reqPayload), fmt.Sprintf("unsupported multiplex request: 0x%08x", msgType))
		return false
	}
}

func (s *MuxServer) handleAliveCheck(conn net.Conn, reqID uint32) error {
	pid := uint32(os.Getpid())
	return sendAlive(conn, reqID, pid)
}

func (s *MuxServer) handleExtInfo(conn net.Conn, reqID uint32, name string) error {
	var msg string
	switch name {
	case "connection":
		targetLine := ""
		if targetID := s.target.CanonicalTargetIdentity(); targetID != "" {
			targetLine = fmt.Sprintf("Target: %s\n", FormatTargetIdentity(targetID))
		}
		msg = fmt.Sprintf("OpenSSH multiplexing control connection\nSocket: %s\n%sControlMaster PID: %d\nActive sessions: %d\n",
			s.controlPath, targetLine, os.Getpid(), s.activeSessions.Load())
	case "channels":
		var b strings.Builder
		b.WriteString("Active Forwardings:\n")
		count := 0
		s.forwards.Range(func(key, value any) bool {
			fmt.Fprintf(&b, "- %v\n", key)
			count++
			return true
		})
		if count == 0 {
			b.WriteString("(none)\n")
		}
		msg = b.String()
	default:
		return sendFailure(conn, reqID, fmt.Sprintf("unknown info type %q", name))
	}
	return WriteMuxPacket(conn, MUX_S_EXT_INFO, EncodeMuxExtInfoResponse(reqID, 1, msg))
}

// handleTerminate always stops the master. The ask/autoask confirmation gates
// admission of new sessions and forwards, not administrative requests from the
// socket's owner: a master configured without a confirmer must stay stoppable,
// and the 0600 socket plus the peer-UID check already bound who may send one.
func (s *MuxServer) handleTerminate(conn net.Conn, reqID uint32) error {
	if s.stoppedListening.CompareAndSwap(false, true) {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.unlinkControlSocketFileIfOurs()
	}
	s.idleMu.Lock()
	s.shuttingDown = true
	s.terminated = true
	s.handoffReserved = false
	s.notifyIdleLocked()
	s.idleMu.Unlock()
	_ = sendOk(conn, reqID)
	go func() {
		time.Sleep(10 * time.Millisecond) // Allow response packet to flush
		_ = s.Shutdown()
	}()
	return nil
}

// handleStopListening unlinks the socket immediately and then retires a master
// that has nothing left to serve. Without the second step a ControlPersist
// daemon sitting idle would never stop: the shutdown paths that watch
// stoppedListening only run when the last active session is released, and there
// is no such session to release.
func (s *MuxServer) handleStopListening(conn net.Conn, reqID uint32) error {
	s.idleMu.Lock()
	s.stopRepliesInFlight++
	s.idleMu.Unlock()

	if s.stoppedListening.CompareAndSwap(false, true) {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.unlinkControlSocketFileIfOurs()
		s.idleMu.Lock()
		s.notifyIdleLocked()
		s.idleMu.Unlock()
	}
	sendErr := sendOk(conn, reqID)

	s.idleMu.Lock()
	s.stopRepliesInFlight--
	s.notifyIdleLocked()
	s.idleMu.Unlock()

	if s.releaseForegroundOnStopIfArmed() {
		return sendErr
	}
	s.shutdownWhenIdle()
	return sendErr
}

// shutdownWhenIdle commits a stopped master to shutdown unless a session is
// still draining. idleMu makes the admission decision atomic against
// addActiveSession, which refuses to start sessions on a shutting-down master.
func (s *MuxServer) shutdownWhenIdle() {
	s.idleMu.Lock()
	if s.shuttingDown || s.handoffReserved || s.hasInFlightControlOrForwardLocked() || s.closed.Load() || s.activeSessions.Load() > 0 || s.activeForwardStreams.Load() > 0 {
		s.idleMu.Unlock()
		return
	}
	s.shuttingDown = true
	s.idleGen++
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	s.idleMu.Unlock()

	go func() { _ = s.Shutdown() }()
}

func (s *MuxServer) handleProxy(conn net.Conn, reqID uint32) error {
	if !s.canAdmitNewSession() {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	if err := s.authorize("proxy session"); err != nil {
		return sendPermissionDenied(conn, reqID, err.Error())
	}
	if !s.addActiveSession() {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	defer s.removeActiveSession()

	if err := sendProxy(conn, reqID); err != nil {
		return err
	}

	s.trackStream(conn)
	defer s.untrackStream(conn)

	return s.serveProxyConn(conn)
}

// ErrSessionNotConfirmed reports that a confirmation-mode master (ControlMaster
// ask/autoask) rejected a request because no approval was granted.
var ErrSessionNotConfirmed = errors.New("connection sharing request was not approved")

// authorize applies the confirmation policy of an ask/autoask master. Any other
// mode, and a server without a confirmation callback, is unaffected.
func (s *MuxServer) authorize(action string) error {
	if s == nil || !s.askConfirmation {
		return nil
	}
	if s.confirmSession == nil {
		return fmt.Errorf("%w: %s", ErrSessionNotConfirmed, action)
	}
	if !s.confirmSession(action) {
		return fmt.Errorf("%w: %s", ErrSessionNotConfirmed, action)
	}
	return nil
}

func normalizeMuxForwardHost(host string, port uint32) string {
	if port == MUX_SPECIAL_PORT_UNIX {
		return host
	}
	trimmed := strings.TrimSpace(host)
	if len(trimmed) >= 2 && trimmed[0] == '[' && trimmed[len(trimmed)-1] == ']' {
		return strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	return trimmed
}

func (s *MuxServer) getLogger() logger.DebugLogger {
	if s == nil || s.logger == nil {
		return logger.NopLogger
	}
	return s.logger
}

func (s *MuxServer) effectiveDialNetwork() string {
	if s == nil {
		return "tcp"
	}
	return normalizeTCPDialNetwork(s.dialNetwork)
}

func (s *MuxServer) effectiveGatewayPortsMode() string {
	if s == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(s.gatewayPortsMode)) {
	case GatewayPortsYes:
		return GatewayPortsYes
	case GatewayPortsClientSpecified:
		return GatewayPortsClientSpecified
	case GatewayPortsNo:
		return GatewayPortsNo
	default:
		if s.gatewayPorts {
			return GatewayPortsYes
		}
		return ""
	}
}

func isTCPNetwork(network string) bool {
	return network == "tcp" || network == "tcp4" || network == "tcp6"
}

type resolvedMuxListen struct {
	network       string
	listenAddr    string
	keyHost       string
	endpointHost  string
	listenPort    uint32
	isDynamicPort bool
}

func cleanMuxUnixSocketPath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("streamlocal listen socket path cannot be empty")
	}
	if filepath.Separator == '\\' && strings.HasPrefix(trimmed, "/") && !strings.Contains(trimmed, `\`) {
		return path.Clean(trimmed), nil
	}
	return filepath.Clean(trimmed), nil
}

func canonicalTCPMuxEndpointHost(network, host string) string {
	if host == "" || host == "*" {
		return "*"
	}
	if strings.EqualFold(host, "localhost") {
		switch network {
		case "tcp4":
			return "127.0.0.1"
		case "tcp6":
			return "::1"
		default:
			return "localhost"
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			if (network == "tcp4" && ip.To4() != nil) || (network == "tcp6" && ip.To4() == nil) {
				return "*"
			}
		}
		return ip.String()
	}
	return strings.ToLower(host)
}

func validateAndNormalizeMuxFwdSpec(
	fwdType uint32,
	listenHost string,
	listenPort uint32,
	connectHost string,
	connectPort uint32,
) (normListenHost string, normConnectHost string, err error) {
	if strings.IndexByte(listenHost, 0) >= 0 {
		return "", "", errors.New("forward listen host contains NUL byte")
	}
	if strings.IndexByte(connectHost, 0) >= 0 {
		return "", "", errors.New("forward connect host contains NUL byte")
	}
	switch fwdType {
	case MUX_FWD_LOCAL, MUX_FWD_REMOTE, MUX_FWD_DYNAMIC:
	default:
		return "", "", fmt.Errorf("unsupported forward type %d", fwdType)
	}

	normListenHost, err = validateMuxFwdListenEndpoint(listenHost, listenPort)
	if err != nil {
		return "", "", err
	}
	normConnectHost, err = validateMuxFwdConnectEndpoint(fwdType, connectHost, connectPort)
	if err != nil {
		return "", "", err
	}
	return normListenHost, normConnectHost, nil
}

func validateMuxFwdListenEndpoint(listenHost string, listenPort uint32) (string, error) {
	if listenPort == MUX_SPECIAL_PORT_UNIX {
		return cleanMuxUnixSocketPath(listenHost)
	}
	if listenPort > 65535 {
		return "", fmt.Errorf("invalid forward listen port %s", strconv.FormatUint(uint64(listenPort), 10))
	}
	return normalizeMuxForwardHost(listenHost, listenPort), nil
}

func validateMuxFwdConnectEndpoint(fwdType uint32, connectHost string, connectPort uint32) (string, error) {
	if fwdType == MUX_FWD_DYNAMIC {
		if connectPort != 0 {
			return "", fmt.Errorf("invalid dynamic forward connect port %s", strconv.FormatUint(uint64(connectPort), 10))
		}
		return normalizeMuxForwardHost(connectHost, connectPort), nil
	}
	if connectPort == MUX_SPECIAL_PORT_UNIX {
		cleanTarget, err := cleanMuxUnixSocketPath(connectHost)
		if err != nil {
			return "", errors.New("streamlocal connect socket path cannot be empty")
		}
		return cleanTarget, nil
	}
	if fwdType == MUX_FWD_REMOTE && connectPort == 0 {
		norm := normalizeMuxForwardHost(connectHost, connectPort)
		if norm == "" {
			return "", nil
		}
		return "", fmt.Errorf("invalid forward connect port %s", strconv.FormatUint(uint64(connectPort), 10))
	}
	if connectPort < 1 || connectPort > 65535 {
		return "", fmt.Errorf("invalid forward connect port %s", strconv.FormatUint(uint64(connectPort), 10))
	}
	norm := normalizeMuxForwardHost(connectHost, connectPort)
	if norm == "" {
		return "", errors.New("forward connect host cannot be empty")
	}
	return norm, nil
}

func (s *MuxServer) resolveMuxForwardListenSpec(fwdType uint32, listenHost string, listenPort uint32) (resolvedMuxListen, error) {
	if strings.IndexByte(listenHost, 0) >= 0 {
		return resolvedMuxListen{}, errors.New("forward listen host contains NUL byte")
	}
	if listenPort == MUX_SPECIAL_PORT_UNIX {
		cleanPath, err := cleanMuxUnixSocketPath(listenHost)
		if err != nil {
			return resolvedMuxListen{}, err
		}
		return resolvedMuxListen{
			network:       "unix",
			listenAddr:    cleanPath,
			keyHost:       cleanPath,
			endpointHost:  cleanPath,
			listenPort:    listenPort,
			isDynamicPort: false,
		}, nil
	}
	if listenPort > 65535 {
		return resolvedMuxListen{}, fmt.Errorf("invalid forward listen port %s", strconv.FormatUint(uint64(listenPort), 10))
	}
	dialNet := s.effectiveDialNetwork()
	trimmed := normalizeMuxForwardHost(listenHost, listenPort)
	portStr := strconv.FormatUint(uint64(listenPort), 10)
	isDyn := isTCPNetwork(dialNet) && listenPort == 0

	switch fwdType {
	case MUX_FWD_LOCAL, MUX_FWD_DYNAMIC:
		if trimmed == "*" || (trimmed == "" && (s.gatewayPorts || s.effectiveGatewayPortsMode() == GatewayPortsYes)) {
			return resolvedMuxListen{
				network:       dialNet,
				listenAddr:    ":" + portStr,
				keyHost:       "*",
				endpointHost:  "*",
				listenPort:    listenPort,
				isDynamicPort: isDyn,
			}, nil
		}
		if trimmed == "" {
			loopback := loopbackListenHost(dialNet)
			return resolvedMuxListen{
				network:       dialNet,
				listenAddr:    net.JoinHostPort(loopback, portStr),
				keyHost:       loopback,
				endpointHost:  loopback,
				listenPort:    listenPort,
				isDynamicPort: isDyn,
			}, nil
		}
		return resolvedMuxListen{
			network:       dialNet,
			listenAddr:    net.JoinHostPort(trimmed, portStr),
			keyHost:       trimmed,
			endpointHost:  canonicalTCPMuxEndpointHost(dialNet, trimmed),
			listenPort:    listenPort,
			isDynamicPort: isDyn,
		}, nil

	case MUX_FWD_REMOTE:
		loopback := remoteLoopbackListenHost(dialNet)
		switch s.effectiveGatewayPortsMode() {
		case GatewayPortsYes:
			return resolvedMuxListen{
				network:       dialNet,
				listenAddr:    remoteWildcardListenAddr(dialNet, portStr),
				keyHost:       "*",
				endpointHost:  "*",
				listenPort:    listenPort,
				isDynamicPort: isDyn,
			}, nil
		case GatewayPortsNo:
			if trimmed == "" || trimmed == "*" {
				return resolvedMuxListen{
					network:       dialNet,
					listenAddr:    net.JoinHostPort(loopback, portStr),
					keyHost:       "localhost",
					endpointHost:  loopback,
					listenPort:    listenPort,
					isDynamicPort: isDyn,
				}, nil
			}
			return resolvedMuxListen{
				network:       dialNet,
				listenAddr:    net.JoinHostPort(trimmed, portStr),
				keyHost:       trimmed,
				endpointHost:  canonicalTCPMuxEndpointHost(dialNet, trimmed),
				listenPort:    listenPort,
				isDynamicPort: isDyn,
			}, nil
		default: // GatewayPortsClientSpecified or unset ("")
			if trimmed == "*" {
				return resolvedMuxListen{
					network:       dialNet,
					listenAddr:    remoteWildcardListenAddr(dialNet, portStr),
					keyHost:       "*",
					endpointHost:  "*",
					listenPort:    listenPort,
					isDynamicPort: isDyn,
				}, nil
			}
			if trimmed == "" {
				return resolvedMuxListen{
					network:       dialNet,
					listenAddr:    net.JoinHostPort(loopback, portStr),
					keyHost:       "localhost",
					endpointHost:  loopback,
					listenPort:    listenPort,
					isDynamicPort: isDyn,
				}, nil
			}
			return resolvedMuxListen{
				network:       dialNet,
				listenAddr:    net.JoinHostPort(trimmed, portStr),
				keyHost:       trimmed,
				endpointHost:  canonicalTCPMuxEndpointHost(dialNet, trimmed),
				listenPort:    listenPort,
				isDynamicPort: isDyn,
			}, nil
		}
	default:
		return resolvedMuxListen{}, fmt.Errorf("unsupported forward type %d", fwdType)
	}
}

func (s *MuxServer) resolveMuxForwardListen(fwdType uint32, listenHost string, listenPort uint32) (network, listenAddr, keyHost string, err error) {
	resolved, err := s.resolveMuxForwardListenSpec(fwdType, listenHost, listenPort)
	if err != nil {
		return "", "", "", err
	}
	return resolved.network, resolved.listenAddr, resolved.keyHost, nil
}

func forwardKey(fwdType uint32, keyHost string, listenPort uint32, connectHost string, connectPort uint32) string {
	return fmt.Sprintf("%d:%s:%d:%s:%d", fwdType, keyHost, listenPort, connectHost, connectPort)
}

func extractAllocatedPort(addr net.Addr) uint32 {
	if addr == nil {
		return 0
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		if tcpAddr.Port <= 0 {
			return 0
		}
		return uint32(tcpAddr.Port)
	}
	_, portStr, err := net.SplitHostPort(addr.String())
	if err == nil {
		if p, err := strconv.ParseUint(portStr, 10, 32); err == nil {
			return uint32(p)
		}
	}
	return 0
}

type muxRemoteSSHListener struct {
	net.Listener
	sshForwardKey string
	closeOnce     sync.Once
	closeErr      error
}

func (l *muxRemoteSSHListener) Close() error {
	l.closeOnce.Do(func() {
		l.closeErr = l.Listener.Close()
	})
	return l.closeErr
}

func remoteSSHForwardListKey(network, listenAddr string, ln net.Listener) string {
	if ln == nil {
		return ""
	}
	if network == "unix" {
		return "unix:" + listenAddr
	}
	if !isTCPNetwork(network) {
		return ""
	}
	host, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return ""
	}
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		return "tcp:" + net.JoinHostPort(host, strconv.Itoa(tcpAddr.Port))
	}
	if alloc := extractAllocatedPort(ln.Addr()); alloc > 0 {
		return "tcp:" + net.JoinHostPort(host, strconv.FormatUint(uint64(alloc), 10))
	}
	return "tcp:" + net.JoinHostPort(host, portStr)
}

func (s *MuxServer) baseContext() context.Context {
	if s != nil && s.serverCtx != nil {
		return s.serverCtx
	}
	return context.Background()
}

func (s *MuxServer) listenRemoteMux(network, listenAddr string) (net.Listener, error) {
	if s == nil || s.sshClient == nil {
		return nil, errors.New("ssh client is nil")
	}
	reqCtx, cancel := context.WithTimeout(s.baseContext(), remoteForwardRequestTimeout)
	defer cancel()
	done := make(chan struct{})
	stop := context.AfterFunc(reqCtx, func() {
		defer close(done)
		_ = s.Shutdown()
	})
	rawLn, err := s.sshClient.Listen(network, listenAddr)
	var ln net.Listener
	if rawLn != nil {
		ln = &muxRemoteSSHListener{
			Listener:      rawLn,
			sshForwardKey: remoteSSHForwardListKey(network, listenAddr, rawLn),
		}
	}
	if !stop() {
		<-done
		if ln != nil {
			s.closeUnpublishedMuxForward(&muxForwardEntry{closer: ln, remote: true})
		}
		if err == nil {
			return nil, reqCtx.Err()
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return ln, nil
}

func (s *MuxServer) closeMuxForwardEntry(entry *muxForwardEntry) {
	s.closeMuxForwardEntryWithShadows(entry, nil)
}

func (s *MuxServer) closeMuxForwardEntryWithShadows(entry *muxForwardEntry, shadows []io.Closer) {
	if entry == nil {
		return
	}
	if entry.closer == nil && len(shadows) == 0 {
		return
	}
	if !entry.remote {
		if entry.closer != nil {
			_ = entry.closer.Close()
		}
		for _, sc := range shadows {
			if sc != nil {
				_ = sc.Close()
			}
		}
		return
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), remoteForwardRequestTimeout)
	defer cancel()
	done := make(chan struct{})
	stop := context.AfterFunc(closeCtx, func() {
		defer close(done)
		_ = s.Shutdown()
	})
	if entry.closer != nil {
		_ = entry.closer.Close()
	}
	for _, sc := range shadows {
		if sc != nil {
			_ = sc.Close()
		}
	}
	if !stop() {
		<-done
	}
}

func (e *muxForwardEntry) takeShadowClosers() []io.Closer {
	if e == nil {
		return nil
	}
	e.closed = true
	shadows := e.shadowClosers
	e.shadowClosers = nil
	return shadows
}

func (s *MuxServer) takeShadowClosers(entry *muxForwardEntry) []io.Closer {
	if entry == nil {
		return nil
	}
	s.idleMu.Lock()
	shadows := entry.takeShadowClosers()
	s.idleMu.Unlock()
	return shadows
}

// closeUnpublishedMuxForward closes a listener that has no Accept loop yet.
// For x/crypto/ssh remote listeners, upstream can hold its forward-list lock
// while enqueueing an incoming channel, so Accept must be drained concurrently
// until the bounded Close completes.
func (s *MuxServer) closeUnpublishedMuxForward(entry *muxForwardEntry) {
	if entry == nil || entry.closer == nil {
		return
	}
	ln, ok := entry.closer.(net.Listener)
	if !entry.remote || !ok {
		s.closeMuxForwardEntry(entry)
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.closeMuxForwardEntry(entry)
	}()
	retry := time.NewTicker(time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-done:
			return
		default:
		}
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
			continue
		}
		select {
		case <-done:
			return
		case <-retry.C:
		}
	}
}

func (s *MuxServer) dialSSHMux(parent context.Context, network, addr string) (net.Conn, error) {
	if s == nil || s.sshClient == nil {
		return nil, errors.New("ssh client is nil")
	}
	base := parent
	if base == nil {
		base = s.baseContext()
	}
	timeout := 15 * time.Second
	if s.requestTimeout > 0 {
		timeout = s.requestTimeout
	}
	dialCtx, cancel := context.WithTimeout(base, timeout)
	defer cancel()
	return s.sshClient.DialContext(dialCtx, network, addr)
}

type muxForwardScope uint8

const (
	muxForwardScopeLocal muxForwardScope = iota + 1
	muxForwardScopeRemote
)

type forwardListenKey struct {
	fwdScope   muxForwardScope
	network    string
	keyHost    string
	listenPort uint32
}

type muxForwardEndpointState struct {
	inFlight      bool
	closing       bool
	done          chan struct{}
	closingWait   chan struct{}
	entry         *muxForwardEntry
	fallbackEntry *muxForwardEntry
}

func (st *muxForwardEndpointState) cancelCandidateEntry() *muxForwardEntry {
	if st == nil {
		return nil
	}
	if st.inFlight {
		return st.fallbackEntry
	}
	return st.entry
}

type muxEndpointAcquireOutcome uint8

const (
	muxEndpointReserved muxEndpointAcquireOutcome = iota + 1
	muxEndpointRetained
	muxEndpointConflict
	muxEndpointShuttingDown
)

type muxForwardEntry struct {
	closer        io.Closer
	fwdType       uint32
	forwardKey    string
	keyHost       string
	endpointHost  string
	connectHost   string
	connectPort   uint32
	listenKey     forwardListenKey
	hasListenKey  bool
	dynamicAlloc  bool
	remote        bool
	sshForwardKey string
	closed        bool
	shadowClosers []io.Closer
	refs          int
}

// retainDuplicateRemoteListenerLocked prevents closing an unpublished
// x/crypto/ssh remote listener when an active published entry already owns the
// identical upstream forward-list key on s.sshClient. x/crypto/ssh's
// tcpListener.Close removes the first matching entry in s.sshClient.forwards
// and sends cancel-tcpip-forward for (host, port), which would tear down the
// active listener. Retaining cand's listener until active closes keeps active
// intact and removes both forward-list entries symmetrically on teardown.
func (s *MuxServer) retainDuplicateRemoteListenerLocked(active, cand *muxForwardEntry) bool {
	if active == nil || cand == nil || cand.closer == nil || active.closed {
		return false
	}
	if !active.remote || !cand.remote || active.sshForwardKey == "" || active.sshForwardKey != cand.sshForwardKey {
		return false
	}
	active.shadowClosers = append(active.shadowClosers, cand.closer)
	if ln, ok := cand.closer.(net.Listener); ok {
		connectHost := active.connectHost
		connectPort := active.connectPort
		go s.serveRemoteForward(ln, connectHost, connectPort)
	}
	return true
}

func muxForwardScopeForType(fwdType uint32) muxForwardScope {
	if fwdType == MUX_FWD_REMOTE {
		return muxForwardScopeRemote
	}
	return muxForwardScopeLocal
}

func makeForwardListenKey(fwdType uint32, resolved resolvedMuxListen) (forwardListenKey, bool) {
	if resolved.isDynamicPort {
		return forwardListenKey{}, false
	}
	return forwardListenKey{
		fwdScope:   muxForwardScopeForType(fwdType),
		network:    resolved.network,
		keyHost:    resolved.endpointHost,
		listenPort: resolved.listenPort,
	}, true
}

func matchesMuxForwardCancelTarget(entry *muxForwardEntry, fwdType uint32, normConnectHost string, connectPort uint32) bool {
	if entry == nil || entry.fwdType != fwdType {
		return false
	}
	if fwdType == MUX_FWD_DYNAMIC {
		return true
	}
	return entry.connectHost == normConnectHost && entry.connectPort == connectPort
}

func sameMuxForwardDestination(entry *muxForwardEntry, fwdType uint32, normConnectHost string, connectPort uint32) bool {
	if entry == nil || entry.dynamicAlloc {
		return false
	}
	return matchesMuxForwardCancelTarget(entry, fwdType, normConnectHost, connectPort)
}

func (s *MuxServer) acquireForwardEndpoint(
	listenKey forwardListenKey,
	fwdType uint32,
	normConnectHost string,
	connectPort uint32,
) (*muxForwardEndpointState, muxEndpointAcquireOutcome) {
	for {
		s.idleMu.Lock()
		if s.shuttingDown || s.closed.Load() {
			s.idleMu.Unlock()
			return nil, muxEndpointShuttingDown
		}
		if s.listenEndpoints == nil {
			s.listenEndpoints = make(map[forwardListenKey]*muxForwardEndpointState)
		}
		cur, exists := s.listenEndpoints[listenKey]
		if !exists {
			slot := &muxForwardEndpointState{
				inFlight: true,
				done:     make(chan struct{}),
			}
			s.listenEndpoints[listenKey] = slot
			s.idleMu.Unlock()
			return slot, muxEndpointReserved
		}
		if cur.inFlight {
			waitCh := cur.done
			s.idleMu.Unlock()
			select {
			case <-waitCh:
				continue
			case <-s.baseContext().Done():
				return nil, muxEndpointShuttingDown
			}
		}
		if cur.closingWait != nil {
			waitCh := cur.closingWait
			s.idleMu.Unlock()
			select {
			case <-waitCh:
				continue
			case <-s.baseContext().Done():
				return nil, muxEndpointShuttingDown
			}
		}
		if cur.entry != nil && sameMuxForwardDestination(cur.entry, fwdType, normConnectHost, connectPort) {
			if fwdType == MUX_FWD_REMOTE {
				cur.entry.refs++
			}
			s.idleMu.Unlock()
			return nil, muxEndpointRetained
		}
		s.idleMu.Unlock()
		return nil, muxEndpointConflict
	}
}

func (s *MuxServer) releaseInFlightEndpointSlotLocked(listenKey forwardListenKey, slot *muxForwardEndpointState) {
	if slot == nil {
		return
	}
	if s.listenEndpoints != nil && s.listenEndpoints[listenKey] == slot {
		if slot.fallbackEntry != nil {
			slot.entry = slot.fallbackEntry
			slot.fallbackEntry = nil
			slot.inFlight = false
			slot.closing = false
		} else {
			slot.inFlight = false
			slot.closing = false
			delete(s.listenEndpoints, listenKey)
		}
	}
	close(slot.done)
	s.notifyIdleLocked()
}

func (s *MuxServer) abortReservedForward(listenKey forwardListenKey, slot *muxForwardEndpointState) {
	if slot == nil {
		return
	}
	s.idleMu.Lock()
	for slot.closingWait != nil {
		waitCh := slot.closingWait
		s.idleMu.Unlock()
		<-waitCh
		s.idleMu.Lock()
	}
	s.releaseInFlightEndpointSlotLocked(listenKey, slot)
	s.scheduleIdleOrShutdownLocked()
	s.idleMu.Unlock()
}

func (s *MuxServer) commitReservedForward(
	listenKey forwardListenKey,
	slot *muxForwardEndpointState,
	key string,
	cand *muxForwardEntry,
) (entry *muxForwardEntry, duplicate bool, shuttingDown bool) {
	entry, duplicate, _, shuttingDown = s.commitReservedForwardSlot(listenKey, slot, key, cand)
	return entry, duplicate, shuttingDown
}

func (s *MuxServer) commitReservedForwardSlot(
	listenKey forwardListenKey,
	slot *muxForwardEndpointState,
	key string,
	cand *muxForwardEntry,
) (entry *muxForwardEntry, duplicate bool, conflict bool, shuttingDown bool) {
	s.idleMu.Lock()
	if slot != nil {
		for slot.closingWait != nil {
			waitCh := slot.closingWait
			s.idleMu.Unlock()
			<-waitCh
			s.idleMu.Lock()
		}
	}
	if s.shuttingDown || s.closed.Load() {
		s.releaseInFlightEndpointSlotLocked(listenKey, slot)
		s.idleMu.Unlock()
		s.closeUnpublishedMuxForward(cand)
		return nil, false, false, true
	}
	if slot != nil && slot.fallbackEntry != nil {
		active := slot.fallbackEntry
		retained := s.retainDuplicateRemoteListenerLocked(active, cand)
		s.releaseInFlightEndpointSlotLocked(listenKey, slot)
		s.idleMu.Unlock()
		if !retained {
			s.closeUnpublishedMuxForward(cand)
		}
		return nil, false, true, false
	}
	if cand.refs <= 0 {
		cand.refs = 1
	}
	cand.forwardKey = key
	if existing, loaded := s.forwards.LoadOrStore(key, cand); loaded {
		if existingEntry, ok := existing.(*muxForwardEntry); ok {
			if cand.fwdType == MUX_FWD_REMOTE {
				existingEntry.refs++
			}
			retained := s.retainDuplicateRemoteListenerLocked(existingEntry, cand)
			if slot != nil {
				if !existingEntry.hasListenKey {
					existingEntry.listenKey = listenKey
					existingEntry.hasListenKey = true
					slot.entry = existingEntry
					slot.inFlight = false
				} else if existingEntry.listenKey == listenKey {
					slot.entry = existingEntry
					slot.inFlight = false
				} else if s.listenEndpoints != nil && s.listenEndpoints[listenKey] == slot {
					delete(s.listenEndpoints, listenKey)
				}
				close(slot.done)
			}
			s.idleMu.Unlock()
			if !retained {
				s.closeUnpublishedMuxForward(cand)
			}
			return existingEntry, true, false, false
		}
	}
	if slot != nil {
		cand.listenKey = listenKey
		cand.hasListenKey = true
		slot.entry = cand
		slot.inFlight = false
		close(slot.done)
	}
	s.idleMu.Unlock()
	return cand, false, false, false
}

func (s *MuxServer) registerBoundMuxForward(
	fwdType uint32,
	resolved resolvedMuxListen,
	normConnectHost string,
	connectPort uint32,
	listenKey forwardListenKey,
	reservedSlot *muxForwardEndpointState,
	ln net.Listener,
) (key string, entry *muxForwardEntry, allocatedPort uint32, dynamicAlloc, duplicate, conflict, shuttingDown bool) {
	keyPort := resolved.listenPort
	if resolved.isDynamicPort {
		allocatedPort = extractAllocatedPort(ln.Addr())
		if allocatedPort >= 1 && allocatedPort <= 65535 {
			keyPort = allocatedPort
		}
	}
	dynamicAlloc = resolved.isDynamicPort && allocatedPort >= 1 && allocatedPort <= 65535
	key = forwardKey(fwdType, resolved.keyHost, keyPort, normConnectHost, connectPort)
	var sshFwdKey string
	if rln, ok := ln.(*muxRemoteSSHListener); ok {
		sshFwdKey = rln.sshForwardKey
	}
	cand := &muxForwardEntry{
		closer:        ln,
		fwdType:       fwdType,
		forwardKey:    key,
		keyHost:       resolved.keyHost,
		endpointHost:  resolved.endpointHost,
		connectHost:   normConnectHost,
		connectPort:   connectPort,
		dynamicAlloc:  dynamicAlloc,
		remote:        fwdType == MUX_FWD_REMOTE,
		sshForwardKey: sshFwdKey,
		refs:          1,
	}
	if reservedSlot != nil {
		entry, duplicate, conflict, shuttingDown = s.commitReservedForwardSlot(listenKey, reservedSlot, key, cand)
	} else {
		entry, duplicate, conflict, shuttingDown = s.publishForward(resolved, allocatedPort, key, cand)
	}
	return key, entry, allocatedPort, dynamicAlloc, duplicate, conflict, shuttingDown
}

func (s *MuxServer) deleteEndpointEntryLocked(entry *muxForwardEntry) {
	if entry == nil || !entry.hasListenKey || s.listenEndpoints == nil {
		return
	}
	cur, exists := s.listenEndpoints[entry.listenKey]
	if !exists || cur == nil {
		return
	}
	if cur.inFlight {
		if cur.fallbackEntry == entry {
			cur.fallbackEntry = nil
		}
		return
	}
	if cur.entry == entry {
		delete(s.listenEndpoints, entry.listenKey)
	}
}

func (s *MuxServer) handleOpenFwd(conn net.Conn, req MuxFwdRequest) error {
	s.idleMu.Lock()
	if s.shuttingDown || s.closed.Load() || s.stoppedListening.Load() {
		// Shutdown already took its listener snapshot; accepting a forward now would
		// leave a listener that outlives the master it belongs to.
		s.idleMu.Unlock()
		return sendFailure(conn, req.RequestID, "mux master is shutting down")
	}
	s.openFwdsInFlight++
	s.idleGen++
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	s.idleMu.Unlock()

	defer func() {
		s.idleMu.Lock()
		s.openFwdsInFlight--
		s.scheduleIdleOrShutdownLocked()
		s.notifyIdleLocked()
		s.idleMu.Unlock()
	}()

	normListenHost, normConnectHost, err := validateAndNormalizeMuxFwdSpec(
		req.FwdType, req.ListenHost, req.ListenPort, req.ConnectHost, req.ConnectPort,
	)
	if err != nil {
		return sendFailure(conn, req.RequestID, err.Error())
	}
	resolved, err := s.resolveMuxForwardListenSpec(req.FwdType, normListenHost, req.ListenPort)
	if err != nil {
		return sendFailure(conn, req.RequestID, err.Error())
	}
	if err := s.authorize("forward"); err != nil {
		return sendPermissionDenied(conn, req.RequestID, err.Error())
	}

	var (
		listenKey    forwardListenKey
		hasListenKey bool
		reservedSlot *muxForwardEndpointState
	)
	if listenKey, hasListenKey = makeForwardListenKey(req.FwdType, resolved); hasListenKey {
		var outcome muxEndpointAcquireOutcome
		reservedSlot, outcome = s.acquireForwardEndpoint(listenKey, req.FwdType, normConnectHost, req.ConnectPort)
		switch outcome {
		case muxEndpointShuttingDown:
			return sendFailure(conn, req.RequestID, "mux master is shutting down")
		case muxEndpointRetained:
			return sendOk(conn, req.RequestID)
		case muxEndpointConflict:
			return sendFailure(conn, req.RequestID, "port forwarding conflict on listen endpoint")
		}
	}

	switch req.FwdType {
	case MUX_FWD_LOCAL:
		return s.openLocalOrDynamicForward(conn, req, resolved, normConnectHost, listenKey, reservedSlot, "local", func(l net.Listener) {
			s.serveLocalForward(l, normConnectHost, req.ConnectPort)
		})

	case MUX_FWD_REMOTE:
		return s.openRemoteForward(conn, req, resolved, normConnectHost, listenKey, reservedSlot)

	case MUX_FWD_DYNAMIC:
		return s.openLocalOrDynamicForward(conn, req, resolved, normConnectHost, listenKey, reservedSlot, "dynamic", s.serveDynamicForward)

	default:
		s.abortReservedForward(listenKey, reservedSlot)
		return sendFailure(conn, req.RequestID, fmt.Sprintf("unsupported forward type %d", req.FwdType))
	}
}

func (s *MuxServer) openLocalOrDynamicForward(
	conn net.Conn,
	req MuxFwdRequest,
	resolved resolvedMuxListen,
	normConnectHost string,
	listenKey forwardListenKey,
	reservedSlot *muxForwardEndpointState,
	kind string,
	serve func(net.Listener),
) error {
	var (
		ln  net.Listener
		err error
	)
	if resolved.network == "unix" {
		ln, err = listenLocalStreamLocal(s.baseContext(), resolved.listenAddr, s.streamLocalBindMask, s.streamLocalBindUnlink)
	} else {
		var lc net.ListenConfig
		ln, err = lc.Listen(s.baseContext(), resolved.network, resolved.listenAddr)
	}
	if err != nil {
		s.abortReservedForward(listenKey, reservedSlot)
		return sendFailure(conn, req.RequestID, fmt.Sprintf("bind %s port %s failed: %v", kind, resolved.listenAddr, err))
	}
	key, entry, _, _, duplicate, conflict, shuttingDown := s.registerBoundMuxForward(
		req.FwdType, resolved, normConnectHost, req.ConnectPort, listenKey, reservedSlot, ln,
	)
	if shuttingDown {
		return sendFailure(conn, req.RequestID, "mux master is shutting down")
	}
	if conflict {
		return sendFailure(conn, req.RequestID, "port forwarding conflict on listen endpoint")
	}
	if duplicate {
		return sendOk(conn, req.RequestID)
	}
	go func(k string, e *muxForwardEntry, l net.Listener) {
		defer s.retireForward(k, e)
		serve(l)
	}(key, entry, ln)
	return sendOk(conn, req.RequestID)
}

func (s *MuxServer) openRemoteForward(
	conn net.Conn,
	req MuxFwdRequest,
	resolved resolvedMuxListen,
	normConnectHost string,
	listenKey forwardListenKey,
	reservedSlot *muxForwardEndpointState,
) error {
	ln, err := s.listenRemoteMux(resolved.network, resolved.listenAddr)
	if err != nil {
		s.abortReservedForward(listenKey, reservedSlot)
		return sendFailure(conn, req.RequestID, fmt.Sprintf("remote listen %s failed: %v", resolved.listenAddr, err))
	}
	if resolved.isDynamicPort {
		allocPort := extractAllocatedPort(ln.Addr())
		if allocPort < 1 || allocPort > 65535 {
			s.abortReservedForward(listenKey, reservedSlot)
			s.closeUnpublishedMuxForward(&muxForwardEntry{
				closer: ln,
				remote: true,
			})
			return sendFailure(conn, req.RequestID, fmt.Sprintf("remote server allocated invalid port %d", allocPort))
		}
	}
	key, entry, allocatedPort, dynamicAlloc, duplicate, conflict, shuttingDown := s.registerBoundMuxForward(
		req.FwdType, resolved, normConnectHost, req.ConnectPort, listenKey, reservedSlot, ln,
	)
	if shuttingDown {
		return sendFailure(conn, req.RequestID, "mux master is shutting down")
	}
	if conflict {
		return sendFailure(conn, req.RequestID, "port forwarding conflict on listen endpoint")
	}
	if duplicate {
		return sendOk(conn, req.RequestID)
	}
	go func(k string, e *muxForwardEntry, l net.Listener) {
		defer s.retireForward(k, e)
		s.serveRemoteForward(l, normConnectHost, req.ConnectPort)
	}(key, entry, ln)

	if dynamicAlloc {
		return sendRemotePort(conn, req.RequestID, allocatedPort)
	}
	return sendOk(conn, req.RequestID)
}

func (s *MuxServer) checkDynamicEndpointConflictLocked(dynKey forwardListenKey, cand *muxForwardEntry) (conflict, retained bool) {
	if s.listenEndpoints == nil {
		return false, false
	}
	cur, exists := s.listenEndpoints[dynKey]
	if !exists || cur == nil {
		return false, false
	}
	if !cur.inFlight {
		return true, s.retainDuplicateRemoteListenerLocked(cur.entry, cand)
	}
	if cur.fallbackEntry != nil {
		return true, s.retainDuplicateRemoteListenerLocked(cur.fallbackEntry, cand)
	}
	return false, false
}

func (s *MuxServer) recordDynamicEndpointLocked(dynKey forwardListenKey, cand *muxForwardEntry) {
	if s.listenEndpoints == nil {
		s.listenEndpoints = make(map[forwardListenKey]*muxForwardEndpointState)
	}
	if cur, exists := s.listenEndpoints[dynKey]; !exists || cur == nil {
		cand.listenKey = dynKey
		cand.hasListenKey = true
		s.listenEndpoints[dynKey] = &muxForwardEndpointState{entry: cand}
	} else if cur.inFlight && cur.fallbackEntry == nil {
		cand.listenKey = dynKey
		cand.hasListenKey = true
		cur.fallbackEntry = cand
	}
}

func (s *MuxServer) lockForPublishForward(hasDynKey bool, dynKey forwardListenKey) bool {
	for {
		s.idleMu.Lock()
		if s.shuttingDown || s.closed.Load() {
			s.idleMu.Unlock()
			return false
		}
		if hasDynKey {
			if waited, aborted := s.waitClosingEndpointLocked(dynKey); waited {
				if aborted {
					return false
				}
				continue
			}
		}
		return true
	}
}

// publishForward registers a dynamically allocated listener this master now
// owns. Shutdown and PrepareHandoff synchronize on idleMu, so a forward never
// slips in after the master committed to handoff or shutdown.
func (s *MuxServer) publishForward(
	resolved resolvedMuxListen,
	allocatedPort uint32,
	key string,
	cand *muxForwardEntry,
) (entry *muxForwardEntry, duplicate bool, conflict bool, shuttingDown bool) {
	var (
		dynKey    forwardListenKey
		hasDynKey bool
	)
	if cand.dynamicAlloc && allocatedPort >= 1 && allocatedPort <= 65535 {
		dynKey = forwardListenKey{
			fwdScope:   muxForwardScopeForType(cand.fwdType),
			network:    resolved.network,
			keyHost:    resolved.endpointHost,
			listenPort: allocatedPort,
		}
		hasDynKey = true
	}

	if !s.lockForPublishForward(hasDynKey, dynKey) {
		s.closeUnpublishedMuxForward(cand)
		return nil, false, false, true
	}

	if cand.refs <= 0 {
		cand.refs = 1
	}
	cand.forwardKey = key

	if hasDynKey {
		if epConflict, retained := s.checkDynamicEndpointConflictLocked(dynKey, cand); epConflict {
			s.idleMu.Unlock()
			if !retained {
				s.closeUnpublishedMuxForward(cand)
			}
			return nil, false, true, false
		}
	}

	if existing, loaded := s.forwards.LoadOrStore(key, cand); loaded {
		existingEntry, _ := existing.(*muxForwardEntry)
		if cand.dynamicAlloc {
			retained := s.retainDuplicateRemoteListenerLocked(existingEntry, cand)
			s.idleMu.Unlock()
			if !retained {
				s.closeUnpublishedMuxForward(cand)
			}
			return nil, false, true, false
		}
		if existingEntry != nil {
			if cand.fwdType == MUX_FWD_REMOTE {
				existingEntry.refs++
			}
			retained := s.retainDuplicateRemoteListenerLocked(existingEntry, cand)
			s.idleMu.Unlock()
			if !retained {
				s.closeUnpublishedMuxForward(cand)
			}
			return existingEntry, true, false, false
		}
	}
	if hasDynKey {
		s.recordDynamicEndpointLocked(dynKey, cand)
	}
	s.idleMu.Unlock()
	return cand, false, false, false
}

func (s *MuxServer) retireForward(key string, entry *muxForwardEntry) {
	s.idleMu.Lock()
	deleted := s.forwards.CompareAndDelete(key, entry)
	shadows := entry.takeShadowClosers()
	s.deleteEndpointEntryLocked(entry)

	var (
		closingSlot      *muxForwardEndpointState
		inFlightCur      *muxForwardEndpointState
		closingWaitDone  chan struct{}
		closeFwdsCounted bool
	)
	if deleted && len(shadows) > 0 && entry != nil && entry.hasListenKey {
		s.closeFwdsInFlight++
		closeFwdsCounted = true
		s.idleGen++
		if s.idleTimer != nil {
			s.idleTimer.Stop()
			s.idleTimer = nil
		}
		abortedWait := false
		for !s.shuttingDown && !s.closed.Load() {
			waited, aborted := s.waitClosingEndpointLocked(entry.listenKey)
			if !waited {
				break
			}
			s.idleMu.Lock()
			if aborted {
				abortedWait = true
				break
			}
		}
		if !abortedWait && !s.shuttingDown && !s.closed.Load() {
			closingSlot, inFlightCur, closingWaitDone = s.beginEndpointCloseBarrierLocked(entry)
		}
	} else if deleted {
		s.scheduleIdleOrShutdownLocked()
		s.notifyIdleLocked()
	}
	s.idleMu.Unlock()

	if len(shadows) > 0 {
		s.closeMuxForwardEntryWithShadows(&muxForwardEntry{remote: entry.remote}, shadows)
	}
	if closingSlot != nil || closingWaitDone != nil || closeFwdsCounted {
		s.idleMu.Lock()
		s.finishEndpointCloseBarrierLocked(entry, closingSlot, inFlightCur, closingWaitDone)
		if closeFwdsCounted {
			s.closeFwdsInFlight--
		}
		s.scheduleIdleOrShutdownLocked()
		s.notifyIdleLocked()
		s.idleMu.Unlock()
	}
}

// trackStream registers an accepted connection for shutdown-driven teardown.
func (s *MuxServer) trackStream(conn net.Conn) {
	if conn == nil {
		return
	}
	s.liveStreams.Store(conn, struct{}{})
	if s.closed.Load() {
		// Shutdown may have already taken its snapshot; close immediately.
		_ = conn.Close()
	}
}

func (s *MuxServer) untrackStream(conn net.Conn) {
	if conn == nil {
		return
	}
	s.liveStreams.Delete(conn)
}

func (s *MuxServer) serveLocalForward(ln net.Listener, connectHost string, connectPort ...uint32) {
	defer func() { _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(local net.Conn) {
			if !s.addActiveForwardStream() {
				_ = local.Close()
				return
			}
			s.trackStream(local)
			defer func() {
				_ = local.Close()
				s.untrackStream(local)
				s.removeActiveForwardStream()
			}()
			var remote net.Conn
			var dialErr error
			dialNet := s.effectiveDialNetwork()
			if len(connectPort) > 0 && connectPort[0] == MUX_SPECIAL_PORT_UNIX {
				remote, dialErr = s.dialSSHMux(s.baseContext(), "unix", connectHost)
			} else if len(connectPort) > 0 {
				remote, dialErr = s.dialSSHMux(s.baseContext(), dialNet, net.JoinHostPort(connectHost, strconv.FormatUint(uint64(connectPort[0]), 10)))
			} else {
				remote, dialErr = s.dialSSHMux(s.baseContext(), dialNet, connectHost)
			}
			if dialErr != nil {
				return
			}
			s.trackStream(remote)
			defer func() {
				_ = remote.Close()
				s.untrackStream(remote)
			}()
			pipeBidirectional(local, remote)
		}(c)
	}
}

func (s *MuxServer) serveRemoteForward(ln net.Listener, connectHost string, connectPort uint32) {
	defer func() { _ = ln.Close() }()
	isDynamic := connectHost == "" && connectPort == 0
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(remote net.Conn) {
			if !s.addActiveForwardStream() {
				_ = remote.Close()
				return
			}
			s.trackStream(remote)
			defer func() {
				_ = remote.Close()
				s.untrackStream(remote)
				s.removeActiveForwardStream()
			}()

			dialNet := s.effectiveDialNetwork()
			if isDynamic {
				var dialedLocal net.Conn
				defer func() {
					if dialedLocal != nil {
						s.untrackStream(dialedLocal)
					}
				}()
				_ = serveSocksConn(s.baseContext(), remote, func(ctx context.Context, destAddr string) (net.Conn, error) {
					dialer := net.Dialer{Timeout: 5 * time.Second}
					local, err := dialer.DialContext(ctx, dialNet, destAddr)
					if err != nil {
						return nil, err
					}
					dialedLocal = local
					s.trackStream(local)
					return local, nil
				}, func(ctx context.Context, c1, c2 net.Conn) error {
					pipeBidirectional(c1, c2)
					return nil
				})
				return
			}

			var local net.Conn
			var dialErr error
			dialer := net.Dialer{Timeout: 5 * time.Second}
			if connectPort == MUX_SPECIAL_PORT_UNIX {
				local, dialErr = dialer.DialContext(s.baseContext(), "unix", connectHost)
			} else {
				localAddr := net.JoinHostPort(connectHost, strconv.FormatUint(uint64(connectPort), 10))
				local, dialErr = dialer.DialContext(s.baseContext(), dialNet, localAddr)
			}
			if dialErr != nil {
				return
			}
			s.trackStream(local)
			defer func() {
				_ = local.Close()
				s.untrackStream(local)
			}()
			pipeBidirectional(local, remote)
		}(c)
	}
}

func (s *MuxServer) serveDynamicForward(ln net.Listener) {
	defer func() { _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.serveDynamicConn(c)
	}
}

// serveDynamicConn terminates one SOCKS4/4a/5 CONNECT on the master's SSH transport.
// It reuses the shared SOCKS negotiation used by Client.DynamicForwardEndpoint.
func (s *MuxServer) serveDynamicConn(conn net.Conn) {
	if !s.addActiveForwardStream() {
		_ = conn.Close()
		return
	}
	s.trackStream(conn)
	defer func() {
		_ = conn.Close()
		s.untrackStream(conn)
		s.removeActiveForwardStream()
	}()

	var dialedRemote net.Conn
	defer func() {
		if dialedRemote != nil {
			s.untrackStream(dialedRemote)
		}
	}()
	dialNet := s.effectiveDialNetwork()
	_ = serveSocksConn(s.baseContext(), conn, func(ctx context.Context, destAddr string) (net.Conn, error) {
		remoteConn, err := s.dialSSHMux(ctx, dialNet, destAddr)
		if err != nil {
			return nil, err
		}
		dialedRemote = remoteConn
		s.trackStream(remoteConn)
		return remoteConn, nil
	}, func(ctx context.Context, c1, c2 net.Conn) error {
		pipeBidirectional(c1, c2)
		return nil
	})
}

// pipeBidirectional copies both directions to completion. A one-way EOF only
// half-closes the peer so in-flight bytes in the other direction are not
// truncated, and the function does not return before both copies have exited.
func pipeBidirectional(c1, c2 io.ReadWriteCloser) {
	var copies sync.WaitGroup
	pipe := func(dst, src io.ReadWriteCloser) {
		defer copies.Done()
		_, _ = io.Copy(dst, src)
		if halfCloser, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = halfCloser.CloseWrite()
			return
		}
		_ = dst.Close()
	}
	copies.Add(2)
	go pipe(c1, c2)
	go pipe(c2, c1)
	copies.Wait()
}

func (s *MuxServer) lookupCloseFwdTargetLocked(
	key string,
	req MuxFwdRequest,
	resolved resolvedMuxListen,
	reqListenKey forwardListenKey,
	hasReqListenKey bool,
	normConnectHost string,
) (matchedKey string, entry *muxForwardEntry, ok bool) {
	matchedKey = key
	if val, found := s.forwards.Load(matchedKey); found {
		if e, isEntry := val.(*muxForwardEntry); isEntry {
			return matchedKey, e, true
		}
	}
	if !resolved.isDynamicPort && hasReqListenKey && s.listenEndpoints != nil {
		candEntry := s.listenEndpoints[reqListenKey].cancelCandidateEntry()
		if matchesMuxForwardCancelTarget(candEntry, req.FwdType, normConnectHost, req.ConnectPort) {
			if candEntry.forwardKey != "" {
				matchedKey = candEntry.forwardKey
			}
			return matchedKey, candEntry, true
		}
	}
	if resolved.isDynamicPort {
		s.forwards.Range(func(k, v any) bool {
			ks, isStr := k.(string)
			e, isEntry := v.(*muxForwardEntry)
			if isStr && isEntry && e.dynamicAlloc &&
				(e.keyHost == resolved.keyHost || e.endpointHost == resolved.endpointHost) &&
				matchesMuxForwardCancelTarget(e, req.FwdType, normConnectHost, req.ConnectPort) {
				matchedKey = ks
				entry = e
				ok = true
				return false
			}
			return true
		})
	}
	return matchedKey, entry, ok
}

func (s *MuxServer) beginEndpointCloseBarrierLocked(entry *muxForwardEntry) (
	closingSlot *muxForwardEndpointState,
	inFlightCur *muxForwardEndpointState,
	closingWaitDone chan struct{},
) {
	if entry == nil || !entry.hasListenKey {
		return nil, nil, nil
	}
	if s.listenEndpoints == nil {
		s.listenEndpoints = make(map[forwardListenKey]*muxForwardEndpointState)
	}
	cur := s.listenEndpoints[entry.listenKey]
	if cur != nil {
		if cur.entry == entry {
			cur.entry = nil
		}
		if cur.fallbackEntry == entry {
			cur.fallbackEntry = nil
		}
		if !cur.closing && (cur.inFlight || cur.entry != nil || cur.fallbackEntry != nil) {
			closingWaitDone = make(chan struct{})
			cur.closingWait = closingWaitDone
			return nil, cur, closingWaitDone
		}
	}
	closingSlot = &muxForwardEndpointState{
		inFlight: true,
		closing:  true,
		done:     make(chan struct{}),
	}
	s.listenEndpoints[entry.listenKey] = closingSlot
	return closingSlot, nil, nil
}

func (s *MuxServer) finishEndpointCloseBarrierLocked(
	entry *muxForwardEntry,
	closingSlot *muxForwardEndpointState,
	inFlightCur *muxForwardEndpointState,
	closingWaitDone chan struct{},
) {
	if closingSlot != nil && entry != nil {
		s.releaseInFlightEndpointSlotLocked(entry.listenKey, closingSlot)
	}
	if closingWaitDone != nil {
		if inFlightCur != nil && inFlightCur.closingWait == closingWaitDone {
			inFlightCur.closingWait = nil
			if entry != nil && !inFlightCur.inFlight && inFlightCur.entry == nil && inFlightCur.fallbackEntry == nil &&
				s.listenEndpoints != nil && s.listenEndpoints[entry.listenKey] == inFlightCur {
				delete(s.listenEndpoints, entry.listenKey)
			}
		}
		close(closingWaitDone)
		s.notifyIdleLocked()
	}
}

func (s *MuxServer) waitClosingEndpointLocked(listenKey forwardListenKey) (waited bool, aborted bool) {
	if s.listenEndpoints == nil {
		return false, false
	}
	cur := s.listenEndpoints[listenKey]
	if cur == nil {
		return false, false
	}
	var waitCh chan struct{}
	switch {
	case cur.closingWait != nil:
		waitCh = cur.closingWait
	case cur.closing:
		waitCh = cur.done
	default:
		return false, false
	}
	s.idleMu.Unlock()
	select {
	case <-waitCh:
		return true, false
	case <-s.baseContext().Done():
		return true, true
	}
}

func (s *MuxServer) handleCloseFwd(conn net.Conn, req MuxFwdRequest) error {
	s.idleMu.Lock()
	if s.shuttingDown || s.closed.Load() {
		s.idleMu.Unlock()
		return sendFailure(conn, req.RequestID, "mux master is shutting down")
	}
	s.closeFwdsInFlight++
	s.idleGen++
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	s.idleMu.Unlock()

	defer func() {
		s.idleMu.Lock()
		s.closeFwdsInFlight--
		s.scheduleIdleOrShutdownLocked()
		s.notifyIdleLocked()
		s.idleMu.Unlock()
	}()

	normListenHost, normConnectHost, err := validateAndNormalizeMuxFwdSpec(
		req.FwdType, req.ListenHost, req.ListenPort, req.ConnectHost, req.ConnectPort,
	)
	if err != nil {
		return sendFailure(conn, req.RequestID, err.Error())
	}
	resolved, err := s.resolveMuxForwardListenSpec(req.FwdType, normListenHost, req.ListenPort)
	if err != nil {
		return sendFailure(conn, req.RequestID, err.Error())
	}
	key := forwardKey(req.FwdType, resolved.keyHost, req.ListenPort, normConnectHost, req.ConnectPort)
	reqListenKey, hasReqListenKey := makeForwardListenKey(req.FwdType, resolved)

	for {
		s.idleMu.Lock()
		if s.shuttingDown || s.closed.Load() {
			s.idleMu.Unlock()
			return sendFailure(conn, req.RequestID, "mux master is shutting down")
		}
		if hasReqListenKey {
			if waited, aborted := s.waitClosingEndpointLocked(reqListenKey); waited {
				if aborted {
					return sendFailure(conn, req.RequestID, "mux master is shutting down")
				}
				continue
			}
		}

		matchedKey, entry, ok := s.lookupCloseFwdTargetLocked(
			key, req, resolved, reqListenKey, hasReqListenKey, normConnectHost,
		)
		if !ok {
			s.idleMu.Unlock()
			return sendFailure(conn, req.RequestID, "forwarding not found")
		}
		if entry.hasListenKey {
			if waited, aborted := s.waitClosingEndpointLocked(entry.listenKey); waited {
				if aborted {
					return sendFailure(conn, req.RequestID, "mux master is shutting down")
				}
				continue
			}
		}

		entry.refs--
		if entry.refs > 0 {
			s.idleMu.Unlock()
			return sendOk(conn, req.RequestID)
		}

		s.forwards.Delete(matchedKey)
		shadows := entry.takeShadowClosers()
		closingSlot, inFlightCur, closingWaitDone := s.beginEndpointCloseBarrierLocked(entry)
		s.idleMu.Unlock()

		s.closeMuxForwardEntryWithShadows(entry, shadows)

		s.idleMu.Lock()
		s.finishEndpointCloseBarrierLocked(entry, closingSlot, inFlightCur, closingWaitDone)
		s.idleMu.Unlock()

		return sendOk(conn, req.RequestID)
	}
}

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

func (s *MuxServer) canAdmitNewSession() bool {
	if s == nil {
		return false
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	return !s.shuttingDown && !s.terminated && !s.closed.Load() && !s.stoppedListening.Load() && !s.handoffReserved
}

func (s *MuxServer) addActiveSession() bool {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()

	if s.shuttingDown || s.terminated || s.closed.Load() || s.stoppedListening.Load() || s.handoffReserved {
		return false
	}

	s.activeSessions.Add(1)
	s.hadActiveSession = true
	s.idleGen++
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	return true
}

func (s *MuxServer) addActiveForwardStream() bool {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()

	if s.shuttingDown || s.closed.Load() {
		return false
	}
	s.activeForwardStreams.Add(1)
	s.idleGen++
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	return true
}

func (s *MuxServer) removeActiveForwardStream() {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()

	newStreams := s.activeForwardStreams.Add(-1)
	s.notifyIdleLocked()
	if newStreams <= 0 && s.activeSessions.Load() <= 0 {
		s.scheduleIdleOrShutdownLocked()
	}
}

func (s *MuxServer) removeActiveSession() {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()

	newCount := s.activeSessions.Add(-1)
	s.notifyIdleLocked()
	if newCount <= 0 && s.activeForwardStreams.Load() <= 0 {
		s.scheduleIdleOrShutdownLocked()
	}
}

func (s *MuxServer) scheduleIdleOrShutdownLocked() {
	if s.shuttingDown || s.handoffReserved || s.closed.Load() {
		return
	}
	if s.activeSessions.Load() > 0 || s.activeForwardStreams.Load() > 0 || s.hasInFlightControlOrForwardLocked() {
		return
	}

	if s.stoppedListening.Load() {
		s.shuttingDown = true
		go func() { _ = s.Shutdown() }()
		return
	}

	if s.persistEnabled && !s.persistIndefinite && s.persistDuration > 0 {
		if s.idleTimer != nil {
			s.idleTimer.Stop()
		}
		s.idleGen++
		gen := s.idleGen
		s.idleTimer = time.AfterFunc(s.persistDuration, func() {
			s.onIdleTimeout(gen)
		})
	} else if !s.persistEnabled && s.hadActiveSession {
		s.shuttingDown = true
		go func() { _ = s.Shutdown() }()
	}
}

func (s *MuxServer) onIdleTimeout(gen uint64) {
	s.idleMu.Lock()
	if s.idleGen != gen {
		s.idleMu.Unlock()
		return
	}

	if s.activeSessions.Load() > 0 || s.activeForwardStreams.Load() > 0 || s.hasInFlightControlOrForwardLocked() {
		s.idleMu.Unlock()
		return
	}

	if s.shuttingDown || s.closed.Load() {
		s.idleMu.Unlock()
		return
	}

	s.shuttingDown = true
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	s.idleMu.Unlock()

	_ = s.Shutdown()
}

// Shutdown gracefully closes the server, listeners, active forwards, and SSH connections.
func (s *MuxServer) Shutdown() error {
	s.shutdownOnce.Do(func() {
		if s.serverCancel != nil {
			s.serverCancel()
		}
		s.closed.Store(true)

		s.idleMu.Lock()
		s.shuttingDown = true
		s.terminated = true
		s.handoffReserved = false
		s.idleGen++
		if s.idleTimer != nil {
			s.idleTimer.Stop()
			s.idleTimer = nil
		}
		s.idleMu.Unlock()

		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.unlinkControlSocketIfOurs()

		var remoteEntries []*muxForwardEntry
		s.forwards.Range(func(key, val any) bool {
			if entry, ok := val.(*muxForwardEntry); ok && entry.closer != nil {
				if entry.remote {
					remoteEntries = append(remoteEntries, entry)
				} else {
					_ = entry.closer.Close()
					for _, sc := range s.takeShadowClosers(entry) {
						if sc != nil {
							_ = sc.Close()
						}
					}
				}
			} else if closer, ok := val.(io.Closer); ok {
				_ = closer.Close()
			}
			return true
		})

		s.liveStreams.Range(func(key, _ any) bool {
			if conn, ok := key.(net.Conn); ok {
				_ = conn.Close()
			}
			return true
		})

		if s.sshClient != nil && s.sshClient.Conn != nil {
			_ = s.sshClient.Close()
		}
		if s.rootConn != nil {
			_ = s.rootConn.Close()
		}
		for _, entry := range remoteEntries {
			_ = entry.closer.Close()
			for _, sc := range s.takeShadowClosers(entry) {
				if sc != nil {
					_ = sc.Close()
				}
			}
		}

		activeMuxServers.CompareAndDelete(s.controlPath, s)
		if s.shutdownChan != nil {
			close(s.shutdownChan)
		}
	})
	return nil
}

// unlinkControlSocketIfOurs removes the control socket only when the path still
// refers to the socket this server created. After -O stop or a replacement, a
// newer master may own the same path and must not lose its listener entry.
func (s *MuxServer) unlinkControlSocketIfOurs() {
	if s.stoppedListening.Load() {
		return
	}
	s.unlinkControlSocketFileIfOurs()
}

func (s *MuxServer) unlinkControlSocketFileIfOurs() {
	if s.controlPath == "" {
		return
	}
	if s.origFi != nil {
		if current, err := os.Lstat(s.controlPath); err != nil || !os.SameFile(s.origFi, current) {
			return
		}
	}
	_ = os.Remove(s.controlPath)
}

// AddForegroundSession adds an active in-process foreground session to prevent idle timeout.
func (s *MuxServer) AddForegroundSession() bool {
	if !s.addActiveSession() {
		return false
	}
	s.idleMu.Lock()
	s.foregroundReleasedByStop = false
	s.idleMu.Unlock()
	return true
}

// RemoveForegroundSession removes an in-process foreground session and arms the idle timer if sessions reach 0.
func (s *MuxServer) RemoveForegroundSession() {
	if s == nil {
		return
	}
	s.idleMu.Lock()
	alreadyReleased := s.foregroundReleasedByStop
	s.releaseForegroundOnStop = false
	s.foregroundReleasedByStop = false
	s.idleMu.Unlock()
	if alreadyReleased {
		return
	}
	s.removeActiveSession()
}

// ReleaseForegroundOnStop marks the master's initial foreground session
// reference (held by a -N process) to be dropped when -O stop arrives, so the
// master retires once any remaining client sessions drain.
func (s *MuxServer) ReleaseForegroundOnStop() {
	if s == nil {
		return
	}
	s.idleMu.Lock()
	alreadyStopped := s.stoppedListening.Load() && !s.foregroundReleasedByStop
	if alreadyStopped {
		s.releaseForegroundOnStop = false
		s.foregroundReleasedByStop = true
	} else {
		s.releaseForegroundOnStop = true
		s.foregroundReleasedByStop = false
	}
	s.idleMu.Unlock()
	if alreadyStopped {
		s.removeActiveSession()
	}
}

func (s *MuxServer) releaseForegroundOnStopIfArmed() bool {
	if s == nil {
		return false
	}
	s.idleMu.Lock()
	shouldRelease := s.releaseForegroundOnStop && !s.foregroundReleasedByStop
	if shouldRelease {
		s.releaseForegroundOnStop = false
		s.foregroundReleasedByStop = true
	}
	s.idleMu.Unlock()
	if shouldRelease {
		s.removeActiveSession()
	}
	return shouldRelease
}

// ActiveSessions returns the current number of active multiplex sessions.
func (s *MuxServer) ActiveSessions() int32 {
	return s.activeSessions.Load()
}

// Wait returns a channel that is closed when the server shuts down.
func (s *MuxServer) Wait() <-chan struct{} {
	return s.shutdownChan
}

// ControlPath returns the active control socket path.
func (s *MuxServer) ControlPath() string {
	return s.controlPath
}

// Helper functions for sending MUX server responses.

func sendOk(conn io.Writer, reqID uint32) error {
	return WriteMuxPacket(conn, MUX_S_OK, EncodeMuxClientRequestID(reqID))
}

func sendFailure(conn io.Writer, reqID uint32, reason string) error {
	return WriteMuxPacket(conn, MUX_S_FAILURE, EncodeMuxError(reqID, reason))
}

func sendPermissionDenied(conn io.Writer, reqID uint32, reason string) error {
	return WriteMuxPacket(conn, MUX_S_PERMISSION_DENIED, EncodeMuxError(reqID, reason))
}

func sendAlive(conn io.Writer, reqID uint32, pid uint32) error {
	return WriteMuxPacket(conn, MUX_S_ALIVE, EncodeMuxAlive(reqID, pid))
}

func sendProxy(conn io.Writer, reqID uint32) error {
	return WriteMuxPacket(conn, MUX_S_PROXY, EncodeMuxClientRequestID(reqID))
}

func sendRemotePort(conn io.Writer, reqID uint32, port uint32) error {
	return WriteMuxPacket(conn, MUX_S_REMOTE_PORT, EncodeMuxRemotePort(reqID, port))
}

func sendSessionOpened(conn io.Writer, reqID uint32, sessionID uint32) error {
	return WriteMuxPacket(conn, MUX_S_SESSION_OPENED, EncodeMuxSessionOpened(reqID, sessionID))
}

func sendExitMessage(conn io.Writer, sessionID uint32, exitValue uint32) error {
	return WriteMuxPacket(conn, MUX_S_EXIT_MESSAGE, EncodeMuxExitMessage(sessionID, exitValue))
}

func sendTTYAllocFail(conn io.Writer, sessionID uint32) error {
	return WriteMuxPacket(conn, MUX_S_TTY_ALLOC_FAIL, EncodeMuxTTYAllocFail(sessionID))
}
