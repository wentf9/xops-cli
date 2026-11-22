package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
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

type muxPhase uint8

const (
	muxPhaseRunning muxPhase = iota
	muxPhaseHandoffReserved
	muxPhaseStoppingListen
	muxPhaseShuttingDown
	muxPhaseClosed
)

// PeerCheckMode controls OS peer credential verification on accepted multiplex
// control connections. Its zero value (PeerCheckEnforce) enforces peer UID/SID
// checks on every accepted connection so callers cannot silently omit verification.
type PeerCheckMode uint8

const (
	// PeerCheckEnforce enforces OS peer credential verification on every accepted
	// control connection (zero-value safe default).
	PeerCheckEnforce PeerCheckMode = iota
	// PeerCheckDisabledForTesting explicitly disables peer credential checks.
	// Use ONLY for synthetic in-memory tests (e.g. net.Pipe) that bypass OS sockets.
	PeerCheckDisabledForTesting
)

// MuxServerOptions configures the multiplex master server.
type MuxServerOptions struct {
	ControlPath       string
	ExpectedUID       uint32
	HasExpectedUID    bool
	PeerCheck         PeerCheckMode
	CheckPeerUID      bool // Retained for API compatibility; PeerCheck controls enforcement (zero-value enforces).
	PersistEnabled    bool
	PersistDuration   time.Duration
	PersistIndefinite bool
	// ConfirmSession authorizes a proxy session, passenger session, or forwarding
	// request on an ask/autoask master. Nil rejects every such request.
	ConfirmSession         func(action string) bool
	AskConfirmation        bool
	SSHClient              *cryptoSSH.Client
	RootConn               net.Conn      // Optional underlying conn to close on Shutdown
	PhysicalRootConn       net.Conn      // Optional outermost physical transport fallback for ProxyJump masters
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
	physicalRoot      net.Conn

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

	listener net.Listener
	target   TargetContext

	// All mutable server lifecycle, work counters, foreground ownership state,
	// idle timer state, and forwarding tables are serialized by idleMu.
	idleMu                        sync.Mutex
	phase                         muxPhase
	stoppedListening              bool
	foregroundHeld                int32
	extraForegroundHeld           int32
	foregroundStopArmed           bool
	stopReleasedInitialForeground bool
	stopConsumedForeground        int32
	hadActiveSession              bool
	activeSessions                int32
	activeForwardStreams          int32
	stopRepliesInFlight           int
	sessionOpensInFlight          int
	openFwdsInFlight              int
	closeFwdsInFlight             int
	idleTimer                     *time.Timer
	idleGen                       uint64
	idleNotify                    chan struct{}
	forwardTable                  muxForwardTable

	shutdownOnce       sync.Once
	shutdownChan       chan struct{}
	transportCloseOnce sync.Once
	transportCloseErr  error
	slot               *fsx.SocketSlot
	slotReleaseOnce    sync.Once
	askConfirmation    bool
	confirmSession     func(action string) bool

	serverCtx    context.Context
	serverCancel context.CancelFunc

	// streamsMu serializes liveLocalStreams, liveRemoteStreams, and streamsClosed.
	// It is a strict leaf lock (never held across I/O or idleMu).
	// liveLocalStreams tracks local accepted/dialed sockets (mux control/proxy/
	// passenger sockets, -L/-D client sockets, and -R local destination sockets).
	// liveRemoteStreams tracks raw SSH channel streams opened on s.sshClient
	// (-L/-D direct-* and -R forwarded-* channels). Shutdown closes the SSH
	// transport via closeTransportBounded() BEFORE draining and closing either
	// set so neither remote.Close() nor pipeBidirectional -> remote.CloseWrite()
	// can block on a write-wedged direct or ProxyJump SSH transport.
	streamsMu         sync.Mutex
	streamsClosed     bool
	liveLocalStreams  map[net.Conn]struct{}
	liveRemoteStreams map[net.Conn]struct{}
}

// NewMuxServer creates and binds a new OpenSSH multiplex master server.
func NewMuxServer(opts MuxServerOptions) (*MuxServer, error) {
	if strings.TrimSpace(opts.ControlPath) == "" || IsNoneValue(opts.ControlPath) {
		return nil, fmt.Errorf("control path cannot be empty or none")
	}
	if opts.SSHClient == nil {
		return nil, fmt.Errorf("ssh client cannot be nil")
	}

	var checkPeer bool
	switch opts.PeerCheck {
	case PeerCheckEnforce:
		checkPeer = true
	case PeerCheckDisabledForTesting:
		checkPeer = false
	default:
		return nil, fmt.Errorf("invalid peer check mode: %d", opts.PeerCheck)
	}

	expectedUID := opts.ExpectedUID
	if checkPeer && !opts.HasExpectedUID && opts.ExpectedUID == 0 {
		expectedUID = localPeerUID()
	}

	slot, err := bindAndLinkSocket(opts.ControlPath)
	if err != nil {
		return nil, err
	}

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
		expectedUID:           expectedUID,
		checkPeerUID:          checkPeer,
		persistEnabled:        opts.PersistEnabled,
		persistDuration:       opts.PersistDuration,
		persistIndefinite:     opts.PersistIndefinite,
		sshClient:             opts.SSHClient,
		rootConn:              opts.RootConn,
		physicalRoot:          opts.PhysicalRootConn,
		listener:              slot.Listener(),
		slot:                  slot,
		shutdownChan:          make(chan struct{}),
		idleNotify:            make(chan struct{}),
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
		server.activeSessions = opts.InitialActiveSessions
		server.foregroundHeld = opts.InitialActiveSessions
		server.hadActiveSession = true
	} else {
		server.idleMu.Lock()
		server.onWorkCountChangedLocked()
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
	Path             string
	Target           TargetContext
	Environment      Environment
	RootConn         net.Conn
	PhysicalRootConn net.Conn
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

	var persistEnabled, persistIndefinite bool
	var persistDuration time.Duration
	if target.Control != nil && target.Control.Persist != "" {
		if setting, err := ParsePersistSetting(target.Control.Persist); err == nil {
			persistEnabled = setting.Enabled()
			persistIndefinite = setting.Indefinite()
			persistDuration = setting.Duration
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
	var agentSocket string
	expandAgentTilde := false
	if opts.AgentSocket != "" {
		if hasControlOrLineSepChar(opts.AgentSocket) {
			return nil, fmt.Errorf("invalid AgentSocket %q: contains invalid control character", opts.AgentSocket)
		}
		agentSocket = strings.TrimSpace(opts.AgentSocket)
	}
	if agentSocket == "" && opts.AllowAgentForward && env.AgentSocket != "" {
		if hasControlOrLineSepChar(env.AgentSocket) {
			return nil, fmt.Errorf("invalid AgentSocket %q: contains invalid control character", env.AgentSocket)
		}
		agentSocket = strings.TrimSpace(env.AgentSocket)
		expandAgentTilde = true
	}
	if agentSocket != "" {
		agentSocket = normalizeExpandedAgentSocketPathWithTilde(agentSocket, env, expandAgentTilde)
	}

	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:            opts.Path,
		ExpectedUID:            expectedUID,
		HasExpectedUID:         true,
		PeerCheck:              PeerCheckEnforce,
		PersistEnabled:         persistEnabled,
		PersistDuration:        persistDuration,
		PersistIndefinite:      persistIndefinite,
		SSHClient:              sshClient,
		RootConn:               opts.RootConn,
		PhysicalRootConn:       opts.PhysicalRootConn,
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

func (s *MuxServer) getLogger() logger.DebugLogger {
	if s == nil || s.logger == nil {
		return logger.NopLogger
	}
	return s.logger
}

func (s *MuxServer) baseContext() context.Context {
	if s != nil && s.serverCtx != nil {
		return s.serverCtx
	}
	return context.Background()
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

func (s *MuxServer) isShuttingDownLocked() bool {
	return s.phase == muxPhaseHandoffReserved || s.phase == muxPhaseShuttingDown || s.phase == muxPhaseClosed
}

// isShuttingDown reports whether this master already committed to shutting down
// (or is currently held in a handoff reservation).
func (s *MuxServer) isShuttingDown() bool {
	if s == nil {
		return true
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	return s.isShuttingDownLocked()
}

func (s *MuxServer) isClosedOrStoppedListening() bool {
	if s == nil {
		return true
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	return s.phase == muxPhaseClosed || s.stoppedListening
}

func (s *MuxServer) disarmIdleTimerLocked() {
	s.idleGen++
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
}

func (s *MuxServer) markStoppedListeningLocked() bool {
	if s.stoppedListening {
		return false
	}
	s.stoppedListening = true
	if s.phase == muxPhaseRunning {
		s.phase = muxPhaseStoppingListen
	}
	s.notifyIdleLocked()
	return true
}

func (s *MuxServer) canAdmitNewWorkLocked() bool {
	return s.phase == muxPhaseRunning && !s.stoppedListening
}

func (s *MuxServer) hasInFlightControlOrForwardLocked() bool {
	return s.stopRepliesInFlight > 0 ||
		s.sessionOpensInFlight > 0 ||
		s.openFwdsInFlight > 0 ||
		s.closeFwdsInFlight > 0 ||
		s.forwardTable.hasInFlightEndpointsLocked()
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
	if s.phase != muxPhaseRunning || s.stoppedListening || s.hasInFlightControlOrForwardLocked() || s.activeSessions > maxSessions {
		return false
	}
	if s.forwardTable.entryCountLocked() > 0 || s.forwardTable.endpointCountLocked() > 0 || s.activeForwardStreams > 0 {
		return false
	}
	s.phase = muxPhaseHandoffReserved
	s.disarmIdleTimerLocked()
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
	return s.phase == muxPhaseHandoffReserved && !s.stoppedListening
}

// CancelHandoff releases a reservation made by PrepareHandoff when a multi-hop
// handoff could not reserve every master in the chain.
func (s *MuxServer) CancelHandoff() {
	if s == nil {
		return
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.phase != muxPhaseHandoffReserved {
		return
	}
	if s.stoppedListening {
		s.phase = muxPhaseStoppingListen
	} else {
		s.phase = muxPhaseRunning
	}
	s.onWorkCountChangedLocked()
}

// StoppedListening reports whether -O stop has unlinked the control socket.
func (s *MuxServer) StoppedListening() bool {
	if s == nil {
		return false
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	return s.stoppedListening
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
		ready := s.phase != muxPhaseRunning || s.stoppedListening ||
			(s.activeSessions <= maxSessions &&
				!s.hasInFlightControlOrForwardLocked() &&
				s.forwardTable.entryCountLocked() == 0 &&
				s.forwardTable.endpointCountLocked() == 0 &&
				s.activeForwardStreams == 0)
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

// Serve enters the client connection accept loop.
func (s *MuxServer) Serve() error {
	type deadliner interface {
		SetDeadline(t time.Time) error
	}
	dl, hasDeadline := s.listener.(deadliner)

	for {
		if hasDeadline && !s.isClosedOrStoppedListening() {
			_ = dl.SetDeadline(time.Now().Add(50 * time.Millisecond))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if s.isClosedOrStoppedListening() {
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
				} else if origFi := s.socketFileInfo(); origFi != nil && !os.SameFile(origFi, currFi) {
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
	firstStop, releaseStop := s.admitStopListening()
	defer releaseStop()

	s.releaseControlSocketSlot()
	if firstStop {
		activeMuxServers.CompareAndDelete(s.controlPath, s)
	}
}

func (s *MuxServer) handleClient(conn net.Conn) {
	s.trackLocalStream(conn)
	defer func() {
		_ = conn.Close()
		s.untrackLocalStream(conn)
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
			s.controlPath, targetLine, os.Getpid(), s.ActiveSessions())
	case "channels":
		s.idleMu.Lock()
		keys := s.forwardTable.listForwardKeysLocked()
		s.idleMu.Unlock()

		var b strings.Builder
		b.WriteString("Active Forwardings:\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "- %s\n", k)
		}
		if len(keys) == 0 {
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
	s.idleMu.Lock()
	_ = s.markStoppedListeningLocked()
	if s.phase != muxPhaseClosed {
		s.phase = muxPhaseShuttingDown
	}
	s.disarmIdleTimerLocked()
	s.notifyIdleLocked()
	s.idleMu.Unlock()

	// Unconditionally synchronize on slot release so every concurrent -O exit
	// observes the control socket unlinked before receiving MUX_S_OK.
	s.releaseControlSocketSlot()
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
	_, releaseStop := s.admitStopListening()
	defer releaseStop()

	// Unconditionally synchronize on slot release so every concurrent -O stop
	// observes the control socket unlinked before receiving MUX_S_OK.
	s.releaseControlSocketSlot()
	return sendOk(conn, reqID)
}

func (s *MuxServer) handleProxy(conn net.Conn, reqID uint32) error {
	ticket, ok := s.admitSessionOpen()
	if !ok {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	defer ticket.Abort()

	if err := s.authorize("proxy session"); err != nil {
		return sendPermissionDenied(conn, reqID, err.Error())
	}
	releaseSession, ok := ticket.Promote()
	if !ok {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	defer releaseSession()

	if err := sendProxy(conn, reqID); err != nil {
		return err
	}

	s.trackLocalStream(conn)
	defer s.untrackLocalStream(conn)

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

func (s *MuxServer) canAdmitNewSession() bool {
	if s == nil {
		return false
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	return s.canAdmitNewWorkLocked()
}

type muxWorkKind uint8

const (
	muxWorkSessionOpen muxWorkKind = iota + 1
	muxWorkOpenForward
	muxWorkCloseForward
	muxWorkStopReply
)

func (s *MuxServer) enterMuxWorkLocked(kind muxWorkKind) (firstStop bool, ok bool) {
	switch kind {
	case muxWorkSessionOpen:
		if !s.canAdmitNewWorkLocked() {
			return false, false
		}
		s.sessionOpensInFlight++
		s.disarmIdleTimerLocked()
		return false, true
	case muxWorkOpenForward:
		if !s.canAdmitNewWorkLocked() {
			return false, false
		}
		s.openFwdsInFlight++
		s.disarmIdleTimerLocked()
		return false, true
	case muxWorkCloseForward:
		if s.isShuttingDownLocked() {
			return false, false
		}
		s.closeFwdsInFlight++
		s.disarmIdleTimerLocked()
		return false, true
	case muxWorkStopReply:
		s.stopRepliesInFlight++
		firstStop = s.markStoppedListeningLocked()
		s.disarmIdleTimerLocked()
		return firstStop, true
	default:
		return false, false
	}
}

func (s *MuxServer) releaseMuxWorkLocked(kind muxWorkKind) {
	switch kind {
	case muxWorkSessionOpen:
		if s.sessionOpensInFlight > 0 {
			s.sessionOpensInFlight--
		}
	case muxWorkOpenForward:
		if s.openFwdsInFlight > 0 {
			s.openFwdsInFlight--
		}
	case muxWorkCloseForward:
		if s.closeFwdsInFlight > 0 {
			s.closeFwdsInFlight--
		}
	case muxWorkStopReply:
		if s.stopRepliesInFlight > 0 {
			s.stopRepliesInFlight--
		}
		s.releaseForegroundOnStopIfArmedLocked()
	default:
		return
	}
	s.onWorkCountChangedLocked()
}

// admitMuxWork atomically checks lifecycle phase admission for kind, increments
// its in-flight counter, disarms any armed idle timer, and returns an idempotent
// release callback that decrements the counter and advances the lifecycle FSM.
func (s *MuxServer) admitMuxWork(kind muxWorkKind) (release func(), ok bool) {
	if s == nil {
		return func() {}, false
	}
	s.idleMu.Lock()
	_, ok = s.enterMuxWorkLocked(kind)
	s.idleMu.Unlock()
	if !ok {
		return func() {}, false
	}
	return sync.OnceFunc(func() {
		s.idleMu.Lock()
		defer s.idleMu.Unlock()
		s.releaseMuxWorkLocked(kind)
	}), true
}

// admitStopListening records an in-flight -O stop (or listener retirement),
// transitions Running -> StoppingListen on the first caller, and returns an
// idempotent release callback that drops stopRepliesInFlight, consumes any
// armed foreground stop release, and triggers idle/drain evaluation.
func (s *MuxServer) admitStopListening() (firstStop bool, release func()) {
	if s == nil {
		return false, func() {}
	}
	s.idleMu.Lock()
	firstStop, _ = s.enterMuxWorkLocked(muxWorkStopReply)
	s.idleMu.Unlock()
	return firstStop, sync.OnceFunc(func() {
		s.idleMu.Lock()
		defer s.idleMu.Unlock()
		s.releaseMuxWorkLocked(muxWorkStopReply)
	})
}

type muxSessionTicketState uint8

const (
	muxTicketOpen muxSessionTicketState = iota
	muxTicketPromoted
	muxTicketAborted
)

// muxSessionTicket tracks an admitted in-flight session open (proxy, passenger
// session, or passenger stdio forward). Callers defer ticket.Abort() and call
// ticket.Promote() once authorization and FD/request setup succeed; both
// transitions are serialized under server.idleMu and idempotent.
type muxSessionTicket struct {
	server *MuxServer
	state  muxSessionTicketState
}

// admitSessionOpen atomically verifies that the master accepts new sessions,
// tracks the admission in sessionOpensInFlight, and disarms the ControlPersist
// idle timer so authorize / recvFiles cannot race with onIdleTimeout.
func (s *MuxServer) admitSessionOpen() (*muxSessionTicket, bool) {
	if s == nil {
		return nil, false
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if _, ok := s.enterMuxWorkLocked(muxWorkSessionOpen); !ok {
		return nil, false
	}
	return &muxSessionTicket{server: s, state: muxTicketOpen}, true
}

// Promote atomically converts an in-flight session admission into an active
// session under idleMu and returns an idempotent release function. When
// admission is rejected (e.g. -O stop, handoff, or shutdown raced with
// authorize/recvFiles), the ticket remains open so the caller's deferred Abort
// releases the in-flight slot only after the rejection reply is written.
func (t *muxSessionTicket) Promote() (releaseSession func(), ok bool) {
	if t == nil || t.server == nil {
		return func() {}, false
	}
	s := t.server
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if t.state != muxTicketOpen || !s.canAdmitNewWorkLocked() {
		return func() {}, false
	}
	t.state = muxTicketPromoted
	if s.sessionOpensInFlight > 0 {
		s.sessionOpensInFlight--
	}
	s.activeSessions++
	s.hadActiveSession = true
	s.disarmIdleTimerLocked()
	return sync.OnceFunc(s.removeActiveSession), true
}

// Abort idempotently releases an unpromoted session admission ticket. Once
// Promote has succeeded (or Abort has already run), Abort is a safe no-op.
func (t *muxSessionTicket) Abort() {
	if t == nil || t.server == nil {
		return
	}
	s := t.server
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if t.state != muxTicketOpen {
		return
	}
	t.state = muxTicketAborted
	s.releaseMuxWorkLocked(muxWorkSessionOpen)
}

func (s *MuxServer) addActiveSession() bool {
	if s == nil {
		return false
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()

	if !s.canAdmitNewWorkLocked() {
		return false
	}

	s.activeSessions++
	s.hadActiveSession = true
	s.disarmIdleTimerLocked()
	return true
}

func (s *MuxServer) addActiveForwardStream() bool {
	if s == nil {
		return false
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()

	if s.isShuttingDownLocked() {
		return false
	}
	s.activeForwardStreams++
	s.disarmIdleTimerLocked()
	return true
}

func (s *MuxServer) removeActiveForwardStream() {
	if s == nil {
		return
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()

	s.activeForwardStreams--
	s.onWorkCountChangedLocked()
}

func (s *MuxServer) removeActiveSession() {
	if s == nil {
		return
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()

	s.activeSessions--
	s.onWorkCountChangedLocked()
}

// onWorkCountChangedLocked is the single lifecycle transition exit after any
// session, forward stream, handoff release, or in-flight control operation changes.
func (s *MuxServer) onWorkCountChangedLocked() {
	s.notifyIdleLocked()
	if s.phase == muxPhaseHandoffReserved || s.phase == muxPhaseShuttingDown || s.phase == muxPhaseClosed {
		return
	}
	if s.activeSessions > 0 || s.activeForwardStreams > 0 || s.hasInFlightControlOrForwardLocked() {
		return
	}

	if s.phase == muxPhaseStoppingListen {
		s.phase = muxPhaseShuttingDown
		s.disarmIdleTimerLocked()
		go func() { _ = s.Shutdown() }()
		return
	}

	if s.persistEnabled && !s.persistIndefinite && s.persistDuration > 0 {
		s.disarmIdleTimerLocked()
		gen := s.idleGen
		s.idleTimer = time.AfterFunc(s.persistDuration, func() {
			s.onIdleTimeout(gen)
		})
	} else if !s.persistEnabled && s.hadActiveSession {
		s.phase = muxPhaseShuttingDown
		s.disarmIdleTimerLocked()
		go func() { _ = s.Shutdown() }()
	}
}

func (s *MuxServer) onIdleTimeout(gen uint64) {
	s.idleMu.Lock()
	if s.idleGen != gen || s.phase != muxPhaseRunning {
		s.idleMu.Unlock()
		return
	}

	if s.activeSessions > 0 || s.activeForwardStreams > 0 || s.hasInFlightControlOrForwardLocked() {
		s.idleMu.Unlock()
		return
	}

	s.phase = muxPhaseShuttingDown
	s.disarmIdleTimerLocked()
	s.notifyIdleLocked()
	s.idleMu.Unlock()

	_ = s.Shutdown()
}

func closeShutdownForwardItem(item shutdownForwardItem) {
	if item.entry != nil && item.entry.closer != nil {
		_ = item.entry.closer.Close()
	}
	for _, sc := range item.shadows {
		if sc != nil {
			_ = sc.Close()
		}
	}
}

// beginShutdown stops accepting new mux connections, unlinks the control
// socket, cancels serverCtx, and removes the server from activeMuxServers
// without performing any blocking SSH transport I/O. Safe to call before
// Shutdown() so Connector.CloseAll can abort physical root transports first.
func (s *MuxServer) beginShutdown() {
	if s == nil {
		return
	}
	if s.serverCancel != nil {
		s.serverCancel()
	}
	s.idleMu.Lock()
	if s.phase != muxPhaseClosed {
		s.phase = muxPhaseShuttingDown
	}
	s.disarmIdleTimerLocked()
	s.notifyIdleLocked()
	s.idleMu.Unlock()

	s.releaseControlSocketSlot()
	activeMuxServers.CompareAndDelete(s.controlPath, s)
}

// closeTransportBounded closes this master's SSH transport exactly once:
// closing s.rootConn before s.sshClient and bounding any multiplexed jump hop
// behind a grace timeout that escalates to s.physicalRoot if the upstream
// bastion is write-wedged or blackholed (while preserving healthy bastions).
func (s *MuxServer) closeTransportBounded() error {
	if s == nil {
		return nil
	}
	s.transportCloseOnce.Do(func() {
		var sshCli *cryptoSSH.Client
		if s.sshClient != nil && s.sshClient.Conn != nil {
			sshCli = s.sshClient
		}
		if s.rootConn == nil && sshCli == nil {
			return
		}

		hasFallback := s.physicalRoot != nil && s.physicalRoot != s.rootConn
		_, isProxyChan := s.rootConn.(*proxyChanConn)
		if !hasFallback && !isProxyChan {
			s.transportCloseErr = interruptSSHTransport(s.rootConn, sshCli)
			return
		}

		done := make(chan error, 1)
		go func() {
			done <- interruptSSHTransport(s.rootConn, sshCli)
		}()

		grace := proxyChanCloseGrace
		if grace <= 0 {
			grace = 90 * time.Millisecond
		}
		if isProxyChan {
			// Let proxyChanConn's own grace timer fire first so its upstream
			// abort hook can cleanly detach/evict a dead pooled bastion before
			// falling back to raw physicalRoot.Close().
			grace *= 2
		}
		timer := time.NewTimer(grace)
		defer timer.Stop()

		select {
		case err := <-done:
			s.transportCloseErr = err
		case <-timer.C:
			var fallbackErr error
			if hasFallback {
				fallbackErr = closeResource(s.physicalRoot, "physical root SSH transport")
			}
			s.transportCloseErr = errors.Join(fallbackErr, <-done)
		}
	})
	return s.transportCloseErr
}

// Shutdown gracefully closes the server, listeners, active forwards, and SSH connections.
func (s *MuxServer) Shutdown() error {
	if s == nil {
		return nil
	}
	s.shutdownOnce.Do(func() {
		s.idleMu.Lock()
		s.phase = muxPhaseClosed
		s.disarmIdleTimerLocked()
		s.notifyIdleLocked()
		localItems, remoteItems := s.forwardTable.snapshotAndDrainForShutdownLocked()
		s.idleMu.Unlock()

		s.beginShutdown()

		for _, item := range localItems {
			closeShutdownForwardItem(item)
		}

		// Close/abort the underlying SSH transport BEFORE closing tracked remote
		// or local streams. Once closeTransportBounded() returns, s.sshClient's
		// mux is dead/EOF (even when s.rootConn or a ProxyJump upstream
		// s.physicalRoot is write-wedged), so neither remote.Close() nor
		// pipeBidirectional -> remote.CloseWrite() triggered by closing
		// liveLocalStreams can block on SSH packet writes.
		_ = s.closeTransportBounded()

		localStreams, remoteStreams := s.drainTrackedStreams()
		for _, conn := range remoteStreams {
			_ = conn.Close()
		}
		for _, conn := range localStreams {
			_ = conn.Close()
		}

		for _, item := range remoteItems {
			closeShutdownForwardItem(item)
		}

		if s.shutdownChan != nil {
			close(s.shutdownChan)
		}
	})
	return nil
}

func (s *MuxServer) socketFileInfo() os.FileInfo {
	if s == nil || s.slot == nil {
		return nil
	}
	return s.slot.FileInfo()
}

// releaseControlSocketSlot releases the owned fsx.SocketSlot (which acquires
// the directory lock, verifies os.SameFile, unlinks the socket, releases the
// directory lock, and closes its listener) before closing any wrapped listener.
func (s *MuxServer) releaseControlSocketSlot() {
	if s == nil {
		return
	}
	s.slotReleaseOnce.Do(func() {
		if s.slot != nil {
			_ = s.slot.Release()
		}
		if s.listener != nil {
			_ = s.listener.Close()
		}
	})
}

func (s *MuxServer) interruptTransportAndShutdown() error {
	if s == nil {
		return nil
	}
	interruptErr := s.closeTransportBounded()
	_ = s.Shutdown()
	return interruptErr
}

// openBoundedMuxChannel opens an SSH channel on the master transport under a bounded
// request timeout and tears down the stalled transport if cancellation races an unresponsive peer.
func (s *MuxServer) openBoundedMuxChannel(ctx context.Context, channelType string, payload []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if s == nil || s.sshClient == nil || s.sshClient.Conn == nil {
		return nil, nil, net.ErrClosed
	}
	if ctx == nil {
		ctx = s.baseContext()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	work, cancel := withTimeoutOrDefault(ctx, s.requestTimeout, defaultSSHHandshakeTimeout)
	defer cancel()

	result := make(chan openChannelResult, 1)
	go func() {
		ch, reqs, err := s.sshClient.OpenChannel(channelType, payload)
		result <- openChannelResult{channel: ch, requests: reqs, err: err}
	}()

	select {
	case opened := <-result:
		if opened.err != nil {
			return nil, nil, opened.err
		}
		if ctxErr := work.Err(); ctxErr != nil {
			go discardAbortedChannelRequests(s.baseContext(), opened.requests)
			_ = s.closeMuxChannelBounded(opened.channel, nil)
			return nil, nil, ctxErr
		}
		return opened.channel, opened.requests, nil
	case <-work.Done():
		select {
		case opened := <-result:
			if opened.channel != nil {
				go discardAbortedChannelRequests(s.baseContext(), opened.requests)
				_ = s.closeMuxChannelBounded(opened.channel, nil)
			}
			return nil, nil, errors.Join(work.Err(), opened.err)
		default:
		}
		interruptErr := s.interruptTransportAndShutdown()
		opened := <-result
		if opened.channel != nil {
			go discardAbortedChannelRequests(s.baseContext(), opened.requests)
			_ = closeResource(opened.channel, "late SSH mux channel")
		}
		return nil, nil, errors.Join(work.Err(), interruptErr, opened.err)
	}
}

// closeMuxChannelBounded closes a mux channel (and optionally joins its worker drain signal)
// within sessionShutdownTimeout, escalating to transport interruption if the peer stalls.
func (s *MuxServer) closeMuxChannelBounded(ch io.Closer, workersDone <-chan struct{}) error {
	if ch == nil && workersDone == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() {
		var closeErr error
		if ch != nil {
			closeErr = closeSSHChannel(ch)
		}
		if workersDone != nil {
			<-workersDone
		}
		done <- closeErr
	}()
	timer := time.NewTimer(sessionShutdownTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		if s == nil {
			return fmt.Errorf("mux channel shutdown exceeded %s", sessionShutdownTimeout)
		}
		interruptErr := s.interruptTransportAndShutdown()
		closeErr := <-done
		return errors.Join(fmt.Errorf("mux channel shutdown exceeded %s", sessionShutdownTimeout), interruptErr, closeErr)
	}
}

// AddForegroundSession adds an active in-process foreground session to prevent idle timeout.
func (s *MuxServer) AddForegroundSession() bool {
	if s == nil {
		return false
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.phase != muxPhaseRunning || s.stoppedListening {
		return false
	}
	s.activeSessions++
	s.foregroundHeld++
	s.hadActiveSession = true
	s.disarmIdleTimerLocked()
	s.notifyIdleLocked()
	return true
}

// RemoveForegroundSession removes an in-process foreground session and arms the idle timer if sessions reach 0.
func (s *MuxServer) RemoveForegroundSession() {
	if s == nil {
		return
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.foregroundHeld > 0 {
		s.foregroundHeld--
		if s.foregroundHeld == 0 {
			s.foregroundStopArmed = false
		}
		s.activeSessions--
		s.onWorkCountChangedLocked()
		return
	}
	if s.stopConsumedForeground > 0 {
		s.stopConsumedForeground--
		s.notifyIdleLocked()
		return
	}
	s.notifyIdleLocked()
}

// AcquireForegroundSession acquires an independent, token-scoped in-process
// foreground session lease. Releasing the returned function decrements only its
// own lease and cannot collide with an initial -N foreground reference consumed
// by -O stop.
func (s *MuxServer) AcquireForegroundSession() (func(), bool) {
	if s == nil {
		return nil, false
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.phase != muxPhaseRunning || s.stoppedListening {
		return nil, false
	}
	s.extraForegroundHeld++
	s.activeSessions++
	s.hadActiveSession = true
	s.disarmIdleTimerLocked()
	s.notifyIdleLocked()
	return sync.OnceFunc(s.releaseExtraForegroundSession), true
}

func (s *MuxServer) releaseExtraForegroundSession() {
	if s == nil {
		return
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.extraForegroundHeld <= 0 {
		return
	}
	s.extraForegroundHeld--
	s.activeSessions--
	s.onWorkCountChangedLocked()
}

// ReleaseForegroundOnStop marks the master's initial foreground session
// reference (held by a -N process) to be dropped when -O stop arrives, so the
// master retires once any remaining client sessions drain.
func (s *MuxServer) ReleaseForegroundOnStop() {
	if s == nil {
		return
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.foregroundStopArmed || s.stopReleasedInitialForeground || s.foregroundHeld <= 0 {
		return
	}
	if s.stoppedListening {
		s.stopReleasedInitialForeground = true
		s.foregroundHeld--
		s.stopConsumedForeground++
		s.activeSessions--
		s.onWorkCountChangedLocked()
		return
	}
	s.foregroundStopArmed = true
}

func (s *MuxServer) releaseForegroundOnStopIfArmedLocked() bool {
	if s == nil || !s.foregroundStopArmed || s.stopReleasedInitialForeground || s.foregroundHeld <= 0 {
		if s != nil {
			s.foregroundStopArmed = false
		}
		return false
	}
	s.foregroundStopArmed = false
	s.stopReleasedInitialForeground = true
	s.foregroundHeld--
	s.stopConsumedForeground++
	s.activeSessions--
	return true
}

// ActiveSessions returns the current number of active multiplex sessions.
func (s *MuxServer) ActiveSessions() int32 {
	if s == nil {
		return 0
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	return s.activeSessions
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
