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
	openFwdsInFlight              int
	closeFwdsInFlight             int
	idleTimer                     *time.Timer
	idleGen                       uint64
	idleNotify                    chan struct{}
	forwardTable                  muxForwardTable

	shutdownOnce    sync.Once
	shutdownChan    chan struct{}
	origFi          os.FileInfo
	unlinkMu        sync.Mutex
	unlinked        bool
	askConfirmation bool
	confirmSession  func(action string) bool

	serverCtx    context.Context
	serverCancel context.CancelFunc

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

	listener, origFi, err := bindAndLinkSocket(opts.ControlPath)
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

func (s *MuxServer) isClosed() bool {
	if s == nil {
		return true
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	return s.phase == muxPhaseClosed
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

func (s *MuxServer) hasInFlightControlOrForwardLocked() bool {
	return s.stopRepliesInFlight > 0 ||
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
	s.idleMu.Lock()
	firstStop := s.markStoppedListeningLocked()
	s.idleMu.Unlock()

	if firstStop {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.unlinkMu.Lock()
		s.unlinked = true
		s.unlinkMu.Unlock()
		activeMuxServers.CompareAndDelete(s.controlPath, s)
	}

	s.idleMu.Lock()
	s.releaseForegroundOnStopIfArmedLocked()
	s.onWorkCountChangedLocked()
	s.idleMu.Unlock()
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
	firstStop := s.markStoppedListeningLocked()
	if s.phase != muxPhaseClosed {
		s.phase = muxPhaseShuttingDown
	}
	s.disarmIdleTimerLocked()
	s.notifyIdleLocked()
	s.idleMu.Unlock()

	if firstStop {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.unlinkControlSocketFileIfOurs()
	}
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
	firstStop := s.markStoppedListeningLocked()
	s.idleMu.Unlock()

	if firstStop {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.unlinkControlSocketFileIfOurs()
	}
	sendErr := sendOk(conn, reqID)

	s.idleMu.Lock()
	s.stopRepliesInFlight--
	s.releaseForegroundOnStopIfArmedLocked()
	s.onWorkCountChangedLocked()
	s.idleMu.Unlock()

	return sendErr
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

func (s *MuxServer) canAdmitNewSession() bool {
	if s == nil {
		return false
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	return s.phase == muxPhaseRunning && !s.stoppedListening
}

func (s *MuxServer) addActiveSession() bool {
	if s == nil {
		return false
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()

	if s.phase != muxPhaseRunning || s.stoppedListening {
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

// Shutdown gracefully closes the server, listeners, active forwards, and SSH connections.
func (s *MuxServer) Shutdown() error {
	s.shutdownOnce.Do(func() {
		if s.serverCancel != nil {
			s.serverCancel()
		}

		s.idleMu.Lock()
		s.phase = muxPhaseClosed
		s.disarmIdleTimerLocked()
		s.notifyIdleLocked()
		localItems, remoteItems := s.forwardTable.snapshotAndDrainForShutdownLocked()
		s.idleMu.Unlock()

		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.unlinkControlSocketFileIfOurs()

		for _, item := range localItems {
			closeShutdownForwardItem(item)
		}

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
		for _, item := range remoteItems {
			closeShutdownForwardItem(item)
		}

		activeMuxServers.CompareAndDelete(s.controlPath, s)
		if s.shutdownChan != nil {
			close(s.shutdownChan)
		}
	})
	return nil
}

// unlinkControlSocketFileIfOurs removes the control socket only when the path still
// refers to the socket this server created. After -O stop or a replacement, a
// newer master may own the same path and must not lose its listener entry.
func (s *MuxServer) unlinkControlSocketFileIfOurs() {
	if s.controlPath == "" || s.origFi == nil {
		return
	}
	s.unlinkMu.Lock()
	defer s.unlinkMu.Unlock()
	if s.unlinked {
		return
	}
	current, err := os.Lstat(s.controlPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.unlinked = true
		}
		return
	}
	if !os.SameFile(s.origFi, current) {
		s.unlinked = true
		return
	}
	if rmErr := os.Remove(s.controlPath); rmErr == nil || os.IsNotExist(rmErr) {
		s.unlinked = true
	}
}

func (s *MuxServer) interruptTransportAndShutdown() error {
	if s == nil {
		return nil
	}
	var sshCli *cryptoSSH.Client
	if s.sshClient != nil && s.sshClient.Conn != nil {
		sshCli = s.sshClient
	}
	interruptErr := interruptSSHTransport(s.rootConn, sshCli)
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

func sendSessionOpened(conn io.Writer, reqID uint32, sessionID uint32) error {
	return WriteMuxPacket(conn, MUX_S_SESSION_OPENED, EncodeMuxSessionOpened(reqID, sessionID))
}

func sendExitMessage(conn io.Writer, sessionID uint32, exitValue uint32) error {
	return WriteMuxPacket(conn, MUX_S_EXIT_MESSAGE, EncodeMuxExitMessage(sessionID, exitValue))
}

func sendTTYAllocFail(conn io.Writer, sessionID uint32) error {
	return WriteMuxPacket(conn, MUX_S_TTY_ALLOC_FAIL, EncodeMuxTTYAllocFail(sessionID))
}
