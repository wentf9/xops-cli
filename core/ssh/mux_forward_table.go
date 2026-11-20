package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

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

func (s *MuxServer) listenRemoteMux(network, listenAddr string) (net.Listener, error) {
	if s == nil || s.sshClient == nil || s.sshClient.Conn == nil {
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

type directStreamlocalOpenMsg struct {
	SocketPath string
	Reserved0  string
	Reserved1  uint32
}

func (s *MuxServer) dialSSHMux(parent context.Context, network, addr string) (net.Conn, error) {
	if s == nil || s.sshClient == nil || s.sshClient.Conn == nil {
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

// dialSSHMuxChannel opens a raw forwarded SSH channel ("direct-tcpip" or
// "direct-streamlocal@openssh.com") under s.requestTimeout without tearing down
// the shared MuxServer on a slow remote open.
func (s *MuxServer) dialSSHMuxChannel(parent context.Context, network, addr string) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if s == nil || s.sshClient == nil || s.sshClient.Conn == nil {
		return nil, nil, errors.New("ssh client is nil")
	}
	chType, payload, err := encodeMuxForwardChannelOpen(network, addr)
	if err != nil {
		return nil, nil, err
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

	client := s.sshClient
	chCh := make(chan openChannelResult)
	abandoned := make(chan struct{})
	go func() {
		ch, reqs, openErr := client.OpenChannel(chType, payload)
		select {
		case chCh <- openChannelResult{channel: ch, requests: reqs, err: openErr}:
		case <-abandoned:
			if ch != nil {
				if reqs != nil {
					go discardAbortedChannelRequests(base, reqs)
				}
				_ = closeSSHChannel(ch)
			}
		}
	}()
	select {
	case res := <-chCh:
		return res.channel, res.requests, res.err
	case <-dialCtx.Done():
		close(abandoned)
		return nil, nil, dialCtx.Err()
	}
}

func encodeMuxForwardChannelOpen(network, addr string) (string, []byte, error) {
	switch network {
	case "unix":
		return "direct-streamlocal@openssh.com", cryptoSSH.Marshal(&directStreamlocalOpenMsg{
			SocketPath: addr,
		}), nil
	case "tcp", "tcp4", "tcp6":
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return "", nil, err
		}
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil || port == 0 || port > 65535 {
			return "", nil, fmt.Errorf("invalid tcp forward port %q", portStr)
		}
		return "direct-tcpip", cryptoSSH.Marshal(&directTCPIPOpenMsg{
			DestAddr:   host,
			DestPort:   uint32(port),
			OriginAddr: "0.0.0.0",
			OriginPort: 0,
		}), nil
	default:
		return "", nil, fmt.Errorf("unsupported forward network %q", network)
	}
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

type forwardSlotState uint8

const (
	forwardSlotOpening forwardSlotState = iota + 1
	forwardSlotActive
	forwardSlotClosing
)

type muxForwardEndpointSlot struct {
	state         forwardSlotState
	done          chan struct{}
	closingWait   chan struct{}
	entry         *muxForwardEntry
	fallbackEntry *muxForwardEntry
}

func (st *muxForwardEndpointSlot) cancelCandidateEntry() *muxForwardEntry {
	if st == nil {
		return nil
	}
	switch st.state {
	case forwardSlotOpening:
		return st.fallbackEntry
	case forwardSlotActive:
		return st.entry
	default:
		return nil
	}
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

// muxForwardTable holds all published forwards and listen-endpoint reservations
// under a single lock (`MuxServer.idleMu`), eliminating split-state windows
// between forward entries and endpoint bind/close barriers.
type muxForwardTable struct {
	entries   map[string]*muxForwardEntry
	endpoints map[forwardListenKey]*muxForwardEndpointSlot
}

type shutdownForwardItem struct {
	entry   *muxForwardEntry
	shadows []io.Closer
}

func (t *muxForwardTable) entryCountLocked() int {
	if t == nil {
		return 0
	}
	return len(t.entries)
}

func (t *muxForwardTable) endpointCountLocked() int {
	if t == nil {
		return 0
	}
	return len(t.endpoints)
}

func (t *muxForwardTable) hasInFlightEndpointsLocked() bool {
	if t == nil {
		return false
	}
	for _, ep := range t.endpoints {
		if ep != nil && (ep.state == forwardSlotOpening || ep.state == forwardSlotClosing || ep.closingWait != nil) {
			return true
		}
	}
	return false
}

func (t *muxForwardTable) listForwardKeysLocked() []string {
	if t == nil || len(t.entries) == 0 {
		return nil
	}
	keys := make([]string, 0, len(t.entries))
	for k := range t.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (t *muxForwardTable) putEntryLocked(key string, entry *muxForwardEntry) {
	if t.entries == nil {
		t.entries = make(map[string]*muxForwardEntry)
	}
	t.entries[key] = entry
}

func (t *muxForwardTable) getEntryLocked(key string) (*muxForwardEntry, bool) {
	if t == nil || t.entries == nil {
		return nil, false
	}
	e, ok := t.entries[key]
	return e, ok
}

func (t *muxForwardTable) loadOrStoreEntryLocked(key string, cand *muxForwardEntry) (existing *muxForwardEntry, loaded bool) {
	if t.entries == nil {
		t.entries = make(map[string]*muxForwardEntry)
	}
	if cur, ok := t.entries[key]; ok {
		return cur, true
	}
	t.entries[key] = cand
	return nil, false
}

func (t *muxForwardTable) deleteEntryLocked(key string) {
	if t != nil && t.entries != nil {
		delete(t.entries, key)
	}
}

func (t *muxForwardTable) deleteEntryIfMatchLocked(key string, target *muxForwardEntry) bool {
	if t == nil || t.entries == nil {
		return false
	}
	if cur, ok := t.entries[key]; ok && cur == target {
		delete(t.entries, key)
		return true
	}
	return false
}

func (t *muxForwardTable) deleteEndpointEntryLocked(entry *muxForwardEntry) {
	if t == nil || entry == nil || !entry.hasListenKey || t.endpoints == nil {
		return
	}
	cur, exists := t.endpoints[entry.listenKey]
	if !exists || cur == nil {
		return
	}
	switch cur.state {
	case forwardSlotOpening:
		if cur.fallbackEntry == entry {
			cur.fallbackEntry = nil
		}
	case forwardSlotActive:
		if cur.entry == entry {
			delete(t.endpoints, entry.listenKey)
		}
	}
}

// snapshotAndDrainForShutdownLocked extracts and deletes every tracked forward
// entry for Shutdown. Local listeners are returned before liveStreams/sshClient
// teardown, while remote listeners are closed after sshClient shutdown so dead
// transports cannot block Shutdown.
func (t *muxForwardTable) snapshotAndDrainForShutdownLocked() (local []shutdownForwardItem, remote []shutdownForwardItem) {
	if t == nil || len(t.entries) == 0 {
		return nil, nil
	}
	for k, entry := range t.entries {
		delete(t.entries, k)
		if entry == nil {
			continue
		}
		t.deleteEndpointEntryLocked(entry)
		shadows := entry.takeShadowClosers()
		if entry.closer == nil && len(shadows) == 0 {
			continue
		}
		item := shutdownForwardItem{entry: entry, shadows: shadows}
		if entry.remote {
			remote = append(remote, item)
		} else {
			local = append(local, item)
		}
	}
	return local, remote
}

func (s *MuxServer) forwardCount() int {
	if s == nil {
		return 0
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	return s.forwardTable.entryCountLocked()
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
) (*muxForwardEndpointSlot, muxEndpointAcquireOutcome) {
	for {
		s.idleMu.Lock()
		if s.isShuttingDownLocked() {
			s.idleMu.Unlock()
			return nil, muxEndpointShuttingDown
		}
		if s.forwardTable.endpoints == nil {
			s.forwardTable.endpoints = make(map[forwardListenKey]*muxForwardEndpointSlot)
		}
		cur, exists := s.forwardTable.endpoints[listenKey]
		if !exists {
			slot := &muxForwardEndpointSlot{
				state: forwardSlotOpening,
				done:  make(chan struct{}),
			}
			s.forwardTable.endpoints[listenKey] = slot
			s.idleMu.Unlock()
			return slot, muxEndpointReserved
		}
		if cur.state == forwardSlotOpening || cur.state == forwardSlotClosing {
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
		if cur.state == forwardSlotActive && cur.entry != nil && sameMuxForwardDestination(cur.entry, fwdType, normConnectHost, connectPort) {
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

func (s *MuxServer) releaseInFlightEndpointSlotLocked(listenKey forwardListenKey, slot *muxForwardEndpointSlot) {
	if slot == nil {
		return
	}
	if s.forwardTable.endpoints != nil && s.forwardTable.endpoints[listenKey] == slot {
		if slot.fallbackEntry != nil {
			slot.entry = slot.fallbackEntry
			slot.fallbackEntry = nil
			slot.state = forwardSlotActive
		} else {
			delete(s.forwardTable.endpoints, listenKey)
		}
	}
	close(slot.done)
	s.notifyIdleLocked()
}

func (s *MuxServer) abortReservedForward(listenKey forwardListenKey, slot *muxForwardEndpointSlot) {
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
	s.onWorkCountChangedLocked()
	s.idleMu.Unlock()
}

func (s *MuxServer) commitReservedForward(
	listenKey forwardListenKey,
	slot *muxForwardEndpointSlot,
	key string,
	cand *muxForwardEntry,
) (entry *muxForwardEntry, duplicate bool, shuttingDown bool) {
	entry, duplicate, _, shuttingDown = s.commitReservedForwardSlot(listenKey, slot, key, cand)
	return entry, duplicate, shuttingDown
}

func (s *MuxServer) commitReservedForwardSlot(
	listenKey forwardListenKey,
	slot *muxForwardEndpointSlot,
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
	if s.isShuttingDownLocked() {
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
	if existingEntry, loaded := s.forwardTable.loadOrStoreEntryLocked(key, cand); loaded && existingEntry != nil {
		if cand.fwdType == MUX_FWD_REMOTE {
			existingEntry.refs++
		}
		retained := s.retainDuplicateRemoteListenerLocked(existingEntry, cand)
		if slot != nil {
			if !existingEntry.hasListenKey || existingEntry.listenKey == listenKey {
				existingEntry.listenKey = listenKey
				existingEntry.hasListenKey = true
				slot.entry = existingEntry
				slot.state = forwardSlotActive
			} else if s.forwardTable.endpoints != nil && s.forwardTable.endpoints[listenKey] == slot {
				delete(s.forwardTable.endpoints, listenKey)
			}
			close(slot.done)
			s.notifyIdleLocked()
		}
		s.idleMu.Unlock()
		if !retained {
			s.closeUnpublishedMuxForward(cand)
		}
		return existingEntry, true, false, false
	}
	if slot != nil {
		cand.listenKey = listenKey
		cand.hasListenKey = true
		slot.entry = cand
		slot.state = forwardSlotActive
		close(slot.done)
		s.notifyIdleLocked()
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
	reservedSlot *muxForwardEndpointSlot,
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

func (s *MuxServer) handleOpenFwd(conn net.Conn, req MuxFwdRequest) error {
	s.idleMu.Lock()
	if s.phase != muxPhaseRunning || s.stoppedListening {
		// Shutdown or -O stop already took effect; accepting a forward now would
		// leave a listener that outlives the master it belongs to.
		s.idleMu.Unlock()
		return sendFailure(conn, req.RequestID, "mux master is shutting down")
	}
	s.openFwdsInFlight++
	s.disarmIdleTimerLocked()
	s.idleMu.Unlock()

	defer func() {
		s.idleMu.Lock()
		s.openFwdsInFlight--
		s.onWorkCountChangedLocked()
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
		reservedSlot *muxForwardEndpointSlot
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
	reservedSlot *muxForwardEndpointSlot,
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
	reservedSlot *muxForwardEndpointSlot,
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
	if s.forwardTable.endpoints == nil {
		return false, false
	}
	cur, exists := s.forwardTable.endpoints[dynKey]
	if !exists || cur == nil {
		return false, false
	}
	if cur.state != forwardSlotOpening {
		return true, s.retainDuplicateRemoteListenerLocked(cur.entry, cand)
	}
	if cur.fallbackEntry != nil {
		return true, s.retainDuplicateRemoteListenerLocked(cur.fallbackEntry, cand)
	}
	return false, false
}

func (s *MuxServer) recordDynamicEndpointLocked(dynKey forwardListenKey, cand *muxForwardEntry) {
	if s.forwardTable.endpoints == nil {
		s.forwardTable.endpoints = make(map[forwardListenKey]*muxForwardEndpointSlot)
	}
	cur, exists := s.forwardTable.endpoints[dynKey]
	if !exists || cur == nil {
		cand.listenKey = dynKey
		cand.hasListenKey = true
		s.forwardTable.endpoints[dynKey] = &muxForwardEndpointSlot{
			state: forwardSlotActive,
			entry: cand,
		}
		return
	}
	if cur.state == forwardSlotOpening && cur.fallbackEntry == nil {
		cand.listenKey = dynKey
		cand.hasListenKey = true
		cur.fallbackEntry = cand
	}
}

func (s *MuxServer) lockForPublishForward(hasDynKey bool, dynKey forwardListenKey) bool {
	for {
		s.idleMu.Lock()
		if s.isShuttingDownLocked() {
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

	if existingEntry, loaded := s.forwardTable.loadOrStoreEntryLocked(key, cand); loaded {
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
	deleted := s.forwardTable.deleteEntryIfMatchLocked(key, entry)
	shadows := entry.takeShadowClosers()
	s.forwardTable.deleteEndpointEntryLocked(entry)

	var (
		closingSlot      *muxForwardEndpointSlot
		inFlightCur      *muxForwardEndpointSlot
		closingWaitDone  chan struct{}
		closeFwdsCounted bool
	)
	if deleted && len(shadows) > 0 && entry != nil && entry.hasListenKey {
		s.closeFwdsInFlight++
		closeFwdsCounted = true
		s.disarmIdleTimerLocked()
		abortedWait := false
		for !s.isShuttingDownLocked() {
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
		if !abortedWait && !s.isShuttingDownLocked() {
			closingSlot, inFlightCur, closingWaitDone = s.beginEndpointCloseBarrierLocked(entry)
		}
	} else if deleted {
		s.onWorkCountChangedLocked()
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
		s.onWorkCountChangedLocked()
		s.idleMu.Unlock()
	}
}

// trackStream registers an accepted connection for shutdown-driven teardown.
func (s *MuxServer) trackStream(conn net.Conn) {
	if conn == nil {
		return
	}
	s.liveStreams.Store(conn, struct{}{})
	if s.isClosed() {
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
	if e, found := s.forwardTable.getEntryLocked(matchedKey); found && e != nil {
		return matchedKey, e, true
	}
	if !resolved.isDynamicPort && hasReqListenKey && s.forwardTable.endpoints != nil {
		candEntry := s.forwardTable.endpoints[reqListenKey].cancelCandidateEntry()
		if matchesMuxForwardCancelTarget(candEntry, req.FwdType, normConnectHost, req.ConnectPort) {
			if candEntry.forwardKey != "" {
				matchedKey = candEntry.forwardKey
			}
			return matchedKey, candEntry, true
		}
	}
	if resolved.isDynamicPort {
		for _, k := range s.forwardTable.listForwardKeysLocked() {
			e := s.forwardTable.entries[k]
			if e != nil && e.dynamicAlloc &&
				(e.keyHost == resolved.keyHost || e.endpointHost == resolved.endpointHost) &&
				matchesMuxForwardCancelTarget(e, req.FwdType, normConnectHost, req.ConnectPort) {
				return k, e, true
			}
		}
	}
	return matchedKey, nil, false
}

func (s *MuxServer) beginEndpointCloseBarrierLocked(entry *muxForwardEntry) (
	closingSlot *muxForwardEndpointSlot,
	inFlightCur *muxForwardEndpointSlot,
	closingWaitDone chan struct{},
) {
	if entry == nil || !entry.hasListenKey {
		return nil, nil, nil
	}
	if s.forwardTable.endpoints == nil {
		s.forwardTable.endpoints = make(map[forwardListenKey]*muxForwardEndpointSlot)
	}
	cur := s.forwardTable.endpoints[entry.listenKey]
	if cur != nil {
		if cur.entry == entry {
			cur.entry = nil
		}
		if cur.fallbackEntry == entry {
			cur.fallbackEntry = nil
		}
		if cur.state != forwardSlotClosing && (cur.state == forwardSlotOpening || cur.entry != nil || cur.fallbackEntry != nil) {
			closingWaitDone = make(chan struct{})
			cur.closingWait = closingWaitDone
			return nil, cur, closingWaitDone
		}
	}
	closingSlot = &muxForwardEndpointSlot{
		state: forwardSlotClosing,
		done:  make(chan struct{}),
	}
	s.forwardTable.endpoints[entry.listenKey] = closingSlot
	return closingSlot, nil, nil
}

func (s *MuxServer) finishEndpointCloseBarrierLocked(
	entry *muxForwardEntry,
	closingSlot *muxForwardEndpointSlot,
	inFlightCur *muxForwardEndpointSlot,
	closingWaitDone chan struct{},
) {
	if closingSlot != nil && entry != nil {
		s.releaseInFlightEndpointSlotLocked(entry.listenKey, closingSlot)
	}
	if closingWaitDone != nil {
		if inFlightCur != nil && inFlightCur.closingWait == closingWaitDone {
			inFlightCur.closingWait = nil
			if entry != nil && inFlightCur.state != forwardSlotOpening && inFlightCur.entry == nil && inFlightCur.fallbackEntry == nil &&
				s.forwardTable.endpoints != nil && s.forwardTable.endpoints[entry.listenKey] == inFlightCur {
				delete(s.forwardTable.endpoints, entry.listenKey)
			}
		}
		close(closingWaitDone)
		s.notifyIdleLocked()
	}
}

func (s *MuxServer) waitClosingEndpointLocked(listenKey forwardListenKey) (waited bool, aborted bool) {
	if s.forwardTable.endpoints == nil {
		return false, false
	}
	cur := s.forwardTable.endpoints[listenKey]
	if cur == nil {
		return false, false
	}
	var waitCh chan struct{}
	switch {
	case cur.closingWait != nil:
		waitCh = cur.closingWait
	case cur.state == forwardSlotClosing:
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
	if s.isShuttingDownLocked() {
		s.idleMu.Unlock()
		return sendFailure(conn, req.RequestID, "mux master is shutting down")
	}
	s.closeFwdsInFlight++
	s.disarmIdleTimerLocked()
	s.idleMu.Unlock()

	defer func() {
		s.idleMu.Lock()
		s.closeFwdsInFlight--
		s.onWorkCountChangedLocked()
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
		if s.isShuttingDownLocked() {
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

		s.forwardTable.deleteEntryLocked(matchedKey)
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
