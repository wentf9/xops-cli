package log

// DiagnosticKind identifies an observed SSH/SFTP lifecycle transition.
type DiagnosticKind string

const (
	Connecting            DiagnosticKind = "connecting"
	Connected             DiagnosticKind = "connected"
	ConnectionReused      DiagnosticKind = "connection_reused"
	HandshakeFailed       DiagnosticKind = "handshake_failed"
	HostKeyChecked        DiagnosticKind = "host_key_checked"
	AuthenticationMethods DiagnosticKind = "authentication_methods"
	AuthenticationAttempt DiagnosticKind = "authentication_attempt"
	Authenticated         DiagnosticKind = "authenticated"
	Negotiated            DiagnosticKind = "negotiated"
	SessionRequest        DiagnosticKind = "session_request"
	SessionStarted        DiagnosticKind = "session_started"
	SessionFinished       DiagnosticKind = "session_finished"
	SessionCleanup        DiagnosticKind = "session_cleanup"
	ForwardLifecycle      DiagnosticKind = "forward_lifecycle"
	SubsystemStarting     DiagnosticKind = "subsystem_starting"
	SubsystemReady        DiagnosticKind = "subsystem_ready"
	SubsystemFailed       DiagnosticKind = "subsystem_failed"
	SFTPVersion           DiagnosticKind = "sftp_version"
	SFTPExtension         DiagnosticKind = "sftp_extension"
	SFTPOperation         DiagnosticKind = "sftp_operation"
	SFTPPacket            DiagnosticKind = "sftp_packet"
	SFTPMalformed         DiagnosticKind = "sftp_malformed"
	SubsystemStderr       DiagnosticKind = "subsystem_stderr"
	FileTransfer          DiagnosticKind = "file_transfer"
)

// Diagnostic contains public protocol metadata only. Never put credentials,
// private keys, file contents, or arbitrary error text in these fields.
// Method describes a selected attempt, not proof that it authenticated.
type Diagnostic struct {
	// Level is 1..3; zero preserves the original DEBUG1 event behavior.
	Level                                      int
	Kind                                       DiagnosticKind
	NodeID, Host, User                         string
	Port                                       int
	Proxied                                    bool
	Accepted                                   bool
	ClientVersion, ServerVersion               string
	KeyExchange, HostKey, Fingerprint          string
	ReadCipher, WriteCipher, ReadMAC, WriteMAC string
	Method                                     string
	Methods                                    []string
	StreamID                                   uint64
	Direction                                  string
	PacketType                                 uint8
	PacketID, PacketLength, ProtocolVersion    uint32
	StatusCode                                 uint32
	HasPacketID                                bool
	HasStatus                                  bool
	HasExitCode                                bool
	ExitCode                                   int64
	Path, Extension, ExtensionVersion          string
	Truncated                                  bool
	Operation, Outcome                         string
	Source, Destination                        string
	Size                                       int64
}

// DiagnosticObserver is optional and independent of DebugLogger. Implementations
// must be concurrency-safe and return promptly (for example, enqueue into a
// bounded buffer). They must not alter authorization or protocol behavior.
// The caller owns the observer and keeps it alive until its connector/clients
// have closed. A nil observer disables all events.
type DiagnosticObserver interface{ ObserveDiagnostic(Diagnostic) }

// EmitDiagnostic does nothing when no observer is installed.
func EmitDiagnostic(observer DiagnosticObserver, event Diagnostic) {
	if DiagnosticEnabled(observer, event.Level) {
		observer.ObserveDiagnostic(event)
	}
}

// DiagnosticEnabled supports an optional DiagnosticLevel() int capability.
// Observers without it accept all levels. Producers can avoid expensive
// metadata decoding when their observer has selected a lower verbosity.
func DiagnosticEnabled(observer DiagnosticObserver, level int) bool {
	if observer == nil {
		return false
	}
	if level < 1 {
		level = 1
	}
	if selected, ok := observer.(interface{ DiagnosticLevel() int }); ok {
		return level <= selected.DiagnosticLevel()
	}
	return true
}
