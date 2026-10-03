// Package ports defines the storage-independent contracts consumed by the MCP
// runtime and implemented by CLI/server hosts and shared execution adapters.
package ports

import (
	"context"
	"io"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/remotefile"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
)

type NodeInfo struct {
	ID        string   `json:"id" jsonschema:"Node ID / Name"`
	Alias     []string `json:"alias,omitempty" jsonschema:"Node aliases"`
	Address   string   `json:"address" jsonschema:"Host address and port"`
	User      string   `json:"user" jsonschema:"SSH user"`
	AuthType  string   `json:"authType" jsonschema:"Authentication type"`
	ProxyJump string   `json:"proxyJump,omitempty" jsonschema:"Proxy jump host"`
	Tags      []string `json:"tags,omitempty" jsonschema:"Node tags"`
}

type NodeQuery struct{ Tag string }
type ResolveRequest struct{ Selectors []string }

type InventorySnapshot struct {
	DomainID       string
	Revision       string
	PolicyRevision string
	Policy         policy.Config
	Nodes          []NodeInfo
}

type Target struct {
	Info NodeInfo
	Plan ssh.ConnectionPlan
	// Version changes only when execution dependencies or relevant policy inputs
	// change. A display-only edit must not automatically change this version.
	Version  string
	Disabled bool
}

type OperationSnapshot struct {
	DomainID       string
	Revision       string
	PolicyRevision string
	Policy         policy.Config
	Targets        map[string]Target
	Selectors      map[string]string
}

type StateSource interface {
	DomainID() string
	List(context.Context, NodeQuery) (InventorySnapshot, error)
	Resolve(context.Context, ResolveRequest) (OperationSnapshot, error)
}

type Phase string

const (
	Inspect       Phase = "inspect"
	Execute       Phase = "execute"
	TransferStart Phase = "transfer_start"
	Commit        Phase = "commit"
	Recovery      Phase = "recovery"
)

type Binding struct {
	DomainID       string
	Scope          string
	Tool           string
	InputDigest    string
	SnapshotDigest string
}

type Admission struct {
	OperationID string
	Phase       Phase
	Snapshot    OperationSnapshot
	Binding     Binding
	// Previous requests an atomic TransferStart -> Commit handoff of this
	// operation's existing admission slot. Gates must validate ownership and
	// binding; failure leaves the old permit intact. It is never wire data.
	Previous Permit `json:"-"`
}

type ExecutionGate interface {
	DomainID() string
	Enter(context.Context, Admission) (Permit, error)
}

type Permit interface {
	Context() context.Context
	Snapshot() OperationSnapshot
	Binding() Binding
	Phase() Phase
	Close() error
}

type AuditEvent = guardrail.AuditEntry
type AuditSink = guardrail.AuditSink

// NoopAudit is an explicit host choice; a missing sink is not interpreted as
// permission to discover a personal audit file.
type NoopAudit struct{}

func (NoopAudit) Append(ctx context.Context, _ AuditEvent) error { return ctx.Err() }

type Command struct {
	Text string
	Sudo bool
}

type CommandResult struct {
	Output    string
	Connected bool
}
type InspectRequest struct {
	Path      string
	Upload    bool
	Overwrite bool
}

// FileSession uses the existing SFTP API while carrying a connection lease and
// permit lifetime. It deliberately does not expose the shared SSH transport.
type FileSession interface {
	Do(context.Context, func(*pkgsftp.Client) error) error
	Upload(context.Context, string, string, sftp.ProgressCallback) error
	Download(context.Context, string, string, sftp.ProgressCallback) error
	CreatePrivateExclusive(context.Context, string, func(io.Writer) error) (bool, bool, error)
	Close() error
}

type Backend interface {
	Run(context.Context, Permit, string, Command) (CommandResult, error)
	OpenFiles(context.Context, Permit, string) (FileSession, error)
	Inspect(context.Context, Permit, string, InspectRequest) (remotefile.Metadata, error)
	OpenTransfer(context.Context, Permit, string) (TransferSession, error)
	Shutdown(context.Context) error
}

// TransferSession retains the original transport until Close. ReserveCommit
// exchanges streaming authority for an already admitted commit permit without
// dialing again. Calls on a session are sequential; Close may interrupt I/O.
type TransferSession interface {
	remotefile.Remote
	ReserveCommit(context.Context, Permit) error
}

type TunnelBackend interface {
	RunTunnel(context.Context, Permit, tunnel.Spec, func(string) bool, func(error)) error
}

type Dependencies struct {
	State      StateSource
	Gate       ExecutionGate
	NewBackend func(context.Context) (Backend, error)
	Audit      AuditSink
}
