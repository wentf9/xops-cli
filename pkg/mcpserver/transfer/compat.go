// Package transfer preserves the legacy import path for the shared state machine.
package transfer

import (
	"context"
	core "github.com/wentf9/xops-cli/core/mcp/transfer"
)

type Direction = core.Direction
type Journal = core.Journal
type Lease = core.Lease
type Limits = core.Limits
type Manager = core.Manager
type Prepared = core.Prepared
type Record = core.Record
type Spec = core.Spec
type State = core.State
type Status = core.Status
type Store = core.Store

const Cancelled = core.Cancelled
const Committing = core.Committing
const Completed = core.Completed
const Download = core.Download
const Expired = core.Expired
const Failed = core.Failed
const Ready = core.Ready
const Streamed = core.Streamed
const Transferring = core.Transferring
const Unknown = core.Unknown
const Upload = core.Upload
const Verifying = core.Verifying

var ErrBusy = core.ErrBusy
var ErrClosed = core.ErrClosed
var ErrConflict = core.ErrConflict
var ErrExpired = core.ErrExpired
var ErrInvalidState = core.ErrInvalidState
var ErrNotFound = core.ErrNotFound
var ErrStoreLocked = core.ErrStoreLocked
var ErrStoreUnusable = core.ErrStoreUnusable
var ErrRecordTooLarge = core.ErrRecordTooLarge
var ErrUnauthorized = core.ErrUnauthorized

func DefaultLimits() Limits                          { return core.DefaultLimits() }
func OpenJournal(directory string) (*Journal, error) { return core.OpenJournal(directory) }
func NewManager(ctx context.Context, store Store, limits Limits) (*Manager, error) {
	return core.NewManager(ctx, store, limits)
}
