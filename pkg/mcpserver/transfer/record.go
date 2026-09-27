// Package transfer manages authorized, single-use file transfer tasks. It is
// independent of MCP sessions so a task can outlive its creation request.
package transfer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

type Direction string

const (
	Upload   Direction = "upload"
	Download Direction = "download"
)

type State string

const (
	Ready        State = "ready"
	Transferring State = "transferring"
	Verifying    State = "verifying"
	Committing   State = "committing"
	Completed    State = "completed"
	Streamed     State = "streamed"
	Failed       State = "failed"
	Cancelled    State = "cancelled"
	Expired      State = "expired"
	Unknown      State = "unknown"
)

const recordVersion = 1

var (
	ErrBusy          = errors.New("transfer capacity unavailable")
	ErrConflict      = errors.New("transfer conflicts with existing task")
	ErrUnauthorized  = errors.New("invalid transfer credential")
	ErrNotFound      = errors.New("transfer not found")
	ErrExpired       = errors.New("transfer start window expired")
	ErrClosed        = errors.New("transfer manager closed")
	ErrInvalidState  = errors.New("transfer state does not permit this operation")
	ErrStoreLocked   = errors.New("transfer metadata is already in use")
	ErrStoreUnusable = errors.New("transfer metadata cannot be persisted")
)

// Spec is the immutable, approved operation. TargetID identifies the resolved
// SSH target and account, including aliases that share a destination lock.
type Spec struct {
	RequestID     string    `json:"requestID"`
	RequestDigest string    `json:"requestDigest,omitempty"`
	RequestedPath string    `json:"requestedPath,omitempty"`
	Scope         string    `json:"scope"`
	Direction     Direction `json:"direction"`
	NodeID        string    `json:"nodeID"`
	TargetID      string    `json:"targetID"`
	RemotePath    string    `json:"remotePath"`
	Size          int64     `json:"size"`
	SHA256        string    `json:"sha256,omitempty"`
	Overwrite     bool      `json:"overwrite"`
	SourceModTime int64     `json:"sourceModTime,omitempty"`
}

func (s Spec) validateIdentity() error {
	if s.RequestDigest != "" && !validHex(s.RequestDigest, sha256.Size) {
		return errors.New("invalid transfer request digest")
	}
	if len(s.RequestedPath) > 4096 || strings.ContainsRune(s.RequestedPath, '\x00') {
		return errors.New("invalid requested transfer path")
	}
	if s.RequestID == "" || len(s.RequestID) > 128 || s.Scope == "" || len(s.Scope) > 256 {
		return errors.New("transfer request ID and authentication scope are required and must be bounded")
	}
	if s.NodeID == "" || len(s.NodeID) > 1024 || s.TargetID == "" || len(s.TargetID) > 1024 {
		return errors.New("transfer node and resolved target are required and must be bounded")
	}
	return nil
}

func (s Spec) validate() error {
	if err := s.validateIdentity(); err != nil {
		return err
	}
	if !path.IsAbs(s.RemotePath) || path.Clean(s.RemotePath) != s.RemotePath || s.RemotePath == "/" ||
		len(s.RemotePath) > 4096 || strings.ContainsRune(s.RemotePath, '\x00') {
		return errors.New("transfer requires a normalized absolute remote file path")
	}
	if s.Size < 0 {
		return errors.New("transfer size cannot be negative")
	}
	switch s.Direction {
	case Upload:
		if !validHex(s.SHA256, sha256.Size) {
			return errors.New("upload requires a lowercase SHA-256 digest")
		}
	case Download:
		if s.Overwrite || s.SHA256 != "" {
			return errors.New("download cannot specify remote overwrite or an upload digest")
		}
	default:
		return errors.New("invalid transfer direction")
	}
	return nil
}

// Status returns the public view without credentials or authentication scope.
func (r Record) Status() Status { return statusOf(r) }

// Record is private journal data, not an HTTP response. TokenDigest must never
// be exposed by tool output or status responses.
type Record struct {
	Version         int       `json:"version"`
	ID              string    `json:"id"`
	OperationID     string    `json:"operationID"`
	Spec            Spec      `json:"spec"`
	TokenDigest     string    `json:"tokenDigest"`
	State           State     `json:"state"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
	StartBefore     time.Time `json:"startBefore"`
	StatusExpiresAt time.Time `json:"statusExpiresAt"`
	TempPath        string    `json:"tempPath,omitempty"`
	TempOwned       bool      `json:"tempOwned"`
	Bytes           int64     `json:"bytes"`
	SHA256          string    `json:"sha256,omitempty"`
	Error           string    `json:"error,omitempty"`
	Warning         string    `json:"warning,omitempty"`
	CleanupPending  bool      `json:"cleanupPending"`
	CancelRequested bool      `json:"cancelRequested"`
	Resolved        bool      `json:"resolved"`
	Resolution      string    `json:"resolution,omitempty"`
}

func (r Record) validate() error {
	if r.Version != recordVersion || !validHex(r.ID, 16) || r.OperationID == "" || len(r.OperationID) > 128 {
		return errors.New("invalid transfer record version or identity")
	}
	if err := r.Spec.validate(); err != nil {
		return fmt.Errorf("validate recorded transfer: %w", err)
	}
	if !validHex(r.TokenDigest, sha256.Size) {
		return errors.New("invalid transfer credential digest")
	}
	if r.CreatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) || !r.StartBefore.After(r.CreatedAt) ||
		!r.StatusExpiresAt.After(r.StartBefore) {
		return errors.New("invalid transfer record timestamps")
	}
	if err := r.validateTemporary(); err != nil {
		return err
	}
	if err := r.validateProgress(); err != nil {
		return err
	}
	return validateState(r.Spec.Direction, r.State)
}

func (r Record) validateTemporary() error {
	if r.TempPath != "" && (r.Spec.Direction != Upload || r.TempPath != temporaryPath(r.Spec.RemotePath, r.ID)) {
		return errors.New("recorded temporary path does not belong to this upload")
	}
	if r.CleanupPending && r.TempPath == "" {
		return errors.New("cleanup requested without an owned temporary path")
	}
	if r.TempOwned && r.TempPath == "" {
		return errors.New("confirmed temporary ownership requires a recorded path")
	}
	if len(r.Error) > 4096 || len(r.Resolution) > 4096 || len(r.Warning) > 4096 {
		return errors.New("transfer diagnostic exceeds record limit")
	}
	return nil
}

func (r Record) validateProgress() error {
	if r.Bytes < 0 || r.Bytes > r.Spec.Size || (r.SHA256 != "" && !validHex(r.SHA256, sha256.Size)) {
		return errors.New("invalid recorded transfer byte count or digest")
	}
	if r.Resolved && (r.State != Unknown || r.Resolution == "") {
		return errors.New("only an uncertain transfer can have an operator resolution")
	}
	if r.State == Completed && (r.Bytes != r.Spec.Size || r.SHA256 != r.Spec.SHA256) {
		return errors.New("completed upload lacks verified content")
	}
	if r.State == Streamed && (r.Bytes != r.Spec.Size || r.SHA256 == "") {
		return errors.New("streamed download lacks verified content")
	}
	return nil
}

func validateState(direction Direction, state State) error {
	switch state {
	case Ready, Transferring, Verifying, Failed, Cancelled, Expired:
		return nil
	case Committing, Completed, Unknown:
		if direction == Upload {
			return nil
		}
	case Streamed:
		if direction == Download {
			return nil
		}
	}
	return fmt.Errorf("invalid state %q for %s", state, direction)
}

func temporaryPath(remotePath, id string) string {
	return path.Join(path.Dir(remotePath), ".xops-transfer-"+id+".tmp")
}

func validHex(value string, bytes int) bool {
	if len(value) != bytes*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func randomHex(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate transfer identifier: %w", err)
	}
	return hex.EncodeToString(b), nil
}
