package credentialfile

import "github.com/wentf9/xops-cli/internal/credentialfile/format"

// Wrapping supplies explicit maintenance material. Password is borrowed only for
// the call and never logged. New wrapping material may create a missing KeyFile
// as 32 random bytes with mode 0600; existing files are validated and reused.
// Unlock and resume require the original file. Published key files are never deleted.
type Wrapping struct {
	Mode     string
	Password []byte
	KeyFile  string
}

// MaintenanceResult reports publication separately from journal/finalization errors.
type MaintenanceResult struct {
	OperationID string       `json:"operation_id"`
	Revision    uint64       `json:"revision"`
	Generation  uint64       `json:"generation"`
	Stage       format.Stage `json:"stage"`
	Applied     bool         `json:"applied"`
	Durable     bool         `json:"durable"`
	// Changed reports cleanup deletions; Applied reports CURRENT publication only.
	Changed bool `json:"changed"`
}

// PruneResult contains the authenticated obsolete revisions selected under the lock.
// At most 256 are processed per call; subsequent plans select the next batch.
type PruneResult struct {
	Revisions   []uint64
	Maintenance MaintenanceResult
}
