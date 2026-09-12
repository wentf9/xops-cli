package credentialfile

import "context"

// Inspection contains bounded public metadata; Authenticated marks verified data.
type Inspection struct {
	Limit         uint64  `json:"limit"`
	Version       uint16  `json:"version"`
	Suite         string  `json:"suite"`
	Revision      uint64  `json:"revision"`
	Generation    uint64  `json:"generation"`
	Unlock        string  `json:"unlock"`
	Authenticated bool    `json:"authenticated"`
	OperationID   string  `json:"operation_id,omitempty"`
	NeedsSource   bool    `json:"needs_source,omitempty"`
	Consumed      *uint64 `json:"consumed,omitempty"`
}

type operationSelection struct{}

// ResumeOperation requires the named operation when nonempty, under recovery locks.
// source is explicit for clone/restore and must be s for single-root operations.
func (s *Store) ResumeOperation(ctx context.Context, id string, source *Store, from, to Wrapping) (MaintenanceResult, error) {
	return s.ResumeFrom(context.WithValue(ctx, operationSelection{}, id), source, from, to)
}
