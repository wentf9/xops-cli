//go:build linux && amd64

package credentialfile

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
)

// RecoveryNeedsSource inspects bounded public recovery hints, including targets
// without CURRENT. It only selects material acquisition; Resume authenticates
// and rechecks the operation before any mutation.
func (s *Store) RecoveryNeedsSource(ctx context.Context) (needed bool, err error) {
	ctx, finish, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer finish()
	ctx, cancel := context.WithTimeout(ctx, min(s.options.Timeout, 30*time.Second))
	defer cancel()
	lock, err := s.lock(ctx, false)
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, lock.close()) }()
	name, dir, err := activeTransaction(ctx, s.root)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer closeFile(&err, dir.file)
	data, err := dir.read(ctx, "state", format.MaxStateBytes)
	if err != nil {
		return false, err
	}
	tx, err := activeTargetHeader(data)
	if err != nil {
		return false, err
	}
	if operationName(tx.OperationID) != name || tx.Target.StoreID != s.storeID {
		return false, format.ErrIdentity
	}
	p, err := s.publication(ctx)
	if errors.Is(err, os.ErrNotExist) {
		switch tx.Operation {
		case format.OpInit:
			return false, nil
		case format.OpClone, format.OpRestore:
			return true, nil
		default:
			return false, ErrMaintenanceRequired
		}
	}
	if err != nil {
		return false, err
	}
	published := p.current.Revision == tx.Target.Revision && p.current.MetaHash == tx.Target.MetaHash
	return !published && tx.Operation != format.OpInit, nil
}
