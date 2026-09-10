//go:build linux && amd64

package credentialfile

import (
	"context"
	"errors"
	"os"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
)

// Inspect reads metadata without unlocking unless verify is explicitly requested.
func (s *Store) Inspect(ctx context.Context, verify bool) (result Inspection, err error) {
	var a *administration
	if verify {
		a, err = s.admin(ctx, false)
		if err != nil {
			return result, err
		}
		defer func() { err = errors.Join(err, a.close()) }()
		if err := a.acquire(); err != nil {
			return result, err
		}
		ctx = a.ctx
	} else {
		work, finish, e := s.begin(ctx)
		if e != nil {
			return result, e
		}
		defer finish()
		ctx = work
		lock, e := s.lock(ctx, false)
		if e != nil {
			return result, e
		}
		defer func() { err = errors.Join(err, lock.close()) }()
	}
	p, err := s.publication(ctx)
	if err != nil {
		return result, err
	}
	result.Limit = format.MaxEncryptions
	result.Version, result.Suite = format.Version, "AES-256-GCM"
	result.Revision, result.Generation = p.current.Revision, p.current.Generation
	result.Unlock = "prompt"
	if p.meta.Suite == format.WrapKeyFile {
		result.Unlock = "key-file"
	}
	name, dir, e := activeTransaction(ctx, s.root)
	if e == nil {
		result.OperationID = name
		data, readErr := dir.read(ctx, "state", format.MaxStateBytes)
		if readErr != nil {
			return result, errors.Join(readErr, dir.file.Close())
		}
		tx, readErr := activeTargetHeader(data)
		if readErr != nil {
			return result, errors.Join(readErr, dir.file.Close())
		}
		result.NeedsSource = tx.Operation != format.OpInit && (p.current.Revision != tx.Target.Revision || p.current.MetaHash != tx.Target.MetaHash)
		if err := dir.file.Close(); err != nil {
			return result, err
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	if verify {
		if err := s.checkArchivedBudget(ctx, p, a.key); err != nil {
			return result, err
		}
		if err := a.check(); err != nil {
			return result, err
		}
		consumed, err := s.inspectConsumed(ctx, p, a.key)
		if err != nil {
			return result, err
		}
		result.Consumed = &consumed
		result.Authenticated = true
	}
	return result, nil
}

func (s *Store) inspectConsumed(ctx context.Context, p publication, key []byte) (consumed uint64, err error) {
	dir, err := keyStateDir(s.root, p.current.Generation)
	if err != nil {
		return 0, err
	}
	defer closeFile(&err, dir.file)
	data, err := dir.read(ctx, "budget", format.MaxStateBytes)
	if err != nil {
		return 0, err
	}
	budget, err := format.OpenBudget(data, key, p.current.VaultID, p.current.Generation, s.storeID)
	return budget.Consumed, err
}
