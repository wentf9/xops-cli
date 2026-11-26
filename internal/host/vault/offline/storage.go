package offline

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

func writeAndVerifyLocked(
	root ports.RootHandle,
	itemDest pathalg.LocalRootedDest,
	aead cipher.AEAD,
	ref secret.Ref,
	encoded []byte,
	//xops:borrowed
	box *secret.SecretBox,
) error {
	limits, err := ports.NewReadLimits(vaultItemMaxBytes)
	if err != nil {
		return err
	}
	prevRaw, prevErr := root.ReadAllBounded(itemDest, limits)
	hadPrev := prevErr == nil
	if prevErr != nil && !errors.Is(prevErr, ports.ErrNotFound) {
		return prevErr
	}
	if err := writeAtomicBytes(root, itemDest, encoded); err != nil {
		return err
	}
	readBack, err := root.ReadAllBounded(itemDest, limits)
	if err != nil {
		rollbackItem(root, itemDest, hadPrev, prevRaw)
		return fmt.Errorf("%w: %w", ports.ErrSecretVerifyFailed, err)
	}
	plain, err := decryptItem(aead, ref, readBack)
	if err != nil {
		rollbackItem(root, itemDest, hadPrev, prevRaw)
		return fmt.Errorf("%w: %w", ports.ErrSecretVerifyFailed, err)
	}
	defer clear(plain)
	verifyErr := secret.WithBytes(plain, func(got *secret.SecretBox) error {
		if !got.Equal(box) {
			return ports.ErrSecretVerifyFailed
		}
		return nil
	})
	if verifyErr != nil {
		rollbackItem(root, itemDest, hadPrev, prevRaw)
		return verifyErr
	}
	return nil
}

func rollbackItem(root ports.RootHandle, itemDest pathalg.LocalRootedDest, hadPrev bool, prevRaw []byte) {
	if hadPrev {
		_ = writeAtomicBytes(root, itemDest, prevRaw)
		return
	}
	_ = root.Remove(itemDest)
}

func writeAtomicBytes(root ports.RootHandle, dest pathalg.LocalRootedDest, data []byte) error {
	return root.AtomicReplace(dest, vaultFilePerm, func(w io.Writer) error {
		n, err := w.Write(data)
		if err == nil && n != len(data) {
			return io.ErrShortWrite
		}
		return err
	})
}

func decryptItem(aead cipher.AEAD, ref secret.Ref, raw []byte) ([]byte, error) {
	item, err := decodeVaultItem(raw, ref)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, item.nonce, item.ciphertext, []byte(itemAADPrefix+ref.String()))
	if err != nil {
		return nil, fmt.Errorf("%w: 凭据密文认证失败", ports.ErrCorruptData)
	}
	return plain, nil
}

func (v *Vault) writeMetaExclusive(ctx context.Context, metaBytes []byte) error {
	md, err := metaDest()
	if err != nil {
		return err
	}
	return v.fs.WithRoot(v.rootDir, func(root ports.RootHandle) error {
		return osfs.WithSidecarLock(ctx, root, md, ports.LockExclusive, vaultFilePerm, func(ports.LockedFile) error {
			if _, sErr := root.Stat(md); sErr == nil {
				return ports.ErrAlreadyExists
			} else if !errors.Is(sErr, ports.ErrNotFound) {
				return sErr
			}
			return writeAtomicBytes(root, md, metaBytes)
		})
	})
}

func (v *Vault) loadMeta(ctx context.Context) (parsedVaultMeta, error) {
	md, err := metaDest()
	if err != nil {
		return parsedVaultMeta{}, err
	}
	limits, err := ports.NewReadLimits(vaultMetaMaxBytes)
	if err != nil {
		return parsedVaultMeta{}, err
	}
	var raw []byte
	err = v.fs.WithRoot(v.rootDir, func(root ports.RootHandle) error {
		if _, sErr := root.Stat(md); errors.Is(sErr, ports.ErrNotFound) {
			return ports.ErrNotFound
		} else if sErr != nil {
			return sErr
		}
		return osfs.WithSidecarLock(ctx, root, md, ports.LockShared, vaultFilePerm, func(ports.LockedFile) error {
			var rErr error
			raw, rErr = root.ReadAllBounded(md, limits)
			return rErr
		})
	})
	if err != nil {
		return parsedVaultMeta{}, err
	}
	return decodeVaultMeta(raw)
}

func (v *Vault) readItemRaw(ctx context.Context, ref secret.Ref) ([]byte, error) {
	_, itemDest, err := itemDestForRef(ref)
	if err != nil {
		return nil, err
	}
	limits, err := ports.NewReadLimits(vaultItemMaxBytes)
	if err != nil {
		return nil, err
	}
	var raw []byte
	err = v.fs.WithRoot(v.rootDir, func(root ports.RootHandle) error {
		if _, sErr := root.Stat(itemDest); errors.Is(sErr, ports.ErrNotFound) {
			return ports.ErrSecretNotFound
		} else if sErr != nil {
			return sErr
		}
		return osfs.WithSidecarLock(ctx, root, itemDest, ports.LockShared, vaultFilePerm, func(ports.LockedFile) error {
			var rErr error
			raw, rErr = root.ReadAllBounded(itemDest, limits)
			if errors.Is(rErr, ports.ErrNotFound) {
				return ports.ErrSecretNotFound
			}
			return rErr
		})
	})
	return raw, err
}
