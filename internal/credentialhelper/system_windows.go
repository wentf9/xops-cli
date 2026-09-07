//go:build windows

package credentialhelper

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/wentf9/xops-cli/pkg/credential"
	"golang.org/x/sys/windows"
)

var (
	modAdvapi32     = windows.NewLazySystemDLL("advapi32.dll")
	procCredReadW   = modAdvapi32.NewProc("CredReadW")
	procCredWriteW  = modAdvapi32.NewProc("CredWriteW")
	procCredDeleteW = modAdvapi32.NewProc("CredDeleteW")
	procCredFree    = modAdvapi32.NewProc("CredFree")
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
	errorNotFound           = 1168 // 0x490 ERROR_NOT_FOUND
	errorNoSuchLogonSession = 1312
	errorAccessDenied       = 5
)

type windowsCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

type windowsNativeStore struct {
	storeID  string
	readOnly bool
	timeout  time.Duration
	mu       sync.RWMutex
}

func newNativeSystemStore(storeID string, cfg SystemStoreConfig) (credential.Store, error) {
	return &windowsNativeStore{
		storeID:  storeID,
		readOnly: cfg.ReadOnly,
		timeout:  cfg.Timeout,
	}, nil
}

func (w *windowsNativeStore) StoreID() string {
	return w.storeID
}

func (w *windowsNativeStore) IsReadOnly() bool {
	return w.readOnly
}

func (w *windowsNativeStore) targetName(ref credential.Ref) string {
	return fmt.Sprintf("xops:%s/%s", ref.StoreID, ref.ItemID)
}

func (w *windowsNativeStore) Get(ctx context.Context, ref credential.Ref) (credential.Secret, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	targetPtr, err := windows.UTF16PtrFromString(w.targetName(ref))
	if err != nil {
		return credential.Secret{}, fmt.Errorf("invalid target name: %w", err)
	}

	var credPtr *windowsCredential
	r1, _, lastErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&credPtr)),
	)
	if r1 == 0 {
		if errno, ok := lastErr.(windows.Errno); ok && errno == errorNotFound {
			return credential.Secret{}, credential.ErrCredentialNotFound
		}
		if errno, ok := lastErr.(windows.Errno); ok && (errno == errorAccessDenied || errno == errorNoSuchLogonSession) {
			return credential.Secret{}, credential.ErrCredentialAccessDenied
		}
		return credential.Secret{}, fmt.Errorf("CredReadW failed: %w", lastErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(credPtr)))

	if credPtr.CredentialBlobSize == 0 || credPtr.CredentialBlob == nil {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}

	blob := unsafe.Slice(credPtr.CredentialBlob, credPtr.CredentialBlobSize)
	return credential.NewSecret(blob), nil
}

func (w *windowsNativeStore) Put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	if w.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	targetPtr, err := windows.UTF16PtrFromString(w.targetName(ref))
	if err != nil {
		return fmt.Errorf("invalid target name: %w", err)
	}

	var blobPtr *byte
	if len(secret.Value) > 0 {
		blobPtr = &secret.Value[0]
	}

	cred := windowsCredential{
		Flags:              0,
		Type:               credTypeGeneric,
		TargetName:         targetPtr,
		Persist:            credPersistLocalMachine,
		CredentialBlobSize: uint32(len(secret.Value)),
		CredentialBlob:     blobPtr,
	}

	r1, _, lastErr := procCredWriteW.Call(
		uintptr(unsafe.Pointer(&cred)),
		0,
	)
	if r1 == 0 {
		return fmt.Errorf("CredWriteW failed: %w", lastErr)
	}
	return nil
}

func (w *windowsNativeStore) Delete(ctx context.Context, ref credential.Ref) error {
	if w.readOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	targetPtr, err := windows.UTF16PtrFromString(w.targetName(ref))
	if err != nil {
		return fmt.Errorf("invalid target name: %w", err)
	}

	r1, _, lastErr := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0,
	)
	if r1 == 0 {
		if errno, ok := lastErr.(windows.Errno); ok && errno == errorNotFound {
			return credential.ErrCredentialNotFound
		}
		return fmt.Errorf("CredDeleteW failed: %w", lastErr)
	}
	return nil
}

func checkPlatformSystemAvailability() error {
	return nil
}
