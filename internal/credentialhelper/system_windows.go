//go:build windows

package credentialhelper

import (
	"encoding/base64"
	"errors"
	"fmt"
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

func newNativeSystemStore(storeID string, cfg SystemStoreConfig) (credential.Store, error) {
	cmdPath, args, env, err := resolveControlledSystemHelper()
	if err != nil {
		return nil, fmt.Errorf("resolve controlled system helper: %w", err)
	}

	mergedEnv := append([]string{}, env...)
	mergedEnv = append(mergedEnv, cfg.Env...)

	opts := ProcessOptions{
		NonInteractive: true,
		Command:        cmdPath,
		Args:           args,
		Env:            mergedEnv,
		Timeout:        cfg.Timeout,
	}

	return NewHelperStore(storeID, opts, cfg.ReadOnly)
}

func windowsActionGet(targetPtr *uint16) (*Response, int) {
	var credPtr *windowsCredential
	r1, _, lastErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&credPtr)),
	)
	if r1 == 0 {
		var errno windows.Errno
		if errors.As(lastErr, &errno) && errno == errorNotFound {
			return &Response{Code: "not-found", Message: "credential not found"}, 1
		}
		if errors.As(lastErr, &errno) && (errno == errorAccessDenied || errno == errorNoSuchLogonSession) {
			return &Response{Code: "denied", Message: "access denied"}, 1
		}
		return &Response{Code: "unavailable", Message: lastErr.Error()}, 1
	}
	defer func() {
		_, _, _ = procCredFree.Call(uintptr(unsafe.Pointer(credPtr)))
	}()

	if credPtr.CredentialBlobSize == 0 || credPtr.CredentialBlob == nil {
		return &Response{Code: "not-found", Message: "credential empty"}, 1
	}

	blob := unsafe.Slice(credPtr.CredentialBlob, credPtr.CredentialBlobSize)
	return &Response{
		Secret: base64.StdEncoding.EncodeToString(blob),
	}, 0
}

func windowsActionStore(targetPtr *uint16, rawSecret string) (*Response, int) {
	if rawSecret == "" {
		return &Response{Code: "unavailable", Message: "secret is empty"}, 1
	}
	secretBytes, err := base64.StdEncoding.DecodeString(rawSecret)
	if err != nil {
		return &Response{Code: "unavailable", Message: "invalid base64 secret"}, 1
	}

	var blobPtr *byte
	if len(secretBytes) > 0 {
		blobPtr = &secretBytes[0]
	}

	cred := windowsCredential{
		Flags:              0,
		Type:               credTypeGeneric,
		TargetName:         targetPtr,
		Persist:            credPersistLocalMachine,
		CredentialBlobSize: uint32(len(secretBytes)),
		CredentialBlob:     blobPtr,
	}

	r1, _, lastErr := procCredWriteW.Call(
		uintptr(unsafe.Pointer(&cred)),
		0,
	)
	if r1 == 0 {
		return &Response{Code: "unavailable", Message: lastErr.Error()}, 1
	}
	return &Response{}, 0
}

func windowsActionErase(targetPtr *uint16) (*Response, int) {
	r1, _, lastErr := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0,
	)
	if r1 == 0 {
		var errno windows.Errno
		if errors.As(lastErr, &errno) && errno == errorNotFound {
			return &Response{Code: "not-found", Message: "credential not found"}, 1
		}
		return &Response{Code: "unavailable", Message: lastErr.Error()}, 1
	}
	return &Response{}, 0
}

func handlePlatformSystemHelper(action Action, req *Request) (*Response, int) {
	if req == nil {
		return &Response{Code: "unavailable", Message: "nil request"}, 1
	}

	targetName := fmt.Sprintf("xops:%s/%s", req.StoreID, req.ItemID)
	targetPtr, err := windows.UTF16PtrFromString(targetName)
	if err != nil {
		return &Response{Code: "unavailable", Message: err.Error()}, 1
	}

	switch action {
	case ActionGet:
		return windowsActionGet(targetPtr)
	case ActionStore:
		return windowsActionStore(targetPtr, req.Secret)
	case ActionErase:
		return windowsActionErase(targetPtr)
	default:
		return &Response{Code: "unavailable", Message: "unsupported action"}, 1
	}
}

func checkPlatformSystemAvailability() error {
	return nil
}
