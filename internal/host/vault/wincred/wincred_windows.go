//go:build windows

package wincred

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/windows"
)

const (
	credTypeGeneric         uint32 = 1
	credPersistLocalMachine uint32 = 2
	winErrNotFound                 = windows.Errno(1168)
	winErrNoLogonSession           = windows.Errno(1312)
	winErrAccessDenied             = windows.Errno(5)
	maxWinCredBlobBytes            = 2560 // Windows Generic Credential 推荐上限
)

// credentialW 精确对齐 Win32 CREDENTIALW ABI（受 secrettaint/sinks_narrow_vault.go 窄钩子审计）。
type credentialW struct {
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

type winAdvapi32Backend struct {
	dll         *windows.LazyDLL
	credReadW   *windows.LazyProc
	credWriteW  *windows.LazyProc
	credDeleteW *windows.LazyProc
	credFree    *windows.LazyProc
}

func newPlatformBackend() Backend {
	dll := windows.NewLazySystemDLL("advapi32.dll")
	return &winAdvapi32Backend{
		dll:         dll,
		credReadW:   dll.NewProc("CredReadW"),
		credWriteW:  dll.NewProc("CredWriteW"),
		credDeleteW: dll.NewProc("CredDeleteW"),
		credFree:    dll.NewProc("CredFree"),
	}
}

func (b *winAdvapi32Backend) Read(target string) ([]byte, error) {
	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
	}
	var credPtr *credentialW
	r1, _, lastErr := b.credReadW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&credPtr)),
	)
	runtime.KeepAlive(targetPtr)
	if r1 == 0 {
		return nil, mapWinCredError(lastErr)
	}
	defer func() {
		_, _, _ = b.credFree.Call(uintptr(unsafe.Pointer(credPtr)))
	}()
	if credPtr == nil || credPtr.CredentialBlobSize == 0 || credPtr.CredentialBlob == nil {
		return []byte{}, nil
	}
	src := unsafe.Slice(credPtr.CredentialBlob, credPtr.CredentialBlobSize)
	out := make([]byte, len(src))
	copy(out, src)
	return out, nil
}

func (b *winAdvapi32Backend) Write(target, user string, box *secret.SecretBox) error {
	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
	}
	userPtr, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
	}
	return box.Use(func(plain []byte) error {
		if len(plain) > maxWinCredBlobBytes {
			return fmt.Errorf("%w: Windows Credential 字节长度超出上限 %d", ports.ErrLimitExceeded, maxWinCredBlobBytes)
		}
		// 复制为本作用域自持独立切片，满足 linearlease 借用零别名不变量，同时仍完整受 secrettaint 污点审计并立即 clear 零化。
		localBlob := bytes.Clone(plain)
		defer clear(localBlob)
		var cred credentialW
		cred.Type = credTypeGeneric
		cred.TargetName = targetPtr
		cred.UserName = userPtr
		cred.Persist = credPersistLocalMachine
		cred.CredentialBlobSize = uint32(len(localBlob))
		if len(localBlob) > 0 {
			cred.CredentialBlob = &localBlob[0]
		}
		r1, _, lastErr := b.credWriteW.Call(uintptr(unsafe.Pointer(&cred)), 0)
		runtime.KeepAlive(targetPtr)
		runtime.KeepAlive(userPtr)
		runtime.KeepAlive(&cred)
		runtime.KeepAlive(localBlob)
		if r1 == 0 {
			return mapWinCredError(lastErr)
		}
		return nil
	})
}

func (b *winAdvapi32Backend) Delete(target string) error {
	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
	}
	r1, _, lastErr := b.credDeleteW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0,
	)
	runtime.KeepAlive(targetPtr)
	if r1 == 0 {
		return mapWinCredError(lastErr)
	}
	return nil
}

func mapWinCredError(err error) error {
	if errno, ok := errors.AsType[windows.Errno](err); ok {
		switch errno {
		case winErrNotFound:
			return ports.ErrSecretNotFound
		case winErrNoLogonSession:
			return ports.ErrVaultLocked
		case winErrAccessDenied:
			return ports.ErrPermissionDenied
		}
	}
	return fmt.Errorf("%w: Windows Credential Manager 调用失败", ports.ErrUnsupported)
}
