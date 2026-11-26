//go:build darwin

package keychain

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	securityFrameworkPath       = "/System/Library/Frameworks/Security.framework/Security"
	coreFoundationFrameworkPath = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

	errSecSuccess               int32 = 0
	errSecAuthFailed            int32 = -25293
	errSecDuplicateItem         int32 = -25299
	errSecItemNotFound          int32 = -25300
	errSecInteractionNotAllowed int32 = -25308
)

type darwinSecurityBackend struct {
	once      sync.Once
	loadErr   error
	symSetUI  uintptr
	symFind   uintptr
	symAdd    uintptr
	symModify uintptr
	symDelete uintptr
	symFree   uintptr
	symCFRel  uintptr
}

func newPlatformBackend() Backend {
	return &darwinSecurityBackend{}
}

func (b *darwinSecurityBackend) ensureLoaded() error {
	b.once.Do(func() {
		secLib, err := purego.Dlopen(securityFrameworkPath, purego.RTLD_LAZY|purego.RTLD_LOCAL)
		if err != nil {
			b.loadErr = fmt.Errorf("%w: 加载 Security.framework 失败: %w", ports.ErrUnsupported, err)
			return
		}
		cfLib, err := purego.Dlopen(coreFoundationFrameworkPath, purego.RTLD_LAZY|purego.RTLD_LOCAL)
		if err != nil {
			b.loadErr = fmt.Errorf("%w: 加载 CoreFoundation.framework 失败: %w", ports.ErrUnsupported, err)
			return
		}
		b.loadErr = b.resolveSymbols(secLib, cfLib)
	})
	return b.loadErr
}

func (b *darwinSecurityBackend) resolveSymbols(secLib, cfLib uintptr) error {
	targets := []struct {
		lib  uintptr
		name string
		dst  *uintptr
	}{
		{secLib, "SecKeychainSetUserInteractionAllowed", &b.symSetUI},
		{secLib, "SecKeychainFindGenericPassword", &b.symFind},
		{secLib, "SecKeychainAddGenericPassword", &b.symAdd},
		{secLib, "SecKeychainItemModifyAttributesAndData", &b.symModify},
		{secLib, "SecKeychainItemDelete", &b.symDelete},
		{secLib, "SecKeychainItemFreeContent", &b.symFree},
		{cfLib, "CFRelease", &b.symCFRel},
	}
	for _, t := range targets {
		sym, err := purego.Dlsym(t.lib, t.name)
		if err != nil || sym == 0 {
			return fmt.Errorf("%w: 解析符号 %s 失败", ports.ErrUnsupported, t.name)
		}
		*t.dst = sym
	}
	// 无头环境下禁用系统钥匙串 GUI 弹窗，确保锁定态严格失败关闭返回 ErrVaultLocked。
	_, _, _ = purego.SyscallN(b.symSetUI, 0)
	return nil
}

func (b *darwinSecurityBackend) Read(service, account string) ([]byte, error) {
	if err := b.ensureLoaded(); err != nil {
		return nil, err
	}
	svcBytes := []byte(service)
	acctBytes := []byte(account)
	var pwdLen uint32
	var pwdPtr unsafe.Pointer
	var itemRef uintptr
	r1, _, _ := purego.SyscallN(
		b.symFind,
		0,
		uintptr(len(svcBytes)),
		bytesDataPtr(svcBytes),
		uintptr(len(acctBytes)),
		bytesDataPtr(acctBytes),
		uintptr(unsafe.Pointer(&pwdLen)),
		uintptr(unsafe.Pointer(&pwdPtr)),
		uintptr(unsafe.Pointer(&itemRef)),
	)
	runtime.KeepAlive(svcBytes)
	runtime.KeepAlive(acctBytes)
	if itemRef != 0 {
		defer func() { _, _, _ = purego.SyscallN(b.symCFRel, itemRef) }()
	}
	if pwdPtr != nil {
		defer func() { _, _, _ = purego.SyscallN(b.symFree, 0, uintptr(pwdPtr)) }()
	}
	if status := int32(r1); status != errSecSuccess {
		return nil, mapDarwinSecStatus(status)
	}
	if pwdLen == 0 || pwdPtr == nil {
		return []byte{}, nil
	}
	src := unsafe.Slice((*byte)(pwdPtr), pwdLen)
	out := make([]byte, len(src))
	copy(out, src)
	return out, nil
}

func (b *darwinSecurityBackend) Write(service, account string, box *secret.SecretBox) error {
	if err := b.ensureLoaded(); err != nil {
		return err
	}
	svcBytes := []byte(service)
	acctBytes := []byte(account)
	return box.Use(func(plain []byte) error {
		var plainPtr uintptr
		if len(plain) > 0 {
			plainPtr = uintptr(unsafe.Pointer(&plain[0]))
		}
		r1, _, _ := purego.SyscallN(
			b.symAdd,
			0,
			uintptr(len(svcBytes)),
			bytesDataPtr(svcBytes),
			uintptr(len(acctBytes)),
			bytesDataPtr(acctBytes),
			uintptr(len(plain)),
			plainPtr,
			0,
		)
		runtime.KeepAlive(svcBytes)
		runtime.KeepAlive(acctBytes)
		runtime.KeepAlive(plain)
		status := int32(r1)
		if status == errSecSuccess {
			return nil
		}
		if status != errSecDuplicateItem {
			return mapDarwinSecStatus(status)
		}
		return b.modifyExisting(svcBytes, acctBytes, plain, plainPtr)
	})
}

func (b *darwinSecurityBackend) modifyExisting(svcBytes, acctBytes, plain []byte, plainPtr uintptr) error {
	itemRef, err := b.findItemRef(svcBytes, acctBytes)
	if err != nil {
		return err
	}
	defer func() { _, _, _ = purego.SyscallN(b.symCFRel, itemRef) }()
	r1, _, _ := purego.SyscallN(b.symModify, itemRef, 0, uintptr(len(plain)), plainPtr)
	runtime.KeepAlive(plain)
	if status := int32(r1); status != errSecSuccess {
		return mapDarwinSecStatus(status)
	}
	return nil
}

func (b *darwinSecurityBackend) Delete(service, account string) error {
	if err := b.ensureLoaded(); err != nil {
		return err
	}
	itemRef, err := b.findItemRef([]byte(service), []byte(account))
	if err != nil {
		return err
	}
	defer func() { _, _, _ = purego.SyscallN(b.symCFRel, itemRef) }()
	r1, _, _ := purego.SyscallN(b.symDelete, itemRef)
	if status := int32(r1); status != errSecSuccess {
		return mapDarwinSecStatus(status)
	}
	return nil
}

func (b *darwinSecurityBackend) findItemRef(svcBytes, acctBytes []byte) (uintptr, error) {
	var itemRef uintptr
	r1, _, _ := purego.SyscallN(
		b.symFind,
		0,
		uintptr(len(svcBytes)),
		bytesDataPtr(svcBytes),
		uintptr(len(acctBytes)),
		bytesDataPtr(acctBytes),
		0,
		0,
		uintptr(unsafe.Pointer(&itemRef)),
	)
	runtime.KeepAlive(svcBytes)
	runtime.KeepAlive(acctBytes)
	if status := int32(r1); status != errSecSuccess {
		return 0, mapDarwinSecStatus(status)
	}
	if itemRef == 0 {
		return 0, ports.ErrSecretNotFound
	}
	return itemRef, nil
}

func bytesDataPtr(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[0]))
}

func mapDarwinSecStatus(status int32) error {
	switch status {
	case errSecItemNotFound:
		return ports.ErrSecretNotFound
	case errSecInteractionNotAllowed, errSecAuthFailed:
		return ports.ErrVaultLocked
	default:
		return fmt.Errorf("%w: macOS Keychain OSStatus=%d", ports.ErrUnsupported, status)
	}
}
