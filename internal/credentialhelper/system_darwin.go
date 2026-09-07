//go:build darwin

package credentialhelper

import (
	"encoding/base64"
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/wentf9/xops-cli/pkg/credential"
)

const (
	errSecSuccess               int32 = 0
	errSecItemNotFound          int32 = -25300
	errSecDuplicateItem         int32 = -25299
	errSecAuthFailed            int32 = -25293
	errSecInteractionNotAllowed int32 = -25308
)

var (
	darwinKeychainInitOnce sync.Once
	darwinKeychainInitErr  error

	secKeychainFindGenericPassword func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength *uint32,
		passwordData *unsafe.Pointer,
		itemRef *uintptr,
	) int32

	secKeychainItemFreeContent func(
		attrList uintptr,
		data unsafe.Pointer,
	) int32

	secKeychainAddGenericPassword func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength uint32,
		passwordData unsafe.Pointer,
		itemRef *uintptr,
	) int32

	secKeychainItemModifyAttributesAndData func(
		itemRef uintptr,
		attrList uintptr,
		length uint32,
		data unsafe.Pointer,
	) int32

	secKeychainItemDelete func(
		itemRef uintptr,
	) int32

	cfRelease func(
		cf uintptr,
	)
)

func initDarwinKeychainAPIs() error {
	darwinKeychainInitOnce.Do(func() {
		secHandle, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_GLOBAL)
		if err != nil {
			darwinKeychainInitErr = fmt.Errorf("dlopen Security framework: %w", err)
			return
		}

		cfHandle, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_GLOBAL)
		if err != nil {
			darwinKeychainInitErr = fmt.Errorf("dlopen CoreFoundation framework: %w", err)
			return
		}

		purego.RegisterLibFunc(&secKeychainFindGenericPassword, secHandle, "SecKeychainFindGenericPassword")
		purego.RegisterLibFunc(&secKeychainItemFreeContent, secHandle, "SecKeychainItemFreeContent")
		purego.RegisterLibFunc(&secKeychainAddGenericPassword, secHandle, "SecKeychainAddGenericPassword")
		purego.RegisterLibFunc(&secKeychainItemModifyAttributesAndData, secHandle, "SecKeychainItemModifyAttributesAndData")
		purego.RegisterLibFunc(&secKeychainItemDelete, secHandle, "SecKeychainItemDelete")
		purego.RegisterLibFunc(&cfRelease, cfHandle, "CFRelease")
	})
	return darwinKeychainInitErr
}

func newNativeSystemStore(storeID string, cfg SystemStoreConfig) (credential.Store, error) {
	cmdPath, args, env, err := resolveControlledSystemHelper()
	if err != nil {
		return nil, fmt.Errorf("resolve controlled system helper: %w", err)
	}

	opts := ProcessOptions{
		Command: cmdPath,
		Args:    args,
		Env:     env,
		Timeout: cfg.Timeout,
	}

	return NewHelperStore(storeID, opts, cfg.ReadOnly)
}

func handlePlatformSystemHelper(action Action, req *Request) (*Response, int) {
	if req == nil {
		return &Response{Code: "unavailable", Message: "nil request"}, 1
	}

	if err := initDarwinKeychainAPIs(); err != nil {
		return &Response{Code: "unavailable", Message: err.Error()}, 1
	}

	service := fmt.Sprintf("xops:%s", req.StoreID)
	account := req.ItemID

	serviceBytes := []byte(service)
	accountBytes := []byte(account)

	var servicePtr *byte
	if len(serviceBytes) > 0 {
		servicePtr = &serviceBytes[0]
	}
	var accountPtr *byte
	if len(accountBytes) > 0 {
		accountPtr = &accountBytes[0]
	}

	switch action {
	case ActionGet:
		var pwLen uint32
		var pwData unsafe.Pointer
		var itemRef uintptr

		status := secKeychainFindGenericPassword(
			0,
			uint32(len(serviceBytes)),
			servicePtr,
			uint32(len(accountBytes)),
			accountPtr,
			&pwLen,
			&pwData,
			&itemRef,
		)
		if itemRef != 0 {
			defer cfRelease(itemRef)
		}

		if status == errSecItemNotFound {
			return &Response{Code: "not-found", Message: "credential not found"}, 1
		}
		if status == errSecAuthFailed || status == errSecInteractionNotAllowed {
			return &Response{Code: "locked", Message: "keychain locked or user interaction not allowed"}, 1
		}
		if status != errSecSuccess {
			return &Response{Code: "unavailable", Message: fmt.Sprintf("SecKeychainFindGenericPassword failed with status %d", status)}, 1
		}
		if pwData == nil {
			return &Response{Code: "not-found", Message: "empty credential"}, 1
		}
		defer secKeychainItemFreeContent(0, pwData)

		if pwLen > MaxResponseBytes {
			return &Response{Code: "unavailable", Message: fmt.Sprintf("credential size %d exceeds limit", pwLen)}, 1
		}

		rawBytes := unsafe.Slice((*byte)(pwData), pwLen)
		copied := make([]byte, pwLen)
		copy(copied, rawBytes)

		return &Response{
			Secret: base64.StdEncoding.EncodeToString(copied),
		}, 0

	case ActionStore:
		if req.Secret == "" {
			return &Response{Code: "unavailable", Message: "secret is empty"}, 1
		}
		secretBytes, err := base64.StdEncoding.DecodeString(req.Secret)
		if err != nil {
			return &Response{Code: "unavailable", Message: "invalid base64 secret"}, 1
		}

		var secretPtr unsafe.Pointer
		if len(secretBytes) > 0 {
			secretPtr = unsafe.Pointer(&secretBytes[0])
		}

		// 检查是否存在同名条目
		var existingItemRef uintptr
		findStatus := secKeychainFindGenericPassword(
			0,
			uint32(len(serviceBytes)),
			servicePtr,
			uint32(len(accountBytes)),
			accountPtr,
			nil,
			nil,
			&existingItemRef,
		)
		if findStatus == errSecSuccess && existingItemRef != 0 {
			defer cfRelease(existingItemRef)
			modStatus := secKeychainItemModifyAttributesAndData(
				existingItemRef,
				0,
				uint32(len(secretBytes)),
				secretPtr,
			)
			if modStatus == errSecAuthFailed || modStatus == errSecInteractionNotAllowed {
				return &Response{Code: "locked", Message: "keychain locked or update denied"}, 1
			}
			if modStatus != errSecSuccess {
				return &Response{Code: "unavailable", Message: fmt.Sprintf("SecKeychainItemModifyAttributesAndData failed: %d", modStatus)}, 1
			}
			return &Response{}, 0
		}

		var newItemRef uintptr
		addStatus := secKeychainAddGenericPassword(
			0,
			uint32(len(serviceBytes)),
			servicePtr,
			uint32(len(accountBytes)),
			accountPtr,
			uint32(len(secretBytes)),
			secretPtr,
			&newItemRef,
		)
		if newItemRef != 0 {
			defer cfRelease(newItemRef)
		}
		if addStatus == errSecDuplicateItem {
			// 若并发写入导致冲突，再次更新
			var retryItemRef uintptr
			if secKeychainFindGenericPassword(0, uint32(len(serviceBytes)), servicePtr, uint32(len(accountBytes)), accountPtr, nil, nil, &retryItemRef) == errSecSuccess && retryItemRef != 0 {
				defer cfRelease(retryItemRef)
				_ = secKeychainItemModifyAttributesAndData(retryItemRef, 0, uint32(len(secretBytes)), secretPtr)
			}
			return &Response{}, 0
		}
		if addStatus == errSecAuthFailed || addStatus == errSecInteractionNotAllowed {
			return &Response{Code: "locked", Message: "keychain locked or add denied"}, 1
		}
		if addStatus != errSecSuccess {
			return &Response{Code: "unavailable", Message: fmt.Sprintf("SecKeychainAddGenericPassword failed: %d", addStatus)}, 1
		}
		return &Response{}, 0

	case ActionErase:
		var itemRef uintptr
		status := secKeychainFindGenericPassword(
			0,
			uint32(len(serviceBytes)),
			servicePtr,
			uint32(len(accountBytes)),
			accountPtr,
			nil,
			nil,
			&itemRef,
		)
		if status == errSecItemNotFound {
			return &Response{Code: "not-found", Message: "credential not found"}, 1
		}
		if status != errSecSuccess {
			return &Response{Code: "unavailable", Message: fmt.Sprintf("find item failed: %d", status)}, 1
		}
		defer cfRelease(itemRef)

		delStatus := secKeychainItemDelete(itemRef)
		if delStatus == errSecItemNotFound {
			return &Response{Code: "not-found", Message: "credential not found"}, 1
		}
		if delStatus == errSecAuthFailed || delStatus == errSecInteractionNotAllowed {
			return &Response{Code: "locked", Message: "keychain locked"}, 1
		}
		if delStatus != errSecSuccess {
			return &Response{Code: "unavailable", Message: fmt.Sprintf("SecKeychainItemDelete failed: %d", delStatus)}, 1
		}
		return &Response{}, 0

	default:
		return &Response{Code: "unavailable", Message: "unsupported action"}, 1
	}
}

func checkPlatformSystemAvailability() error {
	return nil
}
