//go:build darwin

package credentialhelper

import (
	"encoding/base64"
	"testing"
	"unsafe"
)

func stubDarwinAPIs(t *testing.T) {
	t.Helper()
	origFind := secKeychainFindGenericPassword
	origAdd := secKeychainAddGenericPassword
	origMod := secKeychainItemModifyAttributesAndData
	origDel := secKeychainItemDelete
	origRelease := cfRelease
	origInitErr := darwinKeychainInitErr

	// 强制认为 init 已成功
	darwinKeychainInitOnce.Do(func() {})
	darwinKeychainInitErr = nil
	cfRelease = func(_ uintptr) {}

	t.Cleanup(func() {
		secKeychainFindGenericPassword = origFind
		secKeychainAddGenericPassword = origAdd
		secKeychainItemModifyAttributesAndData = origMod
		secKeychainItemDelete = origDel
		cfRelease = origRelease
		darwinKeychainInitErr = origInitErr
	})
}

func TestDarwinNativeHelper_DuplicateConflictRetryFindLocked(t *testing.T) {
	stubDarwinAPIs(t)

	// 模拟首次查找未找到 (返回 errSecItemNotFound)
	// 随后尝试 AddGenericPassword 遇到并发冲突 (返回 errSecDuplicateItem)
	// 紧接着重试查找时返回锁住 (errSecAuthFailed)
	findCallCount := 0
	secKeychainFindGenericPassword = func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength *uint32,
		passwordData *unsafe.Pointer,
		itemRef *uintptr,
	) int32 {
		findCallCount++
		if findCallCount == 1 {
			return errSecItemNotFound
		}
		return errSecAuthFailed
	}

	secKeychainAddGenericPassword = func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength uint32,
		passwordData unsafe.Pointer,
		itemRef *uintptr,
	) int32 {
		return errSecDuplicateItem
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
		Secret:          base64.StdEncoding.EncodeToString([]byte("val")),
	}

	resp, code := handlePlatformSystemHelper(ActionStore, req)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when retry find is locked")
	}
	if resp.Code != "locked" {
		t.Fatalf("expected code 'locked', got %q (msg: %s)", resp.Code, resp.Message)
	}
}

func TestDarwinNativeHelper_DuplicateConflictRetryModDenied(t *testing.T) {
	stubDarwinAPIs(t)

	findCallCount := 0
	secKeychainFindGenericPassword = func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength *uint32,
		passwordData *unsafe.Pointer,
		itemRef *uintptr,
	) int32 {
		findCallCount++
		if findCallCount == 1 {
			return errSecItemNotFound
		}
		if itemRef != nil {
			*itemRef = 0x1234
		}
		return errSecSuccess
	}

	secKeychainAddGenericPassword = func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength uint32,
		passwordData unsafe.Pointer,
		itemRef *uintptr,
	) int32 {
		return errSecDuplicateItem
	}

	// 模拟修改时被拒绝
	secKeychainItemModifyAttributesAndData = func(
		itemRef uintptr,
		attrList uintptr,
		length uint32,
		data unsafe.Pointer,
	) int32 {
		return errSecInteractionNotAllowed
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
		Secret:          base64.StdEncoding.EncodeToString([]byte("val")),
	}

	resp, code := handlePlatformSystemHelper(ActionStore, req)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when retry mod is denied")
	}
	if resp.Code != "locked" {
		t.Fatalf("expected code 'locked', got %q (msg: %s)", resp.Code, resp.Message)
	}
}

func TestDarwinNativeHelper_DuplicateConflictRetryModError(t *testing.T) {
	stubDarwinAPIs(t)

	findCallCount := 0
	secKeychainFindGenericPassword = func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength *uint32,
		passwordData *unsafe.Pointer,
		itemRef *uintptr,
	) int32 {
		findCallCount++
		if findCallCount == 1 {
			return errSecItemNotFound
		}
		if itemRef != nil {
			*itemRef = 0x1234
		}
		return errSecSuccess
	}

	secKeychainAddGenericPassword = func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength uint32,
		passwordData unsafe.Pointer,
		itemRef *uintptr,
	) int32 {
		return errSecDuplicateItem
	}

	secKeychainItemModifyAttributesAndData = func(
		itemRef uintptr,
		attrList uintptr,
		length uint32,
		data unsafe.Pointer,
	) int32 {
		return -1 // 模拟非零系统错误
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
		Secret:          base64.StdEncoding.EncodeToString([]byte("val")),
	}

	resp, code := handlePlatformSystemHelper(ActionStore, req)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when retry mod fails")
	}
	if resp.Code != "unavailable" {
		t.Fatalf("expected code 'unavailable', got %q (msg: %s)", resp.Code, resp.Message)
	}
}

func TestDarwinNativeHelper_DuplicateConflictRetrySuccess(t *testing.T) {
	stubDarwinAPIs(t)

	findCallCount := 0
	secKeychainFindGenericPassword = func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength *uint32,
		passwordData *unsafe.Pointer,
		itemRef *uintptr,
	) int32 {
		findCallCount++
		if findCallCount == 1 {
			return errSecItemNotFound
		}
		if itemRef != nil {
			*itemRef = 0x1234
		}
		return errSecSuccess
	}

	secKeychainAddGenericPassword = func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength uint32,
		passwordData unsafe.Pointer,
		itemRef *uintptr,
	) int32 {
		return errSecDuplicateItem
	}

	modCalled := false
	secKeychainItemModifyAttributesAndData = func(
		itemRef uintptr,
		attrList uintptr,
		length uint32,
		data unsafe.Pointer,
	) int32 {
		modCalled = true
		return errSecSuccess
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
		Secret:          base64.StdEncoding.EncodeToString([]byte("val")),
	}

	resp, code := handlePlatformSystemHelper(ActionStore, req)
	if code != 0 {
		t.Fatalf("expected exit code 0 on successful retry, got %d (code=%s, msg=%s)", code, resp.Code, resp.Message)
	}
	if !modCalled {
		t.Fatal("expected secKeychainItemModifyAttributesAndData to be called during retry")
	}
}
