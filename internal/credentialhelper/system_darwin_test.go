//go:build darwin

package credentialhelper

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func stubDarwinAPIs(t *testing.T) *darwinKeychainAPI {
	t.Helper()
	mock := &darwinKeychainAPI{
		setUserInteractionAllowed: func(_ uint8) int32 {
			return errSecSuccess
		},
		findGenericPassword: func(_ uintptr, _ uint32, _ *byte, _ uint32, _ *byte, _ *uint32, _ *unsafe.Pointer, _ *uintptr) int32 {
			return errSecItemNotFound
		},
		itemFreeContent: func(_ uintptr, _ unsafe.Pointer) int32 {
			return errSecSuccess
		},
		addGenericPassword: func(_ uintptr, _ uint32, _ *byte, _ uint32, _ *byte, _ uint32, _ unsafe.Pointer, _ *uintptr) int32 {
			return errSecSuccess
		},
		itemModifyAttributesAndData: func(_ uintptr, _ uintptr, _ uint32, _ unsafe.Pointer) int32 {
			return errSecSuccess
		},
		itemDelete: func(_ uintptr) int32 {
			return errSecSuccess
		},
		itemCopyKeychain: func(_ uintptr, keychainRef *uintptr) int32 {
			if keychainRef != nil {
				*keychainRef = 0x2000
			}
			return errSecSuccess
		},
		copySearchList: func(searchList *uintptr) int32 {
			if searchList != nil {
				*searchList = 0x3000
			}
			return errSecSuccess
		},
		copyDomainSearchList: func(_ uint32, searchList *uintptr) int32 {
			if searchList != nil {
				*searchList = 0x3000
			}
			return errSecSuccess
		},
		keychainGetStatus: func(_ uintptr, status *uint32) int32 {
			if status != nil {
				*status = kSecUnlockStateStatus // 默认解锁
			}
			return errSecSuccess
		},
		cfArrayGetCount: func(_ uintptr) int {
			return 1
		},
		cfArrayGetValueAtIndex: func(_ uintptr, idx int) uintptr {
			if idx == 0 {
				return 0x2000
			}
			return 0
		},
		cfRelease: func(_ uintptr) {},
	}

	setDarwinMockAPI(mock)
	t.Cleanup(clearDarwinMockAPI)
	return mock
}

func TestDarwinNativeHelper_DuplicateConflictRetryFindLocked(t *testing.T) {
	mock := stubDarwinAPIs(t)

	findCallCount := 0
	mock.findGenericPassword = func(
		_ uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ *uint32,
		_ *unsafe.Pointer,
		_ *uintptr,
	) int32 {
		findCallCount++
		if findCallCount == 1 {
			return errSecItemNotFound
		}
		return errSecAuthFailed
	}

	addCalled := false
	mock.addGenericPassword = func(
		_ uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ uint32,
		_ unsafe.Pointer,
		_ *uintptr,
	) int32 {
		addCalled = true
		return errSecDuplicateItem
	}

	// 初始定位与写入阶段解锁，触发冲突进入重试定位阶段时模拟钥匙串锁定
	mock.keychainGetStatus = func(_ uintptr, status *uint32) int32 {
		if status != nil {
			if addCalled {
				*status = 0 // 重试阶段钥匙串锁定
			} else {
				*status = kSecUnlockStateStatus // 初始阶段解锁
			}
		}
		return errSecSuccess
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
	if !addCalled {
		t.Fatalf("expected addGenericPassword to be called and return errSecDuplicateItem before retry")
	}
	if resp.Code != "locked" {
		t.Fatalf("expected code 'locked', got %q (msg: %s)", resp.Code, resp.Message)
	}
	mappedErr := MapErrorCode(resp.Code, resp.Message)
	if !errors.Is(mappedErr, credential.ErrCredentialStoreLocked) {
		t.Fatalf("expected ErrCredentialStoreLocked, got: %v", mappedErr)
	}
}

func TestDarwinNativeHelper_DuplicateConflictRetryModDenied(t *testing.T) {
	mock := stubDarwinAPIs(t)

	findCallCount := 0
	mock.findGenericPassword = func(
		_ uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ *uint32,
		_ *unsafe.Pointer,
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

	addCalled := false
	mock.addGenericPassword = func(
		_ uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ uint32,
		_ unsafe.Pointer,
		_ *uintptr,
	) int32 {
		addCalled = true
		return errSecDuplicateItem
	}

	modCalled := false
	mock.itemModifyAttributesAndData = func(
		_ uintptr,
		_ uintptr,
		_ uint32,
		_ unsafe.Pointer,
	) int32 {
		modCalled = true
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
	if !addCalled {
		t.Fatalf("expected addGenericPassword to be called and return errSecDuplicateItem before retry")
	}
	if !modCalled {
		t.Fatalf("expected itemModifyAttributesAndData to be called during retry")
	}
	if resp.Code != "denied" {
		t.Fatalf("expected code 'denied', got %q (msg: %s)", resp.Code, resp.Message)
	}
	mappedErr := MapErrorCode(resp.Code, resp.Message)
	if !errors.Is(mappedErr, credential.ErrCredentialAccessDenied) {
		t.Fatalf("expected ErrCredentialAccessDenied, got: %v", mappedErr)
	}
}

func TestDarwinNativeHelper_SignatureChangedAccessDenied(t *testing.T) {
	mock := stubDarwinAPIs(t)

	mock.findGenericPassword = func(
		_ uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ *uint32,
		_ *unsafe.Pointer,
		_ *uintptr,
	) int32 {
		return errSecAuthFailed
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
	}

	resp, code := handlePlatformSystemHelper(ActionGet, req)
	if code == 0 {
		t.Fatalf("expected non-zero exit code on access denied / signature mismatch")
	}
	if resp.Code != "denied" {
		t.Fatalf("expected code 'denied', got %q (msg: %s)", resp.Code, resp.Message)
	}

	mappedErr := MapErrorCode(resp.Code, resp.Message)
	if !errors.Is(mappedErr, credential.ErrCredentialAccessDenied) {
		t.Fatalf("expected ErrCredentialAccessDenied, got: %v", mappedErr)
	}
}

func TestDarwinNativeHelper_FindIOErrorNotReportedAsNotFound(t *testing.T) {
	mock := stubDarwinAPIs(t)

	// 模拟底层的 I/O 故障 (errSecIO = -36)
	mock.findGenericPassword = func(
		_ uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ *uint32,
		_ *unsafe.Pointer,
		_ *uintptr,
	) int32 {
		return errSecIO
	}

	addCalled := false
	mock.addGenericPassword = func(
		_ uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ uint32,
		_ unsafe.Pointer,
		_ *uintptr,
	) int32 {
		addCalled = true
		return errSecSuccess
	}

	deleteCalled := false
	mock.itemDelete = func(_ uintptr) int32 {
		deleteCalled = true
		return errSecSuccess
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
		Secret:          base64.StdEncoding.EncodeToString([]byte("secret-payload")),
	}

	// 1. Get 操作：遇到 I/O 错误必须归类为 unavailable，绝对不能误报为 not-found
	respGet, codeGet := handlePlatformSystemHelper(ActionGet, req)
	if codeGet == 0 {
		t.Fatalf("expected non-zero exit code on I/O error during Get")
	}
	if respGet.Code != "unavailable" {
		t.Fatalf("expected code 'unavailable' on I/O error, got %q (msg: %s)", respGet.Code, respGet.Message)
	}
	if respGet.Code == "not-found" {
		t.Fatalf("query error was swallowed and incorrectly reported as not-found")
	}

	// 2. Store 操作：查询失败无法确认条目是否存在，必须失败关闭，严禁向默认钥匙串新建条目
	respStore, codeStore := handlePlatformSystemHelper(ActionStore, req)
	if codeStore == 0 {
		t.Fatalf("expected non-zero exit code on I/O error during Store")
	}
	if respStore.Code != "unavailable" {
		t.Fatalf("expected code 'unavailable' on I/O error during Store, got %q (msg: %s)", respStore.Code, respStore.Message)
	}
	if addCalled {
		t.Fatalf("addGenericPassword was called despite I/O error during locateItem")
	}

	// 3. Erase 操作：查询失败必须返回 unavailable，严禁误报为 not-found 或执行删除
	respErase, codeErase := handlePlatformSystemHelper(ActionErase, req)
	if codeErase == 0 {
		t.Fatalf("expected non-zero exit code on I/O error during Erase")
	}
	if respErase.Code != "unavailable" {
		t.Fatalf("expected code 'unavailable' on I/O error during Erase, got %q (msg: %s)", respErase.Code, respErase.Message)
	}
	if deleteCalled {
		t.Fatalf("itemDelete was called despite I/O error during Erase")
	}
}

func TestDarwinNativeHelper_StoreFailsClosedWhenSearchListHasLockedKeychain(t *testing.T) {
	mock := stubDarwinAPIs(t)

	kcUnlocked := uintptr(0x2001)
	kcLocked := uintptr(0x2002)

	mock.copySearchList = func(searchList *uintptr) int32 {
		if searchList != nil {
			*searchList = 0x9000
		}
		return errSecSuccess
	}
	mock.cfArrayGetCount = func(arr uintptr) int {
		if arr == 0x9000 {
			return 2
		}
		return 0
	}
	mock.cfArrayGetValueAtIndex = func(arr uintptr, idx int) uintptr {
		if arr == 0x9000 {
			if idx == 0 {
				return kcUnlocked
			}
			if idx == 1 {
				return kcLocked
			}
		}
		return 0
	}

	mock.keychainGetStatus = func(kc uintptr, status *uint32) int32 {
		if status == nil {
			return errSecSuccess
		}
		switch kc {
		case kcUnlocked:
			*status = kSecUnlockStateStatus // 默认/首个钥匙串解锁
		case kcLocked:
			*status = 0 // 次级钥匙串锁定
		}
		return errSecSuccess
	}

	// 解锁的钥匙串返回 not-found
	mock.findGenericPassword = func(
		kc uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ *uint32,
		_ *unsafe.Pointer,
		_ *uintptr,
	) int32 {
		if kc == kcUnlocked {
			return errSecItemNotFound
		}
		t.Fatalf("findGenericPassword should not be called for locked keychain 0x%x", kc)
		return errSecAuthFailed
	}

	addCalled := false
	mock.addGenericPassword = func(
		_ uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ uint32,
		_ unsafe.Pointer,
		_ *uintptr,
	) int32 {
		addCalled = true
		return errSecSuccess
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "shadow-test",
		Secret:          base64.StdEncoding.EncodeToString([]byte("shadow-val")),
	}

	// 核心断言：由于搜索列表中存在锁定的钥匙串，无法确认条目是否存在于锁定库中，
	// 此时 Store 操作必须严格失败关闭 (locked)，严禁盲目向默认库添加同名条目造成条目遮蔽！
	resp, code := handlePlatformSystemHelper(ActionStore, req)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when search list contains locked keychain")
	}
	if resp.Code != "locked" {
		t.Fatalf("expected code 'locked', got %q (msg: %s)", resp.Code, resp.Message)
	}
	if addCalled {
		t.Fatalf("addGenericPassword was called and would shadow existing item in locked keychain!")
	}

	mappedErr := MapErrorCode(resp.Code, resp.Message)
	if !errors.Is(mappedErr, credential.ErrCredentialStoreLocked) {
		t.Fatalf("expected ErrCredentialStoreLocked, got: %v", mappedErr)
	}

	// 同样，Erase 操作也必须失败关闭 (locked)，不可误报 not-found
	respErase, codeErase := handlePlatformSystemHelper(ActionErase, req)
	if codeErase == 0 {
		t.Fatalf("expected non-zero exit code on Erase when search list contains locked keychain")
	}
	if respErase.Code != "locked" {
		t.Fatalf("expected code 'locked' on Erase, got %q (msg: %s)", respErase.Code, respErase.Message)
	}
}

func TestDarwinNativeHelper_ReadOnlyKeychain(t *testing.T) {
	mock := stubDarwinAPIs(t)

	mock.addGenericPassword = func(
		_ uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ uint32,
		_ unsafe.Pointer,
		_ *uintptr,
	) int32 {
		return errSecReadOnly
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
		Secret:          base64.StdEncoding.EncodeToString([]byte("val")),
	}

	resp, code := handlePlatformSystemHelper(ActionStore, req)
	if code == 0 {
		t.Fatalf("expected non-zero exit code on read-only keychain")
	}
	if resp.Code != "read-only" {
		t.Fatalf("expected code 'read-only', got %q (msg: %s)", resp.Code, resp.Message)
	}

	mappedErr := MapErrorCode(resp.Code, resp.Message)
	if !errors.Is(mappedErr, credential.ErrCredentialStoreReadOnly) {
		t.Fatalf("expected ErrCredentialStoreReadOnly, got: %v", mappedErr)
	}
}

func TestDarwinNativeHelper_SetUserInteractionAllowedFailure(t *testing.T) {
	mock := stubDarwinAPIs(t)
	mock.setUserInteractionAllowed = func(_ uint8) int32 {
		return -1
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
	}

	resp, code := handlePlatformSystemHelper(ActionGet, req)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when setUserInteractionAllowed fails")
	}
	if resp.Code != "unavailable" {
		t.Fatalf("expected code 'unavailable', got %q", resp.Code)
	}
	if !strings.Contains(resp.Message, "SecKeychainSetUserInteractionAllowed failed") {
		t.Fatalf("expected message to mention SecKeychainSetUserInteractionAllowed failed, got %q", resp.Message)
	}
}

func TestDarwinNativeHelper_MultiKeychainLockedClassification(t *testing.T) {
	mock := stubDarwinAPIs(t)

	mock.copySearchList = func(searchList *uintptr) int32 {
		if searchList != nil {
			*searchList = 0x8888
		}
		return errSecSuccess
	}
	mock.cfArrayGetCount = func(arr uintptr) int {
		if arr == 0x8888 {
			return 2
		}
		return 0
	}
	mock.cfArrayGetValueAtIndex = func(arr uintptr, idx int) uintptr {
		if arr == 0x8888 {
			switch idx {
			case 0:
				return 0x1000
			case 1:
				return 0x2000
			}
		}
		return 0
	}
	mock.keychainGetStatus = func(kc uintptr, status *uint32) int32 {
		if status != nil {
			switch kc {
			case 0, 0x1000:
				*status = kSecUnlockStateStatus // 默认/KC1 解锁
			case 0x2000:
				*status = 0 // KC2 锁定
			}
		}
		return errSecSuccess
	}

	mock.findGenericPassword = func(kc uintptr, _ uint32, _ *byte, _ uint32, _ *byte, _ *uint32, _ *unsafe.Pointer, _ *uintptr) int32 {
		if kc == 0x1000 {
			return errSecItemNotFound // KC1 解锁但无此条目
		}
		return errSecInteractionNotAllowed
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
	}

	resp, code := handlePlatformSystemHelper(ActionGet, req)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when search list has locked keychain")
	}
	if resp.Code != "locked" {
		t.Fatalf("expected code 'locked', got %q (msg: %s)", resp.Code, resp.Message)
	}
	mappedErr := MapErrorCode(resp.Code, resp.Message)
	if !errors.Is(mappedErr, credential.ErrCredentialStoreLocked) {
		t.Fatalf("expected ErrCredentialStoreLocked, got: %v", mappedErr)
	}
}

func TestDarwinNativeHelper_MultiKeychainTargetUnlockedACLDeniedWithUnrelatedLocked(t *testing.T) {
	mock := stubDarwinAPIs(t)

	// KC1 (0x1000): 目标条目所在库，已解锁
	// KC2 (0x2000): 无关库，已锁定
	mock.copySearchList = func(searchList *uintptr) int32 {
		if searchList != nil {
			*searchList = 0x8888
		}
		return errSecSuccess
	}
	mock.cfArrayGetCount = func(arr uintptr) int {
		if arr == 0x8888 {
			return 2
		}
		return 0
	}
	mock.cfArrayGetValueAtIndex = func(arr uintptr, idx int) uintptr {
		if arr == 0x8888 {
			switch idx {
			case 0:
				return 0x1000
			case 1:
				return 0x2000
			}
		}
		return 0
	}
	mock.keychainGetStatus = func(kc uintptr, status *uint32) int32 {
		if status != nil {
			switch kc {
			case 0, 0x1000:
				*status = kSecUnlockStateStatus // KC1 解锁
			case 0x2000:
				*status = 0 // KC2 锁定
			}
		}
		return errSecSuccess
	}

	mock.findGenericPassword = func(kc uintptr, _ uint32, _ *byte, _ uint32, _ *byte, pwLen *uint32, pwData *unsafe.Pointer, itemRef *uintptr) int32 {
		if kc == 0x1000 {
			if pwLen == nil && pwData == nil && itemRef != nil {
				*itemRef = 0x7777 // 定位阶段成功返回引用
				return errSecSuccess
			}
			return errSecInteractionNotAllowed // 读数据阶段触发 ACL 拒绝
		}
		return errSecItemNotFound
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
	}

	resp, code := handlePlatformSystemHelper(ActionGet, req)
	if code == 0 {
		t.Fatalf("expected non-zero exit code on ACL denied")
	}
	// 核心断言：目标条目所在钥匙串已解锁，即使存在其他锁定的无关钥匙串，必须准确返回 denied，绝不能误判为 locked！
	if resp.Code != "denied" {
		t.Fatalf("expected code 'denied' (got %q, message: %s)", resp.Code, resp.Message)
	}
	mappedErr := MapErrorCode(resp.Code, resp.Message)
	if !errors.Is(mappedErr, credential.ErrCredentialAccessDenied) {
		t.Fatalf("expected strictly ErrCredentialAccessDenied, got: %v", mappedErr)
	}
}

func TestDarwinNativeHelper_MultiKeychainTargetUnlockedACLDeniedWithLockedFirstInSearchList(t *testing.T) {
	mock := stubDarwinAPIs(t)

	// KC1 (0x1000): 无关钥匙串排在前面，已锁定
	// KC2 (0x2000): 目标条目所在钥匙串，已解锁
	mock.copySearchList = func(searchList *uintptr) int32 {
		if searchList != nil {
			*searchList = 0x8888
		}
		return errSecSuccess
	}
	mock.cfArrayGetCount = func(arr uintptr) int {
		if arr == 0x8888 {
			return 2
		}
		return 0
	}
	mock.cfArrayGetValueAtIndex = func(arr uintptr, idx int) uintptr {
		if arr == 0x8888 {
			switch idx {
			case 0:
				return 0x1000
			case 1:
				return 0x2000
			}
		}
		return 0
	}
	mock.keychainGetStatus = func(kc uintptr, status *uint32) int32 {
		if status != nil {
			switch kc {
			case 0x1000:
				*status = 0 // KC1 锁定
			case 0, 0x2000:
				*status = kSecUnlockStateStatus // KC2 解锁
			}
		}
		return errSecSuccess
	}

	mock.findGenericPassword = func(kc uintptr, _ uint32, _ *byte, _ uint32, _ *byte, pwLen *uint32, pwData *unsafe.Pointer, itemRef *uintptr) int32 {
		if kc == 0x2000 {
			if pwLen == nil && pwData == nil && itemRef != nil {
				*itemRef = 0x7777
				return errSecSuccess
			}
			return errSecInteractionNotAllowed
		}
		return errSecItemNotFound
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
	}

	resp, code := handlePlatformSystemHelper(ActionGet, req)
	if code == 0 {
		t.Fatalf("expected non-zero exit code on ACL denied")
	}
	if resp.Code != "denied" {
		t.Fatalf("expected code 'denied' (got %q, message: %s)", resp.Code, resp.Message)
	}
	mappedErr := MapErrorCode(resp.Code, resp.Message)
	if !errors.Is(mappedErr, credential.ErrCredentialAccessDenied) {
		t.Fatalf("expected strictly ErrCredentialAccessDenied, got: %v", mappedErr)
	}
}

func TestDarwinNativeHelper_TargetItemKeychainLockedVsDefaultUnlocked(t *testing.T) {
	mock := stubDarwinAPIs(t)

	// 配置搜索列表包含真实模拟目标钥匙串 0x5000
	mock.copySearchList = func(searchList *uintptr) int32 {
		if searchList != nil {
			*searchList = 0x8888
		}
		return errSecSuccess
	}
	mock.cfArrayGetCount = func(arr uintptr) int {
		if arr == 0x8888 {
			return 1
		}
		return 0
	}
	mock.cfArrayGetValueAtIndex = func(arr uintptr, idx int) uintptr {
		if arr == 0x8888 && idx == 0 {
			return 0x5000
		}
		return 0
	}

	modifyCalled := false
	// 默认钥匙串 (kc=0) 解锁，但目标条目所在的钥匙串 (kc=0x5000) 锁定
	mock.keychainGetStatus = func(kc uintptr, status *uint32) int32 {
		if status != nil {
			switch kc {
			case 0:
				*status = kSecUnlockStateStatus // 默认钥匙串解锁
			case 0x5000:
				if modifyCalled {
					*status = 0 // 修改后检查状态：目标钥匙串已锁定
				} else {
					*status = kSecUnlockStateStatus // 定位阶段目标钥匙串允许检索条目
				}
			}
		}
		return errSecSuccess
	}

	mock.findGenericPassword = func(_ uintptr, _ uint32, _ *byte, _ uint32, _ *byte, _ *uint32, _ *unsafe.Pointer, itemRef *uintptr) int32 {
		if itemRef != nil {
			*itemRef = 0x9000
		}
		return errSecSuccess
	}
	mock.itemCopyKeychain = func(item uintptr, keychainRef *uintptr) int32 {
		if item == 0x9000 && keychainRef != nil {
			*keychainRef = 0x5000
		}
		return errSecSuccess
	}
	mock.itemModifyAttributesAndData = func(_ uintptr, _ uintptr, _ uint32, _ unsafe.Pointer) int32 {
		modifyCalled = true
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
		t.Fatalf("expected non-zero exit code when target item keychain is locked")
	}
	if !modifyCalled {
		t.Fatalf("expected itemModifyAttributesAndData to be called, but it was skipped due to early return")
	}
	if resp.Code != "locked" {
		t.Fatalf("expected code 'locked' based on target item keychain, got %q (msg: %s)", resp.Code, resp.Message)
	}
	mappedErr := MapErrorCode(resp.Code, resp.Message)
	if !errors.Is(mappedErr, credential.ErrCredentialStoreLocked) {
		t.Fatalf("expected ErrCredentialStoreLocked, got: %v", mappedErr)
	}
}

func TestDarwinNativeHelper_TargetItemKeychainUnlockedVsDefaultLocked(t *testing.T) {
	mock := stubDarwinAPIs(t)

	// 配置搜索列表包含真实模拟目标钥匙串 0x5000
	mock.copySearchList = func(searchList *uintptr) int32 {
		if searchList != nil {
			*searchList = 0x8888
		}
		return errSecSuccess
	}
	mock.cfArrayGetCount = func(arr uintptr) int {
		if arr == 0x8888 {
			return 1
		}
		return 0
	}
	mock.cfArrayGetValueAtIndex = func(arr uintptr, idx int) uintptr {
		if arr == 0x8888 && idx == 0 {
			return 0x5000
		}
		return 0
	}

	// 默认钥匙串 (kc=0) 锁定，但目标条目所在的钥匙串 (kc=0x5000) 解锁
	mock.keychainGetStatus = func(kc uintptr, status *uint32) int32 {
		if status != nil {
			switch kc {
			case 0:
				*status = 0 // 默认钥匙串锁定
			case 0x5000:
				*status = kSecUnlockStateStatus // 目标钥匙串解锁
			}
		}
		return errSecSuccess
	}

	mock.findGenericPassword = func(_ uintptr, _ uint32, _ *byte, _ uint32, _ *byte, _ *uint32, _ *unsafe.Pointer, itemRef *uintptr) int32 {
		if itemRef != nil {
			*itemRef = 0x9000
		}
		return errSecSuccess
	}
	mock.itemCopyKeychain = func(item uintptr, keychainRef *uintptr) int32 {
		if item == 0x9000 && keychainRef != nil {
			*keychainRef = 0x5000
		}
		return errSecSuccess
	}

	modifyCalled := false
	mock.itemModifyAttributesAndData = func(_ uintptr, _ uintptr, _ uint32, _ unsafe.Pointer) int32 {
		modifyCalled = true
		return errSecAuthFailed
	}

	req := &Request{
		ProtocolVersion: 1,
		StoreID:         "s",
		ItemID:          "k",
		Secret:          base64.StdEncoding.EncodeToString([]byte("val")),
	}

	resp, code := handlePlatformSystemHelper(ActionStore, req)
	if code == 0 {
		t.Fatalf("expected non-zero exit code on ACL auth failed")
	}
	if !modifyCalled {
		t.Fatalf("expected itemModifyAttributesAndData to be called, but it was skipped due to early return")
	}
	// 关键断言：目标钥匙串已解锁，不能因为默认钥匙串锁定而误判为 locked，必须准确返回 denied！
	if resp.Code != "denied" {
		t.Fatalf("expected code 'denied' (not 'locked'), got %q (msg: %s)", resp.Code, resp.Message)
	}
	mappedErr := MapErrorCode(resp.Code, resp.Message)
	if !errors.Is(mappedErr, credential.ErrCredentialAccessDenied) {
		t.Fatalf("expected ErrCredentialAccessDenied, got: %v", mappedErr)
	}
}

func TestDarwinNativeHelper_DuplicateConflictRetrySuccess(t *testing.T) {
	mock := stubDarwinAPIs(t)

	findCallCount := 0
	mock.findGenericPassword = func(
		_ uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ *uint32,
		_ *unsafe.Pointer,
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

	mock.addGenericPassword = func(
		_ uintptr,
		_ uint32,
		_ *byte,
		_ uint32,
		_ *byte,
		_ uint32,
		_ unsafe.Pointer,
		_ *uintptr,
	) int32 {
		return errSecDuplicateItem
	}

	modCalled := false
	mock.itemModifyAttributesAndData = func(
		_ uintptr,
		_ uintptr,
		_ uint32,
		_ unsafe.Pointer,
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
		t.Fatal("expected itemModifyAttributesAndData to be called during retry")
	}
}

func TestDarwinNativeHelper_DirectRoundtrip(t *testing.T) {
	if err := initDarwinKeychainAPIs(); err != nil {
		t.Skipf("skipping Darwin native helper direct roundtrip test: %v", err)
	}

	storeID := "darwintest"
	itemID := fmt.Sprintf("direct-key-%d", time.Now().UnixNano())
	val1 := "direct-initial-secret-data\n\n\x00\x01\x02\xff"
	b64Val1 := base64.StdEncoding.EncodeToString([]byte(val1))
	val2 := "direct-updated-secret-data\n\xaa\xbb\xcc"
	b64Val2 := base64.StdEncoding.EncodeToString([]byte(val2))

	t.Cleanup(func() {
		eraseReq := &Request{
			ProtocolVersion: 1,
			StoreID:         storeID,
			ItemID:          itemID,
		}
		_, _ = handlePlatformSystemHelper(ActionErase, eraseReq)
	})

	// 1. Store initial value
	storeReq := &Request{
		ProtocolVersion: 1,
		StoreID:         storeID,
		ItemID:          itemID,
		Secret:          b64Val1,
	}
	resp, code := handlePlatformSystemHelper(ActionStore, storeReq)
	if code != 0 {
		t.Fatalf("Store initial failed with code %d: %v", code, resp)
	}

	// 2. Get initial value
	getReq := &Request{
		ProtocolVersion: 1,
		StoreID:         storeID,
		ItemID:          itemID,
	}
	resp, code = handlePlatformSystemHelper(ActionGet, getReq)
	if code != 0 {
		t.Fatalf("Get initial failed with code %d: %v", code, resp)
	}
	if resp.Secret != b64Val1 {
		t.Fatalf("Get initial secret mismatch: got %q, want %q", resp.Secret, b64Val1)
	}

	// 3. Update with different value (verifies duplicate conflict retry & item modification)
	storeReqUpdate := &Request{
		ProtocolVersion: 1,
		StoreID:         storeID,
		ItemID:          itemID,
		Secret:          b64Val2,
	}
	resp, code = handlePlatformSystemHelper(ActionStore, storeReqUpdate)
	if code != 0 {
		t.Fatalf("Store update failed with code %d: %v", code, resp)
	}

	// 4. Get updated value (assert changed to val2, not old val1)
	resp, code = handlePlatformSystemHelper(ActionGet, getReq)
	if code != 0 {
		t.Fatalf("Get updated failed with code %d: %v", code, resp)
	}
	if resp.Secret != b64Val2 {
		t.Fatalf("Get updated secret mismatch: got %q, want %q", resp.Secret, b64Val2)
	}

	// 5. Erase
	eraseReq := &Request{
		ProtocolVersion: 1,
		StoreID:         storeID,
		ItemID:          itemID,
	}
	resp, code = handlePlatformSystemHelper(ActionErase, eraseReq)
	if code != 0 {
		t.Fatalf("Erase failed with code %d: %v", code, resp)
	}

	// 6. Get after erase -> assert not-found
	resp, code = handlePlatformSystemHelper(ActionGet, getReq)
	if code == 0 {
		t.Fatalf("expected non-zero exit code after erase")
	}
	if resp.Code != "not-found" {
		t.Fatalf("expected code 'not-found' after erase, got %q (msg: %s)", resp.Code, resp.Message)
	}
}

func TestDarwinNativeSystemStore_Integration(t *testing.T) {
	if err := initDarwinKeychainAPIs(); err != nil {
		t.Skipf("skipping Darwin native system store integration test: %v", err)
	}

	ctx := context.Background()
	store, err := newNativeSystemStore("darwinsys", SystemStoreConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("newNativeSystemStore failed: %v", err)
	}

	ref := credential.Ref{StoreID: "darwinsys", ItemID: fmt.Sprintf("integ-key-%d", time.Now().UnixNano())}
	secVal1 := []byte("integration-secret-data-1\n\n\x00\x01\x02\xff")
	secVal2 := []byte("integration-secret-data-2-updated\n\x03\x04\x05")

	t.Cleanup(func() {
		_ = store.Delete(context.Background(), ref)
	})

	// 1. Put initial
	if err := store.Put(ctx, ref, credential.NewSecret(secVal1)); err != nil {
		t.Fatalf("Put initial failed: %v", err)
	}

	// 2. Get initial
	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get initial failed: %v", err)
	}
	if string(got.Value) != string(secVal1) {
		t.Fatalf("Get initial value mismatch: got %q, want %q", got.Value, secVal1)
	}
	got.Zero()

	// 3. Put update (verify in-place overwrite)
	if err := store.Put(ctx, ref, credential.NewSecret(secVal2)); err != nil {
		t.Fatalf("Put update failed: %v", err)
	}

	// 4. Get updated
	got2, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get updated failed: %v", err)
	}
	if string(got2.Value) != string(secVal2) {
		t.Fatalf("Get updated value mismatch: got %q, want %q", got2.Value, secVal2)
	}
	got2.Zero()

	// 5. Delete
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// 6. Get after Delete -> assert ErrCredentialNotFound
	_, err = store.Get(ctx, ref)
	if !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got: %v", err)
	}
}

func TestDarwinNativeSystemStore_InFlightTimeoutAndCancel(t *testing.T) {
	ref := credential.Ref{StoreID: "darwin-timeout", ItemID: "hang-key"}
	tmpDir := t.TempDir()

	// 1. 测试运行中超时 (子进程注入实际阻塞信号文件，严格断言 context.DeadlineExceeded)
	signalFileTimeout := filepath.Join(tmpDir, "helper_timeout_ready")
	timeoutStore, err := newNativeSystemStore("darwin-timeout", SystemStoreConfig{
		Timeout: 250 * time.Millisecond,
		Env:     []string{testBlockSignalEnvVar + "=" + signalFileTimeout},
	})
	if err != nil {
		t.Fatalf("newNativeSystemStore failed: %v", err)
	}

	start := time.Now()
	_, err = timeoutStore.Get(context.Background(), ref)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error on hanging helper, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected strictly context.DeadlineExceeded, got: %v", err)
	}
	if _, statErr := os.Stat(signalFileTimeout); os.IsNotExist(statErr) {
		t.Fatal("helper child did not enter blocking execution before exit")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("timeout took too long (%v), process wait delay or termination failed", elapsed)
	}

	// 2. 测试运行中 context 取消 (确保子进程实际已进入阻塞状态后再调用 cancel)
	signalFileCancel := filepath.Join(tmpDir, "helper_cancel_ready")
	cancelStore, err := newNativeSystemStore("darwin-timeout", SystemStoreConfig{
		Timeout: 10 * time.Second,
		Env:     []string{testBlockSignalEnvVar + "=" + signalFileCancel},
	})
	if err != nil {
		t.Fatalf("newNativeSystemStore failed: %v", err)
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	start = time.Now()
	go func() {
		_, getErr := cancelStore.Get(cancelCtx, ref)
		errCh <- getErr
	}()

	// 循环等待确认子进程已经启动并进入阻塞执行状态
	waitStart := time.Now()
	for {
		if _, statErr := os.Stat(signalFileCancel); statErr == nil {
			break
		}
		if time.Since(waitStart) > 5*time.Second {
			t.Fatal("timed out waiting for helper child to signal blocking state")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 子进程已阻塞，触发取消
	cancel()

	select {
	case err = <-errCh:
		elapsed = time.Since(start)
		if err == nil {
			t.Fatal("expected cancel error on hanging helper, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected strictly context.Canceled, got: %v", err)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("cancellation took too long (%v), process cancellation hung", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not exit within 5s after cancellation")
	}
}

func setupIsolatedDarwinKeychain(t *testing.T, securityBin, keychainName, keychainPass string) string {
	t.Helper()

	origDefOut, err := exec.Command(securityBin, "default-keychain").CombinedOutput()
	if err != nil {
		t.Fatalf("query default-keychain failed: %v (%s)", err, origDefOut)
	}
	origDefault := parseKeychainPath(string(origDefOut))

	origListOut, err := exec.Command(securityBin, "list-keychains", "-d", "user").CombinedOutput()
	if err != nil {
		t.Fatalf("query list-keychains failed: %v (%s)", err, origListOut)
	}
	var origKeychains []string
	for _, line := range strings.Split(string(origListOut), "\n") {
		p := parseKeychainPath(line)
		if p != "" {
			origKeychains = append(origKeychains, p)
		}
	}

	// 尽早注册恢复原始系统状态的清理函数（在任何系统配置变更前生效）
	t.Cleanup(func() {
		if origDefault != "" {
			if out, err := exec.Command(securityBin, "default-keychain", "-s", origDefault).CombinedOutput(); err != nil {
				t.Errorf("cleanup restore default-keychain failed: %v (%s)", err, out)
			}
		}
		if len(origKeychains) > 0 {
			var restoreArgs []string
			restoreArgs = append(restoreArgs, "list-keychains", "-d", "user", "-s")
			restoreArgs = append(restoreArgs, origKeychains...)
			if out, err := exec.Command(securityBin, restoreArgs...).CombinedOutput(); err != nil {
				t.Errorf("cleanup restore list-keychains failed: %v (%s)", err, out)
			}
		}
	})

	tmpDir := t.TempDir()
	keychainPath := filepath.Join(tmpDir, keychainName)

	if out, err := exec.Command(securityBin, "create-keychain", "-p", keychainPass, keychainPath).CombinedOutput(); err != nil {
		t.Skipf("cannot create test keychain: %v (%s)", err, out)
	}

	// 创建测试钥匙串成功后，立即注册删除清理函数
	t.Cleanup(func() {
		if out, err := exec.Command(securityBin, "delete-keychain", keychainPath).CombinedOutput(); err != nil {
			t.Errorf("cleanup delete-keychain failed: %v (%s)", err, out)
		}
	})

	if out, err := exec.Command(securityBin, "unlock-keychain", "-p", keychainPass, keychainPath).CombinedOutput(); err != nil {
		t.Fatalf("unlock-keychain failed: %v (%s)", err, out)
	}
	if out, err := exec.Command(securityBin, "set-keychain-settings", "-t", "3600", "-l", keychainPath).CombinedOutput(); err != nil {
		t.Fatalf("set-keychain-settings failed: %v (%s)", err, out)
	}

	if out, err := exec.Command(securityBin, "default-keychain", "-s", keychainPath).CombinedOutput(); err != nil {
		t.Fatalf("set default-keychain failed: %v (%s)", err, out)
	}
	if out, err := exec.Command(securityBin, "list-keychains", "-d", "user", "-s", keychainPath).CombinedOutput(); err != nil {
		t.Fatalf("set list-keychains failed: %v (%s)", err, out)
	}

	return keychainPath
}

func TestDarwinNativeSystemStore_RealKeychainLockUnlock(t *testing.T) {
	if err := initDarwinKeychainAPIs(); err != nil {
		t.Skipf("skipping Darwin Keychain lock/unlock test: %v", err)
	}

	securityBin, err := exec.LookPath("security")
	if err != nil {
		t.Skip("security binary not found")
	}

	keychainPass := "testpass123"
	keychainPath := setupIsolatedDarwinKeychain(t, securityBin, "xops_lock_test.keychain", keychainPass)

	ctx := context.Background()
	store, err := newNativeSystemStore("locktest", SystemStoreConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("newNativeSystemStore failed: %v", err)
	}

	ref := credential.Ref{StoreID: "locktest", ItemID: "lock-key-1"}
	secVal := []byte("secret-payload-in-test-keychain")

	// 1. 正常解锁状态下写入
	if err := store.Put(ctx, ref, credential.NewSecret(secVal)); err != nil {
		t.Fatalf("Put into unlocked keychain failed: %v", err)
	}

	// 2. 读取验证
	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get from unlocked keychain failed: %v", err)
	}
	if string(got.Value) != string(secVal) {
		t.Fatalf("Get value mismatch: got %q, want %q", got.Value, secVal)
	}
	got.Zero()

	// 3. 锁定独立钥匙串
	if out, err := exec.Command(securityBin, "lock-keychain", keychainPath).CombinedOutput(); err != nil {
		t.Fatalf("lock-keychain failed: %v (%s)", err, out)
	}

	// 4. 锁定状态下尝试读取 -> 必须严格断言 ErrCredentialStoreLocked，拒绝普通 API 错误混入
	_, err = store.Get(ctx, ref)
	if err == nil {
		t.Fatal("expected error on locked keychain, got nil")
	}
	if !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("expected strictly ErrCredentialStoreLocked on locked keychain, got: %v", err)
	}

	// 5. 解锁测试钥匙串
	if out, err := exec.Command(securityBin, "unlock-keychain", "-p", keychainPass, keychainPath).CombinedOutput(); err != nil {
		t.Fatalf("unlock-keychain failed: %v (%s)", err, out)
	}

	// 6. 解锁后读取应立即恢复正常
	gotAfterUnlock, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get after unlock failed: %v", err)
	}
	if string(gotAfterUnlock.Value) != string(secVal) {
		t.Fatalf("Get after unlock value mismatch: got %q, want %q", gotAfterUnlock.Value, secVal)
	}
	gotAfterUnlock.Zero()

	// 7. 清理条目
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
}

func TestDarwinNativeSystemStore_RealKeychainACLAccessDenied(t *testing.T) {
	if err := initDarwinKeychainAPIs(); err != nil {
		t.Skipf("skipping Darwin Keychain ACL access denied test: %v", err)
	}

	securityBin, err := exec.LookPath("security")
	if err != nil {
		t.Skip("security binary not found")
	}

	keychainPath := setupIsolatedDarwinKeychain(t, securityBin, "xops_acl_test.keychain", "aclpass123")

	storeID := "acltest"
	itemID := fmt.Sprintf("acl-key-%d", time.Now().UnixNano())
	service := fmt.Sprintf("xops:%s", storeID)

	// 使用 security 命令显式限制访问仅允许 /usr/bin/false，使当前二进制被拒绝访问
	if out, err := exec.Command(securityBin, "add-generic-password",
		"-s", service,
		"-a", itemID,
		"-w", "supersecret-acl-protected",
		"-T", "/usr/bin/false",
		keychainPath,
	).CombinedOutput(); err != nil {
		t.Fatalf("failed to add ACL restricted generic password: %v (%s)", err, out)
	}

	ctx := context.Background()
	store, err := newNativeSystemStore(storeID, SystemStoreConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("newNativeSystemStore failed: %v", err)
	}

	// 读取该条目：钥匙串为解锁状态，但受 ACL 限制当前进程无权访问，必须严格返回 ErrCredentialAccessDenied
	ref := credential.Ref{StoreID: storeID, ItemID: itemID}
	_, err = store.Get(ctx, ref)
	if err == nil {
		t.Fatal("expected access denied error on ACL-restricted item, got nil")
	}
	if !errors.Is(err, credential.ErrCredentialAccessDenied) {
		t.Fatalf("expected strictly ErrCredentialAccessDenied on ACL-restricted item, got: %v", err)
	}
}

func TestDarwinNativeSystemStore_MultiKeychainLockClassification(t *testing.T) {
	if err := initDarwinKeychainAPIs(); err != nil {
		t.Skipf("skipping Darwin Keychain multi-keychain test: %v", err)
	}

	securityBin, err := exec.LookPath("security")
	if err != nil {
		t.Skip("security binary not found")
	}

	primaryPass := "primarypass123"
	secondaryPass := "secondarypass123"

	// primary 钥匙串作为默认钥匙串，且初始解锁
	primaryPath := setupIsolatedDarwinKeychain(t, securityBin, "xops_multi_primary.keychain", primaryPass)

	// 创建 secondary 钥匙串
	secondaryPath := setupSecondaryTestKeychain(t, securityBin, "xops_multi_secondary.keychain", secondaryPass)

	// 配置搜索列表包含两者: primaryPath, secondaryPath
	if out, err := exec.Command(securityBin, "list-keychains", "-d", "user", "-s", primaryPath, secondaryPath).CombinedOutput(); err != nil {
		t.Fatalf("set search list to include both keychains failed: %v (%s)", err, out)
	}

	storeID := "multikc"
	itemID := fmt.Sprintf("multi-key-%d", time.Now().UnixNano())
	secVal := []byte("multi-keychain-secret-val")

	ctx := context.Background()
	store, err := newNativeSystemStore(storeID, SystemStoreConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("newNativeSystemStore failed: %v", err)
	}

	ref := credential.Ref{StoreID: storeID, ItemID: itemID}
	helperPutToSecondaryKeychain(t, securityBin, store, primaryPath, secondaryPath, ref, secVal)

	// 1. 两者均解锁时读取成功
	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get from secondary keychain failed: %v", err)
	}
	if string(got.Value) != string(secVal) {
		t.Fatalf("value mismatch: got %q, want %q", got.Value, secVal)
	}
	got.Zero()

	// 2. 锁定 secondary 钥匙串（此时 primary 默认钥匙串仍然是解锁的）
	if out, err := exec.Command(securityBin, "lock-keychain", secondaryPath).CombinedOutput(); err != nil {
		t.Fatalf("lock secondary keychain failed: %v (%s)", err, out)
	}

	// 3. 读取条目：即使默认钥匙串解锁，搜索列表中的目标条目钥匙串被锁定，必须严格映射为 ErrCredentialStoreLocked，不可误判为 denied
	_, err = store.Get(ctx, ref)
	if err == nil {
		t.Fatal("expected error on locked secondary keychain, got nil")
	}
	if !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("expected strictly ErrCredentialStoreLocked when secondary keychain is locked (default unlocked), got: %v", err)
	}

	// 3.1 尝试写入更新条目：当搜索列表中的 secondary 钥匙串锁定时，必须失败关闭并返回 ErrCredentialStoreLocked，
	// 绝不能在默认的 primary 钥匙串中创建新条目遮蔽原凭据！
	shadowVal := []byte("shadowing-attempt-val")
	err = store.Put(ctx, ref, credential.NewSecret(shadowVal))
	if err == nil {
		t.Fatal("expected error on Put when secondary keychain is locked, got nil")
	}
	if !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("expected strictly ErrCredentialStoreLocked on Put when secondary keychain is locked, got: %v", err)
	}

	// 验证 primaryPath 默认钥匙串中绝对未创建同名条目
	if out, err := exec.Command(securityBin, "find-generic-password", "-s", fmt.Sprintf("xops:%s", storeID), "-a", itemID, primaryPath).CombinedOutput(); err == nil {
		t.Fatalf("Put while secondary keychain was locked created shadowing item in primary keychain! (%s)", out)
	}

	// 3.2 尝试删除条目：同样必须失败关闭并返回 ErrCredentialStoreLocked，不可误报成功或 not-found
	err = store.Delete(ctx, ref)
	if err == nil {
		t.Fatal("expected error on Delete when secondary keychain is locked, got nil")
	}
	if !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("expected strictly ErrCredentialStoreLocked on Delete when secondary keychain is locked, got: %v", err)
	}

	// 4. 解锁 secondary 钥匙串
	if out, err := exec.Command(securityBin, "unlock-keychain", "-p", secondaryPass, secondaryPath).CombinedOutput(); err != nil {
		t.Fatalf("unlock secondary keychain failed: %v (%s)", err, out)
	}

	// 5. 验证跨钥匙串更新覆盖
	updatedSecVal := []byte("multi-keychain-secret-val-updated")
	if err := store.Put(ctx, ref, credential.NewSecret(updatedSecVal)); err != nil {
		t.Fatalf("Put update to secondary keychain item failed: %v", err)
	}

	gotUpdated, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get updated secondary keychain item failed: %v", err)
	}
	if string(gotUpdated.Value) != string(updatedSecVal) {
		t.Fatalf("updated value mismatch: got %q, want %q", gotUpdated.Value, updatedSecVal)
	}
	gotUpdated.Zero()

	// 6. 清理条目
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete secondary keychain item failed: %v", err)
	}
}

func setupSecondaryTestKeychain(t *testing.T, securityBin, name, keychainPass string) string {
	t.Helper()
	tmpDir := t.TempDir()
	secondaryPath := filepath.Join(tmpDir, name)
	if out, err := exec.Command(securityBin, "create-keychain", "-p", keychainPass, secondaryPath).CombinedOutput(); err != nil {
		t.Skipf("cannot create secondary test keychain: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command(securityBin, "delete-keychain", secondaryPath).CombinedOutput(); err != nil {
			t.Errorf("cleanup delete secondary keychain failed: %v (%s)", err, out)
		}
	})

	if out, err := exec.Command(securityBin, "unlock-keychain", "-p", keychainPass, secondaryPath).CombinedOutput(); err != nil {
		t.Fatalf("unlock secondary keychain failed: %v (%s)", err, out)
	}
	if out, err := exec.Command(securityBin, "set-keychain-settings", "-t", "3600", "-l", secondaryPath).CombinedOutput(); err != nil {
		t.Fatalf("set secondary keychain settings failed: %v (%s)", err, out)
	}
	return secondaryPath
}

func helperPutToSecondaryKeychain(t *testing.T, securityBin string, store credential.Store, primaryPath, secondaryPath string, ref credential.Ref, secVal []byte) {
	t.Helper()
	if out, err := exec.Command(securityBin, "default-keychain", "-s", secondaryPath).CombinedOutput(); err != nil {
		t.Fatalf("set default keychain to secondary failed: %v (%s)", err, out)
	}
	if err := store.Put(context.Background(), ref, credential.NewSecret(secVal)); err != nil {
		t.Fatalf("Put into secondary keychain failed: %v", err)
	}
	if out, err := exec.Command(securityBin, "default-keychain", "-s", primaryPath).CombinedOutput(); err != nil {
		t.Fatalf("restore default keychain to primary failed: %v (%s)", err, out)
	}
}

func TestDarwinNativeSystemStore_MultiKeychainTargetUnlockedACLDeniedWithUnrelatedLocked(t *testing.T) {
	if err := initDarwinKeychainAPIs(); err != nil {
		t.Skipf("skipping Darwin Keychain multi-keychain test: %v", err)
	}

	securityBin, err := exec.LookPath("security")
	if err != nil {
		t.Skip("security binary not found")
	}

	primaryPass := "primarypass123"
	secondaryPass := "secondarypass123"

	// primary 钥匙串作为默认钥匙串，且初始解锁
	primaryPath := setupIsolatedDarwinKeychain(t, securityBin, "xops_rev_primary.keychain", primaryPass)

	// 创建 secondary 钥匙串
	secondaryPath := setupSecondaryTestKeychain(t, securityBin, "xops_rev_secondary.keychain", secondaryPass)

	// 配置搜索列表包含两者: [primaryPath, secondaryPath]
	if out, err := exec.Command(securityBin, "list-keychains", "-d", "user", "-s", primaryPath, secondaryPath).CombinedOutput(); err != nil {
		t.Fatalf("set search list to include both keychains failed: %v (%s)", err, out)
	}

	storeID := "revtest"
	itemID := fmt.Sprintf("rev-key-%d", time.Now().UnixNano())
	service := fmt.Sprintf("xops:%s", storeID)

	// 在已解锁的 primaryPath 中写入 ACL 受限条目（仅允许 /usr/bin/false，使 helper 被拒绝）
	if out, err := exec.Command(securityBin, "add-generic-password",
		"-s", service,
		"-a", itemID,
		"-w", "rev-secret",
		"-T", "/usr/bin/false",
		primaryPath,
	).CombinedOutput(); err != nil {
		t.Fatalf("failed to add ACL restricted password to primary keychain: %v (%s)", err, out)
	}

	// 将 secondaryPath 锁定（模拟搜索列表中存在无关锁定库）
	if out, err := exec.Command(securityBin, "lock-keychain", secondaryPath).CombinedOutput(); err != nil {
		t.Fatalf("lock secondary keychain failed: %v (%s)", err, out)
	}

	ctx := context.Background()
	store, err := newNativeSystemStore(storeID, SystemStoreConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("newNativeSystemStore failed: %v", err)
	}

	// 核心断言：目标条目存在于已解锁的 primaryPath 库中（由于 ACL 限制无法读取），
	// 即使搜索列表中存在锁定的 secondaryPath，也绝不能误判为 ErrCredentialStoreLocked，
	// 必须严格判定为 ErrCredentialAccessDenied！
	ref := credential.Ref{StoreID: storeID, ItemID: itemID}
	_, err = store.Get(ctx, ref)
	if err == nil {
		t.Fatal("expected error on ACL-restricted item, got nil")
	}
	if !errors.Is(err, credential.ErrCredentialAccessDenied) {
		t.Fatalf("expected strictly ErrCredentialAccessDenied (not locked), got: %v", err)
	}
	if errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("incorrectly mapped to ErrCredentialStoreLocked due to unrelated locked secondary keychain: %v", err)
	}
}

func parseKeychainPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	trimmed = strings.TrimPrefix(trimmed, "\"")
	trimmed = strings.TrimSuffix(trimmed, "\"")
	return strings.TrimSpace(trimmed)
}
