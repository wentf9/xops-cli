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
	errSecIO                    int32 = -36
	errSecReadOnly              int32 = -25292
	errSecAuthFailed            int32 = -25293
	errSecDuplicateItem         int32 = -25299
	errSecItemNotFound          int32 = -25300
	errSecInteractionNotAllowed int32 = -25308

	kSecUnlockStateStatus uint32 = 1

	kSecPreferencesDomainUser uint32 = 0
)

type darwinKeychainAPI struct {
	setUserInteractionAllowed func(
		allowed uint8,
	) int32

	findGenericPassword func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength *uint32,
		passwordData *unsafe.Pointer,
		itemRef *uintptr,
	) int32

	itemFreeContent func(
		attrList uintptr,
		data unsafe.Pointer,
	) int32

	addGenericPassword func(
		keychain uintptr,
		serviceLength uint32,
		service *byte,
		accountLength uint32,
		account *byte,
		passwordLength uint32,
		passwordData unsafe.Pointer,
		itemRef *uintptr,
	) int32

	itemModifyAttributesAndData func(
		itemRef uintptr,
		attrList uintptr,
		length uint32,
		data unsafe.Pointer,
	) int32

	itemDelete func(
		itemRef uintptr,
	) int32

	itemCopyKeychain func(
		itemRef uintptr,
		keychainRef *uintptr,
	) int32

	copySearchList func(
		searchList *uintptr,
	) int32

	copyDomainSearchList func(
		domain uint32,
		searchList *uintptr,
	) int32

	keychainGetStatus func(
		keychain uintptr,
		status *uint32,
	) int32

	cfArrayGetCount func(
		theArray uintptr,
	) int

	cfArrayGetValueAtIndex func(
		theArray uintptr,
		idx int,
	) uintptr

	cfRelease func(
		cf uintptr,
	)
}

var (
	darwinRealAPIsOnce sync.Once
	darwinRealAPIs     *darwinKeychainAPI
	darwinRealAPIsErr  error

	darwinAPIMu   sync.RWMutex
	darwinMockAPI *darwinKeychainAPI
)

func getDarwinKeychainAPI() (*darwinKeychainAPI, error) {
	darwinAPIMu.RLock()
	mock := darwinMockAPI
	darwinAPIMu.RUnlock()
	if mock != nil {
		return mock, nil
	}

	darwinRealAPIsOnce.Do(func() {
		secHandle, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_GLOBAL)
		if err != nil {
			darwinRealAPIsErr = fmt.Errorf("dlopen Security framework: %w", err)
			return
		}

		cfHandle, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_GLOBAL)
		if err != nil {
			darwinRealAPIsErr = fmt.Errorf("dlopen CoreFoundation framework: %w", err)
			return
		}

		apis := &darwinKeychainAPI{}
		purego.RegisterLibFunc(&apis.setUserInteractionAllowed, secHandle, "SecKeychainSetUserInteractionAllowed")
		purego.RegisterLibFunc(&apis.findGenericPassword, secHandle, "SecKeychainFindGenericPassword")
		purego.RegisterLibFunc(&apis.itemFreeContent, secHandle, "SecKeychainItemFreeContent")
		purego.RegisterLibFunc(&apis.addGenericPassword, secHandle, "SecKeychainAddGenericPassword")
		purego.RegisterLibFunc(&apis.itemModifyAttributesAndData, secHandle, "SecKeychainItemModifyAttributesAndData")
		purego.RegisterLibFunc(&apis.itemDelete, secHandle, "SecKeychainItemDelete")
		purego.RegisterLibFunc(&apis.itemCopyKeychain, secHandle, "SecKeychainItemCopyKeychain")
		purego.RegisterLibFunc(&apis.copySearchList, secHandle, "SecKeychainCopySearchList")
		purego.RegisterLibFunc(&apis.copyDomainSearchList, secHandle, "SecKeychainCopyDomainSearchList")
		purego.RegisterLibFunc(&apis.keychainGetStatus, secHandle, "SecKeychainGetStatus")
		purego.RegisterLibFunc(&apis.cfArrayGetCount, cfHandle, "CFArrayGetCount")
		purego.RegisterLibFunc(&apis.cfArrayGetValueAtIndex, cfHandle, "CFArrayGetValueAtIndex")
		purego.RegisterLibFunc(&apis.cfRelease, cfHandle, "CFRelease")
		darwinRealAPIs = apis
	})

	if darwinRealAPIsErr != nil {
		return nil, darwinRealAPIsErr
	}
	return darwinRealAPIs, nil
}

func setDarwinMockAPI(mock *darwinKeychainAPI) {
	darwinAPIMu.Lock()
	darwinMockAPI = mock
	darwinAPIMu.Unlock()
}

func clearDarwinMockAPI() {
	darwinAPIMu.Lock()
	darwinMockAPI = nil
	darwinAPIMu.Unlock()
}

func initDarwinKeychainAPIs() error {
	_, err := getDarwinKeychainAPI()
	return err
}

func isKeychainLocked(apis *darwinKeychainAPI, kc uintptr) bool {
	if apis == nil || apis.keychainGetStatus == nil {
		return false
	}
	var status uint32
	if res := apis.keychainGetStatus(kc, &status); res == errSecSuccess {
		return (status & kSecUnlockStateStatus) == 0
	}
	return false
}

func isDefaultKeychainLocked(apis *darwinKeychainAPI) bool {
	return isKeychainLocked(apis, 0)
}

func isItemKeychainLocked(apis *darwinKeychainAPI, itemRef uintptr) bool {
	if apis == nil || apis.itemCopyKeychain == nil || itemRef == 0 {
		return isDefaultKeychainLocked(apis)
	}
	var kcRef uintptr
	if res := apis.itemCopyKeychain(itemRef, &kcRef); res == errSecSuccess && kcRef != 0 {
		defer apis.cfRelease(kcRef)
		return isKeychainLocked(apis, kcRef)
	}
	return isDefaultKeychainLocked(apis)
}

type darwinSearchKeychains struct {
	keychains []uintptr
	cfArray   uintptr
}

func getSearchKeychains(apis *darwinKeychainAPI) darwinSearchKeychains {
	if apis == nil || apis.cfArrayGetCount == nil || apis.cfArrayGetValueAtIndex == nil {
		return darwinSearchKeychains{keychains: []uintptr{0}}
	}

	var searchList uintptr
	// 优先查询当前用户首选域 (User Domain) 的钥匙串搜索列表，
	// 避免合并列表中包含系统级钥匙串（如 /Library/Keychains/System.keychain，非 root 环境下通常处于锁定状态）导致全库误判为锁定
	if apis.copyDomainSearchList != nil {
		if res := apis.copyDomainSearchList(kSecPreferencesDomainUser, &searchList); res == errSecSuccess && searchList != 0 {
			// 成功获取用户域搜索列表
		} else if apis.copySearchList != nil {
			_ = apis.copySearchList(&searchList)
		}
	} else if apis.copySearchList != nil {
		_ = apis.copySearchList(&searchList)
	}

	if searchList == 0 {
		return darwinSearchKeychains{keychains: []uintptr{0}}
	}

	count := apis.cfArrayGetCount(searchList)
	if count <= 0 {
		if apis.cfRelease != nil {
			apis.cfRelease(searchList)
		}
		return darwinSearchKeychains{keychains: []uintptr{0}}
	}

	kcList := make([]uintptr, 0, count)
	for i := 0; i < count; i++ {
		kcRef := apis.cfArrayGetValueAtIndex(searchList, i)
		if kcRef != 0 {
			kcList = append(kcList, kcRef)
		}
	}
	if len(kcList) == 0 {
		kcList = append(kcList, 0)
	}

	return darwinSearchKeychains{
		keychains: kcList,
		cfArray:   searchList,
	}
}

func (sk darwinSearchKeychains) release(apis *darwinKeychainAPI) {
	if sk.cfArray != 0 && apis != nil && apis.cfRelease != nil {
		apis.cfRelease(sk.cfArray)
	}
}

type darwinFoundItem struct {
	sk        darwinSearchKeychains
	targetKC  uintptr
	itemRef   uintptr
	found     bool
	hasLocked bool
	errStatus int32
}

func (fi darwinFoundItem) release(apis *darwinKeychainAPI) {
	if fi.itemRef != 0 && apis != nil && apis.cfRelease != nil {
		apis.cfRelease(fi.itemRef)
	}
	fi.sk.release(apis)
}

func darwinLocateItemInSearchList(
	apis *darwinKeychainAPI,
	serviceBytes, accountBytes []byte,
) darwinFoundItem {
	var servicePtr *byte
	if len(serviceBytes) > 0 {
		servicePtr = &serviceBytes[0]
	}
	var accountPtr *byte
	if len(accountBytes) > 0 {
		accountPtr = &accountBytes[0]
	}

	sk := getSearchKeychains(apis)
	hasLocked := false
	var firstErr int32

	for _, kc := range sk.keychains {
		if isKeychainLocked(apis, kc) {
			hasLocked = true
			continue
		}

		var ref uintptr
		status := apis.findGenericPassword(
			kc,
			uint32(len(serviceBytes)),
			servicePtr,
			uint32(len(accountBytes)),
			accountPtr,
			nil,
			nil,
			&ref,
		)
		if status == errSecSuccess && ref != 0 {
			return darwinFoundItem{
				sk:        sk,
				targetKC:  kc,
				itemRef:   ref,
				found:     true,
				hasLocked: hasLocked,
			}
		}
		if status == errSecItemNotFound {
			continue
		}

		// 仅 errSecItemNotFound 视为无匹配，保留 ACL 拒绝、签名变化、I/O 故障等其他错误分类
		if firstErr == 0 {
			firstErr = status
		}
	}

	return darwinFoundItem{
		sk:        sk,
		found:     false,
		hasLocked: hasLocked,
		errStatus: firstErr,
	}
}

func mapDarwinAuthStatus(status int32, isLocked bool, op string) (*Response, int) {
	if status == errSecReadOnly {
		return &Response{Code: "read-only", Message: fmt.Sprintf("keychain is read-only during %s", op)}, 1
	}
	if status == errSecAuthFailed || status == errSecInteractionNotAllowed {
		if isLocked {
			return &Response{Code: "locked", Message: fmt.Sprintf("keychain locked during %s", op)}, 1
		}
		return &Response{Code: "denied", Message: fmt.Sprintf("keychain access denied or signature changed during %s", op)}, 1
	}
	return &Response{Code: "unavailable", Message: fmt.Sprintf("%s failed with status %d", op, status)}, 1
}

func newNativeSystemStore(storeID string, cfg SystemStoreConfig) (credential.Store, error) {
	cmdPath, args, env, err := resolveControlledSystemHelper()
	if err != nil {
		return nil, fmt.Errorf("resolve controlled system helper: %w", err)
	}

	mergedEnv := append([]string{}, env...)
	mergedEnv = append(mergedEnv, cfg.Env...)

	opts := ProcessOptions{
		Command: cmdPath,
		Args:    args,
		Env:     mergedEnv,
		Timeout: cfg.Timeout,
	}

	return NewHelperStore(storeID, opts, cfg.ReadOnly)
}

func darwinActionGet(apis *darwinKeychainAPI, serviceBytes, accountBytes []byte) (*Response, int) {
	var servicePtr *byte
	if len(serviceBytes) > 0 {
		servicePtr = &serviceBytes[0]
	}
	var accountPtr *byte
	if len(accountBytes) > 0 {
		accountPtr = &accountBytes[0]
	}

	foundItem := darwinLocateItemInSearchList(apis, serviceBytes, accountBytes)
	defer foundItem.release(apis)

	if !foundItem.found {
		// 1. 若查询中遇到 ACL 拒绝、I/O 故障等非 not-found 错误，必须保留原始错误分类，严禁误报为 not-found
		if foundItem.errStatus != 0 {
			return mapDarwinAuthStatus(foundItem.errStatus, false, "find item")
		}
		// 2. 若存在锁定库，属于无法检查，返回 locked
		if foundItem.hasLocked {
			return &Response{Code: "locked", Message: "keychain locked during find item"}, 1
		}
		// 3. 只有全部检索且均为 not-found 时才返回 not-found
		return &Response{Code: "not-found", Message: "credential not found"}, 1
	}

	var pwLen uint32
	var pwData unsafe.Pointer
	readStatus := apis.findGenericPassword(
		foundItem.targetKC,
		uint32(len(serviceBytes)),
		servicePtr,
		uint32(len(accountBytes)),
		accountPtr,
		&pwLen,
		&pwData,
		nil,
	)
	if readStatus != errSecSuccess {
		// 目标条目所属钥匙串已证实处于解锁状态，因此此处的认证失败是 ACL 拒绝或签名不匹配，绝不可因其他库锁定而误判为 locked
		return mapDarwinAuthStatus(readStatus, false, "read credential data")
	}
	if pwData == nil {
		return &Response{Code: "not-found", Message: "empty credential"}, 1
	}
	defer apis.itemFreeContent(0, pwData)

	if pwLen > MaxResponseBytes {
		return &Response{Code: "unavailable", Message: fmt.Sprintf("credential size %d exceeds limit", pwLen)}, 1
	}

	rawBytes := unsafe.Slice((*byte)(pwData), pwLen)
	copied := make([]byte, pwLen)
	copy(copied, rawBytes)

	return &Response{
		Secret: base64.StdEncoding.EncodeToString(copied),
	}, 0
}

func darwinActionStore(apis *darwinKeychainAPI, serviceBytes, accountBytes []byte, rawSecret string) (*Response, int) {
	if rawSecret == "" {
		return &Response{Code: "unavailable", Message: "secret is empty"}, 1
	}
	secretBytes, err := base64.StdEncoding.DecodeString(rawSecret)
	if err != nil {
		return &Response{Code: "unavailable", Message: "invalid base64 secret"}, 1
	}

	var servicePtr *byte
	if len(serviceBytes) > 0 {
		servicePtr = &serviceBytes[0]
	}
	var accountPtr *byte
	if len(accountBytes) > 0 {
		accountPtr = &accountBytes[0]
	}
	var secretPtr unsafe.Pointer
	if len(secretBytes) > 0 {
		secretPtr = unsafe.Pointer(&secretBytes[0])
	}

	// 1. 检查是否存在同名条目
	foundItem := darwinLocateItemInSearchList(apis, serviceBytes, accountBytes)
	if foundItem.found {
		defer foundItem.release(apis)
		modStatus := apis.itemModifyAttributesAndData(
			foundItem.itemRef,
			0,
			uint32(len(secretBytes)),
			secretPtr,
		)
		if modStatus != errSecSuccess {
			return mapDarwinAuthStatus(modStatus, isItemKeychainLocked(apis, foundItem.itemRef), "modify existing item")
		}
		return &Response{}, 0
	}

	// 若查询过程中遇到非 not-found 错误（如 ACL 拒绝、I/O 故障），无法确认是否存在，必须失败关闭
	if foundItem.errStatus != 0 {
		errStatus := foundItem.errStatus
		foundItem.release(apis)
		return mapDarwinAuthStatus(errStatus, false, "find existing item before store")
	}

	// 严格区分“确认不存在”和“无法检查”：
	// 若存在未解锁钥匙串，无法排除条目已存在于锁定库中，此时盲目向默认库添加会遮蔽原条目，必须失败关闭
	if foundItem.hasLocked {
		foundItem.release(apis)
		return &Response{Code: "locked", Message: "cannot verify existing credential because keychain in search list is locked"}, 1
	}
	foundItem.release(apis)

	// 2. 只有在确认不存在的前提下，才向默认钥匙串添加新条目
	var newItemRef uintptr
	addStatus := apis.addGenericPassword(
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
		defer apis.cfRelease(newItemRef)
	}
	if addStatus == errSecDuplicateItem {
		return darwinActionStoreRetry(apis, serviceBytes, accountBytes, secretBytes, servicePtr, accountPtr, secretPtr)
	}
	if addStatus != errSecSuccess {
		return mapDarwinAuthStatus(addStatus, isDefaultKeychainLocked(apis), "add item")
	}
	return &Response{}, 0
}

func darwinActionStoreRetry(
	apis *darwinKeychainAPI,
	serviceBytes, accountBytes, secretBytes []byte,
	servicePtr, accountPtr *byte,
	secretPtr unsafe.Pointer,
) (*Response, int) {
	foundItem := darwinLocateItemInSearchList(apis, serviceBytes, accountBytes)
	defer foundItem.release(apis)

	if !foundItem.found {
		if foundItem.errStatus != 0 {
			return mapDarwinAuthStatus(foundItem.errStatus, false, "retry find existing item")
		}
		if foundItem.hasLocked {
			return &Response{Code: "locked", Message: "keychain locked during retry find existing item"}, 1
		}
		return &Response{Code: "unavailable", Message: "failed to acquire item ref after duplicate conflict"}, 1
	}

	retryModStatus := apis.itemModifyAttributesAndData(
		foundItem.itemRef,
		0,
		uint32(len(secretBytes)),
		secretPtr,
	)
	if retryModStatus != errSecSuccess {
		return mapDarwinAuthStatus(retryModStatus, isItemKeychainLocked(apis, foundItem.itemRef), "modify item during retry")
	}
	return &Response{}, 0
}

func darwinActionErase(apis *darwinKeychainAPI, serviceBytes, accountBytes []byte) (*Response, int) {
	foundItem := darwinLocateItemInSearchList(apis, serviceBytes, accountBytes)
	defer foundItem.release(apis)

	if !foundItem.found {
		if foundItem.errStatus != 0 {
			return mapDarwinAuthStatus(foundItem.errStatus, false, "find item for erase")
		}
		if foundItem.hasLocked {
			return &Response{Code: "locked", Message: "keychain locked during find item for erase"}, 1
		}
		return &Response{Code: "not-found", Message: "credential not found"}, 1
	}

	delStatus := apis.itemDelete(foundItem.itemRef)
	if delStatus == errSecItemNotFound {
		return &Response{Code: "not-found", Message: "credential not found"}, 1
	}
	if delStatus != errSecSuccess {
		return mapDarwinAuthStatus(delStatus, isItemKeychainLocked(apis, foundItem.itemRef), "delete item")
	}
	return &Response{}, 0
}

func handlePlatformSystemHelper(action Action, req *Request) (*Response, int) {
	if req == nil {
		return &Response{Code: "unavailable", Message: "nil request"}, 1
	}

	apis, err := getDarwinKeychainAPI()
	if err != nil {
		return &Response{Code: "unavailable", Message: err.Error()}, 1
	}

	// 明确禁止系统弹窗交互，在允许弹窗的 macOS 会话中杜绝等待用户授权挂起
	if apis.setUserInteractionAllowed != nil {
		if status := apis.setUserInteractionAllowed(0); status != errSecSuccess {
			return &Response{
				Code:    "unavailable",
				Message: fmt.Sprintf("SecKeychainSetUserInteractionAllowed failed: %d", status),
			}, 1
		}
	}

	service := fmt.Sprintf("xops:%s", req.StoreID)
	account := req.ItemID

	serviceBytes := []byte(service)
	accountBytes := []byte(account)

	switch action {
	case ActionGet:
		return darwinActionGet(apis, serviceBytes, accountBytes)
	case ActionStore:
		return darwinActionStore(apis, serviceBytes, accountBytes, req.Secret)
	case ActionErase:
		return darwinActionErase(apis, serviceBytes, accountBytes)
	default:
		return &Response{Code: "unavailable", Message: "unsupported action"}, 1
	}
}

func checkPlatformSystemAvailability() error {
	return nil
}
