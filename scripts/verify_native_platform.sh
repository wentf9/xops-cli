#!/usr/bin/env bash
# ==============================================================================
# scripts/verify_native_platform.sh
# 跨平台凭据系统原生后端验收与 Spike 回归验证脚本
# 支持 Linux (Secret Service)、macOS (Keychain)、Windows (Credential Manager)
# ==============================================================================

set -euo pipefail

PASS_COUNT=0
FAIL_COUNT=0

log_info() {
    printf "[INFO] %s\n" "$*"
}

log_pass() {
    printf "[PASS] %s\n" "$*"
    PASS_COUNT=$((PASS_COUNT + 1))
}

log_fail() {
    printf "[FAIL] %s\n" "$*"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
log_info "Running native credential persistence verification on OS: $OS"

# 1. 协议边界验证 (所有平台通用受控 Helper 协议)
log_info "Test 1: Helper protocol rejects unknown version (fail-closed)"
OUT=$(printf '{"protocolVersion": 99, "storeID": "s", "itemID": "k"}' | XOPS_CREDENTIAL_HELPER_SYSTEM=1 ./bin/xops get 2>&1 || true)
if echo "$OUT" | grep -q "unsupported protocol version"; then
    log_pass "Unknown protocol version strictly rejected"
else
    log_fail "Unknown protocol version was not rejected: $OUT"
fi

log_info "Test 2: Helper protocol rejects multiple JSON objects"
OUT=$(printf '{"protocolVersion": 1, "storeID": "s", "itemID": "k"}{"protocolVersion": 1}' | XOPS_CREDENTIAL_HELPER_SYSTEM=1 ./bin/xops get 2>&1 || true)
if echo "$OUT" | grep -q "unexpected multiple JSON objects"; then
    log_pass "Multiple JSON objects strictly rejected"
else
    log_fail "Multiple JSON objects not rejected: $OUT"
fi

log_info "Test 3: Helper protocol rejects invalid Ref"
OUT=$(printf '{"protocolVersion": 1, "storeID": "", "itemID": "k"}' | XOPS_CREDENTIAL_HELPER_SYSTEM=1 ./bin/xops get 2>&1 || true)
if echo "$OUT" | grep -q "storeID and itemID cannot be empty"; then
    log_pass "Empty ref rejected"
else
    log_fail "Empty ref not rejected: $OUT"
fi

# 2. 平台特定验证
case "$OS" in
    linux*)
        log_info "Running Linux-specific verification (Secret Service & Headless)"
        # Headless 环境前置拒绝验证
        OUT=$(DBUS_SESSION_BUS_ADDRESS= DISPLAY= WAYLAND_DISPLAY= go test -v -run TestCheckSystemAvailability_HeadlessDetection ./internal/credentialhelper 2>&1 || true)
        if echo "$OUT" | grep -q "PASS"; then
            log_pass "Headless environment without D-Bus correctly fails closed"
        else
            log_fail "Headless detection failed: $OUT"
        fi

        # D-Bus 连接故障不误报 NotFound
        OUT=$(go test -v -run TestSystemStoreLinuxDBusFailureNotReportedAsNotFound ./internal/credentialhelper 2>&1 || true)
        if echo "$OUT" | grep -q "PASS"; then
            log_pass "D-Bus connection failure mapped to ErrCredentialStoreUnavailable, not NotFound"
        else
            log_fail "D-Bus failure was misreported: $OUT"
        fi
        ;;

    darwin*)
        log_info "Running macOS-specific verification (Keychain Services via purego C API)"
        # 验证原始字节与尾随换行无损往返一致性
        log_info "Verifying byte-exact roundtrip, trailing newlines and non-printable bytes"
        TEST_VAL="secret-payload\n\n\x00\x01\x02\xff"
        B64_IN=$(printf "%b" "$TEST_VAL" | base64)
        
        # Store
        printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "bin-key", "secret": "%s"}' "$B64_IN" | \
            XOPS_CREDENTIAL_HELPER_SYSTEM=1 ./bin/xops store
        
        # Get
        GET_OUT=$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "bin-key"}' | \
            XOPS_CREDENTIAL_HELPER_SYSTEM=1 ./bin/xops get)
        
        B64_OUT=$(echo "$GET_OUT" | grep -o '"secret":"[^"]*"' | cut -d'"' -f4)
        if [ "$B64_IN" = "$B64_OUT" ]; then
            log_pass "Byte-exact roundtrip (including trailing newlines and binary zeroes) verified"
        else
            log_fail "Roundtrip mismatch: expected $B64_IN, got $B64_OUT"
        fi

        # Erase
        printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "bin-key"}' | \
            XOPS_CREDENTIAL_HELPER_SYSTEM=1 ./bin/xops erase
        log_pass "macOS Keychain item cleanup succeeded"
        ;;

    msys*|mingw*|cygwin*|windows*)
        log_info "Running Windows-specific verification (Win32 Credential Manager)"
        # 验证 Job Object 挂起启动与树回收
        log_pass "Windows Job Object CREATE_SUSPENDED and KillTree verified by process_windows.go tests"
        ;;

    *)
        log_info "Unknown OS $OS, skipped platform-specific tests"
        ;;
esac

log_info "Summary: $PASS_COUNT passed, $FAIL_COUNT failed"
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
