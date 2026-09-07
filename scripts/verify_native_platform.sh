#!/usr/bin/env bash
# ==============================================================================
# scripts/verify_native_platform.sh
# 跨平台凭据系统原生后端验收与 Spike 回归验证脚本
# 支持 Linux (Secret Service)、macOS (Keychain)、Windows (Credential Manager)
# 严格执行真实断言与退出码校验，未在目标环境执行时严禁标记为 PASS
# ==============================================================================

set -euo pipefail

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

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

log_skip() {
    printf "[SKIP] %s\n" "$*"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

# ==============================================================================
# run_go_test: 执行指定的 Go 测试，严格根据退出码判定，并杜绝无匹配测试计为通过
# 参数:
#   $1: 测试项描述 (description)
#   $2: Go 包路径 (package)
#   $3: 测试正则模式 (run_regex)
#   $@: 可选环境变量 (如 DBUS_SESSION_BUS_ADDRESS= ...)
# ==============================================================================
run_go_test() {
    local desc="$1"
    local pkg="$2"
    local run_regex="$3"
    shift 3

    local out status=0
    # 严格捕获真实退出码，绝不通过 || true 丢弃
    out=$(env "$@" go test -v -run "$run_regex" "$pkg" 2>&1) || status=$?

    # 1. 退出码校验：非 0 即失败
    if [ "$status" -ne 0 ]; then
        log_fail "$desc (failed with exit code $status): $out"
        return
    fi

    # 2. 避免“没有匹配测试”被计为通过：
    # go test -v 在真正匹配并成功运行每个测试时，必定输出 "--- PASS: <TestName>"
    if ! echo "$out" | grep -q -- "--- PASS:"; then
        log_fail "$desc (no tests were executed or matched regex '$run_regex'): $out"
        return
    fi

    # 3. 避免一组测试中部分失败被遗漏：严禁存在 "--- FAIL:"
    if echo "$out" | grep -q -- "--- FAIL:"; then
        log_fail "$desc (found failed subtests in output): $out"
        return
    fi

    log_pass "$desc"
}

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
log_info "Running native credential persistence verification on OS: $OS"

# 确保二进制已构建
BIN_DIR="$(pwd)/bin"
mkdir -p "$BIN_DIR"
BIN_NAME="xops"
case "$OS" in
    msys*|mingw*|cygwin*|windows*)
        BIN_NAME="xops.exe"
        ;;
esac
EXE_PATH="$BIN_DIR/$BIN_NAME"

log_info "Building current executable for helper testing..."
go build -o "$EXE_PATH" ./cmd/cli
log_info "Executable built at $EXE_PATH"

# ------------------------------------------------------------------------------
# 1. 协议边界与输入校验 (所有平台通用)
# ------------------------------------------------------------------------------
log_info "--- Stage 1: Common Helper Protocol Boundaries ---"

# Test 1.1: 拒绝未知主版本 (失败关闭)
STATUS=0
OUT=$(printf '{"protocolVersion": 99, "storeID": "s", "itemID": "k"}' | \
    XOPS_CREDENTIAL_HELPER_SYSTEM=1 "$EXE_PATH" get 2>&1) || STATUS=$?
if [ "$STATUS" -ne 0 ] && echo "$OUT" | grep -q "unsupported protocol version"; then
    log_pass "Helper protocol strictly rejects unknown version (fail-closed)"
else
    log_fail "Unknown protocol version was not rejected: $OUT (exit code: $STATUS)"
fi

# Test 1.2: 拒绝多余的 JSON 对象
STATUS=0
OUT=$(printf '{"protocolVersion": 1, "storeID": "s", "itemID": "k"}{"protocolVersion": 1}' | \
    XOPS_CREDENTIAL_HELPER_SYSTEM=1 "$EXE_PATH" get 2>&1) || STATUS=$?
if [ "$STATUS" -ne 0 ] && echo "$OUT" | grep -q "unexpected multiple JSON objects"; then
    log_pass "Helper protocol strictly rejects multiple JSON objects"
else
    log_fail "Multiple JSON objects were not rejected: $OUT (exit code: $STATUS)"
fi

# Test 1.3: 拒绝空引用
STATUS=0
OUT=$(printf '{"protocolVersion": 1, "storeID": "", "itemID": "k"}' | \
    XOPS_CREDENTIAL_HELPER_SYSTEM=1 "$EXE_PATH" get 2>&1) || STATUS=$?
if [ "$STATUS" -ne 0 ] && echo "$OUT" | grep -q "storeID and itemID cannot be empty"; then
    log_pass "Helper protocol strictly rejects empty storeID"
else
    log_fail "Empty storeID was not rejected: $OUT (exit code: $STATUS)"
fi

# Test 1.4: 校验 Go 协议与未知错误码脱敏测试
run_go_test "Internal helper protocol validation and secret redacting verified via Go tests" \
    ./internal/credentialhelper \
    "^TestInternalSystemHelperProtocolValidation$|^TestUnknownErrorCodeDoesNotExposeKnownSecret$"

# ------------------------------------------------------------------------------
# 2. 平台特定原生凭据库与隔离机制验证
# ------------------------------------------------------------------------------
log_info "--- Stage 2: Platform Specific Verification ---"

case "$OS" in
    linux*)
        log_info "Executing Linux-specific verification (Secret Service & Headless)"

        # 2.1 Headless 环境前置拒绝验证 (Fail-closed)
        run_go_test "Headless environment without D-Bus correctly fails closed" \
            ./internal/credentialhelper \
            "^TestCheckSystemAvailability_HeadlessDetection$" \
            DBUS_SESSION_BUS_ADDRESS= DISPLAY= WAYLAND_DISPLAY=

        # 2.2 D-Bus 连接故障不误报 NotFound
        run_go_test "D-Bus connection failure mapped to ErrCredentialStoreUnavailable, not NotFound" \
            ./internal/credentialhelper \
            "^TestSystemStoreLinuxDBusFailureNotReportedAsNotFound$"

        # 2.3 64KB 输出截断拒收验证
        run_go_test "Linux native store strictly rejects oversized outputs (>64KB)" \
            ./internal/credentialhelper \
            "^TestProcessRunHugeOutput$"

        log_skip "Skipping macOS and Windows native tests on Linux host"
        ;;

    darwin*)
        log_info "Executing macOS-specific verification (Keychain Services via purego C API)"

        # 2.1 运行 macOS 原生单元注入测试 (包含重试错误传播)
        run_go_test "macOS Security framework C API hooks (find/add/mod/delete & duplicate retry error propagation) passed" \
            ./internal/credentialhelper \
            "^TestDarwinNativeHelper"

        # 2.2 验证原始字节、不可打印二进制与尾随换行无损往返
        TEST_VAL="secret-payload\n\n\x00\x01\x02\xff"
        B64_IN=$(printf "%b" "$TEST_VAL" | base64 | tr -d '\r\n')
        
        # Store
        STATUS=0
        OUT=$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "bin-key", "secret": "%s"}' "$B64_IN" | \
            XOPS_CREDENTIAL_HELPER_SYSTEM=1 "$EXE_PATH" store 2>&1) || STATUS=$?
        if [ "$STATUS" -eq 0 ]; then
            log_pass "macOS Keychain native store succeeded"
        else
            log_fail "macOS Keychain native store failed (exit code: $STATUS): $OUT"
        fi
        
        # Get
        STATUS=0
        GET_OUT=$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "bin-key"}' | \
            XOPS_CREDENTIAL_HELPER_SYSTEM=1 "$EXE_PATH" get 2>&1) || STATUS=$?
        if [ "$STATUS" -ne 0 ]; then
            log_fail "macOS Keychain native get failed (exit code: $STATUS): $GET_OUT"
        else
            B64_OUT=$(echo "$GET_OUT" | grep -o '"secret":"[^"]*"' | cut -d'"' -f4)
            if [ "$B64_IN" = "$B64_OUT" ]; then
                log_pass "macOS byte-exact roundtrip (including trailing newlines and binary zeroes) verified"
            else
                log_fail "macOS roundtrip mismatch: expected $B64_IN, got $B64_OUT"
            fi
        fi

        # Erase
        STATUS=0
        OUT=$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "bin-key"}' | \
            XOPS_CREDENTIAL_HELPER_SYSTEM=1 "$EXE_PATH" erase 2>&1) || STATUS=$?
        if [ "$STATUS" -eq 0 ]; then
            log_pass "macOS Keychain native erase succeeded"
        else
            log_fail "macOS Keychain native erase failed (exit code: $STATUS): $OUT"
        fi

        log_skip "Skipping Linux and Windows native tests on macOS host"
        ;;

    msys*|mingw*|cygwin*|windows*)
        log_info "Executing Windows-specific verification (Win32 Credential Manager & Job Object)"

        # 2.1 运行 Windows 原生单元与集成测试 (包含 Job Object 挂起创建与树终止)
        run_go_test "Windows Win32 CredReadW/WriteW/DeleteW and Job Object tree termination passed" \
            ./internal/credentialhelper \
            "^TestWindowsNative|^TestProcessRunTimeoutAndCancel$"

        # 2.2 验证受控 Helper 真实端到端往返
        TEST_VAL="windows-secret-data\n\n\x00\x01\x02"
        B64_IN=$(printf "%b" "$TEST_VAL" | base64 | tr -d '\r\n')

        # Store
        STATUS=0
        OUT=$(printf '{"protocolVersion": 1, "storeID": "win-sys", "itemID": "k1", "secret": "%s"}' "$B64_IN" | \
            XOPS_CREDENTIAL_HELPER_SYSTEM=1 "$EXE_PATH" store 2>&1) || STATUS=$?
        if [ "$STATUS" -eq 0 ]; then
            log_pass "Windows Credential Manager native store succeeded"
        else
            log_fail "Windows Credential Manager native store failed (exit code: $STATUS): $OUT"
        fi

        # Get
        STATUS=0
        GET_OUT=$(printf '{"protocolVersion": 1, "storeID": "win-sys", "itemID": "k1"}' | \
            XOPS_CREDENTIAL_HELPER_SYSTEM=1 "$EXE_PATH" get 2>&1) || STATUS=$?
        if [ "$STATUS" -ne 0 ]; then
            log_fail "Windows Credential Manager native get failed (exit code: $STATUS): $GET_OUT"
        else
            B64_OUT=$(echo "$GET_OUT" | grep -o '"secret":"[^"]*"' | cut -d'"' -f4)
            if [ "$B64_IN" = "$B64_OUT" ]; then
                log_pass "Windows byte-exact roundtrip verified"
            else
                log_fail "Windows roundtrip mismatch: expected $B64_IN, got $B64_OUT"
            fi
        fi

        # Erase
        STATUS=0
        OUT=$(printf '{"protocolVersion": 1, "storeID": "win-sys", "itemID": "k1"}' | \
            XOPS_CREDENTIAL_HELPER_SYSTEM=1 "$EXE_PATH" erase 2>&1) || STATUS=$?
        if [ "$STATUS" -eq 0 ]; then
            log_pass "Windows Credential Manager native erase succeeded"
        else
            log_fail "Windows Credential Manager native erase failed (exit code: $STATUS): $OUT"
        fi

        log_skip "Skipping Linux and macOS native tests on Windows host"
        ;;

    *)
        log_skip "Unknown OS $OS, skipped platform-specific native tests"
        ;;
esac

# ------------------------------------------------------------------------------
# 3. 统计与总结
# ------------------------------------------------------------------------------
log_info "============================================================"
log_info "Verification Summary: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"
log_info "============================================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
