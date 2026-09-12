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

# ==============================================================================
# exec_helper_with_timeout: 限制受控 Helper 单次调用时长，杜绝调用挂死
# ==============================================================================
exec_helper_with_timeout() {
    local timeout_secs="$1"
    local action="$2"
    local payload="$3"

    if command -v timeout >/dev/null 2>&1; then
        printf "%s" "$payload" | timeout "${timeout_secs}" env XOPS_CREDENTIAL_HELPER_SYSTEM=1 "$EXE_PATH" "$action" 2>&1
    elif command -v gtimeout >/dev/null 2>&1; then
        printf "%s" "$payload" | gtimeout "${timeout_secs}" env XOPS_CREDENTIAL_HELPER_SYSTEM=1 "$EXE_PATH" "$action" 2>&1
    else
        printf "%s" "$payload" | python3 -c '
import sys, subprocess, os
timeout = float(sys.argv[1])
cmd = [sys.argv[2], sys.argv[3]]
env = os.environ.copy()
env["XOPS_CREDENTIAL_HELPER_SYSTEM"] = "1"
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
try:
    out, _ = p.communicate(input=sys.stdin.read(), timeout=timeout)
    sys.stdout.write(out)
    sys.exit(p.returncode)
except subprocess.TimeoutExpired:
    p.kill()
    sys.stderr.write("helper call timed out after " + str(timeout) + "s\n")
    sys.exit(124)
' "${timeout_secs}" "$EXE_PATH" "$action" 2>&1
    fi
}

# ------------------------------------------------------------------------------
# 1. 协议边界与输入校验 (所有平台通用)
# ------------------------------------------------------------------------------
log_info "--- Stage 1: Common Helper Protocol Boundaries ---"

# Test 1.1: 拒绝未知主版本 (失败关闭)
STATUS=0
OUT=$(exec_helper_with_timeout 10 get '{"protocolVersion": 99, "storeID": "s", "itemID": "k"}') || STATUS=$?
if [ "$STATUS" -ne 0 ] && echo "$OUT" | grep -q "unsupported protocol version"; then
    log_pass "Helper protocol strictly rejects unknown version (fail-closed)"
else
    log_fail "Unknown protocol version was not rejected: $OUT (exit code: $STATUS)"
fi

# Test 1.2: 拒绝多余的 JSON 对象
STATUS=0
OUT=$(exec_helper_with_timeout 10 get '{"protocolVersion": 1, "storeID": "s", "itemID": "k"}{"protocolVersion": 1}') || STATUS=$?
if [ "$STATUS" -ne 0 ] && echo "$OUT" | grep -q "unexpected multiple JSON objects"; then
    log_pass "Helper protocol strictly rejects multiple JSON objects"
else
    log_fail "Multiple JSON objects were not rejected: $OUT (exit code: $STATUS)"
fi

# Test 1.3: 拒绝空引用
STATUS=0
OUT=$(exec_helper_with_timeout 10 get '{"protocolVersion": 1, "storeID": "", "itemID": "k"}') || STATUS=$?
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

        # 2.1 运行 macOS 原生单元与集成测试 (包含真实锁/解锁、重试更新与错误传播)
        run_go_test "macOS Security framework C API & Keychain integration tests passed" \
            ./internal/credentialhelper \
            "^TestDarwinNative"

        # 2.2 配置独立测试钥匙串，验证真实二进制端到端往返、更新、锁定/解锁及删除断言
        TEST_KEYCHAIN="/tmp/xops_verify_$$.keychain"
        TEST_KEYCHAIN_SEC="/tmp/xops_verify_sec_$$.keychain"
        KEYCHAIN_PASS="xops-test-pass-$$"
        ORIG_DEFAULT_KEYCHAIN=""
        ORIG_KEYCHAINS=()

        if command -v security >/dev/null 2>&1; then
            raw_def=$(security default-keychain 2>/dev/null || true)
            ORIG_DEFAULT_KEYCHAIN=$(echo "$raw_def" | sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//')

            while IFS= read -r line; do
                p=$(echo "$line" | sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//')
                if [ -n "$p" ]; then
                    ORIG_KEYCHAINS+=("$p")
                fi
            done < <(security list-keychains -d user 2>/dev/null || true)
        fi

        cleanup_darwin_test_keychain() {
            local exit_code=$?
            local cleanup_failed=0
            if command -v security >/dev/null 2>&1; then
                if [ -n "$ORIG_DEFAULT_KEYCHAIN" ]; then
                    if ! security default-keychain -s "$ORIG_DEFAULT_KEYCHAIN"; then
                        log_fail "Failed to restore original default keychain: $ORIG_DEFAULT_KEYCHAIN"
                        cleanup_failed=1
                    fi
                fi
                if [ ${#ORIG_KEYCHAINS[@]} -gt 0 ]; then
                    if ! security list-keychains -d user -s "${ORIG_KEYCHAINS[@]}"; then
                        log_fail "Failed to restore original keychain search list"
                        cleanup_failed=1
                    fi
                fi
                if [ -f "$TEST_KEYCHAIN" ]; then
                    if ! security delete-keychain "$TEST_KEYCHAIN"; then
                        log_fail "Failed to delete test keychain: $TEST_KEYCHAIN"
                        cleanup_failed=1
                    fi
                fi
                if [ -f "$TEST_KEYCHAIN_SEC" ]; then
                    if ! security delete-keychain "$TEST_KEYCHAIN_SEC"; then
                        log_fail "Failed to delete secondary test keychain: $TEST_KEYCHAIN_SEC"
                        cleanup_failed=1
                    fi
                fi
            fi
            if [ "$cleanup_failed" -ne 0 ] && [ "$exit_code" -eq 0 ]; then
                exit 1
            fi
            exit "$exit_code"
        }
        trap cleanup_darwin_test_keychain EXIT INT TERM

        if command -v security >/dev/null 2>&1; then
            if ! security create-keychain -p "$KEYCHAIN_PASS" "$TEST_KEYCHAIN"; then
                log_fail "Failed to create test keychain: $TEST_KEYCHAIN"
            fi
            if ! security unlock-keychain -p "$KEYCHAIN_PASS" "$TEST_KEYCHAIN"; then
                log_fail "Failed to unlock test keychain: $TEST_KEYCHAIN"
            fi
            if ! security set-keychain-settings -t 3600 -l "$TEST_KEYCHAIN"; then
                log_fail "Failed to set test keychain settings: $TEST_KEYCHAIN"
            fi
            if ! security default-keychain -s "$TEST_KEYCHAIN"; then
                log_fail "Failed to set default test keychain: $TEST_KEYCHAIN"
            fi
            if ! security list-keychains -d user -s "$TEST_KEYCHAIN"; then
                log_fail "Failed to configure test keychain search list"
            fi
            log_info "Configured isolated test keychain: $TEST_KEYCHAIN"
        fi

        TEST_ITEM="mac-key-$$-$(date +%s)"
        TEST_VAL_1="secret-payload-initial\n\n\x00\x01\x02\xff"
        B64_IN_1=$(printf "%b" "$TEST_VAL_1" | base64 | tr -d '\r\n')
        TEST_VAL_2="secret-payload-updated\n\xaa\xbb\xcc"
        B64_IN_2=$(printf "%b" "$TEST_VAL_2" | base64 | tr -d '\r\n')

        # Step A: 写入初始凭据 (带超时限制)
        STATUS=0
        OUT=$(exec_helper_with_timeout 15 store \
            "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s", "secret": "%s"}' "$TEST_ITEM" "$B64_IN_1")") || STATUS=$?
        if [ "$STATUS" -eq 0 ]; then
            log_pass "macOS Keychain initial store succeeded"
        else
            log_fail "macOS Keychain initial store failed (exit code: $STATUS): $OUT"
        fi

        # Step B: 读取并断言初始值
        STATUS=0
        GET_OUT=$(exec_helper_with_timeout 15 get \
            "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s"}' "$TEST_ITEM")") || STATUS=$?
        if [ "$STATUS" -ne 0 ]; then
            log_fail "macOS Keychain get initial failed (exit code: $STATUS): $GET_OUT"
        else
            B64_OUT=$(echo "$GET_OUT" | grep -o '"secret":"[^"]*"' | cut -d'"' -f4)
            if [ "$B64_IN_1" = "$B64_OUT" ]; then
                log_pass "macOS byte-exact roundtrip (initial binary with zeroes & newlines) verified"
            else
                log_fail "macOS initial roundtrip mismatch: expected $B64_IN_1, got $B64_OUT"
            fi
        fi

        # Step C: 覆盖写入同一条目更新值 (测试 errSecDuplicateItem 冲突重试与在位更新)
        STATUS=0
        OUT=$(exec_helper_with_timeout 15 store \
            "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s", "secret": "%s"}' "$TEST_ITEM" "$B64_IN_2")") || STATUS=$?
        if [ "$STATUS" -eq 0 ]; then
            log_pass "macOS Keychain update store succeeded"
        else
            log_fail "macOS Keychain update store failed (exit code: $STATUS): $OUT"
        fi

        # Step D: 读取并断言已更新为新值 (且不为旧值)
        STATUS=0
        GET_OUT=$(exec_helper_with_timeout 15 get \
            "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s"}' "$TEST_ITEM")") || STATUS=$?
        if [ "$STATUS" -ne 0 ]; then
            log_fail "macOS Keychain get updated failed (exit code: $STATUS): $GET_OUT"
        else
            B64_OUT=$(echo "$GET_OUT" | grep -o '"secret":"[^"]*"' | cut -d'"' -f4)
            if [ "$B64_IN_2" = "$B64_OUT" ]; then
                log_pass "macOS Keychain in-place update verified (matched updated secret)"
            else
                log_fail "macOS Keychain update mismatch: expected $B64_IN_2, got $B64_OUT"
            fi
        fi

        # Step E: 锁定钥匙串，验证非交互式锁定状态拒绝与 fail-closed 错误映射 (严格断言 code=locked)
        if command -v security >/dev/null 2>&1 && [ -f "$TEST_KEYCHAIN" ]; then
            if ! security lock-keychain "$TEST_KEYCHAIN"; then
                log_fail "Failed to lock test keychain: $TEST_KEYCHAIN"
            fi
            STATUS=0
            LOCKED_OUT=$(exec_helper_with_timeout 15 get \
                "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s"}' "$TEST_ITEM")") || STATUS=$?
            if [ "$STATUS" -ne 0 ] && echo "$LOCKED_OUT" | grep -q '"code":"locked"'; then
                log_pass "macOS Keychain locked state strictly rejected and mapped to code 'locked'"
            else
                log_fail "macOS Keychain locked state was not rejected with code 'locked' (exit code: $STATUS, out: $LOCKED_OUT)"
            fi

            # 解锁钥匙串恢复
            if ! security unlock-keychain -p "$KEYCHAIN_PASS" "$TEST_KEYCHAIN"; then
                log_fail "Failed to unlock test keychain: $TEST_KEYCHAIN"
            fi
        fi

        # Step E.1: 验证多钥匙串搜索列表锁定分类 (默认库解锁，但目标库锁定)
        if command -v security >/dev/null 2>&1 && [ -f "$TEST_KEYCHAIN" ]; then
            if security create-keychain -p "$KEYCHAIN_PASS" "$TEST_KEYCHAIN_SEC"; then
                if security unlock-keychain -p "$KEYCHAIN_PASS" "$TEST_KEYCHAIN_SEC" && \
                   security set-keychain-settings -t 3600 -l "$TEST_KEYCHAIN_SEC"; then
                    security list-keychains -d user -s "$TEST_KEYCHAIN" "$TEST_KEYCHAIN_SEC"

                    MULTI_ITEM="mac-multi-key-$$-$(date +%s)"
                    # 使用 -A 显式授权所有应用（包括 helper）访问，杜绝未授权 ACL 导致初次读取失败
                    if security add-generic-password -s "xops:test-sys" -a "$MULTI_ITEM" -w "multi-sec-val" -A "$TEST_KEYCHAIN_SEC"; then
                        # 1. 验证解锁状态下 helper 能够成功读取次级钥匙串中的条目
                        STATUS=0
                        UNLOCKED_OUT=$(exec_helper_with_timeout 15 get \
                            "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s"}' "$MULTI_ITEM")") || STATUS=$?
                        if [ "$STATUS" -eq 0 ]; then
                            log_pass "macOS Multi-Keychain: helper successfully read item from unlocked secondary keychain"
                        else
                            log_fail "macOS Multi-Keychain: helper failed to read item from unlocked secondary keychain (exit code: $STATUS, out: $UNLOCKED_OUT)"
                        fi

                        # 2. 锁定 secondary 钥匙串（而默认 TEST_KEYCHAIN 钥匙串保持解锁）
                        if security lock-keychain "$TEST_KEYCHAIN_SEC"; then
                            STATUS=0
                            MULTI_OUT=$(exec_helper_with_timeout 15 get \
                                "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s"}' "$MULTI_ITEM")") || STATUS=$?
                            if [ "$STATUS" -ne 0 ] && echo "$MULTI_OUT" | grep -q '"code":"locked"'; then
                                log_pass "macOS Multi-Keychain: locked secondary keychain strictly mapped to code 'locked' (default unlocked)"
                            else
                                log_fail "macOS Multi-Keychain: locked secondary keychain was not mapped to code 'locked' (exit code: $STATUS, out: $MULTI_OUT)"
                            fi

                            # 2.1 验证在 secondary 钥匙串锁定时执行 store 写入：
                            # 必须 fail-closed 报错 locked，绝不能在默认钥匙串中新建同名条目导致遮蔽原凭据！
                            STATUS=0
                            STORE_SHADOW_OUT=$(exec_helper_with_timeout 15 store \
                                "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s", "secret": "%s"}' "$MULTI_ITEM" "$B64_IN_1")") || STATUS=$?
                            if [ "$STATUS" -ne 0 ] && echo "$STORE_SHADOW_OUT" | grep -q '"code":"locked"'; then
                                if security find-generic-password -s "xops:test-sys" -a "$MULTI_ITEM" "$TEST_KEYCHAIN" >/dev/null 2>&1; then
                                    log_fail "macOS Multi-Keychain: store while secondary locked created shadowing item in default keychain!"
                                else
                                    log_pass "macOS Multi-Keychain: store while secondary locked strictly failed closed with code 'locked' and prevented shadowing"
                                fi
                            else
                                log_fail "macOS Multi-Keychain: store while secondary locked did not fail with code 'locked' (exit code: $STATUS, out: $STORE_SHADOW_OUT)"
                            fi

                            security unlock-keychain -p "$KEYCHAIN_PASS" "$TEST_KEYCHAIN_SEC" || true
                            security delete-generic-password -s "xops:test-sys" -a "$MULTI_ITEM" "$TEST_KEYCHAIN_SEC" || true
                        else
                            log_fail "Failed to lock secondary test keychain"
                        fi
                    else
                        log_fail "Failed to add generic password to secondary test keychain"
                    fi

                    # 恢复主测试钥匙串搜索列表
                    security list-keychains -d user -s "$TEST_KEYCHAIN" || true
                fi
                security delete-keychain "$TEST_KEYCHAIN_SEC" 2>/dev/null || true
            fi
        fi

        # Step E.1.2: 验证反向多钥匙串场景 (目标库已解锁但因 ACL 拒绝，无关次级库锁定，严格断言 denied 而非 locked)
        if command -v security >/dev/null 2>&1 && [ -f "$TEST_KEYCHAIN" ]; then
            if security create-keychain -p "$KEYCHAIN_PASS" "$TEST_KEYCHAIN_SEC"; then
                if security unlock-keychain -p "$KEYCHAIN_PASS" "$TEST_KEYCHAIN_SEC"; then
                    # 锁定次级库
                    security lock-keychain "$TEST_KEYCHAIN_SEC" || true

                    # 配置搜索列表包含主库和已锁定的次级库
                    security list-keychains -d user -s "$TEST_KEYCHAIN" "$TEST_KEYCHAIN_SEC"

                    REV_ITEM="mac-rev-key-$$-$(date +%s)"
                    if security add-generic-password -s "xops:test-sys" -a "$REV_ITEM" -w "rev-secret" -T /usr/bin/false "$TEST_KEYCHAIN"; then
                        STATUS=0
                        REV_OUT=$(exec_helper_with_timeout 15 get \
                            "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s"}' "$REV_ITEM")") || STATUS=$?
                        if [ "$STATUS" -ne 0 ] && echo "$REV_OUT" | grep -q '"code":"denied"' && ! echo "$REV_OUT" | grep -q '"code":"locked"'; then
                            log_pass "macOS Multi-Keychain Reverse: ACL denied on unlocked keychain correctly mapped to 'denied' despite unrelated locked keychain"
                        else
                            log_fail "macOS Multi-Keychain Reverse: failed to map to 'denied' or falsely reported 'locked' (exit code: $STATUS, out: $REV_OUT)"
                        fi
                        security delete-generic-password -s "xops:test-sys" -a "$REV_ITEM" "$TEST_KEYCHAIN" || true
                    fi

                    # 恢复主测试钥匙串搜索列表
                    security list-keychains -d user -s "$TEST_KEYCHAIN" || true
                fi
                security delete-keychain "$TEST_KEYCHAIN_SEC" 2>/dev/null || true
            fi
        fi

        # Step E.2: 验证真实钥匙串 ACL / 签名拒绝场景 (测试 -T 限制访问控制)
        if command -v security >/dev/null 2>&1 && [ -f "$TEST_KEYCHAIN" ]; then
            ACL_ITEM="mac-acl-key-$$-$(date +%s)"
            if security add-generic-password -s "xops:test-sys" -a "$ACL_ITEM" -w "acl-secret" -T /usr/bin/false "$TEST_KEYCHAIN"; then
                STATUS=0
                ACL_OUT=$(exec_helper_with_timeout 15 get \
                    "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s"}' "$ACL_ITEM")") || STATUS=$?
                if [ "$STATUS" -ne 0 ] && echo "$ACL_OUT" | grep -q '"code":"denied"'; then
                    log_pass "macOS Keychain ACL/signature mismatch correctly mapped to code 'denied'"
                else
                    log_fail "macOS Keychain ACL mismatch was not mapped to code 'denied' (exit code: $STATUS, out: $ACL_OUT)"
                fi
                if ! security delete-generic-password -s "xops:test-sys" -a "$ACL_ITEM" "$TEST_KEYCHAIN"; then
                    log_fail "Failed to delete ACL test item from test keychain"
                fi
            else
                log_fail "Failed to create ACL test item with restricted access"
            fi
        fi

        # Step F: 删除条目 (erase)
        STATUS=0
        OUT=$(exec_helper_with_timeout 15 erase \
            "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s"}' "$TEST_ITEM")") || STATUS=$?
        if [ "$STATUS" -eq 0 ]; then
            log_pass "macOS Keychain erase succeeded"
        else
            log_fail "macOS Keychain erase failed (exit code: $STATUS): $OUT"
        fi

        # Step G: 严格验证删除效果 (删除后再次读取必须返回非零且提示 not-found)
        STATUS=0
        AFTER_ERASE_OUT=$(exec_helper_with_timeout 15 get \
            "$(printf '{"protocolVersion": 1, "storeID": "test-sys", "itemID": "%s"}' "$TEST_ITEM")") || STATUS=$?
        if [ "$STATUS" -ne 0 ] && echo "$AFTER_ERASE_OUT" | grep -q '"code":"not-found"'; then
            log_pass "macOS Keychain erase verified: subsequent read returned not-found"
        else
            log_fail "macOS Keychain erase verification failed: read after erase did not return not-found (exit code: $STATUS, out: $AFTER_ERASE_OUT)"
        fi

        log_skip "Skipping Linux and Windows native tests on macOS host"
        ;;

    msys*|mingw*|cygwin*|windows*)
        log_info "Executing Windows-specific verification (Win32 Credential Manager & Job Object)"

        # 2.1 运行 Windows 原生单元与集成测试 (包含 Job Object 挂起创建与树终止)
        run_go_test "Windows Win32 CredReadW/WriteW/DeleteW and Job Object tree termination passed" \
            ./internal/credentialhelper \
            "^TestWindowsNative|^TestProcessRunTimeoutAndCancel$"

        # 2.2 验证受控 Helper 真实端到端往返、更新与删除断言
        TEST_ITEM="win-key-$$-$(date +%s)"
        TEST_VAL_1="windows-secret-data-1\n\n\x00\x01\x02"
        B64_IN_1=$(printf "%b" "$TEST_VAL_1" | base64 | tr -d '\r\n')
        TEST_VAL_2="windows-secret-data-2-updated\xaa\xbb"
        B64_IN_2=$(printf "%b" "$TEST_VAL_2" | base64 | tr -d '\r\n')

        # Store 1
        STATUS=0
        OUT=$(exec_helper_with_timeout 15 store \
            "$(printf '{"protocolVersion": 1, "storeID": "win-sys", "itemID": "%s", "secret": "%s"}' "$TEST_ITEM" "$B64_IN_1")") || STATUS=$?
        if [ "$STATUS" -eq 0 ]; then
            log_pass "Windows Credential Manager native store succeeded"
        else
            log_fail "Windows Credential Manager native store failed (exit code: $STATUS): $OUT"
        fi

        # Get 1
        STATUS=0
        GET_OUT=$(exec_helper_with_timeout 15 get \
            "$(printf '{"protocolVersion": 1, "storeID": "win-sys", "itemID": "%s"}' "$TEST_ITEM")") || STATUS=$?
        if [ "$STATUS" -ne 0 ]; then
            log_fail "Windows Credential Manager native get failed (exit code: $STATUS): $GET_OUT"
        else
            B64_OUT=$(echo "$GET_OUT" | grep -o '"secret":"[^"]*"' | cut -d'"' -f4)
            if [ "$B64_IN_1" = "$B64_OUT" ]; then
                log_pass "Windows byte-exact roundtrip verified"
            else
                log_fail "Windows roundtrip mismatch: expected $B64_IN_1, got $B64_OUT"
            fi
        fi

        # Store 2 (Update)
        STATUS=0
        OUT=$(exec_helper_with_timeout 15 store \
            "$(printf '{"protocolVersion": 1, "storeID": "win-sys", "itemID": "%s", "secret": "%s"}' "$TEST_ITEM" "$B64_IN_2")") || STATUS=$?
        if [ "$STATUS" -eq 0 ]; then
            log_pass "Windows Credential Manager native update succeeded"
        else
            log_fail "Windows Credential Manager native update failed (exit code: $STATUS): $OUT"
        fi

        # Get 2
        STATUS=0
        GET_OUT=$(exec_helper_with_timeout 15 get \
            "$(printf '{"protocolVersion": 1, "storeID": "win-sys", "itemID": "%s"}' "$TEST_ITEM")") || STATUS=$?
        if [ "$STATUS" -ne 0 ]; then
            log_fail "Windows Credential Manager native get updated failed (exit code: $STATUS): $GET_OUT"
        else
            B64_OUT=$(echo "$GET_OUT" | grep -o '"secret":"[^"]*"' | cut -d'"' -f4)
            if [ "$B64_IN_2" = "$B64_OUT" ]; then
                log_pass "Windows update verified (matched updated secret)"
            else
                log_fail "Windows update mismatch: expected $B64_IN_2, got $B64_OUT"
            fi
        fi

        # Erase
        STATUS=0
        OUT=$(exec_helper_with_timeout 15 erase \
            "$(printf '{"protocolVersion": 1, "storeID": "win-sys", "itemID": "%s"}' "$TEST_ITEM")") || STATUS=$?
        if [ "$STATUS" -eq 0 ]; then
            log_pass "Windows Credential Manager native erase succeeded"
        else
            log_fail "Windows Credential Manager native erase failed (exit code: $STATUS): $OUT"
        fi

        # Get after Erase
        STATUS=0
        AFTER_ERASE_OUT=$(exec_helper_with_timeout 15 get \
            "$(printf '{"protocolVersion": 1, "storeID": "win-sys", "itemID": "%s"}' "$TEST_ITEM")") || STATUS=$?
        if [ "$STATUS" -ne 0 ] && echo "$AFTER_ERASE_OUT" | grep -q '"code":"not-found"'; then
            log_pass "Windows Credential Manager erase verified: subsequent read returned not-found"
        else
            log_fail "Windows Credential Manager erase verification failed: read after erase did not return not-found (exit code: $STATUS, out: $AFTER_ERASE_OUT)"
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
