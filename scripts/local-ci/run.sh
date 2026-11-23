#!/usr/bin/env bash
# XOps v2 本地多平台测试与 Gate 编排器（层 A：无服务极速过闸主力）
# 职责：
#   1. 从仓库外部私有配置 ~/.config/xops-local-ci/env 加载宿主机与靶机信息（零敏感信息入库）；
#   2. 通过 git archive（干净态）或 tar（--dirty 工作区态）安全投递源码到独立沙箱目录；
#   3. 支持 --auto-power 自动唤醒休眠 VM，并在完成后仅对本次唤醒的 VM 执行 virsh managedsave 回收内存；
#   4. 并发或分目标执行 --smoke（环境与 -race 自检）或 --gate g0..g5 验收，严格校验退出码与真断言。

set -euo pipefail

# ----------------------------- 默认参数 -----------------------------
ENV_FILE="${XOPS_LOCAL_CI_ENV:-$HOME/.config/xops-local-ci/env}"
MODE="gate"
GATE="g2"
TARGETS="linux,win11,freebsd"
DIRTY=0
AUTO_POWER=0
PKG_FILTER=""
DST_SEEDS="${XOPS_DST_SEEDS:-2000}"
REPO_ROOT="$(git rev-parse --show-toplevel)"
RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
WORK_TMP="$(mktemp -d "${TMPDIR:-/tmp}/xops-local-ci-${RUN_ID}.XXXXXX")"
LOG_DIR="${WORK_TMP}/logs"
mkdir -p "$LOG_DIR"

# 记录本次脚本主动唤醒的 VM，退出时仅休眠这些 VM
WOKEN_VMS=()

usage() {
  cat <<'EOF'
用法:
  ./scripts/local-ci/run.sh [选项]

选项:
  --smoke                     运行多平台工具链与 Go -race 冒烟验证（不依赖 v2 目录已创建）
  --gate <g0|g1|g2|g2.5|g3|g4|g5>
                              按 XOps v2 实施计划执行对应门禁（默认: g2）
  --targets <list>            逗号分隔目标列表: linux,win11,ubuntu,freebsd（默认: linux,win11,freebsd）
  --dirty                     打包当前工作区未提交文件（排除 .git/bin/node_modules）；默认仅打 git archive HEAD
  --pkg <pattern>             定向仅测指定 Go 包（如 ./osfs）
  --dst-seeds <N>             DST 确定性仿真种子数（默认: 2000，过闸推荐 10000）
  --auto-power                自动 virsh start 非运行态 VM，结束后对本次唤醒的 VM 执行 virsh managedsave
  --env <path>                指定私有配置文件路径（默认: ~/.config/xops-local-ci/env）
  -h, --help                  显示帮助
EOF
}

# ----------------------------- 参数解析 -----------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --smoke)
      MODE="smoke"
      shift
      ;;
    --gate)
      MODE="gate"
      GATE="${2:?--gate 需要参数}"
      shift 2
      ;;
    --targets)
      TARGETS="${2:?--targets 需要参数}"
      shift 2
      ;;
    --dirty)
      DIRTY=1
      shift
      ;;
    --pkg)
      PKG_FILTER="${2:?--pkg 需要参数}"
      shift 2
      ;;
    --dst-seeds)
      DST_SEEDS="${2:?--dst-seeds 需要参数}"
      shift 2
      ;;
    --auto-power)
      AUTO_POWER=1
      shift
      ;;
    --env)
      ENV_FILE="${2:?--env 需要参数}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "未知参数: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$ENV_FILE" ]]; then
  echo "错误：未找到本地私有配置文件 $ENV_FILE" >&2
  echo "请参照 docs/development/v2-local-multiplatform-ci.md 创建该文件。" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

SSH_BASE_OPTS=(
  -i "$XOPS_CI_SSH_KEY"
  -o BatchMode=yes
  -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=10
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=4
)

# ----------------------------- 清理与休眠钩子 -----------------------------
cleanup() {
  local rc=$?
  if [[ "$AUTO_POWER" -eq 1 && ${#WOKEN_VMS[@]} -gt 0 ]]; then
    echo ">>> [auto-power] 正在将本次唤醒的 VM 休眠回写内存 (virsh managedsave)..."
    for vm in "${WOKEN_VMS[@]}"; do
      echo "    managedsave $vm"
      virsh --connect qemu:///system managedsave "$vm" >/dev/null 2>&1 || true
    done
  fi
  rm -rf "$WORK_TMP"
  exit "$rc"
}
trap cleanup EXIT

# ----------------------------- VM 电源与 SSH 就绪 -----------------------------
ensure_vm_ready() {
  local vm="$1"
  local user="$2"
  local host="$3"
  local state
  state="$(LANG=C virsh --connect qemu:///system domstate "$vm" 2>/dev/null | tr -d '\r' | xargs || true)"
  if [[ "$state" != "running" ]]; then
    if [[ "$AUTO_POWER" -ne 1 ]]; then
      echo "错误：VM $vm 当前状态为 '${state:-unknown}'；请先启动它或传入 --auto-power。" >&2
      return 1
    fi
    echo ">>> [auto-power] 正在唤醒 VM $vm ..."
    virsh --connect qemu:///system start "$vm" >/dev/null
    WOKEN_VMS+=("$vm")
  fi

  # 轮询 SSH 就绪（最多 90 秒）
  local i
  for i in $(seq 1 45); do
    if ssh "${SSH_BASE_OPTS[@]}" "${user}@${host}" "echo READY" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "错误：等待 VM $vm (${user}@${host}) SSH 就绪超时。" >&2
  return 1
}

# ----------------------------- 源码打包 -----------------------------
ARCHIVE_TAR="${WORK_TMP}/src.tar.gz"
pack_source() {
  if [[ "$MODE" == "smoke" ]]; then
    return 0
  fi
  if [[ "$DIRTY" -eq 1 ]]; then
    # 打包当前工作区已跟踪 + 未忽略文件，彻底排除 .git / bin / node_modules
    (
      cd "$REPO_ROOT"
      git ls-files -co --exclude-standard -z | \
        grep -zvE '^(bin/|node_modules/|\.git/)' | \
        tar --null -T - -czf "$ARCHIVE_TAR"
    )
  else
    git -C "$REPO_ROOT" archive --format=tar.gz HEAD -o "$ARCHIVE_TAR"
  fi
}

# ----------------------------- 真断言辅助 -----------------------------
# 当日志中出现测试运行时，确认包含至少一个 PASS 且零 FAIL（排除 [no test files] 空跑假绿）
assert_go_test_evidence() {
  local log_file="$1"
  if grep -qE '^--- FAIL:|^FAIL[[:space:]]' "$log_file"; then
    echo "断言失败：检测到测试失败记录" >&2
    return 1
  fi
  if ! grep -qE '^--- PASS:|^ok[[:space:]]' "$log_file"; then
    echo "断言失败：未检测到有效 PASS/ok 测试执行证据（防空跑假绿）" >&2
    return 1
  fi
  return 0
}

# ----------------------------- 各平台执行器 -----------------------------
run_linux_host() {
  local log="${LOG_DIR}/linux.log"
  if [[ "$MODE" == "smoke" ]]; then
    {
      echo "=== [linux-host] 冒烟自检 ==="
      uname -a
      go version
      golangci-lint --version
      local tmpdir="${WORK_TMP}/smoke-linux"
      mkdir -p "$tmpdir"
      cat <<'EOF' > "${tmpdir}/go.mod"
module xops.local/smoke

go 1.27
EOF
      cat <<'EOF' > "${tmpdir}/smoke_test.go"
package smoke

import (
	"sync/atomic"
	"testing"
)

func TestSmokeRace(t *testing.T) {
	var n atomic.Int64
	done := make(chan struct{})
	go func() {
		n.Add(1)
		close(done)
	}()
	<-done
	if n.Load() != 1 {
		t.Fatalf("unexpected count: %d", n.Load())
	}
}
EOF
      (cd "$tmpdir" && GOWORK=off go test -v -race -count=1 ./...)
    } >"$log" 2>&1
    assert_go_test_evidence "$log"
    return $?
  fi

  # Gate 模式：在宿主机隔离目录解压源码并按当前已落地的 XOps v2 模块渐进验证
  {
    local work="${WORK_TMP}/linux-work"
    mkdir -p "$work"
    tar -xzf "$ARCHIVE_TAR" -C "$work"
    cd "$work"
    echo "=== [linux-host] Gate=${GATE} (DIRTY=${DIRTY}) ==="
    if [[ ! -f tools/xopsvet/go.mod && ! -f core/go.mod ]]; then
      echo "提示：尚未进入 Phase 0（未发现 tools/xopsvet/go.mod 或 core/go.mod），仅执行文档校验。"
      if [[ -f package.json ]]; then
        npm run docs:check
      fi
      exit 0
    fi

    local vettool="${work}/bin/xopsvet$(go env GOEXE)"
    mkdir -p "${work}/bin"
    if [[ -f tools/xopsvet/go.mod ]]; then
      (cd tools/xopsvet && GOWORK=off go test -v -race -count=1 ./... && GOWORK=off go build -o "$vettool" ./cmd/xopsvet)
    fi

    if [[ -f core/go.mod ]]; then
      local target_pkg="${PKG_FILTER:-./...}"
      (
        cd core
        GOWORK=off go build ./...
        if [[ -x "$vettool" ]]; then
          GOWORK=off go vet -vettool="$vettool" ./...
        fi
        GOWORK=off golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./...
        GOWORK=off go test -v -race -shuffle=on -count=1 "$target_pkg"
        if [[ -d internal/pool && ( "$GATE" == "g2" || "$GATE" == "g2.5" || "$GATE" == "g3" || "$GATE" == "g4" || "$GATE" == "g5" ) ]]; then
          GOWORK=off XOPS_DST_SEEDS="$DST_SEEDS" go test -v -race -count=1 -run '^TestDST_' ./...
        fi
        # 交叉编译与交叉 lint 覆盖 Windows 与 macOS
        GOOS=windows GOARCH=amd64 GOWORK=off go build ./...
        GOOS=darwin  GOARCH=amd64 GOWORK=off go build ./...
        GOOS=windows GOARCH=amd64 GOWORK=off golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./...
        GOOS=darwin  GOARCH=amd64 GOWORK=off golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./...
      )
    fi

    if [[ -f go.mod && ( -d cmd/xops || -d internal ) ]]; then
      go build ./...
      if [[ -x "$vettool" ]]; then
        go vet -vettool="$vettool" ./...
      fi
      golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./...
      go test -v -race -shuffle=on -count=1 "${PKG_FILTER:-./...}"
    fi
  } >"$log" 2>&1
}

run_unix_vm() {
  local name="$1"
  local vm="$2"
  local user="$3"
  local host="$4"
  local log="${LOG_DIR}/${name}.log"

  ensure_vm_ready "$vm" "$user" "$host" >>"$log" 2>&1

  if [[ "$MODE" == "smoke" ]]; then
    ssh "${SSH_BASE_OPTS[@]}" "${user}@${host}" "sh -s '$RUN_ID'" <<'REMOTE_SMOKE' >>"$log" 2>&1
set -eu
export PATH="/usr/local/go/bin:/usr/local/bin:$HOME/.local/bin:$PATH"
export GOMODCACHE="/var/cache/xops-ci/mod"
export GOCACHE="/var/cache/xops-ci/build"
export GORACE="atexit_sleep_ms=0"
RUN_ID="$1"
WORK="/tmp/xops-ci/runs/smoke-${RUN_ID}"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK"
uname -a
go version
golangci-lint --version
git --version
cat <<'EOF' > "$WORK/go.mod"
module xops.local/smoke

go 1.27
EOF
cat <<'EOF' > "$WORK/smoke_test.go"
package smoke

import (
	"runtime"
	"sync/atomic"
	"testing"
)

func TestSmokeRace(t *testing.T) {
	var n atomic.Int64
	done := make(chan struct{})
	go func() {
		n.Add(1)
		close(done)
	}()
	<-done
	if n.Load() != 1 {
		t.Fatalf("unexpected count: %d", n.Load())
	}
	t.Logf("native smoke ok on %s/%s", runtime.GOOS, runtime.GOARCH)
}
EOF
cd "$WORK"
GOWORK=off go test -v -race -count=1 ./...
REMOTE_SMOKE
    assert_go_test_evidence "$log"
    return $?
  fi

  # Gate 模式：通过 SSH 流式解压源码到独立沙箱
  local remote_work="/tmp/xops-ci/runs/${GATE}-${RUN_ID}"
  ssh "${SSH_BASE_OPTS[@]}" "${user}@${host}" "mkdir -p '$remote_work' && tar -xzf - -C '$remote_work'" < "$ARCHIVE_TAR" >>"$log" 2>&1

  ssh "${SSH_BASE_OPTS[@]}" "${user}@${host}" "sh -s '$remote_work' '$GATE' '${PKG_FILTER:-./...}'" <<'REMOTE_GATE' >>"$log" 2>&1
set -eu
export PATH="/usr/local/go/bin:/usr/local/bin:$HOME/.local/bin:$PATH"
export GOMODCACHE="/var/cache/xops-ci/mod"
export GOCACHE="/var/cache/xops-ci/build"
export GORACE="atexit_sleep_ms=0"
WORK="$1"
GATE="$2"
TARGET_PKG="$3"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
uname -a
go version

if [ ! -f tools/xopsvet/go.mod ] && [ ! -f core/go.mod ]; then
  echo "SKIP: 尚未进入 Phase 0（未发现 v2 Go 模块）"
  exit 0
fi

VETTOOL="${WORK}/bin/xopsvet$(go env GOEXE)"
mkdir -p "${WORK}/bin"
if [ -f tools/xopsvet/go.mod ]; then
  (cd tools/xopsvet && GOWORK=off go test -v -race -count=1 ./... && GOWORK=off go build -o "$VETTOOL" ./cmd/xopsvet)
fi
if [ -f core/go.mod ]; then
  (
    cd core
    GOWORK=off go build ./...
    if [ -x "$VETTOOL" ]; then
      GOWORK=off go vet -vettool="$VETTOOL" ./...
    fi
    GOWORK=off go test -v -race -shuffle=on -count=1 "$TARGET_PKG"
  )
fi
if [ -f go.mod ] && { [ -d cmd/xops ] || [ -d internal ]; }; then
  go build ./...
  if [ -x "$VETTOOL" ]; then
    go vet -vettool="$VETTOOL" ./...
  fi
  go test -v -race -shuffle=on -count=1 "$TARGET_PKG"
fi
REMOTE_GATE
}

run_win11_vm() {
  local log="${LOG_DIR}/win11.log"
  ensure_vm_ready "$XOPS_CI_WIN_VM" "$XOPS_CI_WIN_USER" "$XOPS_CI_WIN_HOST" >>"$log" 2>&1

  if [[ "$MODE" == "smoke" ]]; then
    local ps_script="${WORK_TMP}/win-smoke.ps1"
    cat <<'EOF' > "$ps_script"
param([Parameter(Mandatory=$true)][string]$RunId)
$ErrorActionPreference = 'Stop'
$env:Path = 'C:\xops-ci\tools\go\bin;C:\xops-ci\bin;C:\xops-ci\tools\mingw64\bin;C:\Program Files\Git\cmd;' + $env:Path
$env:GOMODCACHE = 'C:\xops-ci\cache\mod'
$env:GOCACHE = 'C:\xops-ci\cache\build'
$env:GOTMPDIR = 'C:\xops-ci\tmp'
$env:GORACE = 'atexit_sleep_ms=0'
$work = "C:\xops-ci\runs\smoke-$RunId"
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Output ("OS: " + $os.Caption + " RAM_MB=" + [math]::Round($os.TotalVisibleMemorySize / 1024))
    go version
    golangci-lint --version
    git --version
    gcc --version | Select-Object -First 1
    make --version | Select-Object -First 1
    Set-Content -Path (Join-Path $work 'go.mod') -Encoding utf8NoBOM -Value "module xops.local/smoke`n`ngo 1.27`n"
    Set-Content -Path (Join-Path $work 'smoke_test.go') -Encoding utf8NoBOM -Value @'
package smoke

import (
	"runtime"
	"sync/atomic"
	"testing"
)

func TestSmokeRace(t *testing.T) {
	var n atomic.Int64
	done := make(chan struct{})
	go func() {
		n.Add(1)
		close(done)
	}()
	<-done
	if n.Load() != 1 {
		t.Fatalf("unexpected count: %d", n.Load())
	}
	t.Logf("native smoke ok on %s/%s", runtime.GOOS, runtime.GOARCH)
}
'@
    Push-Location $work
    $env:GOWORK = 'off'
    go test -v -race -count=1 ./...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Pop-Location
} finally {
    Set-Location C:\xops-ci
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $work
}
EOF
    scp "${SSH_BASE_OPTS[@]}" "$ps_script" "${XOPS_CI_WIN_USER}@${XOPS_CI_WIN_HOST}:C:/xops-ci/tmp/smoke-${RUN_ID}.ps1" >>"$log" 2>&1
    local win_rc=0
    ssh "${SSH_BASE_OPTS[@]}" "${XOPS_CI_WIN_USER}@${XOPS_CI_WIN_HOST}" \
      "pwsh -NoProfile -ExecutionPolicy Bypass -File C:\\xops-ci\\tmp\\smoke-${RUN_ID}.ps1 -RunId ${RUN_ID}" >>"$log" 2>&1 || win_rc=$?
    ssh "${SSH_BASE_OPTS[@]}" "${XOPS_CI_WIN_USER}@${XOPS_CI_WIN_HOST}" \
      "del /q C:\\xops-ci\\tmp\\smoke-${RUN_ID}.ps1" >/dev/null 2>&1 || true
    if [[ "$win_rc" -ne 0 ]]; then
      return "$win_rc"
    fi
    assert_go_test_evidence "$log"
    return $?
  fi

  # Gate 模式：上传 tar.gz + 驱动脚本，解压并执行，退出自动清理
  local remote_tar="C:/xops-ci/tmp/src-${RUN_ID}.tar.gz"
  local remote_ps="C:/xops-ci/tmp/gate-${RUN_ID}.ps1"
  local ps_script="${WORK_TMP}/win-gate.ps1"
  cat <<'EOF' > "$ps_script"
param(
    [Parameter(Mandatory=$true)][string]$RunId,
    [Parameter(Mandatory=$true)][string]$Gate,
    [Parameter(Mandatory=$true)][string]$TargetPkg
)
$ErrorActionPreference = 'Stop'
$env:Path = 'C:\xops-ci\tools\go\bin;C:\xops-ci\bin;C:\xops-ci\tools\mingw64\bin;C:\Program Files\Git\cmd;' + $env:Path
$env:GOMODCACHE = 'C:\xops-ci\cache\mod'
$env:GOCACHE = 'C:\xops-ci\cache\build'
$env:GOTMPDIR = 'C:\xops-ci\tmp'
$env:GORACE = 'atexit_sleep_ms=0'
$work = "C:\xops-ci\runs\$Gate-$RunId"
$tarFile = "C:\xops-ci\tmp\src-$RunId.tar.gz"
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    tar.exe -xzf $tarFile -C $work
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Set-Location $work
    go version
    if (!(Test-Path 'tools\xopsvet\go.mod') -and !(Test-Path 'core\go.mod')) {
        Write-Output 'SKIP: 尚未进入 Phase 0（未发现 v2 Go 模块）'
        exit 0
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $work 'bin') | Out-Null
    $vettool = Join-Path $work ('bin\xopsvet' + (go env GOEXE))
    if (Test-Path 'tools\xopsvet\go.mod') {
        Push-Location 'tools\xopsvet'
        $env:GOWORK = 'off'
        go test -v -race -count=1 ./...
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        go build -o $vettool ./cmd/xopsvet
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Pop-Location
    }
    if (Test-Path 'core\go.mod') {
        Push-Location 'core'
        $env:GOWORK = 'off'
        go build ./...
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        if (Test-Path $vettool) {
            go vet "-vettool=$vettool" ./...
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
        go test -v -race -shuffle=on -count=1 $TargetPkg
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Pop-Location
    }
    Remove-Item Env:GOWORK -ErrorAction SilentlyContinue
    if ((Test-Path 'go.mod') -and ((Test-Path 'cmd\xops') -or (Test-Path 'internal'))) {
        go build ./...
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        if (Test-Path $vettool) {
            go vet "-vettool=$vettool" ./...
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
        go test -v -race -shuffle=on -count=1 $TargetPkg
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
} finally {
    Set-Location C:\xops-ci
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $work, $tarFile
}
EOF
  scp "${SSH_BASE_OPTS[@]}" "$ARCHIVE_TAR" "${XOPS_CI_WIN_USER}@${XOPS_CI_WIN_HOST}:${remote_tar}" >>"$log" 2>&1
  scp "${SSH_BASE_OPTS[@]}" "$ps_script" "${XOPS_CI_WIN_USER}@${XOPS_CI_WIN_HOST}:${remote_ps}" >>"$log" 2>&1
  local win_rc=0
  ssh "${SSH_BASE_OPTS[@]}" "${XOPS_CI_WIN_USER}@${XOPS_CI_WIN_HOST}" \
    "pwsh -NoProfile -ExecutionPolicy Bypass -File C:\\xops-ci\\tmp\\gate-${RUN_ID}.ps1 -RunId ${RUN_ID} -Gate ${GATE} -TargetPkg ${PKG_FILTER:-./...}" >>"$log" 2>&1 || win_rc=$?
  ssh "${SSH_BASE_OPTS[@]}" "${XOPS_CI_WIN_USER}@${XOPS_CI_WIN_HOST}" \
    "del /q C:\\xops-ci\\tmp\\gate-${RUN_ID}.ps1" >/dev/null 2>&1 || true
  return "$win_rc"
}

# ----------------------------- 并发调度与汇总 -----------------------------
pack_source

IFS=',' read -r -a TARGET_ARR <<< "$TARGETS"
declare -A PIDS=()
declare -A RESULTS=()

echo ">>> 启动本地多平台执行 [mode=${MODE} gate=${GATE} targets=${TARGETS} dirty=${DIRTY} auto_power=${AUTO_POWER}]"

for t in "${TARGET_ARR[@]}"; do
  t="$(echo "$t" | xargs)"
  case "$t" in
    linux)
      run_linux_host &
      PIDS["$t"]=$!
      ;;
    ubuntu)
      run_unix_vm "ubuntu" "$XOPS_CI_UBUNTU_VM" "$XOPS_CI_UBUNTU_USER" "$XOPS_CI_UBUNTU_HOST" &
      PIDS["$t"]=$!
      ;;
    freebsd)
      run_unix_vm "freebsd" "$XOPS_CI_FREEBSD_VM" "$XOPS_CI_FREEBSD_USER" "$XOPS_CI_FREEBSD_HOST" &
      PIDS["$t"]=$!
      ;;
    win11|windows)
      run_win11_vm &
      PIDS["win11"]=$!
      ;;
    *)
      echo "未知目标平台: $t（可选: linux, win11, ubuntu, freebsd）" >&2
      exit 2
      ;;
  esac
done

OVERALL_RC=0
for t in "${!PIDS[@]}"; do
  if wait "${PIDS[$t]}"; then
    RESULTS["$t"]="PASS"
  else
    RESULTS["$t"]="FAIL"
    OVERALL_RC=1
  fi
done

echo ""
echo "=================================================================="
echo " XOps v2 本地多平台验收证据摘要 (run=${RUN_ID}, mode=${MODE}, gate=${GATE})"
echo "=================================================================="
printf "%-14s %-8s %s\n" "目标平台" "结果" "关键输出摘要"
printf "%-14s %-8s %s\n" "--------------" "--------" "----------------------------------------"
for t in "${!RESULTS[@]}"; do
  status="${RESULTS[$t]}"
  summary="$(grep -E 'go version|native smoke ok|--- PASS:|SKIP:|OS:' "${LOG_DIR}/${t}.log" 2>/dev/null | tr '\r' ' ' | tail -n 2 | paste -sd ' | ' - || true)"
  printf "%-14s %-8s %s\n" "$t" "$status" "${summary:-详见日志}"
done
printf "%-14s %-8s %s\n" "macos-latest" "PENDING" "本地不覆盖 macOS；里程碑由 GitHub Actions macos-latest 补齐原生验证"
echo "=================================================================="

if [[ "$OVERALL_RC" -ne 0 ]]; then
  echo ""
  echo "!!! 失败目标详细日志 !!!"
  for t in "${!RESULTS[@]}"; do
    if [[ "${RESULTS[$t]}" == "FAIL" ]]; then
      echo "--- [$t] ---"
      tail -n 80 "${LOG_DIR}/${t}.log" || true
    fi
  done
fi

exit "$OVERALL_RC"
