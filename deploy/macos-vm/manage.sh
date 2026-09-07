#!/usr/bin/env bash
# ==============================================================================
# deploy/macos-vm/manage.sh
# 本地 macOS 虚拟机 (Docker-OSX / QEMU KVM) 管理与自动化测试辅助脚本
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
KEY_FILE="${SCRIPT_DIR}/id_ed25519"

MACOS_SSH_PORT="${MACOS_SSH_PORT:-50922}"
MACOS_VNC_PORT="${MACOS_VNC_PORT:-5999}"
MACOS_USER="${MACOS_USER:-user}"
MACOS_PASS="${MACOS_PASS:-alpine}"
MACOS_HOST="127.0.0.1"
GUEST_GO_VERSION="${GUEST_GO_VERSION:-1.26.0}"

log_info() {
    printf "[INFO] %s\n" "$*"
}

log_pass() {
    printf "[PASS] %s\n" "$*"
}

log_warn() {
    printf "[WARN] %s\n" "$*"
}

log_fail() {
    printf "[FAIL] %s\n" "$*"
}

# 确保本地拥有专用于虚拟机的 ed25519 密钥对
ensure_ssh_key() {
    if [ ! -f "${KEY_FILE}" ]; then
        log_info "生成 macOS 虚拟机专用 SSH 密钥对: ${KEY_FILE} ..."
        ssh-keygen -t ed25519 -N "" -f "${KEY_FILE}" -C "xops-macos-vm" >/dev/null 2>&1
        chmod 600 "${KEY_FILE}"
        log_pass "SSH 密钥对已生成。"
    fi
}

get_ssh_opts() {
    local batch_mode="${1:-yes}"
    local opts=(
        -o StrictHostKeyChecking=no
        -o UserKnownHostsFile=/dev/null
        -o ConnectTimeout=5
        -p "${MACOS_SSH_PORT}"
    )
    if [ -f "${KEY_FILE}" ]; then
        opts+=(-i "${KEY_FILE}")
    fi
    if [ "$batch_mode" = "yes" ]; then
        opts+=(-o BatchMode=yes)
    fi
    echo "${opts[@]}"
}

check_env() {
    log_info "=== 检查本地 macOS 虚拟化运行前置条件 ==="

    # 1. 检查 /dev/kvm 硬件加速
    if [ -e "/dev/kvm" ]; then
        if [ -r "/dev/kvm" ] && [ -w "/dev/kvm" ]; then
            log_pass "KVM 虚拟化加速就绪 (/dev/kvm 可读写)"
        else
            log_warn "/dev/kvm 存在但当前用户无直接读写权限。请执行: sudo usermod -aG kvm $USER 或 sudo chmod 666 /dev/kvm"
        fi
    else
        log_fail "未检测到 /dev/kvm，请确认 CPU 虚拟化 (VT-x/AMD-V) 已在 BIOS 中开启并加载 kvm 内核模块"
        return 1
    fi

    # 2. 检查 Docker 及 Docker Compose
    if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then
            log_pass "Docker 引擎运行正常"
        else
            log_fail "Docker 守护进程未运行或当前用户无权限访问 docker 套接字"
            return 1
        fi
    else
        log_fail "未检测到 docker 命令，请先安装 Docker"
        return 1
    fi

    if docker compose version >/dev/null 2>&1; then
        log_pass "Docker Compose 插件可用 ($(docker compose version --short 2>/dev/null || true))"
    else
        log_fail "未检测到 docker compose 插件"
        return 1
    fi

    # 3. 检查系统内存与可用磁盘空间
    local free_mem_kb
    free_mem_kb=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    local free_mem_gb=$((free_mem_kb / 1024 / 1024))
    if [ "$free_mem_gb" -ge 6 ]; then
        log_pass "系统可用内存充足 (${free_mem_gb}GB 可用，建议 >= 8GB)"
    else
        log_warn "系统可用内存较低 (${free_mem_gb}GB 可用)，虚拟 macOS 建议保留至少 6~8GB 内存"
    fi

    local free_disk_kb
    free_disk_kb=$(df -k "$SCRIPT_DIR" | awk 'NR==2 {print $4}')
    local free_disk_gb=$((free_disk_kb / 1024 / 1024))
    if [ "$free_disk_gb" -ge 25 ]; then
        log_pass "磁盘可用空间充足 (${free_disk_gb}GB 可用)"
    else
        log_warn "磁盘可用空间较低 (${free_disk_gb}GB 可用)，下载与运行 macOS 镜像建议预留 >= 25GB"
    fi

    ensure_ssh_key
    log_info "环境前置检查完成。"
}

start_vm() {
    check_env
    # 自愈检查：若存在未完成或损坏的 BaseSystem.dmg (且无 BaseSystem.img)，自动清理残留防止 QEMU 启动死循环
    if docker volume inspect xops_macos_disk_data >/dev/null 2>&1; then
        docker run --rm -v xops_macos_disk_data:/data alpine sh -c '
            if [ -f /data/BaseSystem.dmg ] && [ ! -f /data/BaseSystem.img ]; then
                dmg_size=$(wc -c < /data/BaseSystem.dmg 2>/dev/null || echo 0)
                if [ "$dmg_size" -lt 400000000 ]; then
                    rm -f /data/BaseSystem.dmg /data/BaseSystem.chunklist
                fi
            fi
            # 确保存储卷中的主磁盘已格式化为合法的 qcow2 镜像（防止 touch 产生的 0 字节空文件导致 QEMU 启动报错）
            if [ -f /data/mac_hdd_ng.img ] && [ ! -s /data/mac_hdd_ng.img ]; then
                rm -f /data/mac_hdd_ng.img
            fi
        ' 2>/dev/null || true

        # 若主磁盘不存在或大小为 0，预先格式化为合法的 qcow2 镜像
        docker run --rm -v xops_macos_disk_data:/home/arch/OSX-KVM sickcodes/docker-osx:latest bash -c '
            IMG="/home/arch/OSX-KVM/mac_hdd_ng.img"
            if [ ! -f "$IMG" ] || [ ! -s "$IMG" ]; then
                qemu-img create -f qcow2 "$IMG" 64G >/dev/null 2>&1 || true
            fi
        ' 2>/dev/null || true
    fi

    log_info "启动本地 macOS 虚拟机容器 (Docker-OSX)..."
    docker compose -f "${COMPOSE_FILE}" up -d

    # 观察容器启动状态（等待 OpenCore 引导及 QEMU 进程挂载）
    sleep 6
    local container_status
    container_status=$(docker inspect --format '{{.State.Status}} (exit: {{.State.ExitCode}})' xops-macos-vm 2>/dev/null || echo "unknown")
    if echo "$container_status" | grep -q "^running"; then
        log_pass "macOS 容器已正常驻留运行 (ID: xops-macos-vm)！"
    else
        log_fail "macOS 容器启动失败 ($container_status)！"
        log_info "最新容器日志如下:"
        docker compose -f "${COMPOSE_FILE}" logs --tail 30
        log_warn "排查提示:"
        log_warn "1. 若日志显示 'BaseSystem.img: No such file or directory'，说明首次冷启动未能从 Apple CDN 完成恢复镜像下载。"
        log_warn "2. 建议：macOS 跨平台兼容性验证优先推荐使用 GitHub Actions CI (macos-latest)，免去本地虚拟化镜像下载与系统安装过程。"
        return 1
    fi

    log_info "SSH 连接端口: ${MACOS_SSH_PORT} (默认账号: ${MACOS_USER} / 密码: ${MACOS_PASS})"
    log_info "VNC 远程桌面端口: ${MACOS_VNC_PORT}"
    log_info "提示: 首次冷启动需要解压与引导 macOS，可运行 '$0 wait-ready' 等待 SSH 服务就绪与公钥安装，或 '$0 logs' 查看控制台输出。"
}

stop_vm() {
    log_info "停止本地 macOS 虚拟机容器..."
    docker compose -f "${COMPOSE_FILE}" down
    log_info "macOS 容器已停止。"
}

status_vm() {
    log_info "macOS 虚拟机容器状态:"
    docker compose -f "${COMPOSE_FILE}" ps
    if docker inspect xops-macos-vm >/dev/null 2>&1; then
        local health
        health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' xops-macos-vm)
        local status
        status=$(docker inspect --format '{{.State.Status}} (restarting: {{.State.Restarting}})' xops-macos-vm)
        log_info "容器状态: $status, 健康检查: $health"
    fi
}

logs_vm() {
    docker compose -f "${COMPOSE_FILE}" logs -f
}

# 检查 TCP 端口是否开放 (区分连接失败与认证失败)
check_tcp_port() {
    python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
    res = s.connect_ex(("127.0.0.1", int(sys.argv[1])))
    sys.exit(0 if res == 0 else 1)
except Exception:
    sys.exit(1)
finally:
    s.close()
' "${MACOS_SSH_PORT}" 2>/dev/null
}

# 安装 SSH 公钥至虚拟机客体 (自动 PTY 密码握手，无需外部 sshpass/expect 依赖)
install_guest_key() {
    ensure_ssh_key
    log_info "向 macOS 客体安装宿主 SSH 公钥 (${MACOS_USER}@${MACOS_HOST}:${MACOS_SSH_PORT})..."

    local py_res=0
    python3 -c '
import pty, os, sys, select, time

port = int(sys.argv[1])
user = sys.argv[2]
password = sys.argv[3]
pubkey_file = sys.argv[4]

with open(pubkey_file, "r") as f:
    pubkey = f.read().strip()

# 远程执行脚本：确保 .ssh 目录并追加公钥
remote_cmd = f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo \"{pubkey}\" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo KEY_INSTALLED_OK"

ssh_cmd = [
    "ssh",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=10",
    "-p", str(port),
    f"{user}@127.0.0.1",
    remote_cmd
]

pid, fd = pty.fork()
if pid == 0:
    os.execvp("ssh", ssh_cmd)
else:
    buf = b""
    password_sent = False
    start = time.time()
    success = False
    while time.time() - start < 25:
        r, _, _ = select.select([fd], [], [], 0.5)
        if fd in r:
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            lower = buf.lower()
            if (b"password:" in lower or b"password for" in lower) and not password_sent:
                os.write(fd, password.encode() + b"\n")
                password_sent = True
            if b"KEY_INSTALLED_OK" in buf:
                success = True
                break
    _, status = os.waitpid(pid, 0)
    sys.exit(0 if success else 1)
' "${MACOS_SSH_PORT}" "${MACOS_USER}" "${MACOS_PASS}" "${KEY_FILE}.pub" || py_res=$?

    if [ "$py_res" -eq 0 ]; then
        log_pass "SSH 公钥成功安装至客体！后续连接将免密执行。"
        return 0
    else
        log_warn "自动公钥安装失败，尝试通过交互式 ssh-copy-id..."
        ssh-copy-id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "${KEY_FILE}" -p "${MACOS_SSH_PORT}" "${MACOS_USER}@${MACOS_HOST}" || {
            log_fail "公钥配置失败，请确认密码是否为 '${MACOS_PASS}' 或手动执行: ssh -p ${MACOS_SSH_PORT} ${MACOS_USER}@${MACOS_HOST}"
            return 1
        }
    fi
}

wait_ready() {
    ensure_ssh_key
    local max_wait="${1:-360}"
    log_info "等待 macOS 虚拟机 SSH 服务就绪 (超时: ${max_wait}s, 目标: ${MACOS_HOST}:${MACOS_SSH_PORT})..."
    local elapsed=0

    while [ "$elapsed" -lt "$max_wait" ]; do
        # 1. 首先检查 TCP 端口是否连接 (区分服务未就绪 vs 认证失败)
        if check_tcp_port; then
            # 端口已开放，测试 SSH 认证
            read -ra opts < <(get_ssh_opts "yes")
            local ssh_out
            if ssh_out=$(ssh "${opts[@]}" "${MACOS_USER}@${MACOS_HOST}" "echo ready" 2>&1); then
                log_pass "macOS 虚拟机 SSH 服务及公钥认证已完全就绪！(耗时 ${elapsed}s)"
                return 0
            fi

            # 区分错误：若为 Permission denied，说明 SSH 守护进程已就绪，但客体尚未导入公钥
            if echo "$ssh_out" | grep -q -i "Permission denied"; then
                log_info "SSH 服务已建立连接，检测到需要配置公钥认证。正在自动安装公钥..."
                if install_guest_key; then
                    read -ra opts < <(get_ssh_opts "yes")
                    if ssh "${opts[@]}" "${MACOS_USER}@${MACOS_HOST}" "echo ready" >/dev/null 2>&1; then
                        log_pass "macOS 虚拟机 SSH 免密通道已完全建立就绪！"
                        return 0
                    fi
                fi
            elif echo "$ssh_out" | grep -q -E "Connection closed by|kex_exchange_identification"; then
                if [ $((elapsed % 30)) -eq 0 ] && [ "$elapsed" -gt 0 ]; then
                    log_warn "宿主 50922 转发端口已连通，但虚拟机客体 22 端口未启动 SSH (客体可能处于引导菜单或需完成首次系统安装，已等待 ${elapsed}s)..."
                fi
            fi
        fi

        sleep 5
        elapsed=$((elapsed + 5))
        printf "."
    done

    printf "\n"
    log_fail "等待 macOS 虚拟机就绪超时 (${max_wait}s)。"
    log_warn "排查原因:"
    log_warn "1. 宿主 50922 端口由 QEMU 用户态转发监听，但虚拟机内操作系统 (Guest OS) 尚未安装或未开启 Remote Login (SSH)；"
    log_warn "2. 建议：优先推荐使用 GitHub Actions CI (macos-latest)，免本地虚拟化繁重安装，直接完成阶段四兼容性验收。"
    return 1
}

ssh_vm() {
    ensure_ssh_key
    read -ra opts < <(get_ssh_opts "no")
    log_info "正在连接 macOS 虚拟机终端 (SSH: ${MACOS_HOST}:${MACOS_SSH_PORT})..."
    if ! ssh "${opts[@]}" "${MACOS_USER}@${MACOS_HOST}" "$@"; then
        local ret=$?
        if [ "$ret" -eq 255 ]; then
            log_warn "SSH 连接被立即切断 (Connection closed by remote host)。"
            log_warn "说明: 宿主机 50922 是 QEMU 用户态网络转发端口。客体虚拟机内部目前为全新格式化的空白虚拟磁盘 (或仍处于恢复安装环境)，其内部的 22 端口尚未运行 SSH 服务。"
            log_warn "建议: 请优先通过 GitHub Actions CI (macos-latest) 进行全量原生测试与真实 Keychain 验收，免去本地手动安装系统的过程。"
        fi
        return "$ret"
    fi
}

check_or_install_guest_go() {
    ensure_ssh_key
    read -ra opts < <(get_ssh_opts "yes")
    log_info "检查虚拟机客体 Go 工具链版本 (要求: Go 1.26+)..."

    local go_ver_out
    if go_ver_out=$(ssh "${opts[@]}" "${MACOS_USER}@${MACOS_HOST}" "bash -lc 'command -v go && go version'" 2>/dev/null); then
        log_info "客体已安装 Go: $go_ver_out"
        if echo "$go_ver_out" | grep -q -E "go1\.(2[6-9]|[3-9][0-9])"; then
            log_pass "客体 Go 版本满足规范 (>= 1.26)"
            return 0
        else
            log_warn "客体 Go 版本低于 1.26 ($go_ver_out)，需要安装 Go ${GUEST_GO_VERSION}"
        fi
    else
        log_warn "客体未检测到 Go 工具链，正在准备自动配置..."
    fi

    log_info "正在向虚拟机客体安装 Go ${GUEST_GO_VERSION}..."
    ssh "${opts[@]}" "${MACOS_USER}@${MACOS_HOST}" "bash -s" <<'EOF'
set -euo pipefail
GUEST_ARCH=$(uname -m)
case "$GUEST_ARCH" in
    x86_64) GO_ARCH="amd64" ;;
    arm64)  GO_ARCH="arm64" ;;
    *)      GO_ARCH="amd64" ;;
esac

TARBALL="go1.26.0.darwin-${GO_ARCH}.tar.gz"
URL="https://go.dev/dl/${TARBALL}"

echo "[GUEST] Downloading Go for darwin-${GO_ARCH} from ${URL}..."
if ! curl -fsSL -o "/tmp/${TARBALL}" "${URL}"; then
    echo "[GUEST] Direct download failed, checking brew..."
    if command -v brew >/dev/null 2>&1; then
        brew install go
        exit 0
    fi
    echo "[GUEST] Cannot download Go tarball or use brew. Please install Go 1.26+ manually."
    exit 1
fi

echo "[GUEST] Installing Go into /usr/local/go..."
echo "alpine" | sudo -S rm -rf /usr/local/go
echo "alpine" | sudo -S tar -C /usr/local -xzf "/tmp/${TARBALL}"
rm -f "/tmp/${TARBALL}"

# 注入 PATH 到 profile
grep -q "/usr/local/go/bin" ~/.zshrc 2>/dev/null || echo 'export PATH="/usr/local/go/bin:$PATH"' >> ~/.zshrc
grep -q "/usr/local/go/bin" ~/.bash_profile 2>/dev/null || echo 'export PATH="/usr/local/go/bin:$PATH"' >> ~/.bash_profile

echo "[GUEST] Go installation completed:"
/usr/local/go/bin/go version
EOF
    log_pass "虚拟机客体 Go ${GUEST_GO_VERSION} 安装配置就绪！"
}

sync_code() {
    ensure_ssh_key
    local clean_sync="${1:-}"
    read -ra opts < <(get_ssh_opts "yes")
    log_info "同步本地代码库至 macOS 虚拟机: ~/xops-cli/ ..."

    # 若指定 clean 则先清空客体工作目录
    if [ "$clean_sync" = "--clean" ] || [ "${MACOS_SYNC_CLEAN:-false}" = "true" ]; then
        log_info "执行严格纯净同步: 清理虚拟机客体历史构建残留..."
        ssh "${opts[@]}" "${MACOS_USER}@${MACOS_HOST}" "rm -rf ~/xops-cli && mkdir -p ~/xops-cli"
    else
        ssh "${opts[@]}" "${MACOS_USER}@${MACOS_HOST}" "mkdir -p ~/xops-cli"
    fi

    # 严格排除非源码目录，并启用 --delete 消除已重命名或已删除的文件
    if command -v rsync >/dev/null 2>&1; then
        rsync -avz --delete \
            --exclude='.git' \
            --exclude='bin' \
            --exclude='coverage.out' \
            --exclude='deploy/macos-vm' \
            --exclude='*.log' \
            -e "ssh ${opts[*]}" \
            "${PROJECT_ROOT}/" \
            "${MACOS_USER}@${MACOS_HOST}:~/xops-cli/"
    else
        log_warn "未检测到 rsync，使用 tar 清空并管道解压以保障纯净镜像同步..."
        ssh "${opts[@]}" "${MACOS_USER}@${MACOS_HOST}" "rm -rf ~/xops-cli/* ~/xops-cli/.* 2>/dev/null || true"
        tar -C "${PROJECT_ROOT}" \
            --exclude='.git' \
            --exclude='bin' \
            --exclude='coverage.out' \
            --exclude='deploy/macos-vm' \
            --exclude='*.log' \
            -czf - . | ssh "${opts[@]}" "${MACOS_USER}@${MACOS_HOST}" "tar -xzf - -C ~/xops-cli"
    fi
    log_pass "代码同步成功 (已同步最新变更并清理已删除源码)！"
}

run_tests() {
    wait_ready 60
    check_or_install_guest_go
    sync_code "--clean"
    read -ra opts < <(get_ssh_opts "yes")
    log_info "在 macOS 虚拟机内执行原生平台验证脚本..."
    ssh "${opts[@]}" "${MACOS_USER}@${MACOS_HOST}" "bash -lc 'cd ~/xops-cli && ./scripts/verify_native_platform.sh'"
}

show_help() {
    cat <<EOF
使用方法: $(basename "$0") [命令]

可用命令:
  check        检查本地 KVM 加速、Docker、内存、磁盘及本地 SSH 密钥
  up / start   启动本地 macOS 虚拟机 (前台/后台驻留)
  down / stop  停止并清理本地 macOS 虚拟机容器
  status       查看虚拟机容器运行状态与健康检查
  wait-ready   轮询并等待虚拟机客体 SSH 服务启动并自动完成公钥授权
  auth         向虚拟机客体安装专用公钥以建立免密通道
  logs         查看虚拟机启动与 QEMU 控制台实时日志
  ssh [cmd]    通过 SSH 登录虚拟机交互终端或直接执行远程命令
  setup-go     在虚拟机客体内安装或升级 Go 1.26+ 工具链
  sync [--clean] 将当前仓库源码严格镜像同步到虚拟机 ~/xops-cli (支持删除同步)
  test         纯净同步代码并在 macOS 虚拟机中运行 ./scripts/verify_native_platform.sh
  help         显示本帮助信息

环境变量:
  MACOS_SSH_PORT    宿主机 SSH 转发端口 (默认: 50922)
  MACOS_VNC_PORT    宿主机 VNC 远程桌面端口 (默认: 5999)
  MACOS_USER        虚拟机用户名 (默认: user)
  MACOS_PASS        虚拟机初始密码 (默认: alpine)
  MACOS_RAM         虚拟机内存大小 (GB, 默认: 8)
  MACOS_SMP         虚拟机 CPU 核心数 (默认: 4)
  MACOS_SYNC_CLEAN  是否每次同步强制清空目标目录 (默认: false)
  GUEST_GO_VERSION  客体安装的 Go 版本 (默认: 1.26.0)
  DOCKER_OSX_IMAGE  使用的 Docker-OSX 镜像 (默认: sickcodes/docker-osx:latest)
EOF
}

case "${1:-help}" in
    check)
        check_env
        ;;
    up|start)
        start_vm
        ;;
    down|stop)
        stop_vm
        ;;
    status)
        status_vm
        ;;
    wait-ready)
        wait_ready "${2:-360}"
        ;;
    auth)
        install_guest_key
        ;;
    logs)
        logs_vm
        ;;
    ssh)
        shift
        ssh_vm "$@"
        ;;
    setup-go)
        check_or_install_guest_go
        ;;
    sync)
        shift
        sync_code "$@"
        ;;
    test)
        run_tests
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_fail "未知命令: $1"
        show_help
        exit 1
        ;;
esac
