# ==============================================================================
# 变量定义
# ==============================================================================

# 项目名称
BINARY_NAME=xops
# 模块名称
MODULE=github.com/wentf9/xops-cli
# 输出目录（与 .github/workflows/release.yml 上传路径 bin/* 对齐）
BIN_DIR=bin

# ==============================================================================
# 跨平台环境与 Shell 适配 (Windows 原生 cmd.exe / Git Bash / Linux / macOS / FreeBSD)
# ==============================================================================
# Apple's Make uses the parent's PATH to spawn bare recipe commands. On POSIX
# shells, exec forces lookup through the shell with our exported PATH instead.
# Native Windows shells must keep plain tool invocations.
# An explicit GOPATH_BIN (including an empty value) skips Go path discovery.
RUN_TOOL :=
ifeq ($(wildcard /dev/null),/dev/null)
    DEVNULL := /dev/null
else
    DEVNULL := nul
endif

ifeq ($(OS),Windows_NT)
    # Windows 环境
    SHELL_EXT := .exe
    # Windows Make may report sh.exe while actually falling back to cmd.exe.
    # Quoted echo is safe in both shells; && forces Make to invoke the shell.
    # cmd preserves the single quotes, while POSIX shells remove them.
    POSIX_SHELL :=
    ifneq ($(filter sh sh.exe bash bash.exe dash dash.exe zsh zsh.exe ksh ksh.exe,$(notdir $(subst \,/,$(SHELL)))),)
        ifeq ($(shell echo 'xops-posix-shell' && echo 'xops-posix-shell'),xops-posix-shell xops-posix-shell)
            POSIX_SHELL := yes
        endif
    endif
    ifeq ($(POSIX_SHELL),yes)
        # Windows + POSIX Shell (Git Bash / MSYS2 / Cygwin)
        RUN_TOOL := exec
        PYTHON ?= python3
        # cygpath converts drive-letter paths to the shell's mount layout.
        ifeq ($(origin GOPATH_BIN),undefined)
            GOPATH_BIN := $(shell if command -v cygpath >/dev/null 2>&1; then cygpath -u "$$(go env GOPATH)/bin"; else printf '%s/bin' "$$(go env GOPATH)"; fi)
        endif
        ifneq ($(shell test -d "$(GOPATH_BIN)" && echo yes),)
            export PATH := $(GOPATH_BIN):$(PATH)
        endif
        VERSION ?= $(shell git describe --tags --always --dirty 2>$(DEVNULL) || echo unknown)
        COMMIT  ?= $(shell git rev-parse --short HEAD 2>$(DEVNULL) || echo unknown)
        DATE    ?= $(shell date +%Y-%m-%dT%H:%M:%S%z 2>$(DEVNULL) || git log -1 --format=%cI 2>$(DEVNULL) || echo unknown)
        RM_CMD  := rm -rf $(BIN_DIR) coverage.out
        SKILL_DEST := $(HOME)/.gemini/skills/xops-agent
        INSTALL_SKILL_CMD := mkdir -p "$(SKILL_DEST)" && cp -r skills/xops-agent/* "$(SKILL_DEST)/"
        ECHO_BLANK := echo ""
    else
        # Windows 原生环境 (无 sh.exe，纯 cmd.exe / PowerShell)
        PYTHON ?= python
        # 自动将 Go bin 目录加入 PATH (Windows 环境变量使用分号分隔)
        ifeq ($(origin GOPATH_BIN),undefined)
            GOPATH_BIN := $(shell go env GOPATH 2>$(DEVNULL))\bin
        endif
        ifneq ($(wildcard $(GOPATH_BIN)),)
            export PATH := $(GOPATH_BIN);$(PATH)
        endif
        VERSION ?= $(shell git describe --tags --always --dirty 2>$(DEVNULL) || echo unknown)
        COMMIT  ?= $(shell git rev-parse --short HEAD 2>$(DEVNULL) || echo unknown)
        DATE    ?= $(shell powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz'" 2>$(DEVNULL) || git log -1 --format=%cI 2>$(DEVNULL) || echo unknown)
        RM_CMD  := if exist $(subst /,\,$(BIN_DIR)) ( rmdir /s /q $(subst /,\,$(BIN_DIR)) ) & if exist coverage.out ( del /f /q coverage.out )
        INSTALL_SKILL_CMD := powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path (Join-Path $$HOME '.gemini/skills/xops-agent') | Out-Null; Copy-Item -Recurse -Force 'skills/xops-agent/*' (Join-Path $$HOME '.gemini/skills/xops-agent')"
        ECHO_BLANK := echo.
    endif
else
    # Linux / macOS / FreeBSD 环境 (POSIX)
    RUN_TOOL := exec
    PYTHON ?= python3
    SHELL_EXT :=
    ifeq ($(origin GOPATH_BIN),undefined)
        GOPATH_BIN := $(shell go env GOPATH 2>$(DEVNULL))/bin
    endif
    ifneq ($(shell test -d "$(GOPATH_BIN)" && echo yes),)
        export PATH := $(GOPATH_BIN):$(PATH)
    endif

    VERSION ?= $(shell git describe --tags --always --dirty 2>$(DEVNULL) || echo unknown)
    COMMIT  ?= $(shell git rev-parse --short HEAD 2>$(DEVNULL) || echo unknown)
    DATE    ?= $(shell date +%Y-%m-%dT%H:%M:%S%z 2>$(DEVNULL) || git log -1 --format=%cI 2>$(DEVNULL) || echo unknown)
    RM_CMD  := rm -rf $(BIN_DIR) coverage.out
    SKILL_DEST := $(HOME)/.gemini/skills/xops-agent
    INSTALL_SKILL_CMD := mkdir -p "$(SKILL_DEST)" && cp -r skills/xops-agent/* "$(SKILL_DEST)/"
    ECHO_BLANK := echo ""
endif

# 清洗空格与换行
VERSION := $(strip $(VERSION))
COMMIT  := $(strip $(COMMIT))
DATE    := $(strip $(DATE))

# 四端统一验证单一事实源入口（外层不设 GOWORK=off，兼容无 sh.exe 的 Windows 原生 Make）
VERIFY_CMD := $(RUN_TOOL) go run ./scripts/ci/verify.go

# 注入 LDFLAGS（Go 1.27 对 package main 使用 -p main，须绑定 main.<var> 并配合 cmd/xops //xops:buildvar）
LDFLAGS := -s -w \
           -X 'main.buildVersion=$(VERSION)' \
           -X 'main.buildCommit=$(COMMIT)' \
           -X 'main.buildTime=$(DATE)'

# 可复现无 CGO 发布编译参数
BUILD_FLAGS := -trimpath -ldflags "$(LDFLAGS)"

# ==============================================================================
# 编译与多平台发布目标（绝不自动执行 git tag / git push）
# ==============================================================================

.PHONY: default all clean help build build-cli build-all release install-skill
.PHONY: windows windows-arm64 linux linux-arm64 darwin darwin-amd64 darwin-arm64 freebsd freebsd-amd64 freebsd-arm64
.PHONY: xopsvet core cross dst vet lint test test-race test-cover verify verify-cross verify-dst verify-release docs-check ci

default: all

all: clean build

# 默认编译当前系统版本
build: build-cli

build-cli: export CGO_ENABLED := 0
build-cli:
	@echo "Building CLI ($(VERSION)) for current OS..."
	$(RUN_TOOL) go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)$(SHELL_EXT) ./cmd/xops

# ==============================================================================
# 交叉编译矩阵 (Windows / Linux / macOS / FreeBSD, CGO_ENABLED=0)
# ==============================================================================

# 编译 Windows 版本 (amd64)
windows: export GOOS := windows
windows: export GOARCH := amd64
windows: export CGO_ENABLED := 0
windows:
	@echo "Compiling for Windows (amd64)..."
	$(RUN_TOOL) go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME).exe ./cmd/xops

# 编译 Windows 版本 (arm64)
windows-arm64: export GOOS := windows
windows-arm64: export GOARCH := arm64
windows-arm64: export CGO_ENABLED := 0
windows-arm64:
	@echo "Compiling for Windows (arm64)..."
	$(RUN_TOOL) go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-arm64.exe ./cmd/xops

# 编译 Linux 版本 (amd64)
linux: export GOOS := linux
linux: export GOARCH := amd64
linux: export CGO_ENABLED := 0
linux:
	@echo "Compiling for Linux (amd64)..."
	$(RUN_TOOL) go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/xops

# 编译 Linux 版本 (arm64 / aarch64)
linux-arm64: export GOOS := linux
linux-arm64: export GOARCH := arm64
linux-arm64: export CGO_ENABLED := 0
linux-arm64:
	@echo "Compiling for Linux (arm64)..."
	$(RUN_TOOL) go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-linux-aarch64 ./cmd/xops

# 编译 macOS 版本 (Intel & Apple Silicon)
darwin: darwin-amd64 darwin-arm64

darwin-amd64: export GOOS := darwin
darwin-amd64: export GOARCH := amd64
darwin-amd64: export CGO_ENABLED := 0
darwin-amd64:
	@echo "Compiling for macOS (amd64)..."
	$(RUN_TOOL) go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/xops

darwin-arm64: export GOOS := darwin
darwin-arm64: export GOARCH := arm64
darwin-arm64: export CGO_ENABLED := 0
darwin-arm64:
	@echo "Compiling for macOS (arm64)..."
	$(RUN_TOOL) go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/xops

# 编译 FreeBSD 版本 (amd64 & arm64)
freebsd: freebsd-amd64 freebsd-arm64

freebsd-amd64: export GOOS := freebsd
freebsd-amd64: export GOARCH := amd64
freebsd-amd64: export CGO_ENABLED := 0
freebsd-amd64:
	@echo "Compiling for FreeBSD (amd64)..."
	$(RUN_TOOL) go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-freebsd-amd64 ./cmd/xops

freebsd-arm64: export GOOS := freebsd
freebsd-arm64: export GOARCH := arm64
freebsd-arm64: export CGO_ENABLED := 0
freebsd-arm64:
	@echo "Compiling for FreeBSD (arm64)..."
	$(RUN_TOOL) go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-freebsd-arm64 ./cmd/xops

# 编译全平台发布产物（写入 bin/）
release: windows windows-arm64 linux linux-arm64 darwin freebsd

build-all: release

# ==============================================================================
# 清理
# ==============================================================================
clean:
	@echo "Cleaning..."
	@$(RM_CMD)
	@$(RUN_TOOL) go clean

# ==============================================================================
# 三模块护栏、测试与发布验收（统一委托 scripts/ci/verify.go 单一事实源）
# ==============================================================================

XOPS_DST_SEEDS ?= 10000

xopsvet:
	$(VERIFY_CMD) --stage=xopsvet

core:
	$(VERIFY_CMD) --stage=core

verify:
	$(VERIFY_CMD) --stage=all

verify-cross:
	$(VERIFY_CMD) --stage=cross

cross: verify-cross

verify-dst:
	$(VERIFY_CMD) --stage=dst --dst-seeds=$(XOPS_DST_SEEDS)

dst: verify-dst

# 正式发布锁定 core/v1.x.y Tag 后的三模块全量 GOWORK=off 验收门禁
verify-release:
	$(VERIFY_CMD) --stage=all --gowork-off

vet:
	$(VERIFY_CMD) --stage=all --skip-lint

lint:
	$(VERIFY_CMD) --stage=all

test:
	$(VERIFY_CMD) --stage=all --skip-lint

test-race:
	$(VERIFY_CMD) --stage=all --skip-lint

test-cover: export GOWORK := off
test-cover:
	@echo "Running tests with coverage..."
	$(RUN_TOOL) go -C core test ./... -covermode=atomic -coverprofile=../coverage.out
	$(RUN_TOOL) go tool cover -func=coverage.out

docs-check:
	$(RUN_TOOL) npm run docs:check

ci: verify verify-cross docs-check
	@echo "Running CI script unit tests..."
	$(RUN_TOOL) $(PYTHON) -m unittest discover -s scripts -p test_ci_changes.py -v

# ==============================================================================
# 帮助文档
# ==============================================================================
help:
	@echo "使用方法: make [target]"
	@$(ECHO_BLANK)
	@echo "Build & Release Targets (CGO_ENABLED=0 -> $(BIN_DIR)/):"
	@echo "  all             默认目标，清理并编译当前系统版本"
	@echo "  build           编译当前系统版本 (./cmd/xops，含 buildVersion/Commit/Time)"
	@echo "  release         交叉编译全部支持平台 (Windows/Linux/macOS/FreeBSD)"
	@echo "  build-all       同 release"
	@echo "  windows         交叉编译 Windows (amd64) 版本 (.exe)"
	@echo "  windows-arm64   交叉编译 Windows (arm64) 版本 (.exe)"
	@echo "  linux           交叉编译 Linux (amd64) 版本"
	@echo "  linux-arm64     交叉编译 Linux (arm64/aarch64) 版本"
	@echo "  darwin          交叉编译 macOS (amd64 & arm64) 版本"
	@echo "  darwin-amd64    交叉编译 macOS (amd64) 版本"
	@echo "  darwin-arm64    交叉编译 macOS (arm64) 版本"
	@echo "  freebsd         交叉编译 FreeBSD (amd64 & arm64) 版本"
	@echo "  freebsd-amd64   交叉编译 FreeBSD (amd64) 版本"
	@echo "  freebsd-arm64   交叉编译 FreeBSD (arm64) 版本"
	@echo "  install-skill   安装 Gemini CLI 技能 (skills/xops-agent)"
	@echo "  clean           清理 $(BIN_DIR)/ 与 coverage.out 及 Go 构建缓存产物"
	@$(ECHO_BLANK)
	@echo "Verification & Guardrails (via scripts/ci/verify.go):"
	@echo "  verify          运行提交前全量三模块构建、xopsvet、golangci-lint 与竞态测试"
	@echo "  verify-cross    Windows & macOS 交叉编译与跨平台 golangci-lint (别名: cross)"
	@echo "  verify-dst      运行确定性仿真测试 DST (XOPS_DST_SEEDS=$(XOPS_DST_SEEDS), 别名: dst)"
	@echo "  verify-release  发布门禁：三模块全量 GOWORK=off 验收 (--stage=all --gowork-off)"
	@echo "  xopsvet         测试、构建、自检并 lint 编译器护栏 (GOWORK=off)"
	@echo "  core            独立验证 core/ 模块 (GOWORK=off + xopsvet + lint + race)"
	@echo "  vet             运行三模块 xopsvet 与竞态测试 (--skip-lint)"
	@echo "  lint            运行三模块全量验证含 golangci-lint"
	@echo "  test            运行三模块 -race -shuffle=on 测试 (--skip-lint)"
	@echo "  test-race       同 test（全模块强制 -race -shuffle=on）"
	@echo "  test-cover      运行 core/ 覆盖率测试并生成报告"
	@echo "  docs-check      运行双语文档一致性与脚本校验 (npm run docs:check)"
	@echo "  ci              在本地复现完整三模块 CI、跨平台检查、CI 脚本单测与文档校验"
	@$(ECHO_BLANK)
	@echo "macOS Virtualization (Docker-OSX):"
	@echo "  macos-vm-check  检查本地 KVM 与虚拟化环境"
	@echo "  macos-vm-up     启动本地 macOS 虚拟机容器"
	@echo "  macos-vm-down   停止本地 macOS 虚拟机容器"
	@echo "  macos-vm-status 查看虚拟机容器状态"
	@echo "  macos-vm-wait   等待虚拟机客体 SSH 服务就绪"
	@echo "  macos-vm-ssh    SSH 连接到虚拟机终端"
	@echo "  macos-vm-setup-go 在客体安装/检查 Go 1.27+ 工具链"
	@echo "  macos-vm-sync   同步代码至虚拟机 ~/xops-cli"
	@echo "  macos-vm-test   在虚拟机中执行原生验收测试"

# ==============================================================================
# 安装扩展 (Extensions/Skills)
# ==============================================================================
install-skill:
	@echo "Installing xops-agent skill..."
	@$(INSTALL_SKILL_CMD)
	@echo "Skill installed successfully!"

# ==============================================================================
# 本地 macOS 虚拟机验证 (Docker-OSX / KVM)
# ==============================================================================
.PHONY: macos-vm-check macos-vm-up macos-vm-down macos-vm-status macos-vm-wait macos-vm-ssh macos-vm-setup-go macos-vm-sync macos-vm-test

macos-vm-check:
	@bash ./deploy/macos-vm/manage.sh check

macos-vm-up:
	@bash ./deploy/macos-vm/manage.sh up

macos-vm-down:
	@bash ./deploy/macos-vm/manage.sh down

macos-vm-status:
	@bash ./deploy/macos-vm/manage.sh status

macos-vm-wait:
	@bash ./deploy/macos-vm/manage.sh wait-ready

macos-vm-ssh:
	@bash ./deploy/macos-vm/manage.sh ssh

macos-vm-setup-go:
	@bash ./deploy/macos-vm/manage.sh setup-go

macos-vm-sync:
	@bash ./deploy/macos-vm/manage.sh sync

macos-vm-test:
	@bash ./deploy/macos-vm/manage.sh test
