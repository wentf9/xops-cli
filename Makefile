# ==============================================================================
# 变量定义
# ==============================================================================

# 项目名称
BINARY_NAME=xops
# 模块名称
MODULE=github.com/wentf9/xops-cli
# 输出目录
BIN_DIR=bin

# ==============================================================================
# 跨平台环境与 Shell 适配 (Windows / Linux / macOS)
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
        GOWORK_OFF := env GOWORK=off
        SKILL_DEST := $(HOME)/.gemini/skills/xops-agent
        INSTALL_SKILL_CMD := mkdir -p "$(SKILL_DEST)" && cp -r skills/xops-agent/* "$(SKILL_DEST)/"
        ECHO_BLANK := echo ""
    else
        # Windows 原生环境 (cmd.exe / PowerShell)
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
        GOWORK_OFF := set "GOWORK=off" &&
        INSTALL_SKILL_CMD := powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path (Join-Path $$HOME '.gemini/skills/xops-agent') | Out-Null; Copy-Item -Recurse -Force 'skills/xops-agent/*' (Join-Path $$HOME '.gemini/skills/xops-agent')"
        ECHO_BLANK := echo.
    endif
else
    # Linux / macOS 环境 (POSIX)
    RUN_TOOL := exec
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
    GOWORK_OFF := env GOWORK=off
    SKILL_DEST := $(HOME)/.gemini/skills/xops-agent
    INSTALL_SKILL_CMD := mkdir -p "$(SKILL_DEST)" && cp -r skills/xops-agent/* "$(SKILL_DEST)/"
    ECHO_BLANK := echo ""
endif

# 清洗空格与换行
VERSION := $(strip $(VERSION))
COMMIT  := $(strip $(COMMIT))
DATE    := $(strip $(DATE))

# 编译器护栏绝对路径（兼容 POSIX / Windows GOEXE）
VETTOOL := $(abspath $(CURDIR)/$(BIN_DIR))/xopsvet$(shell go env GOEXE)
LINT_FLAGS := --max-issues-per-linter=0 --max-same-issues=0

# 渐进式模块探测（支持 Phase 0 空骨架阶段安全跳过尚未创建的模块）
HAS_XOPSVET := $(strip $(wildcard tools/xopsvet/cmd/xopsvet/*.go))
HAS_CORE_GO := $(strip $(wildcard core/*.go core/*/*.go core/*/*/*.go core/*/*/*/*.go core/*/*/*/*/*.go))
HAS_CORE_DST := $(strip $(wildcard core/internal/pool/*_test.go))
HAS_CLI_GO  := $(strip $(wildcard cmd/xops/*.go))
HAS_ROOT_GO := $(strip $(wildcard cmd/xops/*.go internal/*.go internal/*/*.go internal/*/*/*.go internal/*/*/*/*.go internal/*/*/*/*/*.go))

# 注入 LDFLAGS
LDFLAGS := -s -w \
           -X '$(MODULE)/internal/entry/cli.Version=$(VERSION)' \
           -X '$(MODULE)/internal/entry/cli.Commit=$(COMMIT)' \
           -X '$(MODULE)/internal/entry/cli.BuildTime=$(DATE)'

# ==============================================================================
# 编译命令
# ==============================================================================

.PHONY: all clean help build build-cli xopsvet core dst vet lint test test-race test-cover verify ci release
.PHONY: windows windows-arm64 linux linux-arm64 darwin darwin-amd64 darwin-arm64

default: all

all: clean build

# 默认编译当前系统版本
build: build-cli

build-cli: export CGO_ENABLED := 0
build-cli:
	@echo "Building CLI ($(VERSION)) for current OS..."
ifneq ($(HAS_CLI_GO),)
	$(RUN_TOOL) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)$(SHELL_EXT) ./cmd/xops
else
	@echo "Skipping build-cli: ./cmd/xops has no Go files yet."
endif

# ==============================================================================
# 交叉编译目标 (Cross Compilation)
# ==============================================================================

# 编译 Windows 版本 (64位)
windows: export GOOS := windows
windows: export GOARCH := amd64
windows: export CGO_ENABLED := 0
windows:
	@echo "Compiling for Windows (amd64)..."
	$(RUN_TOOL) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME).exe ./cmd/xops

# 编译 Windows 版本 (ARM64)
windows-arm64: export GOOS := windows
windows-arm64: export GOARCH := arm64
windows-arm64: export CGO_ENABLED := 0
windows-arm64:
	@echo "Compiling for Windows (arm64)..."
	$(RUN_TOOL) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-arm64.exe ./cmd/xops

# 编译 Linux 版本 (64位)
linux: export GOOS := linux
linux: export GOARCH := amd64
linux: export CGO_ENABLED := 0
linux:
	@echo "Compiling for Linux (amd64)..."
	$(RUN_TOOL) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/xops

# 编译 Linux 版本 (aarch64位)
linux-arm64: export GOOS := linux
linux-arm64: export GOARCH := arm64
linux-arm64: export CGO_ENABLED := 0
linux-arm64:
	@echo "Compiling for Linux (arm64)..."
	$(RUN_TOOL) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-linux-aarch64 ./cmd/xops

# 编译 macOS 版本 (Intel & Apple Silicon)
darwin: darwin-amd64 darwin-arm64

darwin-amd64: export GOOS := darwin
darwin-amd64: export GOARCH := amd64
darwin-amd64: export CGO_ENABLED := 0
darwin-amd64:
	@echo "Compiling for macOS (amd64)..."
	$(RUN_TOOL) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/xops

darwin-arm64: export GOOS := darwin
darwin-arm64: export GOARCH := arm64
darwin-arm64: export CGO_ENABLED := 0
darwin-arm64:
	@echo "Compiling for macOS (arm64)..."
	$(RUN_TOOL) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/xops

# 编译所有平台
release: windows windows-arm64 linux linux-arm64 darwin

# ==============================================================================
# 清理
# ==============================================================================
clean:
	@echo "Cleaning..."
	@$(RM_CMD)
	@$(RUN_TOOL) go clean

# ==============================================================================
# 三模块渐进式护栏与测试 (Testing & Verification)
# ==============================================================================

xopsvet: export GOWORK := off
xopsvet:
ifneq ($(HAS_XOPSVET),)
	@echo "Testing and building xopsvet -> $(VETTOOL)..."
	$(RUN_TOOL) go -C tools/xopsvet test -race -count=1 ./...
	$(RUN_TOOL) go -C tools/xopsvet build -o "$(VETTOOL)" ./cmd/xopsvet
	$(RUN_TOOL) go -C tools/xopsvet vet -vettool="$(VETTOOL)" ./...
	cd tools/xopsvet && $(RUN_TOOL) golangci-lint run $(LINT_FLAGS) ./...
else
	@echo "Skipping xopsvet: tools/xopsvet/cmd/xopsvet has no Go files yet (VETTOOL=$(VETTOOL))."
endif

core: export GOWORK := off
core: xopsvet
ifneq ($(HAS_CORE_GO),)
	@echo "Verifying core/ independently (GOWORK=off)..."
	$(RUN_TOOL) go -C core build ./...
ifneq ($(HAS_XOPSVET),)
	$(RUN_TOOL) go -C core vet -vettool="$(VETTOOL)" ./...
endif
	cd core && $(RUN_TOOL) golangci-lint run $(LINT_FLAGS) ./...
	$(RUN_TOOL) go -C core test -race -shuffle=on -count=1 ./...
else
	@echo "Skipping core: core/ has no Go files yet."
endif

dst: export GOWORK := off
dst:
ifneq ($(HAS_CORE_DST),)
	@echo "Running Deterministic Simulation Tests (DST)..."
	XOPS_DST_SEEDS=$${XOPS_DST_SEEDS:-10000} $(RUN_TOOL) go -C core test -race -count=1 -run "^TestDST_" ./...
else
	@echo "Skipping dst: core/internal/pool DST tests not present yet."
endif

vet: xopsvet
ifneq ($(HAS_XOPSVET),)
	@echo "Running xopsvet across available modules (VETTOOL=$(VETTOOL))..."
	$(RUN_TOOL) $(GOWORK_OFF) go -C tools/xopsvet vet -vettool="$(VETTOOL)" ./...
ifneq ($(HAS_CORE_GO),)
	$(RUN_TOOL) $(GOWORK_OFF) go -C core vet -vettool="$(VETTOOL)" ./...
endif
ifneq ($(HAS_ROOT_GO),)
	$(RUN_TOOL) go vet -vettool="$(VETTOOL)" ./...
endif
else
	@echo "Skipping vet: VETTOOL=$(VETTOOL) is not built yet."
endif

lint:
	@echo "Running golangci-lint..."
ifneq ($(HAS_XOPSVET),)
	cd tools/xopsvet && $(RUN_TOOL) $(GOWORK_OFF) golangci-lint run $(LINT_FLAGS) ./...
endif
ifneq ($(HAS_CORE_GO),)
	cd core && $(RUN_TOOL) $(GOWORK_OFF) golangci-lint run $(LINT_FLAGS) ./...
endif
ifneq ($(HAS_ROOT_GO),)
	$(RUN_TOOL) golangci-lint run $(LINT_FLAGS) ./...
endif
ifeq ($(HAS_XOPSVET)$(HAS_CORE_GO)$(HAS_ROOT_GO),)
	@echo "Skipping lint: no Go modules contain Go source files yet."
endif

test:
	@echo "Running tests..."
ifneq ($(HAS_XOPSVET),)
	$(RUN_TOOL) $(GOWORK_OFF) go -C tools/xopsvet test ./... -count=1
endif
ifneq ($(HAS_CORE_GO),)
	$(RUN_TOOL) $(GOWORK_OFF) go -C core test ./... -count=1
endif
ifneq ($(HAS_ROOT_GO),)
	$(RUN_TOOL) go test ./... -count=1
endif
ifeq ($(HAS_XOPSVET)$(HAS_CORE_GO)$(HAS_ROOT_GO),)
	@echo "Skipping test: no Go modules contain Go source files yet."
endif

test-race:
	@echo "Running tests with race detector..."
ifneq ($(HAS_XOPSVET),)
	$(RUN_TOOL) $(GOWORK_OFF) go -C tools/xopsvet test ./... -race -shuffle=on -count=1
endif
ifneq ($(HAS_CORE_GO),)
	$(RUN_TOOL) $(GOWORK_OFF) go -C core test ./... -race -shuffle=on -count=1
endif
ifneq ($(HAS_ROOT_GO),)
	$(RUN_TOOL) go test ./... -race -shuffle=on -count=1
endif
ifeq ($(HAS_XOPSVET)$(HAS_CORE_GO)$(HAS_ROOT_GO),)
	@echo "Skipping test-race: no Go modules contain Go source files yet."
endif

test-cover:
	@echo "Running tests with coverage..."
ifneq ($(HAS_CORE_GO),)
	$(RUN_TOOL) $(GOWORK_OFF) go -C core test ./... -covermode=atomic -coverprofile=../coverage.out
	$(RUN_TOOL) go tool cover -func=coverage.out
else
	@echo "Skipping test-cover: core/ has no Go files yet."
endif

verify: core
ifneq ($(HAS_ROOT_GO),)
	@echo "Verifying root CLI module..."
	$(RUN_TOOL) go build ./...
ifneq ($(HAS_XOPSVET),)
	$(RUN_TOOL) go vet -vettool="$(VETTOOL)" ./...
endif
	$(RUN_TOOL) golangci-lint run $(LINT_FLAGS) ./...
	$(RUN_TOOL) go test ./... -count=1
else
	@echo "Root CLI module has no Go files yet; core/ & xopsvet checks completed."
endif

ci: verify test-race
	@echo "Running docs check..."
	npm run docs:check

# 显示帮助
help:
	@echo "使用方法: make [target]"
	@$(ECHO_BLANK)
	@echo "Targets:"
	@echo "  all             默认目标，清理并编译当前系统版本"
	@echo "  build           仅编译当前系统版本 (./cmd/xops)"
	@echo "  windows         交叉编译 Windows (amd64) 版本 (.exe)"
	@echo "  windows-arm64   交叉编译 Windows (arm64) 版本 (.exe)"
	@echo "  linux           交叉编译 Linux (amd64) 版本"
	@echo "  linux-arm64     交叉编译 Linux (arm64) 版本"
	@echo "  darwin          交叉编译 macOS (amd64 & arm64) 版本"
	@echo "  darwin-amd64    交叉编译 macOS (amd64) 版本"
	@echo "  darwin-arm64    交叉编译 macOS (arm64) 版本"
	@echo "  release         交叉编译所有支持的平台"
	@echo "  install-skill   安装 Gemini CLI 技能"
	@echo "  clean           清理构建文件"
	@$(ECHO_BLANK)
	@echo "Testing & Guardrails:"
	@echo "  xopsvet         测试并构建编译器护栏 $(VETTOOL) (GOWORK=off)"
	@echo "  core            独立验证 core/ 模块 (GOWORK=off + xopsvet + lint + race)"
	@echo "  dst             运行确定性仿真测试 (DST)"
	@echo "  vet             运行 xopsvet 静态检查"
	@echo "  lint            运行 golangci-lint"
	@echo "  test            运行单元测试"
	@echo "  test-race       运行单元测试 (带 -race -shuffle=on)"
	@echo "  test-cover      运行测试并生成覆盖率报告"
	@echo "  verify          运行提交前构建、测试和 Lint 检查"
	@echo "  ci              在本地复现三模块 CI 与文档检查"
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
