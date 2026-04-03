# ==============================================================================
# 变量定义
# ==============================================================================

# 项目名称
BINARY_NAME=xops
# 模块名称 (请替换为你 go.mod 中的 module 内容)
MODULE=github.com/wentf9/xops-cli

# 获取版本信息
# git describe: 获取 v1.0.0-3-g8d8f 格式
# if git info fails, default to "unknown"
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "unknown")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date +%Y-%m-%dT%H:%M:%S%z)

# 注入 LDFLAGS
LDFLAGS := -s -w \
           -X '$(MODULE)/cmd/version.Version=$(VERSION)' \
           -X '$(MODULE)/cmd/version.Commit=$(COMMIT)' \
           -X '$(MODULE)/cmd/version.BuildTime=$(DATE)'

# 输出目录
BIN_DIR=bin

# ==============================================================================
# 自动检测当前系统，处理 .exe 后缀
# ==============================================================================
ifeq ($(OS),Windows_NT)
    # Windows 环境 (Git Bash 或其他 Make 工具)
    SHELL_EXT=.exe
else
    # Linux / Mac 环境
    SHELL_EXT=
endif

# ==============================================================================
# 编译命令
# ==============================================================================

.PHONY: all clean help build build-cli test test-race test-cover bench stress
.PHONY: windows windows-arm64 linux linux-arm64 darwin darwin-amd64 darwin-arm64

default: all

all: clean build

# 默认编译当前系统版本
build: build-cli

build-cli:
	@echo "Building CLI ($(VERSION)) for current OS..."
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)$(SHELL_EXT) ./cmd/cli

# ==============================================================================
# 交叉编译目标 (Cross Compilation)
# ==============================================================================

# 编译 Windows 版本 (64位)
windows:
	@echo "Compiling for Windows (amd64)..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME).exe ./cmd/cli

# 编译 Windows 版本 (ARM64)
windows-arm64:
	@echo "Compiling for Windows (arm64)..."
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-arm64.exe ./cmd/cli

# 编译 Linux 版本 (64位)
linux:
	@echo "Compiling for Linux (amd64)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/cli

# 编译 Linux 版本 (aarch64位)
linux-arm64:
	@echo "Compiling for Linux (arm64)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-linux-aarch64 ./cmd/cli

# 编译 macOS 版本 (Intel & Apple Silicon)
darwin: darwin-amd64 darwin-arm64

darwin-amd64:
	@echo "Compiling for macOS (amd64)..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/cli

darwin-arm64:
	@echo "Compiling for macOS (arm64)..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/cli

# 编译所有平台
release: windows windows-arm64 linux linux-arm64 darwin

# ==============================================================================
# 清理
# ==============================================================================
clean:
	@echo "Cleaning..."
	@rm -rf $(BIN_DIR)
	@go clean

# ==============================================================================
# 测试 (Testing)
# ==============================================================================

test:
	@echo "Running tests..."
	go test ./pkg/... -count=1

test-race:
	@echo "Running tests with race detector..."
	go test ./pkg/... -race -count=1

test-cover:
	@echo "Running tests with coverage..."
	go test ./pkg/... -coverprofile=coverage.out
	go tool cover -func=coverage.out

bench:
	@echo "Running benchmarks..."
	go test ./pkg/utils/concurrent/... -bench=. -benchmem -benchtime=2s -run='^$$' -count=1

stress:
	@echo "Running stress tests..."
	go test ./pkg/utils/concurrent/... -race -run="TestStress" -v -count=1

# 显示帮助
help:
	@echo "使用方法: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all             默认目标，清理并编译当前系统版本"
	@echo "  build           仅编译当前系统版本"
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
	@echo ""
	@echo "Testing:"
	@echo "  test            运行单元测试"
	@echo "  test-race       运行单元测试 (带 race 检测)"
	@echo "  test-cover      运行测试并生成覆盖率报告"
	@echo "  bench           运行 ConcurrentMap 基准测试"
	@echo "  stress          运行 ConcurrentMap 压力测试"

# ==============================================================================
# 安装扩展 (Extensions/Skills)
# ==============================================================================
install-skill:
	@echo "Installing xops-agent skill to ~/.gemini/skills/..."
	@mkdir -p ~/.gemini/skills/xops-agent
	@cp -r skills/xops-agent/* ~/.gemini/skills/xops-agent/
	@echo "Skill installed successfully!"