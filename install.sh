#!/usr/bin/env bash
# XOps CLI 一键安装脚本
# 支持 Linux (amd64/arm64) 和 macOS (amd64/arm64)

set -e

REPO="wentf9/xops-cli"
GITHUB_API="https://api.github.com/repos/$REPO/releases/latest"
INSTALL_DIR="$HOME/.local/bin"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${GREEN}===> 开始安装 XOps CLI...${NC}"

# 检测操作系统
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)
        case "$ARCH" in
            x86_64) BIN_NAME="xops-linux-amd64" ;;
            aarch64|arm64) BIN_NAME="xops-linux-aarch64" ;;
            *) echo -e "${RED}不支持的 Linux 架构: $ARCH${NC}"; exit 1 ;;
        esac
        ;;
    darwin)
        case "$ARCH" in
            x86_64) BIN_NAME="xops-darwin-amd64" ;;
            arm64|aarch64) BIN_NAME="xops-darwin-arm64" ;;
            *) echo -e "${RED}不支持的 macOS 架构: $ARCH${NC}"; exit 1 ;;
        esac
        ;;
    *)
        echo -e "${RED}不支持的操作系统: $OS${NC}"
        echo -e "${YELLOW}请访问 https://github.com/$REPO/releases 手动下载二进制文件。${NC}"
        exit 1
        ;;
esac

# 获取最新版本下载链接
echo "正在获取最新版本信息..."
DOWNLOAD_URL=$(curl -s $GITHUB_API | grep "browser_download_url" | grep "$BIN_NAME\"" | cut -d '"' -f 4)

if [ -z "$DOWNLOAD_URL" ]; then
    echo -e "${RED}未能找到适用于当前系统 ($OS-$ARCH) 的最新版本。${NC}"
    exit 1
fi

echo -e "下载地址: ${YELLOW}$DOWNLOAD_URL${NC}"

# 下载并安装 CLI
TMP_BIN="/tmp/xops"
curl -sL -o "$TMP_BIN" "$DOWNLOAD_URL"
chmod +x "$TMP_BIN"

echo "正在将可执行文件安装到 $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
mv "$TMP_BIN" "$INSTALL_DIR/xops"

# 配置环境变量
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "${YELLOW}警告: $INSTALL_DIR 不在你的 PATH 环境变量中。${NC}"
    
    SHELL_NAME=$(basename "$SHELL")
    PROFILE_FILE=""
    
    if [ "$SHELL_NAME" = "zsh" ]; then
        PROFILE_FILE="$HOME/.zshrc"
    elif [ "$SHELL_NAME" = "bash" ]; then
        if [ "$OS" = "darwin" ]; then
            PROFILE_FILE="$HOME/.bash_profile"
        else
            PROFILE_FILE="$HOME/.bashrc"
        fi
    else
        PROFILE_FILE="$HOME/.profile"
    fi
    
    echo -e "正在尝试将 $INSTALL_DIR 添加到 $PROFILE_FILE..."
    echo -e "\n# xops cli\nexport PATH=\"\$PATH:$INSTALL_DIR\"" >> "$PROFILE_FILE"
    echo -e "${GREEN}已添加！请运行 'source $PROFILE_FILE' 或重启终端以使其生效。${NC}"
fi

if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
    echo -e "${GREEN}xops 命令安装成功!\n(版本: \n$($INSTALL_DIR/xops --version 2>/dev/null || echo '未知'))${NC}"
else
    echo -e "${GREEN}xops 命令已下载到 $INSTALL_DIR/xops。${NC}"
fi

echo -e "${GREEN}===> 安装完成！${NC}"
echo -e "你可以通过运行 ${YELLOW}xops${NC} 开始使用了。"