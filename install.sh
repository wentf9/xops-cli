#!/usr/bin/env bash
# XOps CLI installer: Linux and macOS, amd64 and arm64. Bash 3.2+.
set -euo pipefail

VERSION=${XOPS_VERSION:-latest}
REPO=${XOPS_REPO:-wentf9/xops-cli}
INSTALL_DIR=${XOPS_INSTALL_DIR:-"$HOME/.local/bin"}
TOKEN=${GITHUB_TOKEN:-${GH_TOKEN:-}}
NO_PATH=0
STAGE='Preparing installation'
TEMP_DIR=''
TEMP_BIN=''

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'HELP'
Usage: bash install.sh [options]
  --version VERSION   latest (default), v0.14.0 or 0.14.0
  --repo OWNER/REPO   Default: wentf9/xops-cli
  --install-dir DIR  Default: ~/.local/bin
  --no-path          Do not update the shell profile
  -h, --help         Show help
Environment defaults: XOPS_VERSION, XOPS_REPO, XOPS_INSTALL_DIR.
Authentication: GITHUB_TOKEN, falling back to GH_TOKEN.
Requires curl, jq or Python 3, and sha256sum or shasum.
HELP
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version|--repo|--install-dir)
            [[ $# -ge 2 && -n "$2" ]] || fail "$1 requires a value."
            case "$1" in
                --version) VERSION=$2 ;;
                --repo) REPO=$2 ;;
                --install-dir) INSTALL_DIR=$2 ;;
            esac
            shift 2 ;;
        --no-path) NO_PATH=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unknown option: $1. Use --help." ;;
    esac
done
[[ "$REPO" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]] || fail 'Repo must be owner/repository.'
[[ "$VERSION" =~ ^[a-zA-Z0-9_.+-]+$ ]] || fail 'Version must be latest or a release version.'
# Tokens go through curl stdin, never command arguments or error output.
case "$TOKEN" in *$'\n'*|*$'\r'*|*'"'*|*'\'*) fail 'GitHub token contains invalid characters.' ;; esac
case "$INSTALL_DIR" in *:*|*$'\n'*|*$'\r'*) fail 'Install directory cannot contain a colon or newline.' ;; esac
for tool in curl mktemp; do command -v "$tool" >/dev/null 2>&1 || fail "Required tool not found: $tool."; done
if command -v jq >/dev/null 2>&1; then
    JSON_TOOL=jq
elif command -v python3 >/dev/null 2>&1; then
    JSON_TOOL=python3
else
    fail 'JSON parsing requires jq or Python 3. Install one and retry.'
fi
if command -v sha256sum >/dev/null 2>&1; then
    HASH_TOOL=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    HASH_TOOL=shasum
else
    fail 'SHA256 verification requires sha256sum or shasum.'
fi

OS=$(uname -s)
ARCH=$(uname -m)
case "$OS/$ARCH" in
    Linux/x86_64|Linux/amd64) ASSET='xops-linux-amd64' ;;
    Linux/aarch64|Linux/arm64) ASSET='xops-linux-aarch64' ;;
    Darwin/x86_64|Darwin/amd64) ASSET='xops-darwin-amd64' ;;
    Darwin/arm64|Darwin/aarch64) ASSET='xops-darwin-arm64' ;;
    *) fail "Unsupported system: $OS/$ARCH. See https://github.com/$REPO/releases." ;;
esac

# This invocation owns both temporary paths. Never remove the destination binary.
cleanup() {
    [[ -z "$TEMP_BIN" ]] || rm -f -- "$TEMP_BIN"
    [[ -z "$TEMP_DIR" ]] || rm -rf -- "$TEMP_DIR"
    return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'fail "$STAGE failed. Check file permissions and available disk space."' ERR
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/xops-install.XXXXXXXX")

fetch() {
    local url=$1 output=$2 accept=$3 authenticated=$4 status
    local options=(-q --silent --show-error --location --proto '=https' --proto-redir '=https'
        --connect-timeout 15 --max-time 300 --output "$output" --write-out '%{http_code}'
        --header 'User-Agent: xops-installer' --header "Accept: $accept")
    if [[ "$authenticated" == 1 && -n "$TOKEN" ]]; then
        if ! status=$(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" |
            curl "${options[@]}" --config - "$url" 2>/dev/null); then
            fail "$STAGE failed: network, TLS or timeout error. Check connectivity and proxy settings."
        fi
    else
        if ! status=$(curl "${options[@]}" "$url" 2>/dev/null); then
            fail "$STAGE failed: network, TLS or timeout error. Check connectivity and proxy settings."
        fi
    fi
    case "$status" in
        200) ;;
        401) fail "$STAGE failed (HTTP 401): check GITHUB_TOKEN / GH_TOKEN." ;;
        403|429) fail "$STAGE failed (HTTP $status): check token permissions or wait for the rate limit to reset." ;;
        404) fail "$STAGE failed (HTTP 404): check repo $REPO, version $VERSION and private repository access." ;;
        *) fail "$STAGE failed (HTTP $status). Retry later or check https://github.com/$REPO/releases." ;;
    esac
}

API_URL="https://api.github.com/repos/$REPO/releases/latest"
if [[ "$VERSION" != latest ]]; then
    TAG=$VERSION
    [[ "$TAG" == v* ]] || TAG="v$TAG"
    TAG=${TAG//+/%2B}
    API_URL="https://api.github.com/repos/$REPO/releases/tags/$TAG"
fi
STAGE="Fetching release $VERSION from $REPO"
printf '%s...\n' "$STAGE"
fetch "$API_URL" "$TEMP_DIR/release.json" application/vnd.github+json 1

# Parse exact asset names; formatted, minified and escaped JSON are equivalent.
if [[ "$JSON_TOOL" == jq ]]; then
    if ! jq -er --arg name "$ASSET" '
        . as $release | [.assets[] | select(.name == $name)] |
        if length != 1 then error("missing or duplicate asset") else .[0] end |
        [.browser_download_url, .digest, (.id | tostring), $release.tag_name] |
        .[] | if type == "string" and (test("[\r\n]") | not) then . else error("invalid field") end
    ' "$TEMP_DIR/release.json" > "$TEMP_DIR/asset" 2>/dev/null; then
        fail "Release metadata is invalid, or lacks a unique $ASSET with a SHA256 digest. Check https://github.com/$REPO/releases."
    fi
else
    if ! python3 - "$TEMP_DIR/release.json" "$ASSET" > "$TEMP_DIR/asset" 2>/dev/null <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    release = json.load(stream)
assets = [a for a in release['assets'] if a['name'] == sys.argv[2]]
if len(assets) != 1:
    raise ValueError('missing or duplicate asset')
a = assets[0]
for value in [a['browser_download_url'], a['digest'], str(a['id']), release['tag_name']]:
    if not isinstance(value, str) or '\n' in value or '\r' in value:
        raise ValueError('invalid field')
    print(value)
PYTHON
    then
        fail "Release metadata is invalid, or lacks a unique $ASSET with a SHA256 digest. Check https://github.com/$REPO/releases."
    fi
fi
{
    IFS= read -r DOWNLOAD_URL
    IFS= read -r DIGEST
    IFS= read -r ASSET_ID
    IFS= read -r RELEASE_TAG
} < "$TEMP_DIR/asset"
[[ "$DIGEST" =~ ^sha256:[a-fA-F0-9]{64}$ ]] || fail "$ASSET has no valid GitHub SHA256 digest. Choose a release that provides one."
[[ "$DOWNLOAD_URL" == https://github.com/* ]] || fail 'Asset download URL must use HTTPS on github.com.'
if [[ -n "$TOKEN" ]]; then
    [[ "$ASSET_ID" =~ ^[0-9]+$ ]] || fail 'Release asset has no valid GitHub asset ID.'
    DOWNLOAD_URL="https://api.github.com/repos/$REPO/releases/assets/$ASSET_ID"
fi

STAGE="Creating installation directory $INSTALL_DIR"
mkdir -p -- "$INSTALL_DIR"
INSTALL_DIR=$(cd -- "$INSTALL_DIR" && pwd -P)
case "$INSTALL_DIR" in *:*|*$'\n'*|*$'\r'*) fail 'Resolved installation directory cannot contain a colon or newline.' ;; esac
# Stage on the destination filesystem; mv then atomically replaces the old file.
TEMP_BIN=$(mktemp "$INSTALL_DIR/.xops-install.XXXXXXXX")
STAGE="Downloading $ASSET ($RELEASE_TAG)"
printf '%s...\n' "$STAGE"
fetch "$DOWNLOAD_URL" "$TEMP_BIN" application/octet-stream 1
[[ -s "$TEMP_BIN" ]] || fail 'Downloaded file is empty; existing installation was not replaced.'
STAGE="Verifying SHA256 for $ASSET"
if [[ "$HASH_TOOL" == sha256sum ]]; then
    ACTUAL_HASH=$(sha256sum "$TEMP_BIN")
else
    ACTUAL_HASH=$(shasum -a 256 "$TEMP_BIN")
fi
ACTUAL_HASH=${ACTUAL_HASH%% *}
# GNU sha256sum prefixes a backslash when the filename needs escaping.
ACTUAL_HASH=${ACTUAL_HASH#\\}
EXPECTED_HASH=${DIGEST#sha256:}
ACTUAL_HASH=$(printf '%s' "$ACTUAL_HASH" | tr '[:upper:]' '[:lower:]')
EXPECTED_HASH=$(printf '%s' "$EXPECTED_HASH" | tr '[:upper:]' '[:lower:]')
[[ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]] || fail "SHA256 mismatch for $ASSET. Expected $EXPECTED_HASH; received $ACTUAL_HASH. Existing installation was not replaced."
printf 'SHA256 verified: %s\n' "$ACTUAL_HASH"
STAGE="Installing $INSTALL_DIR/xops"
chmod 755 "$TEMP_BIN"
[[ ! -d "$INSTALL_DIR/xops" ]] || fail "$INSTALL_DIR/xops is a directory; choose another installation directory."
mv -f -- "$TEMP_BIN" "$INSTALL_DIR/xops"
TEMP_BIN=''
printf 'Installed XOps CLI %s to %s/xops\n' "$RELEASE_TAG" "$INSTALL_DIR"

if [[ "$NO_PATH" == 0 && ":${PATH:-}:" != *":$INSTALL_DIR:"* ]]; then
    # Quote as POSIX shell data, not executable path text (spaces, quotes, $, `).
    QUOTED_DIR="'${INSTALL_DIR//\'/\'\\\'\'}'"
    PATH_LINE="export PATH=$QUOTED_DIR:\"\$PATH\""
    LOGIN_SHELL=${SHELL:-}
    case "${LOGIN_SHELL##*/}" in
        zsh) PROFILE="${ZDOTDIR:-$HOME}/.zshrc" ;;
        bash)
            if [[ "$OS" == Darwin ]]; then PROFILE="$HOME/.bash_profile"; else PROFILE="$HOME/.bashrc"; fi ;;
        fish)
            printf 'Add %s to PATH with fish_add_path, then run xops --help.\n' "$INSTALL_DIR"
            exit 0 ;;
        *) PROFILE="$HOME/.profile" ;;
    esac
    STAGE="Updating $PROFILE (binary installed; use --no-path to skip profile updates)"
    if ! grep -Fqx -- "$PATH_LINE" "$PROFILE" 2>/dev/null; then
        printf '\n# xops cli\n%s\n' "$PATH_LINE" >> "$PROFILE"
    fi
    printf 'PATH configured in %s. Restart the terminal or source this file.\n' "$PROFILE"
fi
printf 'Run %s/xops --help to get started.\n' "$INSTALL_DIR"
