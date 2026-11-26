// Package vault 提供 XOps v2 凭据存储出站适配器的统一路由门面与跨平台本机钥匙串构造器（ADR-011 / P4-T4）。
//
// 为确保 FFI/unsafe 后端（Windows CREDENTIALW、macOS purego Security.framework、Linux D-Bus Secret Service）
// 与纯离线 XChaCha20-Poly1305 AEAD 凭据库物理隔离，各具体实现拆分为独立子包：
//   - internal/host/vault/offline：Argon2id + XChaCha20-Poly1305 dirfd 离线库（0 unsafe）；
//   - internal/host/vault/wincred：Windows Credential Manager（CREDENTIALW + LazyProc.Call）；
//   - internal/host/vault/keychain：macOS Keychain（purego.SyscallN，CGO_ENABLED=0）；
//   - internal/host/vault/secretservice：Linux FreeDesktop Secret Service（godbus/dbus/v5 + DH AES-128-CBC）；
//   - internal/host/vault/helper：外部凭据助手与隔离式 Argon2id KDF 子进程协议。
package vault
