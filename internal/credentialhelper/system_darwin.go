//go:build darwin

package credentialhelper

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func newNativeSystemStore(storeID string, cfg SystemStoreConfig) (credential.Store, error) {
	cmdPath, args, env, err := resolveControlledSystemHelper()
	if err != nil {
		return nil, fmt.Errorf("resolve controlled system helper: %w", err)
	}

	opts := ProcessOptions{
		Command: cmdPath,
		Args:    args,
		Env:     env,
		Timeout: cfg.Timeout,
	}

	return NewHelperStore(storeID, opts, cfg.ReadOnly)
}

func handlePlatformSystemHelper(action Action, req *Request) (*Response, int) {
	if req == nil {
		return &Response{Code: "unavailable", Message: "nil request"}, 1
	}

	service := fmt.Sprintf("xops:%s", req.StoreID)
	account := req.ItemID

	switch action {
	case ActionGet:
		cmd := exec.Command("/usr/bin/security", "find-generic-password", "-s", service, "-a", account, "-w")
		stdout, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && exitErr.ExitCode() == 44 {
				return &Response{Code: "not-found", Message: "credential not found"}, 1
			}
			return &Response{Code: "locked", Message: "keychain locked or denied"}, 1
		}

		if len(stdout) > MaxResponseBytes {
			return &Response{Code: "unavailable", Message: "keychain output exceeded limit"}, 1
		}

		// 严禁 TrimRight，完整保留末尾换行和所有字节
		if len(stdout) == 0 {
			return &Response{Code: "not-found", Message: "empty secret"}, 1
		}

		return &Response{
			Secret: base64.StdEncoding.EncodeToString(stdout),
		}, 0

	case ActionStore:
		if req.Secret == "" {
			return &Response{Code: "unavailable", Message: "secret is empty"}, 1
		}
		secretBytes, err := base64.StdEncoding.DecodeString(req.Secret)
		if err != nil {
			return &Response{Code: "unavailable", Message: "invalid base64 secret"}, 1
		}

		// 秘密严禁进入命令行参数：通过 security 交互模式 (-i) 的 stdin 传递指令，避免 ps 泄露
		cmd := exec.Command("/usr/bin/security", "-i")
		var stdinBuf strings.Builder
		stdinBuf.WriteString("add-generic-password -s ")
		stdinBuf.WriteString(escapeArg(service))
		stdinBuf.WriteString(" -a ")
		stdinBuf.WriteString(escapeArg(account))
		stdinBuf.WriteString(" -w ")
		stdinBuf.WriteString(escapeArg(string(secretBytes)))
		stdinBuf.WriteString(" -U\n")
		cmd.Stdin = strings.NewReader(stdinBuf.String())

		if err := cmd.Run(); err != nil {
			return &Response{Code: "locked", Message: "failed to save to keychain"}, 1
		}
		return &Response{}, 0

	case ActionErase:
		cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-s", service, "-a", account)
		if err := cmd.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && exitErr.ExitCode() == 44 {
				return &Response{Code: "not-found", Message: "credential not found"}, 1
			}
			return &Response{Code: "unavailable", Message: "failed to delete from keychain"}, 1
		}
		return &Response{}, 0

	default:
		return &Response{Code: "unavailable", Message: "unsupported action"}, 1
	}
}

func escapeArg(s string) string {
	var buf strings.Builder
	buf.WriteByte('"')
	for _, r := range s {
		if r == '"' || r == '\\' {
			buf.WriteByte('\\')
		}
		buf.WriteRune(r)
	}
	buf.WriteByte('"')
	return buf.String()
}

func checkPlatformSystemAvailability() error {
	return nil
}
