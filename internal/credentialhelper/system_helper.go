package credentialhelper

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"

	"github.com/wentf9/xops-cli/pkg/credential"
)

const internalHelperEnvVar = "XOPS_CREDENTIAL_HELPER_SYSTEM"

func init() {
	if os.Getenv(internalHelperEnvVar) == "1" {
		runInternalSystemHelper()
	}
}

func runInternalSystemHelper() {
	limitedStdin := io.LimitReader(os.Stdin, MaxResponseBytes+1)
	data, err := io.ReadAll(limitedStdin)
	if err != nil {
		sendHelperErrorAndExit("unavailable", fmt.Sprintf("read helper request: %v", err))
	}
	if len(data) == 0 {
		sendHelperErrorAndExit("unavailable", "empty helper request")
	}
	if len(data) > MaxResponseBytes {
		sendHelperErrorAndExit("unavailable", fmt.Sprintf("helper request exceeded maximum limit of %d bytes", MaxResponseBytes))
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	var req Request
	if err := dec.Decode(&req); err != nil {
		sendHelperErrorAndExit("unavailable", fmt.Sprintf("decode helper request: %v", err))
	}

	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		sendHelperErrorAndExit("unavailable", "unexpected multiple JSON objects or trailing data in request")
	}

	if req.ProtocolVersion != ProtocolVersion {
		sendHelperErrorAndExit("unavailable", fmt.Sprintf("unsupported protocol version %d (expected %d)", req.ProtocolVersion, ProtocolVersion))
	}

	ref := credential.Ref{StoreID: req.StoreID, ItemID: req.ItemID}
	if !ref.IsComplete() {
		sendHelperErrorAndExit("unavailable", "storeID and itemID cannot be empty")
	}
	if err := ref.Validate(); err != nil {
		sendHelperErrorAndExit("unavailable", fmt.Sprintf("invalid credential ref: %v", err))
	}

	var action Action
	if len(os.Args) > 1 {
		action = Action(os.Args[len(os.Args)-1])
	}
	switch action {
	case ActionGet, ActionStore, ActionErase:
	default:
		sendHelperErrorAndExit("unavailable", fmt.Sprintf("unsupported action %q", action))
	}

	if action == ActionStore {
		if req.Secret == "" {
			sendHelperErrorAndExit("unavailable", "secret is empty for store action")
		}
		if _, err := base64.StdEncoding.DecodeString(req.Secret); err != nil {
			sendHelperErrorAndExit("unavailable", fmt.Sprintf("invalid base64 secret in request: %v", err))
		}
	}

	resp, code := handlePlatformSystemHelper(action, &req)
	if resp == nil {
		resp = &Response{}
	}
	_ = json.NewEncoder(os.Stdout).Encode(resp)
	os.Exit(code)
}

func sendHelperErrorAndExit(code, message string) {
	resp := Response{
		Code:    code,
		Message: message,
	}
	_ = json.NewEncoder(os.Stdout).Encode(resp)
	os.Exit(1)
}

func resolveControlledSystemHelper() (string, []string, []string, error) {
	cmdName := DefaultSystemHelperCommand
	if runtime.GOOS == "windows" {
		cmdName += ".exe"
	}
	if p, err := exec.LookPath(cmdName); err == nil {
		return p, nil, nil, nil
	}

	exe, err := os.Executable()
	if err != nil {
		return "", nil, nil, fmt.Errorf("resolve current executable for helper: %w", err)
	}
	return exe, nil, []string{internalHelperEnvVar + "=1"}, nil
}
