package credentialhelper

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

const internalHelperEnvVar = "XOPS_CREDENTIAL_HELPER_SYSTEM"

func init() {
	if os.Getenv(internalHelperEnvVar) == "1" {
		runInternalSystemHelper()
	}
}

func runInternalSystemHelper() {
	dec := json.NewDecoder(os.Stdin)
	var req Request
	if err := dec.Decode(&req); err != nil {
		resp := Response{
			Code:    "unavailable",
			Message: err.Error(),
		}
		_ = json.NewEncoder(os.Stdout).Encode(resp)
		os.Exit(1)
	}

	var action Action
	if len(os.Args) > 1 {
		action = Action(os.Args[len(os.Args)-1])
	}

	resp, code := handlePlatformSystemHelper(action, &req)
	if resp == nil {
		resp = &Response{}
	}
	_ = json.NewEncoder(os.Stdout).Encode(resp)
	os.Exit(code)
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
