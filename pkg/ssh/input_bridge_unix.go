//go:build !windows

package ssh

import core "github.com/wentf9/xops-cli/core/ssh"

func platformInputBridge() core.InputBridge { return nil }
