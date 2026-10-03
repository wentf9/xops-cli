//go:build !windows

package sshenv

import core "github.com/wentf9/xops-cli/core/ssh"

func platformInputBridge() core.InputBridge { return nil }
