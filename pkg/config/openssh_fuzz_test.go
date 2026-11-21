package config

import (
	"bytes"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func FuzzOpenSSHConfigParser(f *testing.F) {
	seeds := []string{
		"",
		"# comment only\n",
		"Host app\n  HostName 10.0.0.1\n  User ops\n  Port 2222\n",
		"Host \"a b\" !bad.*\n\tUser=alice\n\tProxyCommand\t/bin/sh -c \"echo #keep\" # trailing\n",
		"Host app\n  SetEnv \"FOO=hello world\" \"BAR=x#y\"\n  SendEnv \"LC_*\" -LANG\n",
		"Host app\n  LocalForward 127.0.0.1:8080 [::1]:80\n  RemoteForward 0 localhost:9000\n  DynamicForward 1080\n",
		"Include nonexistent/*.conf\nHost *\n  ProxyJump none\n  ProxyCommand fallback %h %p\n",
		"Match host app exec \"false\"\n  User matchuser\nHost app\n  IdentityFile none\n",
		"Host [fe80::1%eth0]\r\n  User v6\r\n  ControlMaster autoask\r\n  ControlPersist 5m\r\n",
		"Host \"unterminated\n  User broken\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		parser, err := NewOpenSSHParserFromReader(bytes.NewReader(data))
		if err != nil || parser == nil {
			return
		}
		_ = parser.HasHost("app")
		_, _, _, _ = parser.GetVirtualNode("app")
		_, _ = parser.GetSSHOptions("app")
		_, _ = parser.GetControlConfig("app")
		if ep, epErr := ssh.NewEndpoint("10.0.0.1", 22); epErr == nil {
			_ = parser.FindConcreteHostsByAddress(ep)
		}
	})
}
