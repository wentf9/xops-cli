//go:build unix

package sys

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/ports"
)

func lookupLocalIdentityOS() (ports.LocalIdentityInfo, error) {
	host, err := os.Hostname()
	if err != nil {
		return zeroVal[ports.LocalIdentityInfo](), fmt.Errorf("查询本机主机名失败: %w", err)
	}
	uid := strconv.Itoa(os.Getuid())
	var username, home string
	if cur, uErr := user.Current(); uErr == nil && cur != nil {
		username = strings.TrimSpace(cur.Username)
		home = strings.TrimSpace(cur.HomeDir)
		if strings.TrimSpace(cur.Uid) != "" {
			uid = strings.TrimSpace(cur.Uid)
		}
	}
	if username == "" {
		if envUser, ok := os.LookupEnv("USER"); ok {
			username = strings.TrimSpace(envUser)
		}
	}
	if home == "" {
		if h, hErr := os.UserHomeDir(); hErr == nil {
			home = strings.TrimSpace(h)
		}
	}
	return ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{
		LocalHost: strings.TrimSpace(host),
		LocalUser: username,
		LocalUID:  uid,
		HomeDir:   home,
	})
}
