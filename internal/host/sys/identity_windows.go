//go:build windows

package sys

import (
	"os"
	"os/user"
	"strings"

	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func lookupLocalIdentityOS() (ports.LocalIdentityInfo, error) {
	host, err := os.Hostname()
	if err != nil {
		return zeroVal[ports.LocalIdentityInfo](), i18n.Wrap(err, i18n.KeyHostSysHostnameFailed)
	}
	var username, uid, home string
	if cur, uErr := user.Current(); uErr == nil && cur != nil {
		username = strings.TrimSpace(cur.Username)
		uid = strings.TrimSpace(cur.Uid)
		home = strings.TrimSpace(cur.HomeDir)
	}
	if username == "" {
		if envUser, ok := os.LookupEnv("USERNAME"); ok {
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
