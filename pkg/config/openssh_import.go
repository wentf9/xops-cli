package config

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"
	"github.com/wentf9/xops-cli/pkg/models"
)

// OpenSSHHost is a concrete Host entry that can be persisted in the XOps inventory.
// Wildcard and negated patterns are intentionally excluded because they do not
// identify a single inventory node.
type OpenSSHHost struct {
	Name     string
	Host     models.Host
	Identity models.Identity
	Node     models.Node
}

// ParseOpenSSHHosts parses concrete Host entries from an OpenSSH configuration.
// It does not connect to any remote host or modify the source configuration.
func ParseOpenSSHHosts(r io.Reader, defaultUser string) ([]OpenSSHHost, error) {
	cfg, err := ssh_config.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("parse openssh configuration: %w", err)
	}

	hosts := make([]OpenSSHHost, 0)
	seen := make(map[string]struct{})
	for _, block := range cfg.Hosts {
		for _, pattern := range block.Patterns {
			name := pattern.String()
			if !isConcreteSSHHost(name) {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}

			host, err := openSSHHostFromConfig(cfg, name, defaultUser)
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, host)
			seen[name] = struct{}{}
		}
	}

	return hosts, nil
}

func isConcreteSSHHost(pattern string) bool {
	return pattern != "" &&
		!strings.HasPrefix(pattern, "!") &&
		!strings.ContainsAny(pattern, "*?")
}

func openSSHHostFromConfig(cfg *ssh_config.Config, name, defaultUser string) (OpenSSHHost, error) {
	address, err := openSSHValue(cfg, name, "HostName", name)
	if err != nil {
		return OpenSSHHost{}, err
	}
	user, err := openSSHValue(cfg, name, "User", defaultUser)
	if err != nil {
		return OpenSSHHost{}, err
	}
	portValue, err := openSSHValue(cfg, name, "Port", "22")
	if err != nil {
		return OpenSSHHost{}, err
	}
	port, err := strconv.ParseUint(strings.TrimSpace(portValue), 10, 16)
	if err != nil || port == 0 {
		return OpenSSHHost{}, fmt.Errorf("parse openssh port for host %q: %q", name, portValue)
	}
	keyPath, err := openSSHValue(cfg, name, "IdentityFile", "")
	if err != nil {
		return OpenSSHHost{}, err
	}
	proxyJump, err := openSSHValue(cfg, name, "ProxyJump", "")
	if err != nil {
		return OpenSSHHost{}, err
	}
	if strings.EqualFold(proxyJump, "none") {
		proxyJump = ""
	}

	return OpenSSHHost{
		Name: name,
		Host: models.Host{
			Address: address,
			Port:    uint16(port),
		},
		Identity: models.Identity{
			User:     user,
			AuthType: "auto",
			KeyPath:  expandHomeDir(keyPath),
		},
		Node: models.Node{
			Alias:     []string{name},
			Tags:      []string{"openssh"},
			ProxyJump: proxyJump,
			SudoMode:  models.SudoModeAuto,
		},
	}, nil
}

func openSSHValue(cfg *ssh_config.Config, host, key, fallback string) (string, error) {
	value, err := cfg.Get(host, key)
	if err != nil {
		return "", fmt.Errorf("read openssh %s for host %q: %w", key, host, err)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	return value, nil
}
