package config

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/ssh"
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

// ParseOpenSSHHosts parses concrete Host entries from an OpenSSH configuration
// (including Include directives). It does not connect to any remote host or
// modify the source configuration.
func ParseOpenSSHHosts(r io.Reader, defaultUser string) ([]OpenSSHHost, error) {
	if r == nil {
		return nil, nil
	}
	cfg, err := decodeOpenSSHReader(r)
	if err != nil {
		return nil, fmt.Errorf("parse openssh configuration: %w", err)
	}

	hosts := make([]OpenSSHHost, 0)
	var walkErr error
	walkConcreteSSHHostNames(cfg, func(name string) bool {
		host, hErr := openSSHHostFromConfig(cfg, name, defaultUser)
		if hErr != nil {
			walkErr = hErr
			return false
		}
		hosts = append(hosts, host)
		return true
	})
	if walkErr != nil {
		return nil, walkErr
	}

	return hosts, nil
}

func isConcreteSSHHost(pattern string) bool {
	return pattern != "" &&
		!strings.HasPrefix(pattern, "!") &&
		!strings.ContainsAny(pattern, "*?")
}

func openSSHHostFromConfig(doc *sshConfigDoc, name, defaultUser string) (OpenSSHHost, error) {
	address, err := resolveOpenSSHHostName(doc, name)
	if err != nil {
		return OpenSSHHost{}, fmt.Errorf("resolve openssh HostName for host %q: %w", name, err)
	}
	user := openSSHValue(doc, name, "User", defaultUser)
	portValue := openSSHValue(doc, name, "Port", "22")
	port, err := strconv.ParseUint(strings.TrimSpace(portValue), 10, 16)
	if err != nil || port == 0 {
		return OpenSSHHost{}, fmt.Errorf("parse openssh port for host %q: %q", name, portValue)
	}
	keyPath := openSSHValue(doc, name, "IdentityFile", "")
	proxyWinner, _, _ := firstMatchingOpenSSHProxy(doc, name)
	var proxyJump string
	if proxyWinner == "proxyjump" {
		proxyJump = openSSHValue(doc, name, "ProxyJump", "")
		if strings.EqualFold(proxyJump, "none") {
			proxyJump = ""
		}
	}

	expandedKeyPath, err := normalizeConfigIdentityKeyPath(keyPath)
	if err != nil {
		return OpenSSHHost{}, err
	}

	sshOpts, err := parseOpenSSHOptions(doc, name)
	if err != nil {
		return OpenSSHHost{}, err
	}
	sshOpts = normalizeImportedSSHOptions(sshOpts)

	return OpenSSHHost{
		Name: name,
		Host: models.Host{
			Address: address,
			Port:    uint16(port),
		},
		Identity: models.Identity{
			User:     user,
			AuthType: "auto",
			KeyPath:  expandedKeyPath,
		},
		Node: models.Node{
			Alias:      []string{name},
			Tags:       []string{"openssh"},
			ProxyJump:  proxyJump,
			SudoMode:   models.SudoModeAuto,
			SSHOptions: sshOpts,
		},
	}, nil
}

// normalizeImportedSSHOptions makes imported ssh.Options valid under the
// persisted schema rules without weakening them. OpenSSH inherits ControlPersist
// independently of ControlMaster, so a host that resolved to ControlMaster=no
// can carry a ControlPersist it never asked for; that combination is contradictory
// once materialized, and the master mode wins.
func normalizeImportedSSHOptions(opts *ssh.Options) *ssh.Options {
	if opts == nil || opts.IsEmpty() {
		return nil
	}
	// Only import mux and transport options into persisted node configurations;
	// never persist trust or auth-policy options from ~/.ssh/config into nodes.
	cloned := opts.FilterByClasses(ssh.OptionClassMux, ssh.OptionClassTransport)
	if cloned == nil || cloned.IsEmpty() {
		return nil
	}
	pathVal := cloned.ControlPath()
	masterMode := cloned.ControlMaster()
	persistVal := cloned.ControlPersist()

	if pathVal == "" {
		// An OpenSSH host with ControlMaster or ControlPersist but no ControlPath
		// cannot form a standalone node multiplexing config without failing schema
		// validation when no global ControlPath is set.
		cloned.Delete(ssh.OptionControlMaster)
		cloned.Delete(ssh.OptionControlPersist)
	} else {
		if masterMode == ssh.ControlMasterNo && persistVal != "" {
			enabled, _, _, err := ssh.ParseControlPersist(persistVal)
			if err != nil || enabled {
				cloned.Delete(ssh.OptionControlPersist)
			}
		}
		if pathVal == "none" {
			_ = cloned.Set(ssh.OptionControlMaster, string(ssh.ControlMasterNo))
			cloned.Delete(ssh.OptionControlPersist)
		}
	}
	if cloned.IsEmpty() {
		return nil
	}
	return cloned
}

func openSSHValue(doc *sshConfigDoc, host, key, fallback string) string {
	value := firstSSHConfigKeyValue(doc, host, key)
	if value == "" {
		return fallback
	}
	return value
}
