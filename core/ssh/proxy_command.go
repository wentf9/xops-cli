package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

var (
	// ErrProxyCommandUnavailable reports that ProxyCommand was requested in an
	// environment where local command dialing is disabled (e.g. MCP / headless core).
	ErrProxyCommandUnavailable = errors.New("ProxyCommand dialer is not enabled in this environment")

	// ErrLocalCommandUnavailable reports that LocalCommand execution was requested in an
	// environment where local command execution is disabled.
	ErrLocalCommandUnavailable = errors.New("LocalCommand runner is not enabled in this environment")
)

// proxyCommandDialer dials an SSH transport over Environment.DialProxyCommand
// after strict token sanitization and expansion.
type proxyCommandDialer struct {
	connector *Connector
	planNode  connectionPlanNode
}

var _ Dialer = (*proxyCommandDialer)(nil)

func (d *proxyCommandDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *proxyCommandDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if d == nil || d.connector == nil || d.connector.environment.DialProxyCommand == nil {
		return nil, ErrProxyCommandUnavailable
	}
	if d.planNode.cfg == nil {
		return nil, errors.New("missing client configuration for ProxyCommand")
	}
	rawCmd := d.planNode.cfg.Options.ActiveProxyCommand()
	if rawCmd == "" {
		return nil, errors.New("empty ProxyCommand")
	}

	target := d.connector.buildTargetContext(d.planNode)
	if templateUsesPercentToken(rawCmd, 'n') {
		origHost, err := resolveLocalExecOriginalHost(
			d.planNode.cfg.OriginalHost,
			d.planNode.cfg.NodeID,
			d.planNode.name,
			d.planNode.cfg.Address,
		)
		if err != nil {
			return nil, err
		}
		target.OriginalHost = origHost
	}
	expanded, err := ExpandProxyCommand(rawCmd, d.connector.environment, target)
	if err != nil {
		return nil, err
	}

	dialCtx := ctx
	var cancel context.CancelFunc
	if timeout := d.connector.getNodeHandshakeTimeout(d.planNode.cfg); timeout > 0 {
		dialCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	conn, err := d.connector.environment.DialProxyCommand(dialCtx, expanded)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("ProxyCommand dialer returned nil connection")
	}
	if err := dialCtx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	remoteHost := strings.TrimPrefix(strings.TrimSuffix(target.Host, "]"), "[")
	port := target.Port
	if port <= 0 {
		port = 22
	}
	return &proxyCommandConn{
		Conn:       conn,
		localAddr:  proxyEndpointAddr("127.0.0.1:0"),
		remoteAddr: proxyEndpointAddr(net.JoinHostPort(remoteHost, strconv.Itoa(port))),
	}, nil
}

type proxyEndpointAddr string

func (proxyEndpointAddr) Network() string  { return "stdio" }
func (a proxyEndpointAddr) String() string { return string(a) }

type proxyCommandConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *proxyCommandConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *proxyCommandConn) RemoteAddr() net.Addr { return c.remoteAddr }

// RunPostAuthLocalCommand expands and executes LocalCommand via Environment.RunLocalCommand
// when PermitLocalCommand=yes and LocalCommand is set (and not "none").
// Multiplexed control slaves are skipped automatically; daemon modes gate whether to invoke this helper at the CLI layer.
func (c *Client) RunPostAuthLocalCommand(ctx context.Context) error {
	if c == nil {
		return errors.New("nil SSH client")
	}
	if c.IsMultiplexed() {
		return nil
	}
	connCfg := c.ConnectionConfig()
	if !connCfg.Options.PermitLocalCommand() {
		return nil
	}
	rawCmd := connCfg.Options.LocalCommand()
	if rawCmd == "" || rawCmd == "none" {
		return nil
	}
	if c.environment.RunLocalCommand == nil {
		return ErrLocalCommandUnavailable
	}

	port := connCfg.Port
	if port <= 0 {
		port = 22
	}
	user := connCfg.User
	if user == "" {
		user = c.environment.LocalUser
	}
	var origHost string
	if templateUsesPercentToken(rawCmd, 'n') {
		var err error
		origHost, err = resolveLocalExecOriginalHost(connCfg.OriginalHost, connCfg.NodeID, "", connCfg.Address)
		if err != nil {
			return err
		}
	}
	target := TargetContext{
		Host:         connCfg.Address,
		Port:         port,
		User:         user,
		OriginalHost: origHost,
		JumpHost:     NormalizeProxyJump(connCfg.ProxyJump),
		KeyPath:      connCfg.KeyPath,
	}
	expanded, err := ExpandLocalCommand(rawCmd, c.environment, target)
	if err != nil {
		return err
	}
	if expanded == "" || expanded == "none" {
		return nil
	}
	return c.environment.RunLocalCommand(ctx, expanded)
}

// resolveLocalExecOriginalHost derives the %n (OriginalHost) token for ProxyCommand and
// LocalCommand without altering Connector.buildTargetContext globally (which ControlPath
// and mux handoff rely on). Any explicit non-empty OriginalHost is preserved verbatim so
// unsafe values fail closed in ValidateSafeExecToken. When OriginalHost is unset, internal
// NodeIDs ("openssh:<alias>" or "user@host:port") are decomposed after validating each piece.
func resolveLocalExecOriginalHost(explicitOriginalHost, nodeID, fallbackName, fallbackAddr string) (string, error) {
	if explicit := strings.TrimSpace(explicitOriginalHost); explicit != "" {
		return explicit, nil
	}
	rawID := strings.TrimSpace(nodeID)
	if rawID == "" {
		rawID = strings.TrimSpace(fallbackName)
	}
	if rawID == "" {
		return strings.TrimSpace(fallbackAddr), nil
	}

	candidate := rawID
	if after, ok := strings.CutPrefix(candidate, "openssh:"); ok {
		if after == "" {
			return "", fmt.Errorf("%w: empty host in node identifier %q", ErrUnsafeExecToken, rawID)
		}
		candidate = after
	}

	if atIdx := strings.LastIndexByte(candidate, '@'); atIdx != -1 {
		userPart := candidate[:atIdx]
		if err := ValidateSafeExecToken("%r", userPart); err != nil {
			return "", err
		}
		candidate = candidate[atIdx+1:]
		if candidate == "" {
			return "", fmt.Errorf("%w: empty host in node identifier %q", ErrUnsafeExecToken, rawID)
		}
	}

	return extractLocalExecHostSpec(candidate)
}

func extractLocalExecHostSpec(hostSpec string) (string, error) {
	if strings.HasPrefix(hostSpec, "[") {
		if strings.HasSuffix(hostSpec, "]") {
			if err := ValidateSafeExecToken("%n", hostSpec); err != nil {
				return "", err
			}
			return cleanHostLiteral(hostSpec), nil
		}
		_, port, err := net.SplitHostPort(hostSpec)
		if err != nil {
			return "", fmt.Errorf("%w: malformed host specification %q", ErrUnsafeExecToken, hostSpec)
		}
		if err := ValidateSafeExecToken("%p", port); err != nil {
			return "", err
		}
		rawBracketedHost := hostSpec[:len(hostSpec)-len(port)-1]
		if err := ValidateSafeExecToken("%n", rawBracketedHost); err != nil {
			return "", err
		}
		return cleanHostLiteral(rawBracketedHost), nil
	}

	if strings.Count(hostSpec, ":") == 1 {
		host, port, err := net.SplitHostPort(hostSpec)
		if err != nil {
			return "", fmt.Errorf("%w: malformed host specification %q", ErrUnsafeExecToken, hostSpec)
		}
		if err := ValidateSafeExecToken("%p", port); err != nil {
			return "", err
		}
		if err := ValidateSafeExecToken("%n", host); err != nil {
			return "", err
		}
		return host, nil
	}

	if err := ValidateSafeExecToken("%n", hostSpec); err != nil {
		return "", err
	}
	return cleanHostLiteral(hostSpec), nil
}
