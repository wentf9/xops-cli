package ssh

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// ConnectionPlan is an immutable connection snapshot. Hops are ordered from
// the first directly reachable jump to the final target, without plaintext
// secrets. Scope separates consumers that share node names or credentials.
type ConnectionPlan struct {
	Scope string
	Hops  []ConnectionConfig
}

// CapturePlan resolves a complete snapshot from a host-supplied immutable
// in-memory provider. It never dials or retains that provider after returning.
func CapturePlan(ctx context.Context, provider ConnectionProvider, nodeID, scope string) (_ ConnectionPlan, retErr error) {
	if ctx == nil || provider == nil {
		return ConnectionPlan{}, errors.New("plan capture context and provider are required")
	}
	connector := NewConnector(provider)
	defer func() { retErr = errors.Join(retErr, connector.CloseAll()) }()
	resolved, err := connector.resolveConnectionPlan(ctx, nodeID)
	if err != nil {
		return ConnectionPlan{}, err
	}
	plan := ConnectionPlan{Scope: scope}
	for index := len(resolved) - 1; index >= 0; index-- {
		cfg := resolved[index].cfg.ToConnectionConfig()
		cfg.NodeID = resolved[index].name
		cfg.ProxyJump = ""
		if len(plan.Hops) > 0 {
			cfg.ProxyJump = plan.Hops[len(plan.Hops)-1].NodeID
		}
		plan.Hops = append(plan.Hops, cfg)
	}
	return normalizePlan(plan)
}

// PlanConnection leases one connection generation. Close releases this lease;
// it does not close transports still leased by another operation. Client is
// borrowed from the lease and must not outlive it.
type PlanConnection struct {
	Client *Client
	close  func() error
}

func (c *PlanConnection) Close() error {
	if c == nil || c.close == nil {
		return nil
	}
	return c.close()
}

type planEntry struct {
	key       string
	connector *Connector
	refs      int
	retired   bool
}

// Retirement markers cover work admitted before publication that has not yet
// reached ConnectPlan. Once this bounded history fills, new generations use
// uncached leases rather than forgetting a retirement and resurrecting a pool.
const maxRetiredPlans = 4096

type planProvider struct{ configs map[string]ClientConfig }

func (p *planProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	cfg, ok := p.configs[nodeID]
	if !ok {
		return nil, fmt.Errorf("node %q is outside the captured connection plan", nodeID)
	}
	return &cfg, nil
}

// ConnectionKey hashes the complete normalized plan, including source and
// trust versions. It is not a file-transfer destination lock or authorization.
func ConnectionKey(plan ConnectionPlan) (string, error) {
	plan, err := normalizePlan(plan)
	if err != nil {
		return "", err
	}
	// Version tokens may be arbitrary bytes (legacy CAS hashes). Encode them
	// losslessly before JSON hashing; invalid UTF-8 must not collapse versions.
	for i := range plan.Hops {
		plan.Hops[i].AuthUpdateToken = base64.StdEncoding.EncodeToString([]byte(plan.Hops[i].AuthUpdateToken))
		plan.Hops[i].SudoUpdateToken = base64.StdEncoding.EncodeToString([]byte(plan.Hops[i].SudoUpdateToken))
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("encode connection plan: %w", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func normalizePlan(plan ConnectionPlan) (ConnectionPlan, error) {
	if plan.Scope == "" || len(plan.Scope) > 256 || len(plan.Hops) == 0 || len(plan.Hops) > 32 {
		return ConnectionPlan{}, errors.New("connection plan requires a bounded scope and 1 to 32 hops")
	}
	plan.Hops = slices.Clone(plan.Hops)
	seen := make(map[string]bool)
	previous := ""
	for index, hop := range plan.Hops {
		if hop.NodeID == "" || len(hop.NodeID) > 1024 || strings.ContainsAny(hop.NodeID, ",\x00\r\n") || seen[hop.NodeID] {
			return ConnectionPlan{}, errors.New("connection plan contains an invalid or duplicate node ID")
		}
		if hop.Address == "" || hop.User == "" || hop.Port < 0 || hop.Port > 65535 {
			return ConnectionPlan{}, errors.New("connection plan contains an invalid SSH endpoint")
		}
		if hop.ProxyJump != "" && hop.ProxyJump != previous {
			return ConnectionPlan{}, errors.New("connection plan jump must reference the previous captured hop")
		}
		if hop.Port == 0 {
			hop.Port = 22
		}
		hop.ProxyJump = previous
		if !hop.HasOriginalProxyJump {
			hop.OriginalProxyJump, hop.HasOriginalProxyJump = hop.ProxyJump, true
		}
		seen[hop.NodeID] = true
		plan.Hops[index], previous = hop, hop.NodeID
	}
	return plan, nil
}

// ConnectPlan never reads the connector's mutable ConnectionProvider. The
// source references and complete jump chain are copied into a generation-owned
// provider; legacy credential recording is disabled for these snapshots.
func (c *Connector) ConnectPlan(ctx context.Context, plan ConnectionPlan) (*PlanConnection, error) {
	if ctx == nil {
		return nil, errors.New("connection plan context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plan, err := normalizePlan(plan)
	if err != nil {
		return nil, err
	}
	key, err := ConnectionKey(plan)
	if err != nil {
		return nil, err
	}
	entry, err := c.acquirePlan(key, plan)
	if err != nil {
		return nil, err
	}
	defer c.connectWG.Done()
	client, err := entry.connector.Connect(ctx, plan.Hops[len(plan.Hops)-1].NodeID)
	if err == nil {
		err = c.ensureOpen()
	}
	if err != nil {
		return nil, errors.Join(err, c.releasePlan(entry, true))
	}
	return &PlanConnection{Client: client, close: sync.OnceValue(func() error { return c.releasePlan(entry, false) })}, nil
}

func (c *Connector) acquirePlan(key string, plan ConnectionPlan) (*planEntry, error) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed {
		return nil, ErrConnectorClosed
	}
	if c.plans == nil {
		c.plans = make(map[string]*planEntry)
		c.allPlans = make(map[*planEntry]struct{})
	}
	entry := c.plans[key]
	if entry == nil {
		provider := &planProvider{configs: make(map[string]ClientConfig)}
		for _, hop := range plan.Hops {
			provider.configs[hop.NodeID] = clientConfigFromPlan(hop)
		}
		connector := NewConnector(provider,
			WithEnvironment(c.environment), WithLogger(c.getLogger()), WithDialer(c.baseDialer),
			WithHandshakeTimeout(c.getHandshakeTimeout()), WithInteractionTimeout(c.interactionTimeout),
			WithSecretResolver(c.secretResolver), WithKeySource(c.keySource), WithHostKeyVerifier(c.hostKeyVerifier),
			WithPasswordPromptPattern(c.PasswordPromptPattern),
		)
		c.kaMu.Lock()
		keepAlive := c.keepAliveCfg
		c.kaMu.Unlock()
		if keepAlive != nil {
			connector.EnableKeepAlive(keepAlive.ctx, keepAlive.interval, keepAlive.timeout)
		}
		_, retired := c.retiredPlans[key]
		entry = &planEntry{key: key, connector: connector, retired: retired || c.disablePlanCache}
		if !entry.retired {
			c.plans[key] = entry
		}
		c.allPlans[entry] = struct{}{}
	}
	entry.refs++
	c.connectWG.Add(1)
	return entry, nil
}

func clientConfigFromPlan(cfg ConnectionConfig) ClientConfig {
	return ClientConfig{
		NodeID: cfg.NodeID, Address: cfg.Address, Port: cfg.Port, User: cfg.User, AuthType: cfg.AuthType,
		KeyPath: cfg.KeyPath, KeyRef: cfg.KeyRef, TrustVersion: cfg.TrustVersion,
		AuthUpdateToken: cfg.AuthUpdateToken, SudoUpdateToken: cfg.SudoUpdateToken, SudoMode: cfg.SudoMode,
		ProxyJump: cfg.ProxyJump, OriginalProxyJump: cfg.OriginalProxyJump, HasOriginalProxyJump: cfg.HasOriginalProxyJump,
		PasswordPromptPattern: cfg.PasswordPromptPattern,
	}
}

// RetirePlan stops new reuse of this cached generation and drains its existing
// leases. This is cache invalidation, not authorization/revocation: callers must
// check current operation bindings before requesting any plan again.
func (c *Connector) RetirePlan(plan ConnectionPlan) error {
	key, err := ConnectionKey(plan)
	if err != nil {
		return err
	}
	c.lifecycleMu.Lock()
	if c.closed {
		c.lifecycleMu.Unlock()
		return nil
	}
	if !c.disablePlanCache {
		if len(c.retiredPlans) >= maxRetiredPlans {
			c.disablePlanCache = true
			clear(c.retiredPlans)
		} else {
			if c.retiredPlans == nil {
				c.retiredPlans = make(map[string]struct{})
			}
			c.retiredPlans[key] = struct{}{}
		}
	}
	entry := c.plans[key]
	if entry == nil {
		c.lifecycleMu.Unlock()
		return nil
	}
	entry.retired = true
	delete(c.plans, key)
	closeNow := entry.refs == 0
	c.lifecycleMu.Unlock()
	if closeNow {
		return c.closePlan(entry)
	}
	return nil
}

func (c *Connector) releasePlan(entry *planEntry, failed bool) error {
	c.lifecycleMu.Lock()
	entry.refs--
	if failed || c.closed {
		entry.retired = true
	}
	if entry.retired && c.plans[entry.key] == entry {
		delete(c.plans, entry.key)
	}
	closeNow := entry.retired && entry.refs == 0
	c.lifecycleMu.Unlock()
	if closeNow {
		return c.closePlan(entry)
	}
	return nil
}

func (c *Connector) closePlan(entry *planEntry) error {
	err := entry.connector.CloseAll()
	c.lifecycleMu.Lock()
	delete(c.allPlans, entry)
	c.lifecycleMu.Unlock()
	return err
}
