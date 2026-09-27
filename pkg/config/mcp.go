package config

import "slices"

// MCPConfig stores network service settings and references to authentication
// material. Plaintext bearer tokens never belong in configuration snapshots.
type MCPConfig struct {
	Transport       string   `yaml:"transport,omitempty"`
	Listen          string   `yaml:"listen,omitempty"`
	PublicURL       string   `yaml:"public_url,omitempty"`
	TokenFile       string   `yaml:"token_file,omitempty"`
	TokenEnv        string   `yaml:"token_env,omitempty"`
	StateDir        string   `yaml:"state_dir,omitempty"`
	AllowedHosts    []string `yaml:"allowed_hosts,omitempty"`
	AllowedOrigins  []string `yaml:"allowed_origins,omitempty"`
	HeaderTimeout   string   `yaml:"header_timeout,omitempty"`
	BodyTimeout     string   `yaml:"body_timeout,omitempty"`
	StreamIdle      string   `yaml:"stream_idle_timeout,omitempty"`
	ToolTimeout     string   `yaml:"tool_timeout,omitempty"`
	SessionTimeout  string   `yaml:"session_timeout,omitempty"`
	ShutdownTimeout string   `yaml:"shutdown_timeout,omitempty"`
	StartWindow     string   `yaml:"transfer_start_window,omitempty"`
	Retention       string   `yaml:"transfer_retention,omitempty"`
	TotalTimeout    string   `yaml:"transfer_timeout,omitempty"`
	CommitTimeout   string   `yaml:"commit_timeout,omitempty"`
	MaxSessions     *int     `yaml:"max_sessions,omitempty"`
	MaxRequests     *int     `yaml:"max_requests,omitempty"`
	MaxFileBytes    *int64   `yaml:"max_file_bytes,omitempty"`
	MaxActive       *int     `yaml:"max_active_transfers,omitempty"`
	MaxPerTarget    *int     `yaml:"max_transfers_per_target,omitempty"`
	MaxReady        *int     `yaml:"max_ready_transfers,omitempty"`
	MaxRecords      *int     `yaml:"max_transfer_records,omitempty"`
}

func (c *MCPConfig) Clone() *MCPConfig {
	if c == nil {
		return nil
	}
	out := *c
	out.AllowedHosts, out.AllowedOrigins = slices.Clone(c.AllowedHosts), slices.Clone(c.AllowedOrigins)
	out.MaxSessions = cloneMCPValue(c.MaxSessions)
	out.MaxRequests = cloneMCPValue(c.MaxRequests)
	out.MaxFileBytes = cloneMCPValue(c.MaxFileBytes)
	out.MaxActive = cloneMCPValue(c.MaxActive)
	out.MaxPerTarget = cloneMCPValue(c.MaxPerTarget)
	out.MaxReady = cloneMCPValue(c.MaxReady)
	out.MaxRecords = cloneMCPValue(c.MaxRecords)
	return &out
}

func cloneMCPValue[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}
