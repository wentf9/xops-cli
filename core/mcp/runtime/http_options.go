package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
)

const httpProtocolVersion = "2025-11-25"

// HTTPOptions configures authenticated Streamable HTTP. Token is consumed at
// construction; the runtime retains only its digest, never a printable token.
type HTTPOptions struct {
	Listen    string
	PublicURL string
	Token     string
	// TokenVerifier supplies deployment-owned authentication. It is mutually
	// exclusive with Token and must return a stable, nonempty UserID. The
	// optional Extra["tokenID"] identifies the credential, not the client.
	TokenVerifier   auth.TokenVerifier
	StateDir        string
	AllowedHosts    []string
	AllowedOrigins  []string
	HeaderTimeout   time.Duration
	BodyTimeout     time.Duration
	StreamIdle      time.Duration
	ToolTimeout     time.Duration
	SessionTimeout  time.Duration
	ShutdownTimeout time.Duration
	MaxSessions     int
	MaxRequests     int // Per-lane capacity, including independent dynamic authentication.
	Transfers       transfer.Limits
	tokenDigest     [32]byte
	scope           string
	hostScheme      string
}

func DefaultHTTPOptions() HTTPOptions {
	return HTTPOptions{
		Listen: "127.0.0.1:8080", HeaderTimeout: 10 * time.Second, BodyTimeout: 30 * time.Second,
		StreamIdle: time.Minute, ToolTimeout: 5 * time.Minute, SessionTimeout: 15 * time.Minute,
		ShutdownTimeout: 45 * time.Second, MaxSessions: 32, MaxRequests: 64,
		Transfers: transfer.DefaultLimits(),
	}
}

// ValidateLimits lets host configuration adapters validate typed limits before
// loading authentication material or starting a runtime.
func (o *HTTPOptions) ValidateLimits() error { return o.validateLimits() }

// WithHTTP switches the runtime to HTTP tools and session-based Streamable
// HTTP. Start it with Runtime.ServeHTTP rather than the stdio Run entry point.
func WithHTTP(options HTTPOptions) Option {
	return func(cfg *serverConfig) {
		copyOptions := options
		copyOptions.AllowedHosts = slices.Clone(options.AllowedHosts)
		copyOptions.AllowedOrigins = slices.Clone(options.AllowedOrigins)
		cfg.http = &copyOptions
	}
}

func (o *HTTPOptions) validate() error {
	if err := o.validateAuthentication(); err != nil {
		return err
	}
	if o.StateDir == "" {
		return errors.New("HTTP transfer state directory is required")
	}
	host, _, err := net.SplitHostPort(o.Listen)
	if err != nil {
		return fmt.Errorf("invalid HTTP listen address: %w", err)
	}
	if o.PublicURL == "" {
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("LAN HTTP listener requires an explicit public URL")
		}
		o.PublicURL = "http://" + o.Listen
	}
	public, err := parseHTTPOrigin(o.PublicURL)
	if err != nil {
		return fmt.Errorf("invalid HTTP public URL: %w", err)
	}
	o.PublicURL = public
	u, err := url.Parse(public)
	if err != nil {
		return fmt.Errorf("parse HTTP public URL: %w", err)
	}
	o.hostScheme = u.Scheme
	o.AllowedHosts = append(o.AllowedHosts, strings.ToLower(u.Host))
	for i, allowed := range o.AllowedHosts {
		host, err := normalizeHTTPHost(allowed, o.hostScheme)
		if err != nil {
			return errors.New("allowed HTTP hosts must be explicit host names or addresses with optional ports")
		}
		o.AllowedHosts[i] = host
	}
	o.AllowedOrigins = append(o.AllowedOrigins, public)
	for i, allowed := range o.AllowedOrigins {
		origin, err := parseHTTPOrigin(allowed)
		if err != nil {
			return fmt.Errorf("invalid allowed HTTP origin: %w", err)
		}
		o.AllowedOrigins[i] = origin
	}
	if err := o.validateLimits(); err != nil {
		return err
	}
	if o.TokenVerifier == nil {
		o.tokenDigest = sha256.Sum256([]byte(o.Token))
		o.scope = hex.EncodeToString(o.tokenDigest[:])
	}
	o.Token = ""
	return nil
}

func (o *HTTPOptions) validateAuthentication() error {
	if o.TokenVerifier != nil && o.Token != "" {
		return errors.New("HTTP Token and TokenVerifier are mutually exclusive")
	}
	if o.TokenVerifier == nil && (len(o.Token) < 32 || len(o.Token) > 4096 || strings.ContainsAny(o.Token, " \t\r\n")) {
		return errors.New("HTTP authentication token must contain 32 to 4096 bytes without whitespace")
	}
	return nil
}

func (o *HTTPOptions) validateLimits() error {
	if o.HeaderTimeout <= 0 || o.BodyTimeout <= 0 || o.StreamIdle <= 0 || o.ToolTimeout <= 0 || o.SessionTimeout <= 0 || o.ShutdownTimeout <= 0 {
		return errors.New("HTTP timeouts must be positive")
	}
	if o.MaxSessions <= 0 || o.MaxSessions > 1024 || o.MaxRequests <= 0 || o.MaxRequests > 4096 {
		return errors.New("HTTP session and request limits must be positive")
	}
	if err := o.Transfers.Validate(); err != nil {
		return err
	}
	return nil
}

func parseHTTPOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("HTTP origin cannot be parsed")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" ||
		strings.ContainsAny(u.Host, "*\\ \t\r\n") || u.Opaque != "" {
		return "", errors.New("HTTP origin must be an explicit http(s) origin without credentials, path, query or fragment")
	}
	host, err := canonicalHTTPAuthority(u)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + host, nil
}

func canonicalHTTPAuthority(u *url.URL) (string, error) {
	port := u.Port()
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", errors.New("HTTP origin port is out of range")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("HTTP origin has an empty port")
	}
	host := strings.ToLower(u.Host)
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		host = strings.ToLower(u.Hostname())
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return host, nil
}

func normalizeHTTPHost(host, scheme string) (string, error) {
	if strings.ContainsAny(host, "/?#@") {
		return "", errors.New("invalid HTTP host")
	}
	origin, err := parseHTTPOrigin(scheme + "://" + host)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(origin, scheme+"://"), nil
}
