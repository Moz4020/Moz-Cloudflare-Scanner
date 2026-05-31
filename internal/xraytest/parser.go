package xraytest

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// VLESSConfig holds parsed parameters from a VLESS or Trojan share URL.
// Check the Protocol field to know which type this is.
type VLESSConfig struct {
	// Protocol is "vless" or "trojan".
	Protocol string

	// VLESS-specific
	UUID       string
	Encryption string
	Flow       string

	// Trojan-specific
	Password string

	// Common
	Address string
	Port    int

	// Transport
	Network     string // ws, grpc, xhttp, tcp
	Path        string
	Host        string
	ServiceName string // gRPC
	Mode        string // gRPC multi/gun, xhttp auto
	Authority   string // gRPC

	// TLS
	Security    string // tls, reality, none
	SNI         string
	Fingerprint string
	ALPN        []string
	Insecure    bool

	// Metadata
	Remark string
}

// ParseProxyURL auto-detects the protocol (vless:// or trojan://) and parses
// the share URL into a VLESSConfig. Returns an error if the scheme is unknown.
func ParseProxyURL(raw string) (*VLESSConfig, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "vless://"):
		return ParseVLESS(raw)
	case strings.HasPrefix(raw, "trojan://"):
		return ParseTrojan(raw)
	default:
		return nil, fmt.Errorf("unsupported URL scheme — must start with vless:// or trojan://")
	}
}

// ParseVLESS parses a vless:// share URL into a VLESSConfig.
func ParseVLESS(raw string) (*VLESSConfig, error) {
	if !strings.HasPrefix(raw, "vless://") {
		return nil, fmt.Errorf("not a vless:// URL")
	}

	// vless://UUID@address:port?params#remark
	// URL parse doesn't handle the UUID as userinfo well, so we do it manually
	raw = strings.TrimPrefix(raw, "vless://")

	// Split remark
	remark := ""
	if idx := strings.LastIndex(raw, "#"); idx != -1 {
		remark = raw[idx+1:]
		raw = raw[:idx]
	}
	remark, _ = url.QueryUnescape(remark)

	// Split params
	params := url.Values{}
	if idx := strings.Index(raw, "?"); idx != -1 {
		var err error
		params, err = url.ParseQuery(raw[idx+1:])
		if err != nil {
			return nil, fmt.Errorf("parsing query params: %w", err)
		}
		raw = raw[:idx]
	}

	// Split UUID@address:port
	atIdx := strings.Index(raw, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("missing @ in URL")
	}
	uuid := raw[:atIdx]
	hostPort := raw[atIdx+1:]

	// Parse host:port
	host, portStr, err := splitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("parsing host:port %q: %w", hostPort, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		// The '?' separator may have been silently dropped by some paste
		// handlers. Recover: extract leading digits as port and treat the
		// remainder as additional query params.
		port, params, err = recoverMissingQuerySep(portStr, params)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", portStr)
		}
	}

	cfg := &VLESSConfig{
		Protocol:    "vless",
		UUID:        uuid,
		Address:     host,
		Port:        port,
		Encryption:  paramOr(params, "encryption", "none"),
		Flow:        params.Get("flow"),
		Network:     paramOr(params, "type", "tcp"),
		Security:    paramOr(params, "security", "none"),
		SNI:         params.Get("sni"),
		Fingerprint: paramOr(params, "fp", ""),
		Insecure:    params.Get("insecure") == "1" || params.Get("allowInsecure") == "1",
		Remark:      remark,
	}

	// Transport-specific
	switch cfg.Network {
	case "ws":
		cfg.Path = paramOr(params, "path", "/")
		cfg.Host = paramOr(params, "host", cfg.SNI)
	case "grpc":
		cfg.ServiceName = params.Get("serviceName")
		cfg.Authority = params.Get("authority")
		cfg.Mode = paramOr(params, "mode", "gun")
	case "xhttp", "splithttp":
		cfg.Path = paramOr(params, "path", "/")
		cfg.Host = paramOr(params, "host", cfg.SNI)
		cfg.Mode = paramOr(params, "mode", "auto")
	}

	// ALPN
	if alpnStr := params.Get("alpn"); alpnStr != "" {
		cfg.ALPN = strings.Split(alpnStr, ",")
	}

	return cfg, nil
}

// WithAddress returns a copy of the config with the address replaced.
// Port is preserved. This is used to swap in a candidate CF IP.
func (c *VLESSConfig) WithAddress(newAddr string) *VLESSConfig {
	copy := *c
	copy.Address = newAddr
	return &copy
}

// WithEndpoint returns a copy of the config with the address and port replaced.
func (c *VLESSConfig) WithEndpoint(newAddr string, newPort int) *VLESSConfig {
	copy := *c
	copy.Address = newAddr
	copy.Port = newPort
	return &copy
}

// ToShareURL reconstructs a vless:// share URL from the config.
func (c *VLESSConfig) ToShareURL() string {
	params := url.Values{}
	params.Set("encryption", c.Encryption)
	params.Set("security", c.Security)
	params.Set("type", c.Network)

	if c.SNI != "" {
		params.Set("sni", c.SNI)
	}
	if c.Fingerprint != "" {
		params.Set("fp", c.Fingerprint)
	}
	if c.Insecure {
		params.Set("allowInsecure", "1")
	}
	if len(c.ALPN) > 0 {
		params.Set("alpn", strings.Join(c.ALPN, ","))
	}

	switch c.Network {
	case "ws":
		params.Set("path", c.Path)
		if c.Host != "" {
			params.Set("host", c.Host)
		}
	case "grpc":
		params.Set("serviceName", c.ServiceName)
		if c.Authority != "" {
			params.Set("authority", c.Authority)
		}
		if c.Mode != "" {
			params.Set("mode", c.Mode)
		}
	case "xhttp", "splithttp":
		params.Set("path", c.Path)
		if c.Host != "" {
			params.Set("host", c.Host)
		}
		if c.Mode != "" {
			params.Set("mode", c.Mode)
		}
	}

	remark := url.QueryEscape(c.Remark)
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", c.UUID, c.Address, c.Port, params.Encode(), remark)
}

func splitHostPort(hostPort string) (string, string, error) {
	// Handle IPv6 [addr]:port
	if strings.HasPrefix(hostPort, "[") {
		end := strings.Index(hostPort, "]")
		if end == -1 {
			return "", "", fmt.Errorf("missing ] in IPv6 address")
		}
		host := hostPort[1:end]
		if end+1 >= len(hostPort) || hostPort[end+1] != ':' {
			return "", "", fmt.Errorf("missing port after IPv6 address")
		}
		return host, hostPort[end+2:], nil
	}

	// Regular host:port
	lastColon := strings.LastIndex(hostPort, ":")
	if lastColon == -1 {
		return "", "", fmt.Errorf("missing port")
	}
	return hostPort[:lastColon], hostPort[lastColon+1:], nil
}

// recoverMissingQuerySep handles URLs where the '?' separator between port and
// query params was silently dropped (common with certain terminal paste modes).
// Input: portStr like "2053encryption=none&security=tls&sni=..."
// It extracts the leading digit run as the port and merges the rest into params.
func recoverMissingQuerySep(portStr string, params url.Values) (int, url.Values, error) {
	i := 0
	for i < len(portStr) && portStr[i] >= '0' && portStr[i] <= '9' {
		i++
	}
	if i == 0 || i == len(portStr) {
		return 0, params, fmt.Errorf("cannot recover port from %q", portStr)
	}
	port, err := strconv.Atoi(portStr[:i])
	if err != nil {
		return 0, params, err
	}
	extra, _ := url.ParseQuery(portStr[i:])
	if params == nil {
		params = make(url.Values)
	}
	for k, vs := range extra {
		if _, exists := params[k]; !exists {
			params[k] = vs
		}
	}
	return port, params, nil
}

func paramOr(params url.Values, key, fallback string) string {
	v := params.Get(key)
	if v == "" {
		return fallback
	}
	return v
}

// ParseTrojan parses a trojan:// share URL.
// Format: trojan://password@address:port?params#remark
func ParseTrojan(raw string) (*VLESSConfig, error) {
	if !strings.HasPrefix(raw, "trojan://") {
		return nil, fmt.Errorf("not a trojan:// URL")
	}

	raw = strings.TrimPrefix(raw, "trojan://")

	// Split remark
	remark := ""
	if idx := strings.LastIndex(raw, "#"); idx != -1 {
		remark = raw[idx+1:]
		raw = raw[:idx]
	}
	remark, _ = url.QueryUnescape(remark)

	// Split params
	params := url.Values{}
	if idx := strings.Index(raw, "?"); idx != -1 {
		var err error
		params, err = url.ParseQuery(raw[idx+1:])
		if err != nil {
			return nil, fmt.Errorf("parsing query params: %w", err)
		}
		raw = raw[:idx]
	}

	// Split password@address:port
	atIdx := strings.Index(raw, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("missing @ in URL")
	}
	password, _ := url.QueryUnescape(raw[:atIdx])
	hostPort := raw[atIdx+1:]

	host, portStr, err := splitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("parsing host:port %q: %w", hostPort, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port, params, err = recoverMissingQuerySep(portStr, params)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", portStr)
		}
	}

	cfg := &VLESSConfig{
		Protocol:    "trojan",
		Password:    password,
		Address:     host,
		Port:        port,
		Network:     paramOr(params, "type", "tcp"),
		Security:    paramOr(params, "security", "tls"),
		SNI:         params.Get("sni"),
		Fingerprint: paramOr(params, "fp", ""),
		Insecure:    params.Get("insecure") == "1" || params.Get("allowInsecure") == "1",
		Remark:      remark,
	}

	switch cfg.Network {
	case "ws":
		cfg.Path = paramOr(params, "path", "/")
		cfg.Host = paramOr(params, "host", cfg.SNI)
	case "grpc":
		cfg.ServiceName = params.Get("serviceName")
		cfg.Authority = params.Get("authority")
		cfg.Mode = paramOr(params, "mode", "gun")
	case "xhttp", "splithttp":
		cfg.Path = paramOr(params, "path", "/")
		cfg.Host = paramOr(params, "host", cfg.SNI)
		cfg.Mode = paramOr(params, "mode", "auto")
	}

	if alpnStr := params.Get("alpn"); alpnStr != "" {
		cfg.ALPN = strings.Split(alpnStr, ",")
	}

	return cfg, nil
}
