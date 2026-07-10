package xraytest

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// VLESSConfig holds parsed parameters from a VLESS XHTTP share URL.
type VLESSConfig struct {
	Protocol string

	UUID       string
	Encryption string
	Flow       string

	// Common
	Address string
	Port    int

	// XHTTP transport
	Network    string // xhttp
	Path       string
	Host       string
	Mode       string
	XHTTPExtra map[string]interface{}

	// TLS
	Security    string // tls, reality, none
	SNI         string
	Fingerprint string
	ALPN        []string
	Insecure    bool

	// Metadata
	Remark string
}

// ParseProxyURL parses a VLESS XHTTP share URL.
func ParseProxyURL(raw string) (*VLESSConfig, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "vless://") {
		return nil, fmt.Errorf("unsupported URL scheme — this scanner accepts only vless:// XHTTP configs")
	}
	return ParseVLESS(raw)
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
		Network:     paramOr(params, "type", ""),
		Security:    paramOr(params, "security", "none"),
		SNI:         params.Get("sni"),
		Fingerprint: paramOr(params, "fp", ""),
		Insecure:    params.Get("insecure") == "1" || params.Get("allowInsecure") == "1",
		Remark:      remark,
	}

	switch cfg.Network {
	case "xhttp":
		cfg.Path = paramOr(params, "path", "/")
		cfg.Host = paramOr(params, "host", cfg.SNI)
		cfg.Mode = paramOr(params, "mode", "auto")
		cfg.XHTTPExtra, err = parseXHTTPExtra(params)
		if err != nil {
			return nil, err
		}
	case "":
		return nil, fmt.Errorf("unsupported transport: missing type=xhttp")
	default:
		return nil, fmt.Errorf("unsupported transport %q — this scanner accepts only xhttp", cfg.Network)
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
	if c.Flow != "" {
		params.Set("flow", c.Flow)
	}

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

	params.Set("path", c.Path)
	if c.Host != "" {
		params.Set("host", c.Host)
	}
	if c.Mode != "" {
		params.Set("mode", c.Mode)
	}
	if len(c.XHTTPExtra) > 0 {
		if extra, err := json.Marshal(c.XHTTPExtra); err == nil {
			params.Set("extra", string(extra))
		}
	}

	remark := url.PathEscape(c.Remark)
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

func parseXHTTPExtra(params url.Values) (map[string]interface{}, error) {
	raw := strings.TrimSpace(params.Get("extra"))
	if raw == "" {
		return nil, nil
	}

	var extra map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &extra); err != nil {
		return nil, fmt.Errorf("parsing xhttp extra JSON: %w", err)
	}
	if len(extra) == 0 {
		return nil, nil
	}
	return extra, nil
}
