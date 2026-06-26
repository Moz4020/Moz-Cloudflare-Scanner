package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/moz/moz-cloudflare-scanner/internal/result"
)

// sniHostnames is a list of well-known Cloudflare hostnames used as SNI values.
// Rotating SNI reduces the chance of deep-packet inspection blackholing.
var sniHostnames = []string{
	"speed.cloudflare.com",
	"www.cloudflare.com",
	"cloudflare.com",
	"1.1.1.1.cdn.cloudflare.net",
	"blog.cloudflare.com",
}

// Config holds parameters for a single probe session.
type Config struct {
	Port               int
	Mode               Mode
	Tries              int
	Timeout            time.Duration
	SNI                string // empty = rotate automatically
	SpeedBytes         int64  // optional HTTP download sample size; 0 disables it
	InsecureSkipVerify bool   // skip TLS cert verification (use for Phase 1 where Phase 2 validates properly)
	AcceptCFHTTPError  bool   // accept any Cloudflare HTTP response when xray will validate next
}

// WithPort returns a copy of Config targeting another remote port.
func (c Config) WithPort(port int) Config {
	c.Port = port
	return c
}

// Mode selects the probe type.
type Mode int

const (
	ModeTCP  Mode = iota // bare TCP connect
	ModeTLS              // TLS handshake (no HTTP)
	ModeHTTP             // full HTTPS GET /cdn-cgi/trace
)

func (m Mode) String() string {
	switch m {
	case ModeTLS:
		return "tls"
	case ModeHTTP:
		return "http"
	default:
		return "tcp"
	}
}

// ParseMode parses a mode string.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(s) {
	case "tcp":
		return ModeTCP, nil
	case "tls":
		return ModeTLS, nil
	case "http", "https":
		return ModeHTTP, nil
	default:
		return ModeTCP, fmt.Errorf("unknown mode %q (want tcp|tls|http)", s)
	}
}

// Probe runs a full measurement session against ip and returns a Result.
func Probe(ctx context.Context, ip net.IP, cfg Config) *result.Result {
	r := &result.Result{
		IP:        ip,
		Port:      cfg.Port,
		ProbeMode: cfg.Mode.String(),
		Timestamp: time.Now(),
		Latencies: make([]time.Duration, cfg.Tries),
		AcceptCF:  cfg.AcceptCFHTTPError,
	}
	if cfg.Mode == ModeHTTP && cfg.SpeedBytes > 0 {
		r.SpeedTested = true
	}

	for i := 0; i < cfg.Tries; i++ {
		if ctx.Err() != nil {
			break
		}
		sni := cfg.SNI
		if sni == "" && cfg.Mode == ModeHTTP {
			sni = "speed.cloudflare.com"
		} else if sni == "" {
			sni = sniHostnames[rand.Intn(len(sniHostnames))]
		}

		var lat time.Duration
		var tlsOk bool
		var httpStatus int
		var colo string
		var throughput float64

		switch cfg.Mode {
		case ModeTCP:
			lat = probeTCP(ctx, ip, cfg.Port, cfg.Timeout)
		case ModeTLS:
			lat, tlsOk = probeTLS(ctx, ip, cfg.Port, sni, cfg.Timeout, cfg.InsecureSkipVerify)
		case ModeHTTP:
			lat, tlsOk, httpStatus, colo, throughput = probeHTTP(ctx, ip, cfg.Port, sni, cfg.Timeout, cfg.SpeedBytes, cfg.InsecureSkipVerify)
		}

		r.Latencies[i] = lat
		if tlsOk {
			r.TLSOk = true
		}
		if httpStatus != 0 {
			r.HTTPStatus = httpStatus
		}
		if colo != "" {
			r.Colo = colo
		}
		if throughput > 0 {
			r.Throughput = throughput
		}

		// Small jitter between tries to avoid looking like a scanner
		if i < cfg.Tries-1 {
			jitter := time.Duration(rand.Intn(50)+10) * time.Millisecond
			select {
			case <-ctx.Done():
			case <-time.After(jitter):
			}
		}
	}

	return r
}

// probeTCP measures a raw TCP connect time.
func probeTCP(ctx context.Context, ip net.IP, port int, timeout time.Duration) time.Duration {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	dl := time.Now().Add(timeout)
	dialCtx, cancel := context.WithDeadline(ctx, dl)
	defer cancel()

	d := net.Dialer{}
	start := time.Now()
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return 0
	}
	lat := time.Since(start)
	setLingerZero(conn)
	conn.Close()
	return lat
}

// probeTLS measures a TLS handshake time.
func probeTLS(ctx context.Context, ip net.IP, port int, sni string, timeout time.Duration, insecure bool) (time.Duration, bool) {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	dl := time.Now().Add(timeout)
	dialCtx, cancel := context.WithDeadline(ctx, dl)
	defer cancel()

	d := tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		},
	}

	start := time.Now()
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return 0, false
	}
	lat := time.Since(start)
	setLingerZero(conn)
	conn.Close()
	return lat, true
}

// probeHTTP fetches /cdn-cgi/trace to confirm the IP is a real Cloudflare edge
// and to determine the colo identifier.
func probeHTTP(ctx context.Context, ip net.IP, port int, sni string, timeout time.Duration, speedBytes int64, insecure bool) (
	lat time.Duration, tlsOk bool, httpStatus int, colo string, throughput float64,
) {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	// Budget split: TCP gets ¼, TLS gets ½, leaving ¼ guaranteed for the HTTP
	// GET+response. Without this, on DPI-throttled networks the TLS handshake
	// can silently consume the entire http.Client.Timeout, making the HTTP
	// phase impossible and producing false-positive packet loss.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{Timeout: timeout / 4}).DialContext(ctx, network, addr)
			if err == nil {
				setLingerZero(conn)
			}
			return conn, err
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecure,
		},
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: timeout / 2,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	scheme := "https"
	if port == 80 {
		scheme = "http"
	}
	url := fmt.Sprintf("%s://%s/cdn-cgi/trace", scheme, sni)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "moz-cloudflare-scanner/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, 0, "", 0
	}
	lat = time.Since(start)
	defer resp.Body.Close()

	tlsOk = resp.TLS != nil
	httpStatus = resp.StatusCode
	colo = parseColoRay(resp.Header.Get("CF-Ray"))

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if traceColo := parseColoCDN(string(body)); traceColo != "" {
		colo = traceColo
	}

	if httpStatus >= 200 && httpStatus < 400 && colo != "" && speedBytes > 0 {
		throughput = probeDownload(ctx, ip, port, timeout, speedBytes)
	}

	return
}

// probeDownload fetches a small sample from speed.cloudflare.com while forcing
// the TCP connection to the candidate IP. This is still not a full Xray/V2Ray
// test, but it catches many IPs that handshake cleanly and then stall on data.
func probeDownload(ctx context.Context, ip net.IP, port int, timeout time.Duration, bytes int64) float64 {
	if bytes <= 0 {
		return 0
	}

	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{Timeout: timeout / 4}).DialContext(ctx, network, addr)
			if err == nil {
				setLingerZero(conn)
			}
			return conn, err
		},
		TLSClientConfig: &tls.Config{
			ServerName: "speed.cloudflare.com",
			MinVersion: tls.VersionTLS12,
		},
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: timeout / 2,
	}
	client := &http.Client{Timeout: timeout, Transport: transport}

	scheme := "https"
	if port == 80 {
		scheme = "http"
	}
	url := fmt.Sprintf("%s://speed.cloudflare.com/__down?bytes=%d", scheme, bytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "moz-cloudflare-scanner/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0
	}

	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, bytes))
	if err != nil || n <= 0 {
		return 0
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(n) / elapsed
}

// parseColoCDN extracts the "colo" field from /cdn-cgi/trace responses.
func parseColoCDN(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "colo=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "colo="))
		}
	}
	return ""
}

func parseColoRay(ray string) string {
	parts := strings.Split(ray, "-")
	if len(parts) < 2 {
		return ""
	}
	colo := strings.TrimSpace(parts[len(parts)-1])
	if len(colo) < 3 {
		return ""
	}
	return strings.ToUpper(colo[:3])
}

func setLingerZero(conn net.Conn) {
	if conn == nil {
		return
	}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
}
