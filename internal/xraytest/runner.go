package xraytest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all" // register all xray features
)

var portCounter atomic.Int32

const (
	traceProbeURL        = "https://cp.cloudflare.com/cdn-cgi/trace"
	connectivityTimeout  = 5 * time.Second
	transportTimeout     = 3 * time.Second
)

func init() {
	portCounter.Store(20000)
}

// nextPort returns the next available port for testing.
func nextPort() int {
	return int(portCounter.Add(1))
}

// ValidationResult holds the outcome of testing a VLESS config through xray.
type ValidationResult struct {
	IP         string
	Port       int
	Success    bool
	Latency    time.Duration // time to first byte
	Throughput float64       // bytes/sec for download test
	BytesRecv  int64
	Error      string
	Transport  string // ws, grpc, xhttp
	Retries    int    // how many attempts were needed
}

// ValidateConfig starts an xray instance with the given config, sends test
// traffic through it, and returns the result. Retries once on failure.
func ValidateConfig(ctx context.Context, cfg *VLESSConfig, timeout time.Duration) *ValidationResult {
	res := validateOnce(ctx, cfg, timeout)
	if !res.Success && shouldRetryValidation(ctx, res.Error) {
		// Retry once — DPI is flaky
		time.Sleep(500 * time.Millisecond)
		res2 := validateOnce(ctx, cfg, timeout)
		res2.Retries = 1
		if res2.Success {
			return res2
		}
		res.Retries = 1
	}
	return res
}

func shouldRetryValidation(ctx context.Context, errText string) bool {
	if ctx.Err() != nil {
		return false
	}
	errText = strings.ToLower(errText)
	if errText == "" {
		return true
	}
	noRetry := []string{
		"build config",
		"decode json",
		"start xray",
		"tls handshake timeout",
		"context deadline exceeded",
		"i/o timeout",
	}
	for _, needle := range noRetry {
		if strings.Contains(errText, needle) {
			return false
		}
	}
	return true
}

func validateOnce(ctx context.Context, cfg *VLESSConfig, timeout time.Duration) *ValidationResult {
	res := &ValidationResult{
		IP:        cfg.Address,
		Port:      cfg.Port,
		Transport: cfg.Network,
	}

	socksPort := nextPort()

	configJSON, err := BuildXrayConfig(cfg, socksPort)
	if err != nil {
		res.Error = fmt.Sprintf("build config: %v", err)
		return res
	}

	tmpFile, err := os.CreateTemp("", "xray-test-*.json")
	if err != nil {
		res.Error = fmt.Sprintf("create temp file: %v", err)
		return res
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(configJSON); err != nil {
		tmpFile.Close()
		res.Error = fmt.Sprintf("write config: %v", err)
		return res
	}
	tmpFile.Close()

	tmpFile2, err := os.Open(tmpFile.Name())
	if err != nil {
		res.Error = fmt.Sprintf("reopen config: %v", err)
		return res
	}

	jsonConfig, err := serial.DecodeJSONConfig(tmpFile2)
	tmpFile2.Close()
	if err != nil {
		res.Error = fmt.Sprintf("decode json config: %v", err)
		return res
	}

	pbConfig, err := jsonConfig.Build()
	if err != nil {
		res.Error = fmt.Sprintf("build config: %v", err)
		return res
	}

	instance, err := xcore.New(pbConfig)
	if err != nil {
		res.Error = fmt.Sprintf("create instance: %v", err)
		return res
	}

	if err := instance.Start(); err != nil {
		res.Error = fmt.Sprintf("start xray: %v", err)
		return res
	}
	defer instance.Close()

	if !waitForPort(socksPort, 3*time.Second) {
		res.Error = "socks port not ready after 3s"
		return res
	}

	proxyURL := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)

	testCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Step 1: lightweight connectivity check and true TTFB latency.
	traceOk, latency, traceErr := proxyConnectivityCheck(testCtx, proxyURL)
	res.Latency = latency
	if !traceOk {
		res.Error = fmt.Sprintf("connectivity: %v", traceErr)
		return res
	}

	res.Success = true
	return res
}

// proxyConnectivityCheck performs a lightweight GET /cdn-cgi/trace through the
// SOCKS5 proxy to cp.cloudflare.com. It returns true when the response body
// contains "colo=", proving that real Cloudflare traffic flowed through the proxy.
func proxyConnectivityCheck(ctx context.Context, proxyAddr string) (bool, time.Duration, error) {
	clientTimeout := minDuration(clientTimeoutForContext(ctx, connectivityTimeout), connectivityTimeout)
	transport := proxyTransport(proxyAddr, minDuration(clientTimeout, transportTimeout))
	client := &http.Client{
		Transport: transport,
		Timeout:   clientTimeout,
	}

	start := time.Now()
	var latency time.Duration
	gotFirst := false
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			if !gotFirst {
				latency = time.Since(start)
				gotFirst = true
			}
		},
	}
	traceCtx := httptrace.WithClientTrace(ctx, trace)

	req, err := http.NewRequestWithContext(traceCtx, http.MethodGet, traceProbeURL, nil)
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("User-Agent", "moz-cloudflare-scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return false, latency, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, latency, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if !strings.Contains(string(body), "colo=") {
		return false, latency, fmt.Errorf("no colo in trace response")
	}
	if !gotFirst {
		latency = time.Since(start)
	}
	return true, latency, nil
}

func proxyTransport(proxyAddr string, timeout time.Duration) *http.Transport {
	if timeout <= 0 {
		timeout = transportTimeout
	}
	return &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(proxyAddr)
		},
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
}

func clientTimeoutForContext(ctx context.Context, fallback time.Duration) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fallback
	}
	if remaining := time.Until(deadline); remaining > 0 {
		return remaining
	}
	return fallback
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// waitForPort waits until a TCP port is accepting connections.
func waitForPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
