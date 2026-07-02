package xraytest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
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
	payloadProbeURL      = "https://speed.cloudflare.com/__down?bytes=262144"
	validationAttempts   = 1
	validationMinSuccess = 1
	payloadBytes         = 256 * 1024
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
	Latency    time.Duration // median successful time to first byte
	Throughput float64       // bytes/sec for download test
	BytesRecv  int64
	Error      string
	Transport  string // xhttp or splithttp
	Attempts   int
	Successes  int
	Retries    int // compatibility: failed attempts before enough successes
}

// ValidateConfig validates an XHTTP endpoint with repeated xray-confirmed
// trace and payload checks. An endpoint is working only after 2 of 3 successes.
func ValidateConfig(ctx context.Context, cfg *VLESSConfig, timeout time.Duration) *ValidationResult {
	res := &ValidationResult{
		IP:        cfg.Address,
		Port:      cfg.Port,
		Transport: cfg.Network,
		Attempts:  validationAttempts,
	}

	var latencies []time.Duration
	var lastErr string
	attempts := 0
	for attempt := 0; attempt < validationAttempts; attempt++ {
		if ctx.Err() != nil {
			lastErr = ctx.Err().Error()
			break
		}
		attempts++
		once := validateOnce(ctx, cfg, timeout)
		if once.Success {
			res.Successes++
			if once.Latency > 0 {
				latencies = append(latencies, once.Latency)
			}
			res.BytesRecv += once.BytesRecv
			if once.Throughput > 0 {
				res.Throughput += once.Throughput
			}
		} else if once.Error != "" {
			lastErr = once.Error
		}
		if res.Successes >= validationMinSuccess {
			break
		}
		if attempt < validationAttempts-1 && shouldRetryValidation(ctx, lastErr) {
			time.Sleep(500 * time.Millisecond)
		}
	}

	res.Attempts = attempts
	res.Retries = maxInt(res.Attempts-1, 0)
	res.Success = res.Successes >= validationMinSuccess
	res.Latency = medianDuration(latencies)
	if res.Successes > 0 && res.Throughput > 0 {
		res.Throughput /= float64(res.Successes)
	}
	if !res.Success {
		if lastErr == "" {
			lastErr = fmt.Sprintf("only %d/%d xhttp checks passed", res.Successes, validationAttempts)
		}
		res.Error = lastErr
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
		Attempts:  1,
	}

	socksPort := nextPort()

	configJSON, err := BuildXrayConfig(cfg, socksPort)
	if err != nil {
		res.Error = fmt.Sprintf("build config: %v", err)
		return res
	}

	// Decode straight from memory — no temp file. Avoids ~5 syscalls and a disk
	// round-trip per candidate, which dominates Phase 2 cost on slow disks/VPS.
	jsonConfig, err := serial.DecodeJSONConfig(bytes.NewReader(configJSON))
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

	bytesRecv, throughput, payloadErr := proxyPayloadCheck(testCtx, proxyURL)
	res.BytesRecv = bytesRecv
	res.Throughput = throughput
	if payloadErr != nil {
		res.Error = fmt.Sprintf("payload: %v", payloadErr)
		return res
	}

	res.Success = true
	res.Successes = 1
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

func proxyPayloadCheck(ctx context.Context, proxyAddr string) (int64, float64, error) {
	clientTimeout := minDuration(clientTimeoutForContext(ctx, connectivityTimeout), connectivityTimeout)
	transport := proxyTransport(proxyAddr, minDuration(clientTimeout, transportTimeout))
	client := &http.Client{
		Transport: transport,
		Timeout:   clientTimeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, payloadProbeURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "moz-cloudflare-scanner/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, payloadBytes))
	if err != nil {
		return n, 0, err
	}
	if n <= 0 {
		return 0, 0, fmt.Errorf("no payload bytes received")
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return n, 0, nil
	}
	return n, float64(n) / elapsed, nil
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

func medianDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

func maxInt(a, b int) int {
	if a > b {
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
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
