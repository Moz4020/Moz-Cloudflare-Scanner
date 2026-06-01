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
	"sync"
	"sync/atomic"
	"time"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all" // register all xray features
)

var portCounter atomic.Int32

const (
	speedSampleBytes     = 512 * 1024
	speedSampleBytesFast = 64 * 1024
	speedMinBytes        = 8 * 1024
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

	// Step 2: best-effort download speed (does not affect Success).
	speedCtx, speedCancel := context.WithTimeout(testCtx, speedBudget(timeout, latency))
	defer speedCancel()
	bytesRecv, throughput := measureProxySpeed(speedCtx, proxyURL, cfg)
	res.BytesRecv = bytesRecv
	res.Throughput = throughput
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

type speedTarget struct {
	url      string
	relaxed  bool
	minBytes int64
}

func speedBudget(total, spent time.Duration) time.Duration {
	budget := total / 2
	if budget < 8*time.Second {
		budget = 8 * time.Second
	}
	remaining := total - spent
	if remaining < budget {
		budget = remaining
	}
	if budget < 2*time.Second {
		return 2 * time.Second
	}
	return budget
}

func measureProxySpeed(ctx context.Context, proxyAddr string, cfg *VLESSConfig) (int64, float64) {
	samples := []int64{speedSampleBytesFast, speedSampleBytes}
	for _, sample := range samples {
		for _, target := range speedTestTargets(cfg, sample) {
			bytesRecv, throughput, err := downloadThroughProxy(ctx, proxyAddr, target.url, sample, target.relaxed)
			if err == nil && bytesRecv >= target.minBytes && throughput > 0 {
				return bytesRecv, throughput
			}
		}
	}

	// WS/xhttp tunnels often block speed.cloudflare.com but still carry trace traffic.
	// Estimate throughput by saturating the known-good trace endpoint in parallel.
	return burstProxyThroughput(ctx, proxyAddr, traceProbeURL, speedSampleBytesFast)
}

func speedTestTargets(cfg *VLESSConfig, sampleBytes int64) []speedTarget {
	minBytes := int64(speedMinBytes)
	if sampleBytes < minBytes {
		minBytes = sampleBytes / 2
	}
	if minBytes < 4096 {
		minBytes = 4096
	}

	var targets []speedTarget
	add := func(rawURL string, relaxed bool) {
		if rawURL == "" {
			return
		}
		targets = append(targets, speedTarget{
			url:      rawURL,
			relaxed:  relaxed,
			minBytes: minBytes,
		})
	}

	if cfg != nil {
		host := cfg.Host
		if host == "" {
			host = cfg.SNI
		}
		if host != "" {
			paths := []string{"/"}
			if cfg.Path != "" {
				paths = append([]string{cfg.Path}, paths...)
			}
			seen := make(map[string]struct{})
			for _, path := range paths {
				if !strings.HasPrefix(path, "/") {
					path = "/" + path
				}
				u := "https://" + host + path
				if _, ok := seen[u]; ok {
					continue
				}
				seen[u] = struct{}{}
				add(u, true)
			}
		}
	}

	add(fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", sampleBytes), false)
	add("https://www.cloudflare.com/", true)
	return targets
}

func burstProxyThroughput(ctx context.Context, proxyAddr, url string, targetBytes int64) (int64, float64) {
	if targetBytes <= 0 {
		return 0, 0
	}

	start := time.Now()
	var total int64
	const workers = 8

	for total < targetBytes && ctx.Err() == nil {
		var wg sync.WaitGroup
		var batch int64
		var mu sync.Mutex

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, _, err := downloadThroughProxy(ctx, proxyAddr, url, 16384, true)
				if err != nil || n <= 0 {
					return
				}
				mu.Lock()
				batch += n
				mu.Unlock()
			}()
		}
		wg.Wait()
		if batch == 0 {
			break
		}
		total += batch
	}

	elapsed := time.Since(start).Seconds()
	if total < 4096 || elapsed <= 0 {
		return total, 0
	}
	return total, float64(total) / elapsed
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

// downloadThroughProxy fetches a URL through a SOCKS5 proxy and returns bytes
// received plus throughput in bytes/sec. When relaxed is true, any HTTP response
// with a readable body counts (needed for WS endpoints that answer 400/404).
func downloadThroughProxy(ctx context.Context, proxyAddr, dlURL string, maxBytes int64, relaxed bool) (int64, float64, error) {
	if maxBytes <= 0 {
		return 0, 0, fmt.Errorf("invalid maxBytes %d", maxBytes)
	}

	client := &http.Client{
		Transport: proxyTransport(proxyAddr, transportTimeout),
		Timeout:   minDuration(clientTimeoutForContext(ctx, 8*time.Second), 8*time.Second),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
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

	if !relaxed && (resp.StatusCode < 200 || resp.StatusCode >= 400) {
		return 0, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if relaxed && resp.StatusCode >= 500 {
		return 0, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBytes))
	elapsed := time.Since(start).Seconds()
	if err != nil || n <= 0 || elapsed <= 0 {
		return n, 0, err
	}
	return n, float64(n) / elapsed, nil
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
