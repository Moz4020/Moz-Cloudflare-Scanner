package xraytest

import (
	"bytes"
	"context"
	"crypto/rand"
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
	traceProbeURL        = "http://1.1.1.1/cdn-cgi/trace"
	validationAttempts   = 3
	validationMinSuccess = 3
	connectivityTimeout  = 5 * time.Second
	transportTimeout     = 5 * time.Second
	uploadTimeout        = 4 * time.Second
)

var uploadProbeURL = "https://speed.cloudflare.com/__up"

// UploadProbeBytes is the standard payload used for one opt-in upload sample.
// It is intentionally small: the result is a route-quality signal, not a
// full internet speed test.
const UploadProbeBytes int64 = 64 * 1024

// UploadProbeBytes128 is the larger optional payload for users who want a
// steadier measurement on faster routes.
const UploadProbeBytes128 int64 = 128 * 1024

// MaxUploadProbeBytes is the largest payload accepted by one upload sample.
const MaxUploadProbeBytes int64 = UploadProbeBytes128

// UploadBudgetBytes is the maximum upload payload reserved by one Phase 2
// scan. The UI can run the probe on many candidates without consuming an
// unbounded amount of the user's connection.
const UploadBudgetBytes int64 = 4 * 1024 * 1024

// UploadBudgetBytes128 is the scan-wide cap used with the 128 KiB sample.
const UploadBudgetBytes128 int64 = 8 * 1024 * 1024

// UploadBudgetForBytes returns the scan-wide upload budget for a selected
// sample size. Zero disables the upload probe.
func UploadBudgetForBytes(payloadBytes int64) int64 {
	switch {
	case payloadBytes >= UploadProbeBytes128:
		return UploadBudgetBytes128
	case payloadBytes > 0:
		return UploadBudgetBytes
	default:
		return 0
	}
}

func init() {
	portCounter.Store(20000)
}

// nextPort returns the next available port for testing.
func nextPort() int {
	return int(portCounter.Add(1))
}

// ValidationResult holds the outcome of testing a VLESS config through xray.
type ValidationResult struct {
	IP            string
	Port          int
	Success       bool
	Latency       time.Duration // median successful time to first byte
	Error         string
	Transport     string // xhttp
	Attempts      int
	Successes     int
	Retries       int           // compatibility: failed attempts before enough successes
	Phase1Latency time.Duration // physical RTT from Phase 1
	UploadTested  bool          // true when the opt-in upload sample was attempted
	UploadBytes   int64         // payload size reserved for the upload sample
	UploadKbps    float64       // measured upload throughput, 0 if unavailable
	UploadError   string        // upload-only error; does not invalidate Xray success
}

// ValidationOptions controls optional quality measurements performed while
// the Xray session is already running. UploadBytes=0 leaves the upload probe
// disabled.
type ValidationOptions struct {
	UploadBytes  int64
	BeforeUpload func() bool // optional reservation; false skips without sending data
}

// ValidateConfig validates an XHTTP endpoint with repeated xray-confirmed
// trace checks. An endpoint is working only after 3 of 3 successes.
func ValidateConfig(ctx context.Context, cfg *VLESSConfig, timeout time.Duration) *ValidationResult {
	return ValidateConfigWithOptions(ctx, cfg, timeout, ValidationOptions{})
}

// ValidateConfigWithOptions validates a config and may perform one bounded
// upload sample through the same Xray session after all trace checks pass.
// Upload measurement is deliberately a quality metric, not part of the
// strict 3/3 validation gate.
func ValidateConfigWithOptions(ctx context.Context, cfg *VLESSConfig, timeout time.Duration, options ValidationOptions) *ValidationResult {
	res := &ValidationResult{
		IP:        cfg.Address,
		Port:      cfg.Port,
		Transport: cfg.Network,
		Attempts:  validationAttempts,
	}

	if timeout <= 0 {
		timeout = connectivityTimeout
	}

	// Starting Xray is much more expensive than issuing another request through
	// an already-running instance. Keep one instance alive for all attempts for
	// this candidate and close it once validation is complete.
	session, err := startSession(ctx, cfg, minDuration(timeout, 3*time.Second))
	if err != nil {
		res.Error = err.Error()
		res.Attempts = 0
		return res
	}
	defer session.Close()

	var latencies []time.Duration
	var lastErr string
	attempts := 0
	for attempt := 0; attempt < validationAttempts; attempt++ {
		if ctx.Err() != nil {
			lastErr = ctx.Err().Error()
			break
		}
		attempts++

		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		ok, latency, err := proxyConnectivityCheck(attemptCtx, session.proxyURL, session.client)
		cancel()

		if ok {
			res.Successes++
			if latency > 0 {
				latencies = append(latencies, latency)
			}
		} else {
			if err != nil {
				lastErr = err.Error()
			}
			break // Break early because a single failure means we can't reach 3/3 successes!
		}
	}

	res.Attempts = attempts
	res.Retries = maxInt(res.Attempts-1, 0)
	res.Success = res.Successes >= validationMinSuccess
	res.Latency = medianDuration(latencies)
	if res.Success && options.UploadBytes > 0 && ctx.Err() == nil &&
		(options.BeforeUpload == nil || options.BeforeUpload()) {
		bytesToSend := minInt64(options.UploadBytes, MaxUploadProbeBytes)
		res.UploadBytes = bytesToSend
		res.UploadTested = true
		uploadCtx, cancel := context.WithTimeout(ctx, minDuration(timeout, uploadTimeout))
		res.UploadKbps, err = proxyUploadSpeed(uploadCtx, session.proxyURL, session.client, bytesToSend)
		if err != nil {
			res.UploadError = err.Error()
		}
		cancel()
	}
	if !res.Success {
		if lastErr == "" {
			lastErr = fmt.Sprintf("only %d/%d xhttp checks passed", res.Successes, validationAttempts)
		}
		res.Error = lastErr
	}
	return res
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

type validationSession struct {
	instance *xcore.Instance
	proxyURL string
	client   *http.Client
}

func (s *validationSession) Close() {
	if s == nil || s.instance == nil {
		return
	}
	if s.client != nil {
		if transport, ok := s.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	_ = s.instance.Close()
}

func startSession(ctx context.Context, cfg *VLESSConfig, timeout time.Duration) (*validationSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	socksPort := nextPort()

	configJSON, err := BuildXrayConfig(cfg, socksPort)
	if err != nil {
		return nil, fmt.Errorf("build config: %v", err)
	}

	// Decode straight from memory — no temp file. Avoids ~5 syscalls and a disk
	// round-trip per candidate, which dominates Phase 2 cost on slow disks/VPS.
	jsonConfig, err := serial.DecodeJSONConfig(bytes.NewReader(configJSON))
	if err != nil {
		return nil, fmt.Errorf("decode json config: %v", err)
	}

	pbConfig, err := jsonConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("build config: %v", err)
	}

	instance, err := xcore.New(pbConfig)
	if err != nil {
		return nil, fmt.Errorf("create instance: %v", err)
	}

	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, fmt.Errorf("start xray: %v", err)
	}

	startupTimeout := minDuration(timeout, 3*time.Second)
	if !waitForPort(ctx, socksPort, startupTimeout) {
		_ = instance.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("socks port not ready after %s", startupTimeout)
	}

	proxyURL := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
	return &validationSession{
		instance: instance,
		proxyURL: proxyURL,
		client: &http.Client{
			Transport: proxyTransport(proxyURL, minDuration(timeout, transportTimeout)),
		},
	}, nil
}

// proxyConnectivityCheck performs a lightweight GET /cdn-cgi/trace through the
// SOCKS5 proxy to 1.1.1.1. It returns true when the response body
// contains "colo=", proving that real Cloudflare traffic flowed through the proxy.
func proxyConnectivityCheck(ctx context.Context, proxyAddr string, client *http.Client) (bool, time.Duration, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, connectivityTimeout)
		defer cancel()
	}
	if client == nil {
		clientTimeout := minDuration(clientTimeoutForContext(ctx, connectivityTimeout), connectivityTimeout)
		client = &http.Client{
			Transport: proxyTransport(proxyAddr, minDuration(clientTimeout, transportTimeout)),
			Timeout:   clientTimeout,
		}
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

// proxyUploadSpeed sends one non-compressible, bounded payload through the
// candidate's proxy. WroteRequest is used so server response processing does
// not distort the upload measurement.
func proxyUploadSpeed(ctx context.Context, proxyAddr string, client *http.Client, payloadBytes int64) (float64, error) {
	if payloadBytes <= 0 {
		return 0, fmt.Errorf("upload payload is empty")
	}
	if payloadBytes > MaxUploadProbeBytes {
		payloadBytes = MaxUploadProbeBytes
	}
	if client == nil {
		clientTimeout := minDuration(clientTimeoutForContext(ctx, uploadTimeout), uploadTimeout)
		client = &http.Client{
			Transport: proxyTransport(proxyAddr, minDuration(clientTimeout, transportTimeout)),
			Timeout:   clientTimeout,
		}
	}

	payload := make([]byte, payloadBytes)
	if _, err := rand.Read(payload); err != nil {
		return 0, fmt.Errorf("create upload payload: %v", err)
	}

	start := time.Now()
	writeFinished := time.Time{}
	trace := &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil && writeFinished.IsZero() {
				writeFinished = time.Now()
			}
		},
	}
	traceCtx := httptrace.WithClientTrace(ctx, trace)
	req, err := http.NewRequestWithContext(traceCtx, http.MethodPost, uploadProbeURL, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", "moz-cloudflare-scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("upload HTTP %d", resp.StatusCode)
	}

	duration := time.Since(start)
	if !writeFinished.IsZero() {
		duration = writeFinished.Sub(start)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("upload completed too quickly to measure")
	}
	return float64(len(payload)) / duration.Seconds() / 1024, nil
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
func waitForPort(ctx context.Context, port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		remaining := time.Until(deadline)
		attemptTimeout := minDuration(remaining, 200*time.Millisecond)
		dialCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		cancel()
		if err == nil {
			conn.Close()
			return true
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return false
		case <-timer.C:
		}
	}
	return false
}
