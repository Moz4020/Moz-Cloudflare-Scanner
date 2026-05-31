package xraytest

import (
	"strings"
	"testing"
	"time"
)

func TestSpeedTestTargetsPreferConfigHost(t *testing.T) {
	cfg := &VLESSConfig{
		Network: "ws",
		Host:    "worker.example.dev",
		Path:    "/ws-path",
		SNI:     "worker.example.dev",
	}
	targets := speedTestTargets(cfg, speedSampleBytes)

	if len(targets) < 3 {
		t.Fatalf("targets = %d, want at least 3", len(targets))
	}
	if !targets[0].relaxed || targets[0].url != "https://worker.example.dev/ws-path" {
		t.Fatalf("first target = %+v", targets[0])
	}
	if !strings.HasPrefix(targets[len(targets)-2].url, "https://speed.cloudflare.com/__down?bytes=") {
		t.Fatalf("speed URL missing, got %+v", targets)
	}
}

func TestSpeedBudgetReservesTimeForSpeedTest(t *testing.T) {
	got := speedBudget(20*time.Second, 900*time.Millisecond)
	if got < 8*time.Second {
		t.Fatalf("budget = %s, want at least 8s", got)
	}
}

func TestBurstProxyThroughputRequiresMinimumBytes(t *testing.T) {
	// No server here — just ensure helper handles empty work gracefully.
	bytes, tp := burstProxyThroughput(t.Context(), "socks5://127.0.0.1:1", traceProbeURL, speedSampleBytesFast)
	if bytes != 0 || tp != 0 {
		t.Fatalf("expected zero result on unreachable proxy, got bytes=%d tp=%f", bytes, tp)
	}
}
