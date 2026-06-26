package xraytest

import (
	"strings"
	"testing"
)

func TestParseVLESSXHTTP(t *testing.T) {
	raw := "vless://abcdef12-3456-7890-abcd-ef1234567890@example.com:443?encryption=none&security=tls&sni=example.com&fp=chrome&alpn=h2%2Chttp%2F1.1&insecure=1&allowInsecure=1&type=xhttp&host=example.com&path=%2Fdownload&mode=auto#CF-XHTTP"
	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network != "xhttp" {
		t.Fatalf("network = %q, want xhttp", cfg.Network)
	}
	if cfg.Host != "example.com" || cfg.Path != "/download" {
		t.Fatalf("host/path = %q %q", cfg.Host, cfg.Path)
	}
	if cfg.Mode != "auto" {
		t.Fatalf("mode = %q, want auto", cfg.Mode)
	}
	rebuilt := cfg.ToShareURL()
	if !strings.Contains(rebuilt, "type=xhttp") {
		t.Fatalf("rebuilt URL missing xhttp type: %s", rebuilt)
	}
}

func TestParseVLESSSplitHTTP(t *testing.T) {
	raw := "vless://abcdef12-3456-7890-abcd-ef1234567890@example.com:443?encryption=none&security=tls&sni=example.com&type=splithttp&path=%2Fdownload&host=example.com#test"
	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network != "splithttp" {
		t.Fatalf("network = %q, want splithttp", cfg.Network)
	}
}

func TestParseProxyURLRejectsUnsupportedSchemes(t *testing.T) {
	cases := []string{
		"",
		"trojan://something",
		"vmess://something",
	}
	for _, raw := range cases {
		if _, err := ParseProxyURL(raw); err == nil {
			t.Fatalf("expected error for %q", raw)
		}
	}
}

func TestParseVLESSRejectsUnsupportedTransport(t *testing.T) {
	raw := "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&type=ws&path=%2Fdownload&host=example.com#test"
	if _, err := ParseVLESS(raw); err == nil {
		t.Fatal("expected ws transport to be rejected")
	}
	raw = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&type=grpc&serviceName=download#test"
	if _, err := ParseVLESS(raw); err == nil {
		t.Fatal("expected grpc transport to be rejected")
	}
	raw = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls#test"
	if _, err := ParseVLESS(raw); err == nil {
		t.Fatal("expected missing transport to be rejected")
	}
}

func TestParseVLESSInvalid(t *testing.T) {
	cases := []string{
		"vless://no-at-sign",
		"vless://uuid@host-no-port",
	}
	for _, raw := range cases {
		if _, err := ParseVLESS(raw); err == nil {
			t.Fatalf("expected error for %q", raw)
		}
	}
}

func TestToShareURLRemarkUsesPercentSpaces(t *testing.T) {
	raw := "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&sni=example.com&type=xhttp&path=%2Fdownload&host=example.com#Moz%20Fast%201"
	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Remark = "Moz Fast 1"
	rebuilt := cfg.ToShareURL()
	if strings.Contains(rebuilt, "#Moz+Fast+1") {
		t.Fatalf("remark used + escaping: %s", rebuilt)
	}
	if !strings.Contains(rebuilt, "#Moz%20Fast%201") {
		t.Fatalf("remark did not use percent-space escaping: %s", rebuilt)
	}
}

func TestWithAddress(t *testing.T) {
	raw := "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&sni=example.com&type=xhttp&path=%2Fdownload&host=example.com#test"
	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatal(err)
	}
	swapped := cfg.WithAddress("172.66.40.1")
	if swapped.Address != "172.66.40.1" || swapped.Port != 443 {
		t.Fatalf("swapped = %s:%d", swapped.Address, swapped.Port)
	}
}
