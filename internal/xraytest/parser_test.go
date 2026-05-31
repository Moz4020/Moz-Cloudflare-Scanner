package xraytest

import (
	"fmt"
	"testing"
)

func TestParseVLESS_WS(t *testing.T) {
	raw := "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&sni=example.com&fp=chrome&alpn=h2%2Chttp%2F1.1&insecure=1&allowInsecure=1&type=ws&host=example.com&path=%2Fdownload#CF-WS-079xe1rr"

	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatalf("ParseVLESS failed: %v", err)
	}

	assertEqual(t, "UUID", cfg.UUID, "12345678-1234-1234-1234-123456789abc")
	assertEqual(t, "Address", cfg.Address, "example.com")
	assertEqual(t, "Port", itoa(cfg.Port), "443")
	assertEqual(t, "Network", cfg.Network, "ws")
	assertEqual(t, "Security", cfg.Security, "tls")
	assertEqual(t, "SNI", cfg.SNI, "example.com")
	assertEqual(t, "Fingerprint", cfg.Fingerprint, "chrome")
	assertEqual(t, "Path", cfg.Path, "/download")
	assertEqual(t, "Host", cfg.Host, "example.com")
	assertEqual(t, "Remark", cfg.Remark, "CF-WS-079xe1rr")

	if !cfg.Insecure {
		t.Error("expected Insecure=true")
	}
	if len(cfg.ALPN) != 2 || cfg.ALPN[0] != "h2" || cfg.ALPN[1] != "http/1.1" {
		t.Errorf("unexpected ALPN: %v", cfg.ALPN)
	}
}

func TestParseVLESS_GRPC(t *testing.T) {
	raw := "vless://87654321-4321-4321-4321-cba987654321@example.com:8443?encryption=none&security=tls&sni=example.com&fp=chrome&alpn=h2&insecure=1&allowInsecure=1&type=grpc&authority=example.com&serviceName=download&mode=multi#CF-GRPC-f8k8s2jp"

	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatalf("ParseVLESS failed: %v", err)
	}

	assertEqual(t, "UUID", cfg.UUID, "87654321-4321-4321-4321-cba987654321")
	assertEqual(t, "Port", itoa(cfg.Port), "8443")
	assertEqual(t, "Network", cfg.Network, "grpc")
	assertEqual(t, "ServiceName", cfg.ServiceName, "download")
	assertEqual(t, "Authority", cfg.Authority, "example.com")
	assertEqual(t, "Mode", cfg.Mode, "multi")
}

func TestParseVLESS_XHTTP(t *testing.T) {
	raw := "vless://abcdef12-3456-7890-abcd-ef1234567890@test.example.org:2053?encryption=none&security=tls&sni=test.example.org&fp=chrome&alpn=h2%2Chttp%2F1.1&insecure=1&allowInsecure=1&type=xhttp&host=test.example.org&path=%2Fdownload&mode=auto#CF-XHTTP-o9xk21gf"

	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatalf("ParseVLESS failed: %v", err)
	}

	assertEqual(t, "UUID", cfg.UUID, "abcdef12-3456-7890-abcd-ef1234567890")
	assertEqual(t, "Port", itoa(cfg.Port), "2053")
	assertEqual(t, "Network", cfg.Network, "xhttp")
	assertEqual(t, "Path", cfg.Path, "/download")
	assertEqual(t, "Host", cfg.Host, "test.example.org")
	assertEqual(t, "Mode", cfg.Mode, "auto")
}

func TestWithAddress(t *testing.T) {
	raw := "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=%2Fdownload&host=example.com#test"

	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatalf("ParseVLESS failed: %v", err)
	}

	swapped := cfg.WithAddress("172.66.40.1")

	assertEqual(t, "original address", cfg.Address, "example.com")
	assertEqual(t, "swapped address", swapped.Address, "172.66.40.1")
	assertEqual(t, "port preserved", itoa(swapped.Port), "443")
	assertEqual(t, "SNI preserved", swapped.SNI, "example.com")
	assertEqual(t, "Host preserved", swapped.Host, "example.com")
}

func TestParseVLESS_Invalid(t *testing.T) {
	cases := []string{
		"",
		"vmess://something",
		"vless://no-at-sign",
		"vless://uuid@host-no-port",
	}
	for _, c := range cases {
		_, err := ParseVLESS(c)
		if err == nil {
			t.Errorf("expected error for %q, got nil", c)
		}
	}
}

func assertEqual(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q, want %q", field, got, want)
	}
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
