package ui

import (
	"testing"
	"time"
)

func TestConfigProbeFromURLUsesConfigPortSNIAndWebSocket(t *testing.T) {
	raw := "vless://3441b906-471f-4160-8f2c-a981793e6155@104.17.89.5:2087?encryption=none&security=tls&sni=moz-cloudflare-test.example.com&fp=chrome&insecure=0&allowInsecure=0&type=ws&host=moz-cloudflare-test.example.com&path=%2F#CF"

	cfg, err := configProbeFromURL(raw, 7*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Port != 2087 {
		t.Fatalf("port = %d, want 2087", cfg.Port)
	}
	if cfg.SNI != "moz-cloudflare-test.example.com" {
		t.Fatalf("SNI = %q", cfg.SNI)
	}
	if cfg.WebSocketHost != "moz-cloudflare-test.example.com" {
		t.Fatalf("WebSocketHost = %q", cfg.WebSocketHost)
	}
	if cfg.WebSocketPath != "/" {
		t.Fatalf("WebSocketPath = %q, want /", cfg.WebSocketPath)
	}
	if !cfg.RequireWebSocket {
		t.Fatal("RequireWebSocket = false, want true")
	}
	if !cfg.AcceptCFHTTPError {
		t.Fatal("AcceptCFHTTPError = false, want true")
	}
}

func TestConfigProbeFromURLUsesHTTPForXHTTPPhase1(t *testing.T) {
	raw := "vless://3441b906-471f-4160-8f2c-a981793e6155@104.17.122.146:443?encryption=mlkem768x25519plus.native.0rtt.test&security=tls&sni=insane.mozsub.ir&fp=chrome&alpn=h2%2Chttp%2F1.1&type=xhttp&host=insane.mozsub.ir&path=%2Fmozzywozzy&mode=auto#Main-Moz"

	cfg, err := configProbeFromURL(raw, 7*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Port != 443 {
		t.Fatalf("port = %d, want 443", cfg.Port)
	}
	if cfg.Tries != 1 {
		t.Fatalf("tries = %d, want 1", cfg.Tries)
	}
	if cfg.Mode.String() != "http" {
		t.Fatalf("mode = %s, want http", cfg.Mode.String())
	}
	if cfg.SNI != "insane.mozsub.ir" {
		t.Fatalf("SNI = %q", cfg.SNI)
	}
	if !cfg.AcceptCFHTTPError {
		t.Fatal("AcceptCFHTTPError = false, want true")
	}
	if cfg.RequireWebSocket {
		t.Fatal("RequireWebSocket = true, want false")
	}
}
