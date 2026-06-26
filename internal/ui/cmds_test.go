package ui

import (
	"testing"
	"time"
)

func TestConfigProbeFromURLUsesHTTPForXHTTPPhase1(t *testing.T) {
	raw := "vless://3441b906-471f-4160-8f2c-a981793e6155@104.17.122.146:443?encryption=mlkem768x25519plus.native.0rtt.test&security=tls&sni=insane.mozsub.ir&fp=chrome&alpn=h2%2Chttp%2F1.1&type=xhttp&host=insane.mozsub.ir&path=%2Fmozzywozzy&mode=auto#Main-Moz"

	cfg, err := configProbeFromURL(raw, 7*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Port != 443 {
		t.Fatalf("port = %d, want 443", cfg.Port)
	}
	if cfg.Tries != 2 {
		t.Fatalf("tries = %d, want 2", cfg.Tries)
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
}
