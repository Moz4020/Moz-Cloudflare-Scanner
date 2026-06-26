package xraytest

import (
	"encoding/json"
	"testing"
)

func TestBuildXrayConfigXHTTP(t *testing.T) {
	cfg := &VLESSConfig{
		UUID:        "abcdef12-3456-7890-abcd-ef1234567890",
		Address:     "104.17.122.146",
		Port:        443,
		Encryption:  "none",
		Network:     "xhttp",
		Path:        "/mozzywozzy",
		Host:        "insane.mozsub.ir",
		Mode:        "auto",
		Security:    "tls",
		SNI:         "insane.mozsub.ir",
		Fingerprint: "chrome",
		ALPN:        []string{"h2", "http/1.1"},
		XHTTPExtra: map[string]interface{}{
			"scMaxEachPostBytes":   "1000000",
			"scMinPostsIntervalMs": "30",
		},
	}
	configBytes, err := BuildXrayConfig(cfg, 10812)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(configBytes, &parsed); err != nil {
		t.Fatal(err)
	}
	proxy := parsed["outbounds"].([]interface{})[0].(map[string]interface{})
	stream := proxy["streamSettings"].(map[string]interface{})
	if stream["network"].(string) != "xhttp" {
		t.Fatalf("network = %v, want xhttp", stream["network"])
	}
	if _, ok := stream["wsSettings"]; ok {
		t.Fatal("wsSettings should not be present")
	}
	if _, ok := stream["grpcSettings"]; ok {
		t.Fatal("grpcSettings should not be present")
	}
	xhttpSettings := stream["xhttpSettings"].(map[string]interface{})
	if xhttpSettings["host"].(string) != "insane.mozsub.ir" {
		t.Fatalf("host = %v", xhttpSettings["host"])
	}
}

func TestBuildXrayConfigAddressSwap(t *testing.T) {
	raw := "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&sni=example.com&type=xhttp&path=%2Fdownload&host=example.com#test"
	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatal(err)
	}
	swapped := cfg.WithAddress("104.18.5.1")
	configBytes, err := BuildXrayConfig(swapped, 10811)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(configBytes, &parsed); err != nil {
		t.Fatal(err)
	}
	proxy := parsed["outbounds"].([]interface{})[0].(map[string]interface{})
	settings := proxy["settings"].(map[string]interface{})
	vnext := settings["vnext"].([]interface{})[0].(map[string]interface{})
	if vnext["address"].(string) != "104.18.5.1" {
		t.Fatalf("address = %v", vnext["address"])
	}
}
