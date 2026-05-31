package xraytest

import (
	"encoding/json"
	"testing"
)

func TestBuildXrayConfig_WS(t *testing.T) {
	cfg := &VLESSConfig{
		UUID:        "12345678-1234-1234-1234-123456789abc",
		Address:     "172.66.40.1",
		Port:        443,
		Encryption:  "none",
		Network:     "ws",
		Path:        "/download",
		Host:        "example.com",
		Security:    "tls",
		SNI:         "example.com",
		Fingerprint: "chrome",
		ALPN:        []string{"h2", "http/1.1"},
		Insecure:    true,
	}

	configBytes, err := BuildXrayConfig(cfg, 10809)
	if err != nil {
		t.Fatalf("BuildXrayConfig failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(configBytes, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check inbound port
	inbounds := parsed["inbounds"].([]interface{})
	inbound := inbounds[0].(map[string]interface{})
	if inbound["port"].(float64) != 10809 {
		t.Errorf("inbound port: got %v, want 10809", inbound["port"])
	}

	// Check outbound has vnext with correct address
	outbounds := parsed["outbounds"].([]interface{})
	proxy := outbounds[0].(map[string]interface{})
	settings := proxy["settings"].(map[string]interface{})
	vnext := settings["vnext"].([]interface{})
	server := vnext[0].(map[string]interface{})

	if server["address"].(string) != "172.66.40.1" {
		t.Errorf("address: got %v, want 172.66.40.1", server["address"])
	}
	if server["port"].(float64) != 443 {
		t.Errorf("port: got %v, want 443", server["port"])
	}

	// Check stream settings
	stream := proxy["streamSettings"].(map[string]interface{})
	if stream["network"].(string) != "ws" {
		t.Errorf("network: got %v, want ws", stream["network"])
	}

	tlsSettings := stream["tlsSettings"].(map[string]interface{})
	if tlsSettings["serverName"].(string) != "example.com" {
		t.Errorf("serverName: got %v, want example.com", tlsSettings["serverName"])
	}

	wsSettings := stream["wsSettings"].(map[string]interface{})
	if wsSettings["path"].(string) != "/download" {
		t.Errorf("path: got %v, want /download", wsSettings["path"])
	}
	// Host is now in headers map (xray-core format) instead of a top-level "host" field.
	headers := wsSettings["headers"].(map[string]interface{})
	if headers["Host"].(string) != "example.com" {
		t.Errorf("headers.Host: got %v, want example.com", headers["Host"])
	}
}

func TestBuildXrayConfig_GRPC(t *testing.T) {
	cfg := &VLESSConfig{
		UUID:        "87654321-4321-4321-4321-cba987654321",
		Address:     "172.66.40.1",
		Port:        8443,
		Encryption:  "none",
		Network:     "grpc",
		ServiceName: "download",
		Authority:   "example.com",
		Mode:        "multi",
		Security:    "tls",
		SNI:         "example.com",
		Fingerprint: "chrome",
		ALPN:        []string{"h2"},
		Insecure:    true,
	}

	configBytes, err := BuildXrayConfig(cfg, 10810)
	if err != nil {
		t.Fatalf("BuildXrayConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(configBytes, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	outbounds := parsed["outbounds"].([]interface{})
	proxy := outbounds[0].(map[string]interface{})
	stream := proxy["streamSettings"].(map[string]interface{})

	if stream["network"].(string) != "grpc" {
		t.Errorf("network: got %v, want grpc", stream["network"])
	}

	grpcSettings := stream["grpcSettings"].(map[string]interface{})
	if grpcSettings["serviceName"].(string) != "download" {
		t.Errorf("serviceName: got %v, want download", grpcSettings["serviceName"])
	}
	if grpcSettings["multiMode"].(bool) != true {
		t.Error("multiMode should be true")
	}
}

func TestBuildXrayConfig_AddressSwap(t *testing.T) {
	raw := "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=%2Fdownload&host=example.com#test"

	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatalf("ParseVLESS failed: %v", err)
	}

	// Swap address to CF IP
	swapped := cfg.WithAddress("104.18.5.1")

	configBytes, err := BuildXrayConfig(swapped, 10811)
	if err != nil {
		t.Fatalf("BuildXrayConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(configBytes, &parsed)

	outbounds := parsed["outbounds"].([]interface{})
	proxy := outbounds[0].(map[string]interface{})
	settings := proxy["settings"].(map[string]interface{})
	vnext := settings["vnext"].([]interface{})
	server := vnext[0].(map[string]interface{})

	// Address should be the CF IP
	if server["address"].(string) != "104.18.5.1" {
		t.Errorf("address: got %v, want 104.18.5.1", server["address"])
	}

	// SNI should still be the domain
	stream := proxy["streamSettings"].(map[string]interface{})
	tlsSettings := stream["tlsSettings"].(map[string]interface{})
	if tlsSettings["serverName"].(string) != "example.com" {
		t.Errorf("SNI should remain example.com, got %v", tlsSettings["serverName"])
	}
}
