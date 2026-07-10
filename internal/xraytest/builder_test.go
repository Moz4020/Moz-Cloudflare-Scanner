package xraytest

import (
	"bytes"
	"encoding/json"
	"testing"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
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

func TestXrayCoreInstantiationWithMLKEMAndVision(t *testing.T) {
	raw := "vless://XXXXXXXXXXXXXX@104.17.117.11:2083?encryption=mlkem768x25519plus.native.0rtt.bPY9RsXBQzs1IIC0T6PMHpR1rHKQ5YJTwgBaCSjEF7VeAG0C9sRUm7Rp2XmHc6iGNlZNmjGUvJlD5HkFtcqx1rwAEAtlfjMaZ1ldUJR1YjIxTBs4yWAnmYkk8bulfFqCY1dzrOSMlvgDGdw3V1i6cRujKAPDhmkTe2TFCRIMO6HHG8JqbtUmZtAVKBeonXlxnZhT9oCm8PcywQe7hottMHTLqxgAkAGT-uLKC3KXJNWA2UMsclSJZvNPsrFvNqg9T0c-COesU5EbXfFwWEDB8Yw2zvGXskuALTdGnqtZqoKfU_UaBAZKpPWtgFVwhWDOL1qrI6OHXZhg0QseryrE3JGn3Ugx1NeT82u8ydi9JcAvi-zB9IRmt2QhZXIUZVLMuWmom_ZiViogHiqxcuovRGqvg1dBikRSUJTCL1Msffc4zxVeodYr01zJipRy3jMGtjxS0yOvP0CgPkIWC-doa9If5bG9XIi3FHsKidpKylBmlRevhvMFstSBy9grEtFS4ipJwnCc5nczCead8IyBm0GK8zSPoTkWj-g99EuARAeBepgwd6rOHug4jJHOsYZzJOkGf_ZKp7aA89RBaro1ibXLDgEZp7geLgcg5QwM_SA0OQGdnjRno4qkXbGsKFNvOqA9aLc-pzab3fmFwmFXeJd_Liw7suEbABW2JGZiOpXKwews0WDIQhlYbwkmU1CIxzeiLKpPZUN1GfFu_uqtYoU-iqjKUXlPBgcuJ7VVIPAUl0FLe_BBiNtMJMuG7JG61pEaAjiUxhJgFCVbr9kmLSR-zdVUZRmSEdurtUweVzZU84VGh-gruOMfkDsxw9yr2kG8xqY5i5aGzwnBHvF5eEQtKeeOc3ekwMWI5mN948oAfLwjD0VtTcUve5K1mFZCwwaYeUUeunqlF3B5ZKUpcCCIxOJ7bCfNOqmNGKq4qIgQ3yHNFTdifHtRfMy634F31ohLpgQFWDsE5qO__JRoOHi8Iol-6tidnmdd4xUCB0MPixCQ1sa1HOM8rkJzmaYsyZq-5JQOyjs-WFatYtGXkGyi6vVYD7GUzsyWpZynurR0Deh5t4jEmmMQc0aFxoOwQpWPg_hKtNpYnqF-TuEiadmnBbapYRgABEuJZ_MkusiF2VcRQbNqaRVcD3a-F1RlshW0T_V5F5QMHKmzUkoqhNdjw6sstlEk2QoKQRpOUzQrRopV2moKryWNxTyZF2MsVXUA8byRdeK5-rNSYzqffPxNC2BRVmhY3tsSuAtcQwgnBWABrlpiXJgrKQSAzGIzcHAGV4jAKqowl8aa2MeKXBEa_QG_BedVs0S6r7s_2esrMOB-NBSsNIUKPDAoBMwHvTawsBXKGyKlx1W5ncvNm5AzgwKTGTwq2KgBvIxGfkpbWoC0jNoJjNYfvRTL8kmli0lA5FeSnHcxMiFx9pszQfmkj2Frw3S9WUIj2oKyXJU_rjQvt_qtCdDPnpFDVPbB_YOe8PQt8xURd8VtlGxPnFYHlUuQJxEFaaTN2Nkl8vq2K8tfypUgmsU29sttT-d1ioEHvbPOoegI7tYQaNor7xQQDNZo1JD6khdYxOErZpY&flow=xtls-rprx-vision&security=tls&sni=api.xxxx.site&fp=chrome&alpn=h2&insecure=0&allowInsecure=0&type=xhttp&host=api.XXXXX.site&path=%2Fapi%2Fv3%2Ftelemetry&mode=stream-one"
	cfg, err := ParseProxyURL(raw)
	if err != nil {
		t.Fatal(err)
	}

	configBytes, err := BuildXrayConfig(cfg, 10811)
	if err != nil {
		t.Fatal(err)
	}

	jsonConfig, err := serial.DecodeJSONConfig(bytes.NewReader(configBytes))
	if err != nil {
		t.Fatalf("xray serial decode failed: %v", err)
	}

	pbConfig, err := jsonConfig.Build()
	if err != nil {
		t.Fatalf("xray pbConfig build failed: %v", err)
	}

	instance, err := xcore.New(pbConfig)
	if err != nil {
		t.Fatalf("xray core creation failed: %v", err)
	}

	if err := instance.Start(); err != nil {
		t.Fatalf("xray core failed to start: %v", err)
	}
	_ = instance.Close()
}
