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

func TestParseVLESSRejectsSplitHTTP(t *testing.T) {
	raw := "vless://abcdef12-3456-7890-abcd-ef1234567890@example.com:443?encryption=none&security=tls&sni=example.com&type=splithttp&path=%2Fdownload&host=example.com#test"
	if _, err := ParseVLESS(raw); err == nil {
		t.Fatal("expected splithttp transport to be rejected")
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

func TestMLKEMAndXTLSVision(t *testing.T) {
	raw := "vless://XXXXXXXXXXXXXX@104.17.117.11:2083?encryption=mlkem768x25519plus.native.0rtt.bPY9RsXBQzs1IIC0T6PMHpR1rHKQ5YJTwgBaCSjEF7VeAG0C9sRUm7Rp2XmHc6iGNlZNmjGUvJlD5HkFtcqx1rwAEAtlfjMaZ1ldUJR1YjIxTBs4yWAnmYkk8bulfFqCY1dzrOSMlvgDGdw3V1i6cRujKAPDhmkTe2TFCRIMO6HHG8JqbtUmZtAVKBeonXlxnZhT9oCm8PcywQe7hottMHTLqxgAkAGT-uLKC3KXJNWA2UMsclSJZvNPsrFvNqg9T0c-COesU5EbXfFwWEDB8Yw2zvGXskuALTdGnqtZqoKfU_UaBAZKpPWtgFVwhWDOL1qrI6OHXZhg0QseryrE3JGn3Ugx1NeT82u8ydi9JcAvi-zB9IRmt2QhZXIUZVLMuWmom_ZiViogHiqxcuovRGqvg1dBikRSUJTCL1Msffc4zxVeodYr01zJipRy3jMGtjxS0yOvP0CgPkIWC-doa9If5bG9XIi3FHsKidpKylBmlRevhvMFstSBy9grEtFS4ipJwnCc5nczCead8IyBm0GK8zSPoTkWj-g99EuARAeBepgwd6rOHug4jJHOsYZzJOkGf_ZKp7aA89RBaro1ibXLDgEZp7geLgcg5QwM_SA0OQGdnjRno4qkXbGsKFNvOqA9aLc-pzab3fmFwmFXeJd_Liw7suEbABW2JGZiOpXKwews0WDIQhlYbwkmU1CIxzeiLKpPZUN1GfFu_uqtYoU-iqjKUXlPBgcuJ7VVIPAUl0FLe_BBiNtMJMuG7JG61pEaAjiUxhJgFCVbr9kmLSR-zdVUZRmSEdurtUweVzZU84VGh-gruOMfkDsxw9yr2kG8xqY5i5aGzwnBHvF5eEQtKeeOc3ekwMWI5mN948oAfLwjD0VtTcUve5K1mFZCwwaYeUUeunqlF3B5ZKUpcCCIxOJ7bCfNOqmNGKq4qIgQ3yHNFTdifHtRfMy634F31ohLpgQFWDsE5qO__JRoOHi8Iol-6tidnmdd4xUCB0MPixCQ1sa1HOM8rkJzmaYsyZq-5JQOyjs-WFatYtGXkGyi6vVYD7GUzsyWpZynurR0Deh5t4jEmmMQc0aFxoOwQpWPg_hKtNpYnqF-TuEiadmnBbapYRgABEuJZ_MkusiF2VcRQbNqaRVcD3a-F1RlshW0T_V5F5QMHKmzUkoqhNdjw6sstlEk2QoKQRpOUzQrRopV2moKryWNxTyZF2MsVXUA8byRdeK5-rNSYzqffPxNC2BRVmhY3tsSuAtcQwgnBWABrlpiXJgrKQSAzGIzcHAGV4jAKqowl8aa2MeKXBEa_QG_BedVs0S6r7s_2esrMOB-NBSsNIUKPDAoBMwHvTawsBXKGyKlx1W5ncvNm5AzgwKTGTwq2KgBvIxGfkpbWoC0jNoJjNYfvRTL8kmli0lA5FeSnHcxMiFx9pszQfmkj2Frw3S9WUIj2oKyXJU_rjQvt_qtCdDPnpFDVPbB_YOe8PQt8xURd8VtlGxPnFYHlUuQJxEFaaTN2Nkl8vq2K8tfypUgmsU29sttT-d1ioEHvbPOoegI7tYQaNor7xQQDNZo1JD6khdYxOErZpY&flow=xtls-rprx-vision&security=tls&sni=api.xxxx.site&fp=chrome&alpn=h2&insecure=0&allowInsecure=0&type=xhttp&host=api.XXXXX.site&path=%2Fapi%2Fv3%2Ftelemetry&mode=stream-one&extra=%7B%22mode%22%3A%22stream-one%22%2C%22xmux%22%3A%7B%22cMaxReuseTimes%22%3A0%2C%22hKeepAlivePeriod%22%3A0%2C%22hMaxRequestTimes%22%3A%22600-900%22%2C%22hMaxReusableSecs%22%3A%221800-3000%22%2C%22maxConnections%22%3A6%7D%7D#Moz%20VPN-Moz"
	cfg, err := ParseProxyURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.Encryption, "mlkem768x25519plus.native.0rtt") || len(cfg.Encryption) < 100 {
		t.Fatalf("unexpected encryption value: %q", cfg.Encryption)
	}
	if cfg.Flow != "xtls-rprx-vision" {
		t.Fatalf("flow = %q, want xtls-rprx-vision", cfg.Flow)
	}
	configBytes, err := BuildXrayConfig(cfg, 10811)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configBytes), `"flow": "xtls-rprx-vision"`) {
		t.Fatal("missing flow in config")
	}
	if !strings.Contains(cfg.ToShareURL(), "flow=xtls-rprx-vision") {
		t.Fatal("generated share URL is missing the Vision flow")
	}
}
