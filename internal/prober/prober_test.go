package prober

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestParseColoCDN(t *testing.T) {
	body := "fl=1\ncolo=FRA\nhttp=http/2\n"
	if got := parseColoCDN(body); got != "FRA" {
		t.Fatalf("parseColoCDN = %q, want FRA", got)
	}
}

func TestParseColoRay(t *testing.T) {
	if got := parseColoRay("8790abcd-FRA"); got != "FRA" {
		t.Fatalf("parseColoRay = %q, want FRA", got)
	}
}

func TestProbeSupportsIPv6TCPEndpoints(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer listener.Close()

	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	r := Probe(context.Background(), net.ParseIP("::1"), Config{
		Port:    port,
		Mode:    ModeTCP,
		Tries:   1,
		Timeout: time.Second,
	})
	if !r.IsHealthy() {
		t.Fatalf("IPv6 TCP probe was unhealthy: %+v", r)
	}
}

func TestProbeHTTPUsesSharedPinnedTransport(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "8790abcd-FRA")
		_, _ = w.Write([]byte("colo=FRA\n"))
	}))
	defer server.Close()

	_, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	r := Probe(context.Background(), net.ParseIP("127.0.0.1"), Config{
		Port:               port,
		Mode:               ModeHTTP,
		Tries:              1,
		Timeout:            time.Second,
		SNI:                "127.0.0.1",
		InsecureSkipVerify: true,
	})
	if !r.IsHealthy() || r.Colo != "FRA" || r.HTTPStatus != http.StatusOK {
		t.Fatalf("HTTP probe result = %+v", r)
	}
}
