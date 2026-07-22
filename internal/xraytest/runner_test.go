package xraytest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyUploadSpeedIsBounded(t *testing.T) {
	var received int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upload body: %v", err)
		}
		received = len(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	oldURL := uploadProbeURL
	uploadProbeURL = server.URL
	defer func() { uploadProbeURL = oldURL }()

	client := server.Client()
	gotKbps, err := proxyUploadSpeed(context.Background(), "", client, MaxUploadProbeBytes*2)
	if err != nil {
		t.Fatalf("proxyUploadSpeed returned error: %v", err)
	}
	if received != int(MaxUploadProbeBytes) {
		t.Fatalf("received %d bytes, want %d", received, MaxUploadProbeBytes)
	}
	if gotKbps <= 0 {
		t.Fatalf("upload speed = %f, want positive", gotKbps)
	}
}

func TestProxyUploadSpeedHonorsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}))
	defer server.Close()

	oldURL := uploadProbeURL
	uploadProbeURL = server.URL
	defer func() { uploadProbeURL = oldURL }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := proxyUploadSpeed(ctx, "", server.Client(), UploadProbeBytes); err == nil {
		t.Fatal("expected canceled upload to return an error")
	}
}

func TestUploadBudgetForBytes(t *testing.T) {
	if got := UploadBudgetForBytes(0); got != 0 {
		t.Fatalf("disabled upload budget = %d, want 0", got)
	}
	if got := UploadBudgetForBytes(UploadProbeBytes); got != UploadBudgetBytes {
		t.Fatalf("64 KiB upload budget = %d, want %d", got, UploadBudgetBytes)
	}
	if got := UploadBudgetForBytes(UploadProbeBytes128); got != UploadBudgetBytes128 {
		t.Fatalf("128 KiB upload budget = %d, want %d", got, UploadBudgetBytes128)
	}
}
