package engine

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moz/moz-cloudflare-scanner/internal/prober"
	"github.com/moz/moz-cloudflare-scanner/internal/result"
)

func TestRunJobsUsesBoundedWorkersAndTracksStats(t *testing.T) {
	e := New(Config{
		Concurrency: 2,
		ProbeConfig: prober.Config{
			Mode:    prober.ModeTCP,
			Tries:   1,
			Timeout: 100 * time.Millisecond,
		},
	})
	jobs := make(chan Job, 2)
	jobs <- Job{IP: net.ParseIP("127.0.0.1"), Port: 1}
	jobs <- Job{IP: net.ParseIP("127.0.0.1"), Port: 1}
	close(jobs)

	var got atomic.Int64
	results := make(chan *result.Result, 2)
	e.RunJobs(context.Background(), jobs, func(r *result.Result) {
		got.Add(1)
		results <- r
	})
	if got.Load() != 2 {
		t.Fatalf("callback count = %d, want 2", got.Load())
	}
	if tested := e.Stats().Tested.Load(); tested != 2 {
		t.Fatalf("tested = %d, want 2", tested)
	}
	if failed := e.Stats().Failed.Load(); failed != 2 {
		for i := 0; i < 2; i++ {
			r := <-results
			t.Logf("result %d: %+v", i, r)
		}
		t.Fatalf("failed = %d, want 2", failed)
	}
	if inFlight := e.Stats().InFlight.Load(); inFlight != 0 {
		t.Fatalf("in-flight = %d, want 0", inFlight)
	}
}
