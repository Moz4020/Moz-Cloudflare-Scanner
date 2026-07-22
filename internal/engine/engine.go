package engine

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/moz/moz-cloudflare-scanner/internal/prober"
	"github.com/moz/moz-cloudflare-scanner/internal/result"
)

// Config controls engine behaviour.
type Config struct {
	Concurrency int
	RateLimit   float64 // probes per second, <=0 means unlimited
	ProbeConfig prober.Config
}

// Stats exposes real-time counters.
type Stats struct {
	Tested   atomic.Int64
	Healthy  atomic.Int64
	Failed   atomic.Int64
	InFlight atomic.Int64
}

// ResultFunc is called for every completed probe result. It is invoked from
// worker goroutines, so implementations must be goroutine-safe.
type ResultFunc func(*result.Result)

// Job identifies an IP and remote port to probe.
type Job struct {
	IP   net.IP
	Port int
}

// Engine orchestrates a pool of prober goroutines.
type Engine struct {
	cfg     Config
	stats   Stats
	limiter *rate.Limiter
}

// New creates a new Engine.
func New(cfg Config) *Engine {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 100
	}
	return &Engine{cfg: cfg, limiter: newLimiter(cfg.RateLimit)}
}

func newLimiter(rateLimit float64) *rate.Limiter {
	if rateLimit <= 0 {
		return nil
	}
	burst := int(rateLimit) + 1
	if burst < 1 {
		burst = 1
	}
	return rate.NewLimiter(rate.Limit(rateLimit), burst)
}

// Stats returns a pointer to the live statistics.
func (e *Engine) Stats() *Stats {
	return &e.stats
}

// Run consumes IPs from src, probes each one, and forwards results to fn.
// It blocks until src is exhausted or ctx is cancelled.
func (e *Engine) Run(ctx context.Context, src <-chan net.IP, fn ResultFunc) {
	jobs := make(chan Job, e.cfg.Concurrency*2)
	go func() {
		defer close(jobs)
		for {
			select {
			case <-ctx.Done():
				return
			case ip, ok := <-src:
				if !ok {
					return
				}
				select {
				case <-ctx.Done():
					return
				case jobs <- Job{IP: ip, Port: e.cfg.ProbeConfig.Port}:
				}
			}
		}
	}()
	e.runJobs(ctx, jobs, fn, e.cfg, e.limiter)
}

// RunJobs consumes IP/port jobs using the engine's bounded worker pool.
func (e *Engine) RunJobs(ctx context.Context, src <-chan Job, fn ResultFunc) {
	e.runJobs(ctx, src, fn, e.cfg, e.limiter)
}

func (e *Engine) runJobs(ctx context.Context, src <-chan Job, fn ResultFunc, cfg Config, limiter *rate.Limiter) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 100
	}
	jobs := make(chan Job, cfg.Concurrency*2)
	var wg sync.WaitGroup

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}
					e.stats.InFlight.Add(1)
					r := prober.Probe(ctx, job.IP, cfg.ProbeConfig.WithPort(job.Port))
					e.stats.InFlight.Add(-1)
					e.stats.Tested.Add(1)
					if r.IsHealthy() {
						e.stats.Healthy.Add(1)
					} else {
						e.stats.Failed.Add(1)
					}
					if fn != nil {
						fn(r)
					}
				}
			}
		}()
	}

enqueue:
	for {
		select {
		case <-ctx.Done():
			break enqueue
		case job, ok := <-src:
			if !ok {
				break enqueue
			}
			if limiter != nil {
				if err := limiter.Wait(ctx); err != nil {
					break enqueue
				}
			}
			select {
			case <-ctx.Done():
				break enqueue
			case jobs <- job:
			}
		}
	}
	close(jobs)
	wg.Wait()
}

// RunList probes a fixed slice of IPs (used in `moz-cloudflare-scanner test`).
func (e *Engine) RunList(ctx context.Context, ips []net.IP, fn ResultFunc) {
	// Raise the timeout floor for the final validation round so slow IPs
	// still get a fair chance rather than being cut off too early.
	cfg := e.cfg
	cfg.ProbeConfig.Timeout = max(cfg.ProbeConfig.Timeout, 10*time.Second)

	ch := make(chan Job, len(ips))
	for _, ip := range ips {
		ch <- Job{IP: ip, Port: cfg.ProbeConfig.Port}
	}
	close(ch)

	e.runJobs(ctx, ch, fn, cfg, newLimiter(cfg.RateLimit))
}
