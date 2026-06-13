package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/moz/moz-cloudflare-scanner/internal/result"
	"github.com/moz/moz-cloudflare-scanner/internal/xraytest"
)

var liveResultWriter *LiveResultWriter

func setLiveResultWriter(w *LiveResultWriter) { liveResultWriter = w }

func clearLiveResultWriter() { liveResultWriter = nil }

// LiveResultWriter appends scan results to a text file the user can open while
// the scan runs. The file is rewritten on each update so external viewers refresh.
type LiveResultWriter struct {
	mu sync.Mutex

	path         string
	started      time.Time
	withConfig   bool
	phase        int
	phase1Only   bool
	phase1Done   bool
	phase1Rows   []*result.Result
	phase2Rows   []*xraytest.ValidationResult
	phase1Probed int
	lastFlush    time.Time
	pendingFlush int
}

func newLiveResultWriter(withConfig bool) (*LiveResultWriter, string, error) {
	path, err := liveResultFilePath()
	if err != nil {
		return nil, "", err
	}
	w := &LiveResultWriter{
		path:       path,
		started:    time.Now(),
		withConfig: withConfig,
		phase:      1,
	}
	if err := w.flush(); err != nil {
		return nil, "", err
	}
	return w, path, nil
}

func liveResultFilePath() (string, error) {
	name := fmt.Sprintf("MozCloudflareScannerResult-%s.txt", time.Now().Format("20060102-150405"))
	for _, dir := range resultFileDirs() {
		if dir == "" {
			continue
		}
		return filepath.Join(dir, name), nil
	}
	return name, nil
}

func resultFileDirs() []string {
	seen := make(map[string]struct{})
	var dirs []string
	add := func(dir string) {
		if dir == "" {
			return
		}
		if _, ok := seen[dir]; ok {
			return
		}
		seen[dir] = struct{}{}
		dirs = append(dirs, dir)
	}
	if wd, err := os.Getwd(); err == nil {
		add(wd)
	}
	if exe, err := os.Executable(); err == nil {
		add(filepath.Dir(exe))
	}
	return dirs
}

func (w *LiveResultWriter) AddPhase1(r *result.Result) {
	if w == nil || r == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.phase1Probed++
	if r.IsHealthy() {
		w.phase1Rows = append(w.phase1Rows, r)
	}
	_ = w.writeLockedThrottled()
}

func (w *LiveResultWriter) BeginPhase2() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.phase = 2
	w.phase1Done = true
	w.phase2Rows = nil
	_ = w.writeLockedNow()
}

func (w *LiveResultWriter) FinishPhase1Only() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.phase1Only = true
	w.phase1Done = true
	_ = w.writeLockedNow()
}

func (w *LiveResultWriter) AddPhase2(v *xraytest.ValidationResult) {
	if w == nil || v == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.phase2Rows = append(w.phase2Rows, v)
	_ = w.writeLockedThrottled()
}

func (w *LiveResultWriter) flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeLockedNow()
}

func (w *LiveResultWriter) writeLockedThrottled() error {
	w.pendingFlush++
	if time.Since(w.lastFlush) < 1000*time.Millisecond {
		return nil
	}
	return w.writeLockedNow()
}

func (w *LiveResultWriter) writeLockedNow() error {
	w.pendingFlush = 0
	w.lastFlush = time.Now()

	var sb strings.Builder
	sb.WriteString("Moz Cloudflare Scanner — live results\n")
	sb.WriteString(fmt.Sprintf("Started: %s\n", w.started.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Updated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	if w.withConfig {
		sb.WriteString("Plan: Phase 1 connectivity, then Phase 2 xray validation\n")
		sb.WriteString("Note: Phase 1 entries are candidates. Phase 2 decides what actually works.\n")
	} else {
		sb.WriteString("Plan: Phase 1 connectivity only\n")
	}
	sb.WriteString("\n")

	healthy := len(w.phase1Rows)
	label := "healthy"
	statusLabel := "STATUS"
	if w.withConfig {
		label = "candidates"
		statusLabel = "PHASE 1"
	}
	sb.WriteString(fmt.Sprintf("=== Phase 1 — connectivity (%d %s / %d probed) ===\n\n", healthy, label, w.phase1Probed))
	sb.WriteString(endpointHeader(statusLabel) + "\n")
	sb.WriteString(tableSeparator(76) + "\n")

	rows := append([]*result.Result(nil), w.phase1Rows...)
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Avg() < rows[j].Avg()
	})
	if len(rows) == 0 {
		sb.WriteString("  (no healthy results yet)\n")
	} else {
		for _, r := range rows {
			status := "healthy"
			if w.withConfig {
				status = "candidate"
			}
			if !r.IsHealthy() {
				status = "fail"
			}
			sb.WriteString(endpointCandidateRow(r, status) + "\n")
		}
	}

	if w.phase >= 2 && !w.phase1Only {
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("=== Phase 2 — xray validation (%d tested) ===\n\n", len(w.phase2Rows)))
		success, failed, skipped := validationOutcomeCounts(w.phase2Rows)
		sb.WriteString(fmt.Sprintf("Summary: working %d, failed %d, skipped %d, success %.1f%%\n\n",
			success, failed, skipped, validationSuccessRate(success, failed)))
		sb.WriteString(validationHeader() + "\n")
		sb.WriteString(tableSeparator(76) + "\n")
		if len(w.phase2Rows) == 0 {
			sb.WriteString("  (no validation results yet)\n")
		} else {
			var failures []string
			for _, r := range w.phase2Rows {
				status := "fail"
				if r.Success {
					status = "working"
				} else if isSkippedValidation(r) {
					status = "skipped"
				} else if r.Error != "" {
					status = r.Error
					failures = append(failures, fmt.Sprintf("%s: %s", formatEndpoint(r.IP, r.Port), r.Error))
					if len(status) > statusColWidth {
						status = status[:statusColWidth-1] + "..."
					}
				}
				sb.WriteString(validationRow(r, status) + "\n")
			}
			if len(failures) > 0 {
				sb.WriteString("\nLatest failures:\n")
				start := len(failures) - 5
				if start < 0 {
					start = 0
				}
				for _, failure := range failures[start:] {
					sb.WriteString("  " + failure + "\n")
				}
			}
		}
	}

	return os.WriteFile(w.path, []byte(sb.String()), 0644)
}
