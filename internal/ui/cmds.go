package ui

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/moz/moz-cloudflare-scanner/internal/ipsrc"
	"github.com/moz/moz-cloudflare-scanner/internal/prober"
	"github.com/moz/moz-cloudflare-scanner/internal/result"
	"github.com/moz/moz-cloudflare-scanner/internal/xraytest"
)

// scanCancel holds the cancel function for the active scan so the TUI can
// abort it when the user presses esc/q.
var scanCancel context.CancelFunc

// prog is set by main before launching the Bubble Tea program so the
// background goroutines can send messages back.
var prog *tea.Program

// SetProgram must be called before any scan command is started.
func SetProgram(p *tea.Program) { prog = p }

// runConfigPhase1 runs Phase 1 of "Scan with Config": a fast connectivity scan
// that finds healthy Cloudflare IPs (or validates IPs from a file), then signals
// the UI to start Phase 2 (xray validation) with selected candidates.
func runConfigPhase1(opts configPhase1Options) {
	var probeCfg prober.Config
	var err error
	if strings.TrimSpace(opts.rawURL) == "" {
		probeCfg = defaultPhase1ProbeConfig(opts.timeout)
	} else {
		probeCfg, err = configProbeFromURL(opts.rawURL, opts.timeout)
		if err != nil {
			if prog != nil {
				prog.Send(ConfigPhase1ErrMsg{Err: fmt.Sprintf("invalid URL: %v", err)})
			}
			return
		}
	}
	ports := opts.ports
	if len(ports) == 0 {
		ports = []int{probeCfg.Port}
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	defer cancel()

	callback := func(r *result.Result) {
		if liveResultWriter != nil {
			liveResultWriter.AddPhase1(r)
		}
		if prog != nil {
			prog.Send(ConfigPhase1ResultMsg{Result: r})
		}
	}

	var ipStream <-chan net.IP
	neighborEnabled := false
	var neighborNets []*net.IPNet
	var neighborRadius, neighborPerHit, neighborMaxTotal int

	if opts.sourceMode == configIPSourceFile {
		ips, err := loadDefaultIPsFile()
		if err != nil {
			if prog != nil {
				prog.Send(ConfigPhase1ErrMsg{Err: err.Error()})
			}
			return
		}
		if len(ips) == 0 {
			if prog != nil {
				prog.Send(ConfigPhase1ErrMsg{Err: "ips.txt is empty — add IPs, endpoints, or small CIDRs"})
			}
			return
		}
		ipStream = streamStaticIPs(ctx, ips)
	} else {
		src, err := ipsrc.New(true, false, nil)
		if err != nil {
			if prog != nil {
				prog.Send(ConfigPhase1DoneMsg{})
			}
			return
		}
		ipStream = src.Stream(ctx, opts.count)
		neighborEnabled = true
		neighborNets = src.IPv4Nets()
		neighborRadius = ipsrc.DefaultNeighborRadius
		neighborPerHit = ipsrc.DefaultNeighborPerHit
		neighborMaxTotal = ipsrc.DefaultNeighborMaxTotal
	}

	// We collect healthy results from the primary scan to use for neighbor expansion later
	var healthyResults []*result.Result
	var healthyMu sync.Mutex

	primaryCallback := func(r *result.Result) {
		callback(r)
		if r.IsHealthy() {
			healthyMu.Lock()
			healthyResults = append(healthyResults, r)
			healthyMu.Unlock()
		}
	}

	// Stage 1A: Primary Scan
	runConfigPortProbes(ctx, ipStream, ports, opts.concurrency, probeCfg, primaryCallback)

	// Stage 1B: Balanced Neighbor Scan (only if primary scan wasn't cancelled)
	if neighborEnabled && len(healthyResults) > 0 && ctx.Err() == nil {
		neighborIPs := gatherNeighbors(healthyResults, neighborNets, neighborRadius, neighborPerHit, neighborMaxTotal)
		if len(neighborIPs) > 0 {
			// Notify TUI that we are beginning neighbor scan
			if prog != nil {
				prog.Send(ConfigPhase1NeighboringMsg{Neighboring: true})
				newTotal := opts.count*len(ports) + len(neighborIPs)*len(ports)
				prog.Send(ConfigPhase1TotalUpdateMsg{Total: newTotal})
			}

			// Stream neighbor IPs
			neighborStream := make(chan net.IP, len(neighborIPs))
			for _, nip := range neighborIPs {
				neighborStream <- nip
			}
			close(neighborStream)

			// Probes on neighbors (which don't recursively expand neighbors since neighborEnabled is false here)
			runConfigPortProbes(ctx, neighborStream, ports, opts.concurrency, probeCfg, callback)
		}
	}

	if liveResultWriter != nil {
		_ = liveResultWriter.flush()
	}

	if prog != nil {
		prog.Send(ConfigPhase1DoneMsg{})
	}
}

func streamStaticIPs(ctx context.Context, ips []net.IP) <-chan net.IP {
	ch := make(chan net.IP, len(ips))
	go func() {
		defer close(ch)
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				return
			case ch <- ip:
			}
		}
	}()
	return ch
}

type configProbeJob struct {
	ip   net.IP
	port int
}

// gatherNeighbors gathers up to maxTotal unique neighbor IPs from healthy results,
// using a round-robin approach to ensure a balanced spread across all healthy IPs.
func gatherNeighbors(healthy []*result.Result, nets []*net.IPNet, radius, perHit, maxTotal int) []net.IP {
	if len(healthy) == 0 || maxTotal <= 0 {
		return nil
	}

	var neighborLists [][]net.IP
	for _, hr := range healthy {
		around := ipsrc.NeighborsAround(hr.IP, nets, radius, perHit)
		if len(around) > 0 {
			neighborLists = append(neighborLists, around)
		}
	}

	if len(neighborLists) == 0 {
		return nil
	}

	var neighbors []net.IP
	seenIPs := make(map[string]struct{})

	maxLen := 0
	for _, list := range neighborLists {
		if len(list) > maxLen {
			maxLen = len(list)
		}
	}

	ipCount := 0
	for step := 0; step < maxLen; step++ {
		for _, list := range neighborLists {
			if step >= len(list) {
				continue
			}
			nip := list[step]
			nipStr := nip.String()
			if _, ok := seenIPs[nipStr]; ok {
				continue
			}
			seenIPs[nipStr] = struct{}{}
			neighbors = append(neighbors, nip)
			ipCount++
			if ipCount >= maxTotal {
				return neighbors
			}
		}
	}

	return neighbors
}

func runConfigPortProbes(ctx context.Context, ips <-chan net.IP, ports []int, concurrency int, base prober.Config, callback func(*result.Result)) {
	if concurrency <= 0 {
		concurrency = 50
	}

	jobs := make(chan configProbeJob, maxInt(concurrency*4, len(ports)*concurrency*2))
	var pending int64
	seen := make(map[string]struct{})
	var seenMu sync.Mutex

	jobKey := func(ip net.IP, port int) string {
		return fmt.Sprintf("%s:%d", ip.String(), port)
	}

	submit := func(ip net.IP, port int) bool {
		key := jobKey(ip, port)
		seenMu.Lock()
		if _, ok := seen[key]; ok {
			seenMu.Unlock()
			return false
		}
		seen[key] = struct{}{}
		seenMu.Unlock()

		atomic.AddInt64(&pending, 1)
		job := configProbeJob{ip: ip, port: port}
		select {
		case <-ctx.Done():
			atomic.AddInt64(&pending, -1)
			return false
		case jobs <- job:
			return true
		}
	}

	enqueueIP := func(ip net.IP) {
		for _, port := range ports {
			submit(ip, port)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					atomic.AddInt64(&pending, -1)
					continue
				}
				r := prober.Probe(ctx, job.ip, base.WithPort(job.port))
				callback(r)
				atomic.AddInt64(&pending, -1)
			}
		}()
	}

	go func() {
		defer func() {
			for atomic.LoadInt64(&pending) > 0 {
				select {
				case <-ctx.Done():
					close(jobs)
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
			close(jobs)
		}()

		for ip := range ips {
			if ctx.Err() != nil {
				return
			}
			enqueueIP(ip)
		}
	}()

	wg.Wait()
}

func defaultPhase1ProbeConfig(timeout time.Duration) prober.Config {
	return prober.Config{
		Port:       443,
		Mode:       prober.ModeHTTP,
		Tries:      3,
		Timeout:    timeout,
		SNI:        "speed.cloudflare.com",
		SpeedBytes: 0,
	}
}

func configProbeFromURL(rawURL string, timeout time.Duration) (prober.Config, error) {
	cfg, err := xraytest.ParseProxyURL(rawURL)
	if err != nil {
		return prober.Config{}, err
	}

	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Host
	}

	probeCfg := prober.Config{
		Port:               cfg.Port,
		Mode:               prober.ModeTLS,
		Tries:              1,
		Timeout:            timeout,
		SNI:                sni,
		InsecureSkipVerify: true,
	}
	if cfg.Network == "ws" {
		probeCfg.Mode = prober.ModeHTTP
		probeCfg.Tries = 2
		probeCfg.AcceptCFHTTPError = true
		probeCfg.WebSocketHost = cfg.Host
		probeCfg.WebSocketPath = cfg.Path
		probeCfg.RequireWebSocket = true
	} else if cfg.Network == "xhttp" || cfg.Network == "splithttp" || cfg.Network == "grpc" {
		probeCfg.Mode = prober.ModeHTTP
		probeCfg.AcceptCFHTTPError = true
	}
	return probeCfg, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func ipsFileSearchPaths() []string {
	seen := make(map[string]struct{})
	add := func(paths *[]string, path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		*paths = append(*paths, path)
	}

	var paths []string
	if wd, err := os.Getwd(); err == nil {
		add(&paths, filepath.Join(wd, "ips.txt"))
	}
	if exe, err := os.Executable(); err == nil {
		add(&paths, filepath.Join(filepath.Dir(exe), "ips.txt"))
	}
	return paths
}

func loadDefaultIPsFile() ([]net.IP, error) {
	var firstErr error
	for _, path := range ipsFileSearchPaths() {
		ips, err := loadIPs(path)
		if err == nil {
			return ips, nil
		}
		if !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("ips.txt not found — place it next to the binary or run folder")
}

type configEndpoint struct {
	IP   net.IP
	Port int
}

func loadDefaultEndpointsFile(defaultPort int) ([]configEndpoint, string, error) {
	for _, path := range ipsFileSearchPaths() {
		endpoints, err := loadEndpoints(path, defaultPort)
		if err == nil {
			return endpoints, path, nil
		}
	}
	return nil, "", fmt.Errorf("ips.txt not found — place it next to the binary or run folder")
}

func loadIPs(path string) ([]net.IP, error) {
	var f *os.File
	var err error
	if path == "" || path == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
	}
	var ips []net.IP
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineIPs, err := parseIPSourceLine(sc.Text())
		if err != nil {
			return nil, err
		}
		for _, ip := range lineIPs {
			key := ip.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			ips = append(ips, ip)
		}
	}
	return ips, sc.Err()
}

const maxIPsTxtCIDRExpansion = 65536

func parseIPSourceLine(line string) ([]net.IP, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(strings.ToLower(line), "ip") {
		return nil, nil
	}
	field := strings.TrimSpace(strings.SplitN(line, ",", 2)[0])
	if parts := strings.Fields(field); len(parts) > 0 {
		field = parts[0]
	}
	if field == "" {
		return nil, nil
	}
	if strings.Contains(field, "/") {
		return expandCIDRLine(field)
	}
	if endpoint, ok := parseEndpointLine(field, 443); ok {
		return []net.IP{endpoint.IP}, nil
	}
	return nil, nil
}

func expandCIDRLine(raw string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q in ips.txt: %w", raw, err)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("IPv6 CIDR %q in ips.txt is not supported in config source mode", raw)
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("CIDR %q is not IPv4", raw)
	}
	size := uint64(1) << uint(bits-ones)
	if size > maxIPsTxtCIDRExpansion {
		return nil, fmt.Errorf("CIDR %q expands to %d IPs; maximum allowed in ips.txt is %d", raw, size, maxIPsTxtCIDRExpansion)
	}
	base := binary.BigEndian.Uint32(ipNet.IP.To4())
	out := make([]net.IP, 0, int(size))
	for i := uint64(0); i < size; i++ {
		next := make(net.IP, 4)
		binary.BigEndian.PutUint32(next, base+uint32(i))
		if ipNet.Contains(next) {
			out = append(out, next)
		}
	}
	return out, nil
}

func loadEndpoints(path string, defaultPort int) ([]configEndpoint, error) {
	var f *os.File
	var err error
	if path == "" || path == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
	}
	if defaultPort <= 0 {
		defaultPort = 443
	}

	var endpoints []configEndpoint
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		endpoint, ok := parseEndpointLine(sc.Text(), defaultPort)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s:%d", endpoint.IP.String(), endpoint.Port)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, sc.Err()
}

func parseEndpointLine(line string, defaultPort int) (configEndpoint, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(strings.ToLower(line), "ip") {
		return configEndpoint{}, false
	}
	field := strings.TrimSpace(strings.SplitN(line, ",", 2)[0])
	if parts := strings.Fields(field); len(parts) > 0 {
		field = parts[0]
	}
	if field == "" {
		return configEndpoint{}, false
	}
	if ip := net.ParseIP(field); ip != nil {
		return configEndpoint{IP: ip, Port: defaultPort}, true
	}

	host, portStr, err := net.SplitHostPort(field)
	if err != nil && strings.Count(field, ":") == 1 {
		idx := strings.LastIndex(field, ":")
		host, portStr = field[:idx], field[idx+1:]
		err = nil
	}
	if err != nil {
		return configEndpoint{}, false
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return configEndpoint{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return configEndpoint{}, false
	}
	return configEndpoint{IP: ip, Port: port}, true
}

// ---------------------------------------------------------------------------
// Stability Tester Commands & Messages
// ---------------------------------------------------------------------------

type StabilityStartMsg struct {
	Total int
}

type StabilityResultMsg struct {
	Result *result.Result
}

type StabilityDoneMsg struct{}

type StabilityErrMsg struct {
	Err string
}

func runStabilityTest(tries int, interval time.Duration, workers int, defaultPort int, timeout time.Duration) tea.Cmd {
	return func() tea.Msg {
		if prog == nil {
			return nil
		}

		endpoints, _, err := loadDefaultEndpointsFile(defaultPort)
		if err != nil {
			prog.Send(StabilityErrMsg{Err: err.Error()})
			return nil
		}
		if len(endpoints) == 0 {
			prog.Send(StabilityErrMsg{Err: "ips.txt has no valid IPs or endpoints"})
			return nil
		}

		var ctx context.Context
		ctx, scanCancel = context.WithCancel(context.Background())

		go func() {
			numWorkers := workers
			if numWorkers > len(endpoints) {
				numWorkers = len(endpoints)
			}
			if numWorkers <= 0 {
				numWorkers = 1
			}

			type task struct {
				endpoint configEndpoint
			}
			taskChan := make(chan task, len(endpoints))
			for _, ep := range endpoints {
				taskChan <- task{endpoint: ep}
			}
			close(taskChan)

			var wg sync.WaitGroup
			for i := 0; i < numWorkers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-ctx.Done():
							return
						case t, ok := <-taskChan:
							if !ok {
								return
							}
							ep := t.endpoint
							
							r := &result.Result{
								IP:        ep.IP,
								Port:      ep.Port,
								ProbeMode: "tcp",
								Timestamp: time.Now(),
								Latencies: make([]time.Duration, tries),
							}

							for j := 0; j < tries; j++ {
								if ctx.Err() != nil {
									break
								}
								start := time.Now()
								conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ep.IP.String(), ep.Port), timeout)
								duration := time.Since(start)

								if err == nil {
									conn.Close()
									r.Latencies[j] = duration
								} else {
									r.Latencies[j] = 0
								}

								if j < tries-1 {
									select {
									case <-ctx.Done():
										return
									case <-time.After(interval):
									}
								}
							}
							prog.Send(StabilityResultMsg{Result: r})
						}
					}
				}()
			}
			wg.Wait()
			if ctx.Err() == nil {
				prog.Send(StabilityDoneMsg{})
			}
		}()

		return StabilityStartMsg{Total: len(endpoints)}
	}
}

