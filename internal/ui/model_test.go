package ui

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/moz/moz-cloudflare-scanner/internal/result"
	"github.com/moz/moz-cloudflare-scanner/internal/xraytest"
)

func TestMenuOnlyShowsMainWorkflow(t *testing.T) {
	if len(menuEntries) != 5 {
		t.Fatalf("menu entries = %d, want 5", len(menuEntries))
	}
	if menuEntries[0].label != "Find Working IPs" {
		t.Fatalf("first menu item = %q, want Find Working IPs", menuEntries[0].label)
	}
	if menuEntries[1].label != "Generate V2Ray Configs" {
		t.Fatalf("second menu item = %q, want Generate V2Ray Configs", menuEntries[1].label)
	}
	if menuEntries[2].label != "Test IP Stability" {
		t.Fatalf("third menu item = %q, want Test IP Stability", menuEntries[2].label)
	}
	for _, entry := range menuEntries {
		for _, removed := range []string{"Quick Scan", "Custom Scan", "Test IPs", "Discover Colos"} {
			if entry.label == removed {
				t.Fatalf("removed menu item %q is still visible", removed)
			}
		}
	}
}

func TestAboutMentionsLinuxVPS(t *testing.T) {
	m := NewApp("test")
	view := m.viewAbout()
	if !strings.Contains(view, "Linux VPS") {
		t.Fatalf("about view does not mention Linux VPS: %q", view)
	}
	if strings.Contains(view, "for Windows.") {
		t.Fatalf("about view still reads Windows-only: %q", view)
	}
}

func TestConfigOptionalShowsPhase2WorkerCap(t *testing.T) {
	m := NewApp("test")
	m.configOptionalRow = 2
	view := m.viewConfigOptional()
	if !strings.Contains(view, fmt.Sprintf("capped at %d", maxPhase2Workers)) {
		t.Fatalf("optional config view does not show worker cap: %q", view)
	}
}

func TestResolvePhase1OptionsUsesRandomCloudflareDefaults(t *testing.T) {
	m := NewApp("test")
	m.configURL = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&type=xhttp&host=example.com&path=%2F#test"
	m.configCountIdx = 2

	opts := m.resolvePhase1Options()
	if opts.count != 20000 {
		t.Fatalf("count = %d, want 20000", opts.count)
	}
	if opts.concurrency != 100 {
		t.Fatalf("concurrency = %d, want 100", opts.concurrency)
	}
	if opts.timeout.String() != "3s" {
		t.Fatalf("timeout = %s, want 3s", opts.timeout)
	}
	if opts.rawURL != m.configURL {
		t.Fatal("rawURL was not preserved")
	}
	if opts.sourceMode != configIPSourceDefault {
		t.Fatalf("sourceMode = %d, want default", opts.sourceMode)
	}
}

func TestResolvePhase1OptionsFromFile(t *testing.T) {
	m := NewApp("test")
	m.configIPMode = configIPSourceFile
	opts := m.resolvePhase1Options()
	if opts.sourceMode != configIPSourceFile {
		t.Fatalf("sourceMode = %d, want ips.txt", opts.sourceMode)
	}
}

func TestResolveConfigPortsMultiSelect(t *testing.T) {
	m := NewApp("test")
	m.configURL = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&type=xhttp&host=example.com&path=%2F#test"
	m.configSelectedPorts = map[int]bool{443: true, 8443: true}

	got := m.resolveConfigPorts()
	want := []string{"443", "8443"}
	parts := make([]string, len(got))
	for i, port := range got {
		parts[i] = strconv.Itoa(port)
	}
	if strings.Join(parts, ",") != strings.Join(want, ",") {
		t.Fatalf("ports = %v, want %v", got, want)
	}
}

func TestLoadDefaultIPsFileFindsWorkingDirectoryFile(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := writeIPsFile(filepath.Join(dir, "ips.txt"), []string{"104.18.1.1", "104.18.1.2"}); err != nil {
		t.Fatal(err)
	}

	ips, err := loadDefaultIPsFile()
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("loaded %d IPs, want 2", len(ips))
	}
}

func TestLoadIPsSupportsCIDRsAndEndpoints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ips.txt")
	text := strings.Join([]string{
		"45.130.125.0/30",
		"104.18.1.1:8443",
		"104.18.1.1:443",
		"# comment",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(text), 0644); err != nil {
		t.Fatal(err)
	}

	ips, err := loadIPs(path)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(ips))
	for i, ip := range ips {
		got[i] = ip.String()
	}
	want := []string{
		"45.130.125.0",
		"45.130.125.1",
		"45.130.125.2",
		"45.130.125.3",
		"104.18.1.1",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ips = %v, want %v", got, want)
	}
}

func TestLoadIPsRejectsHugeCIDR(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ips.txt")
	if err := os.WriteFile(path, []byte("45.130.0.0/15\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadIPs(path); err == nil || !strings.Contains(err.Error(), "maximum allowed") {
		t.Fatalf("loadIPs error = %v, want maximum allowed error", err)
	}
}

func TestLoadDefaultIPsFileReturnsParseError(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ips.txt"), []byte("45.130.0.0/15\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadDefaultIPsFile(); err == nil || !strings.Contains(err.Error(), "maximum allowed") {
		t.Fatalf("loadDefaultIPsFile error = %v, want maximum allowed error", err)
	}
}

func TestWorkingIPsOnlyIncludesSuccessfulValidationResults(t *testing.T) {
	got := workingIPs([]*xraytest.ValidationResult{
		{IP: "104.18.1.1", Success: true},
		{IP: "104.18.1.2", Success: false},
		{IP: "104.18.1.1", Success: true},
		nil,
		{IP: "", Success: true},
	})
	want := []string{"104.18.1.1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("working IPs = %v, want %v", got, want)
	}
}

func TestWriteIPsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ips.txt")
	if err := writeIPsFile(path, []string{"104.18.1.1", "104.18.1.2"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), "104.18.1.1\n104.18.1.2\n"; got != want {
		t.Fatalf("file contents = %q, want %q", got, want)
	}
}

func TestCopyWorkingIPsNoSuccesses(t *testing.T) {
	m := AppModel{
		configResults: []*xraytest.ValidationResult{
			{IP: "104.18.1.2", Success: false},
		},
	}
	if got := m.copyWorkingIPs(); got != "no working endpoints to copy" {
		t.Fatalf("message = %q", got)
	}
}

func TestFormatValidationLatency(t *testing.T) {
	if got := formatValidationLatency(250 * time.Millisecond); got != "250ms" {
		t.Fatalf("latency = %q, want 250ms", got)
	}
	if got := formatValidationLatency(1500 * time.Millisecond); got != "1.5s" {
		t.Fatalf("latency = %q, want 1.5s", got)
	}
}

func TestWorkingEndpointsIncludePorts(t *testing.T) {
	got := workingEndpoints([]*xraytest.ValidationResult{
		{IP: "104.18.1.1", Port: 443, Success: true},
		{IP: "104.18.1.1", Port: 8443, Success: true},
		{IP: "104.18.1.2", Port: 443, Success: false},
	})
	want := []string{"104.18.1.1:443", "104.18.1.1:8443"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("working endpoints = %v, want %v", got, want)
	}
}

func TestWorkingEndpointsSortByLowestLatency(t *testing.T) {
	got := workingEndpoints([]*xraytest.ValidationResult{
		{IP: "104.18.1.3", Port: 443, Success: true, Latency: 300 * time.Millisecond},
		{IP: "104.18.1.1", Port: 443, Success: true, Latency: 80 * time.Millisecond},
		{IP: "104.18.1.2", Port: 443, Success: true, Latency: 150 * time.Millisecond},
		{IP: "104.18.1.4", Port: 443, Success: true},
	})
	want := []string{
		"104.18.1.1:443",
		"104.18.1.2:443",
		"104.18.1.3:443",
		"104.18.1.4:443",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("working endpoints = %v, want %v", got, want)
	}
}

func TestWorkingEndpointsKeepsFastestDuplicate(t *testing.T) {
	got := workingEndpoints([]*xraytest.ValidationResult{
		{IP: "104.18.1.1", Port: 443, Success: true, Latency: 300 * time.Millisecond},
		{IP: "104.18.1.2", Port: 443, Success: true, Latency: 150 * time.Millisecond},
		{IP: "104.18.1.1", Port: 443, Success: true, Latency: 80 * time.Millisecond},
	})
	want := []string{"104.18.1.1:443", "104.18.1.2:443"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("working endpoints = %v, want %v", got, want)
	}
}

func TestVisibleValidationRowsFinishedPrefersStableWorkingResults(t *testing.T) {
	rows := visibleValidationRows([]*xraytest.ValidationResult{
		{IP: "104.18.1.3", Port: 443, Success: false, Error: "failed"},
		{IP: "104.18.1.2", Port: 443, Success: true, Successes: 3, Attempts: 3, Throughput: 200 * 1024, Latency: 180 * time.Millisecond},
		{IP: "104.18.1.1", Port: 443, Success: true, Successes: 2, Attempts: 3, Throughput: 900 * 1024, Latency: 70 * time.Millisecond},
	}, 3, true)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0].IP != "104.18.1.2" || rows[1].IP != "104.18.1.1" {
		t.Fatalf("finished rows order = %v", rows)
	}
}

func TestVisibleValidationRowsRunningShowsRecentRows(t *testing.T) {
	rows := visibleValidationRows([]*xraytest.ValidationResult{
		{IP: "104.18.1.1"},
		{IP: "104.18.1.2"},
		{IP: "104.18.1.3"},
	}, 2, false)
	if len(rows) != 2 || rows[0].IP != "104.18.1.2" || rows[1].IP != "104.18.1.3" {
		t.Fatalf("running rows = %v", rows)
	}
}

func TestParseEndpointLineSupportsIPAndPort(t *testing.T) {
	endpoint, ok := parseEndpointLine("104.17.122.146:8443", 443)
	if !ok {
		t.Fatal("endpoint was not parsed")
	}
	if endpoint.IP.String() != "104.17.122.146" || endpoint.Port != 8443 {
		t.Fatalf("endpoint = %s:%d, want 104.17.122.146:8443", endpoint.IP, endpoint.Port)
	}

	endpoint, ok = parseEndpointLine("104.18.152.95", 443)
	if !ok {
		t.Fatal("plain IP was not parsed")
	}
	if endpoint.Port != 443 {
		t.Fatalf("default port = %d, want 443", endpoint.Port)
	}
}

func TestGenerateV2RayConfigsWritesConfigsTxt(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ips.txt"), []byte("104.17.122.146:443\n104.18.152.95:8443\n"), 0644); err != nil {
		t.Fatal(err)
	}

	raw := "vless://11111111-1111-1111-1111-111111111111@104.16.74.220:443?encryption=none&security=tls&sni=insane.mozsub.ir&alpn=h2%2Chttp%2F1.1&type=xhttp&host=insane.mozsub.ir&path=%2Fmozzywozzy&mode=auto#Main-Moz"
	path, count, err := generateV2RayConfigs(raw, "Test-fast")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
	if filepath.Base(path) != "configs.txt" {
		t.Fatalf("output path = %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	first, err := xraytest.ParseProxyURL(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := xraytest.ParseProxyURL(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	if first.Address != "104.17.122.146" || first.Port != 443 {
		t.Fatalf("first endpoint = %s:%d", first.Address, first.Port)
	}
	if second.Address != "104.18.152.95" || second.Port != 8443 {
		t.Fatalf("second endpoint = %s:%d", second.Address, second.Port)
	}
	if first.Host != "insane.mozsub.ir" || first.Network != "xhttp" {
		t.Fatalf("config details were not preserved: host=%s network=%s", first.Host, first.Network)
	}
	if first.Remark != "Test-fast 1" || second.Remark != "Test-fast 2" {
		t.Fatalf("remarks = %q / %q, want numbered prefix", first.Remark, second.Remark)
	}
}

func TestOnlyCurrentWorkflowPagesRemain(t *testing.T) {
	if PageConfigPhase2 != 6 {
		t.Fatalf("page enum includes removed legacy scan pages; last page = %d", PageConfigPhase2)
	}
}

func TestCleanPastedConfigURLUsesFirstNonEmptyLine(t *testing.T) {
	raw := "\r\n  vless://uuid@example.com:443?type=xhttp  \r\n"
	if got := cleanPastedConfigURL(raw); got != "vless://uuid@example.com:443?type=xhttp" {
		t.Fatalf("cleanPastedConfigURL = %q", got)
	}
}

func TestPastedConfigDoesNotLaunchScan(t *testing.T) {
	m := NewApp("test")
	m.page = PageConfigOptional
	m.configOptionalRow = 0

	next, cmd := m.handleConfigOptionalKey(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune("vless://uuid@example.com:443?type=xhttp\n"),
		Paste: true,
	})
	got := next.(AppModel)
	if cmd != nil {
		t.Fatal("paste returned a command; want nil")
	}
	if got.page != PageConfigOptional {
		t.Fatalf("page = %v, want PageConfigOptional", got.page)
	}
	if got.configInput.Value() != "vless://uuid@example.com:443?type=xhttp" {
		t.Fatalf("config input = %q", got.configInput.Value())
	}
	if !strings.Contains(got.statusMsg, "press Enter") {
		t.Fatalf("status = %q", got.statusMsg)
	}
}

func TestTrailingPasteEntersDoNotLaunchScan(t *testing.T) {
	m := NewApp("test")
	m.page = PageConfigOptional
	m.configOptionalRow = 0
	m.configInput.SetValue("vless://uuid@example.com:443?type=xhttp")

	next, cmd := m.handleConfigOptionalKey(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(AppModel)
	if cmd != nil {
		t.Fatal("first enter returned command; want nil")
	}
	if m.configOptionalRow != 1 {
		t.Fatalf("row after first enter = %d, want 1", m.configOptionalRow)
	}

	next, cmd = m.handleConfigOptionalKey(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(AppModel)
	if cmd != nil {
		t.Fatal("second enter returned command; want nil")
	}
	if m.configOptionalRow != 2 {
		t.Fatalf("row after second enter = %d, want 2", m.configOptionalRow)
	}
}

func TestConfigInputRowDoesNotTreatKAsNavigation(t *testing.T) {
	m := NewApp("test")
	m.page = PageConfigOptional
	m.configOptionalRow = 0

	next, _ := m.handleConfigOptionalKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	got := next.(AppModel)
	if got.configInput.Value() != "k" {
		t.Fatalf("config input = %q, want k", got.configInput.Value())
	}
	if got.configOptionalRow != 0 {
		t.Fatalf("row = %d, want 0", got.configOptionalRow)
	}
}

func TestConfigInputRowValidationAndNavigationBlock(t *testing.T) {
	m := NewApp("test")
	m.page = PageConfigOptional
	m.configOptionalRow = 0

	// 1. Paste invalid URL
	next, _ := m.handleConfigOptionalKey(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune("trojan://uuid@example.com:443?type=ws"),
		Paste: true,
	})
	got := next.(AppModel)
	if !strings.Contains(got.statusMsg, "invalid URL") {
		t.Fatalf("statusMsg should show invalid URL on paste, got: %q", got.statusMsg)
	}

	// 2. Try to move down/enter with invalid config — should block navigation
	got.configInput.SetValue("invalid-config-url")
	next2, _ := got.handleConfigOptionalKey(tea.KeyMsg{Type: tea.KeyEnter})
	got2 := next2.(AppModel)
	if got2.configOptionalRow != 0 {
		t.Fatalf("expected optional row to remain 0 (blocked navigation), got %d", got2.configOptionalRow)
	}
	if !strings.Contains(got2.statusMsg, "invalid URL") {
		t.Fatalf("expected status message warning on block, got: %q", got2.statusMsg)
	}

	// 3. Clear/Correct input and try again — should allow navigation
	got2.configInput.SetValue("")
	next3, _ := got2.handleConfigOptionalKey(tea.KeyMsg{Type: tea.KeyEnter})
	got3 := next3.(AppModel)
	if got3.configOptionalRow != 1 {
		t.Fatalf("expected row to advance to 1 with empty config, got %d", got3.configOptionalRow)
	}
	if got3.statusMsg != "" {
		t.Fatalf("expected statusMsg to be cleared, got %q", got3.statusMsg)
	}
}

func TestParsedConfigSummaryShowsXHTTPAndEncryption(t *testing.T) {
	raw := "vless://11111111-1111-1111-1111-111111111111@104.17.122.146:443?encryption=mlkem768x25519plus.native.0rtt.bE9x9OGq01jLGzKdCeP88_YCTxIJ8rIa4pxl7cQleEI&security=tls&sni=insane.mozsub.ir&type=xhttp&host=insane.mozsub.ir&path=%2Fmozzywozzy&mode=auto#Main-Moz"
	got := parsedConfigSummary(raw)
	for _, want := range []string{"vless", "xhttp", "insane.mozsub.ir", "mlkem"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q does not contain %q", got, want)
		}
	}
}

func TestSelectPhase2CandidatesSpreadsLatency(t *testing.T) {
	var results []*result.Result
	for i := 0; i < 100; i++ {
		results = append(results, phase2CandidateForTest(
			fmt.Sprintf("104.16.0.%d", i+1),
			time.Duration(100+i)*time.Millisecond,
		))
	}

	got := selectPhase2Candidates(results, 10)
	if len(got) != 10 {
		t.Fatalf("selected %d candidates, want 10", len(got))
	}
	if maxPhase2LatencyForTest(got) < 180*time.Millisecond {
		t.Fatalf("selected candidates only cover up to %s; want higher-latency candidates included", maxPhase2LatencyForTest(got))
	}
}

func TestSelectPhase2CandidatesDiversifiesRanges(t *testing.T) {
	var results []*result.Result
	for i := 0; i < 40; i++ {
		results = append(results, phase2CandidateForTest(
			fmt.Sprintf("104.25.0.%d", i+1),
			time.Duration(100+i)*time.Millisecond,
		))
	}
	for i := 0; i < 20; i++ {
		results = append(results, phase2CandidateForTest(
			fmt.Sprintf("104.17.122.%d", i+1),
			time.Duration(180+i)*time.Millisecond,
		))
	}
	for i := 0; i < 20; i++ {
		results = append(results, phase2CandidateForTest(
			fmt.Sprintf("104.18.152.%d", i+1),
			time.Duration(200+i)*time.Millisecond,
		))
	}

	got := selectPhase2Candidates(results, 6)
	if !phase2SelectionHasPrefix(got, "104.17.") {
		t.Fatalf("selection did not include 104.17 range: %v", phase2SelectionIPs(got))
	}
	if !phase2SelectionHasPrefix(got, "104.18.") {
		t.Fatalf("selection did not include 104.18 range: %v", phase2SelectionIPs(got))
	}
}

func TestSelectPhase2CandidatesAllUsesSpreadOrder(t *testing.T) {
	var results []*result.Result
	for i := 0; i < 100; i++ {
		results = append(results, phase2CandidateForTest(
			fmt.Sprintf("104.16.0.%d", i+1),
			time.Duration(100+i)*time.Millisecond,
		))
	}

	got := selectPhase2Candidates(results, 0)
	if len(got) != 100 {
		t.Fatalf("selected %d candidates, want all", len(got))
	}
	if got[5].Avg() < 180*time.Millisecond {
		t.Fatalf("all-candidate order stayed too latency-sorted; sixth latency = %s", got[5].Avg())
	}
}

func TestSelectPhase2CandidatesDeduplicatesEndpoints(t *testing.T) {
	results := []*result.Result{
		phase2CandidateForTest("104.18.1.1", 100*time.Millisecond),
		phase2CandidateForTest("104.18.1.1", 110*time.Millisecond),
		phase2CandidateForTest("104.18.1.2", 120*time.Millisecond),
	}
	got := selectPhase2Candidates(results, 0)
	if len(got) != 2 {
		t.Fatalf("selected %d candidates, want 2", len(got))
	}
	if got[0].IP.String() != "104.18.1.1" || got[1].IP.String() != "104.18.1.2" {
		t.Fatalf("selected candidates = %v", phase2SelectionIPs(got))
	}
}

func TestGatherNeighborsRoundRobin(t *testing.T) {
	_, loopbackNet, err := net.ParseCIDR("127.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	nets := []*net.IPNet{loopbackNet}

	r1 := &result.Result{IP: net.ParseIP("127.0.0.10"), Latencies: []time.Duration{10 * time.Millisecond}, ProbeMode: "tcp"}
	r2 := &result.Result{IP: net.ParseIP("127.0.0.20"), Latencies: []time.Duration{20 * time.Millisecond}, ProbeMode: "tcp"}

	neighbors := gatherNeighbors([]*result.Result{r1, r2}, nets, 2, 4, 6)

	if len(neighbors) != 6 {
		t.Fatalf("expected 6 neighbors, got %d", len(neighbors))
	}

	expected := []string{
		"127.0.0.11",
		"127.0.0.21",
		"127.0.0.9",
		"127.0.0.19",
		"127.0.0.12",
		"127.0.0.22",
	}

	for i, ip := range neighbors {
		if ip.String() != expected[i] {
			t.Errorf("at index %d: expected %s, got %s", i, expected[i], ip.String())
		}
	}
}

func TestPhase2WorkerCountScalesForLargeBatches(t *testing.T) {
	if got := phase2WorkerCount(2000); got != 32 {
		t.Fatalf("workers for large batch = %d, want 32", got)
	}
	if got := phase2WorkerCount(3); got != 3 {
		t.Fatalf("workers for small batch = %d, want 3", got)
	}
}

func TestClampPhase2Workers(t *testing.T) {
	if got := clampPhase2Workers(100); got != maxPhase2Workers {
		t.Fatalf("clamped workers = %d, want %d", got, maxPhase2Workers)
	}
	if got := clampPhase2Workers(12); got != 12 {
		t.Fatalf("clamped workers = %d, want 12", got)
	}
}

func TestUniquePhase2Candidates(t *testing.T) {
	got := uniquePhase2Candidates([]*result.Result{
		phase2CandidateForTest("104.18.1.1", 100*time.Millisecond),
		phase2CandidateForTest("104.18.1.1", 200*time.Millisecond),
		phase2CandidateForTest("104.18.1.2", 150*time.Millisecond),
		nil,
	})
	if len(got) != 2 {
		t.Fatalf("unique candidates = %d, want 2", len(got))
	}
	if got[0].IP.String() != "104.18.1.1" || got[1].IP.String() != "104.18.1.2" {
		t.Fatalf("unique candidates = %v", phase2SelectionIPs(got))
	}
}

func TestValidationOutcomeCountsSeparatesSkipped(t *testing.T) {
	success, failed, skipped := validationOutcomeCounts([]*xraytest.ValidationResult{
		{Success: true},
		{Success: false, Error: "tls handshake timeout"},
		{Success: false, Error: "skipped: canceled"},
	})
	if success != 1 || failed != 1 || skipped != 1 {
		t.Fatalf("counts = success %d failed %d skipped %d, want 1/1/1", success, failed, skipped)
	}
	if got := validationSuccessRate(success, failed); got != 50 {
		t.Fatalf("success rate = %.1f, want 50.0", got)
	}
}

func phase2CandidateForTest(ip string, latency time.Duration) *result.Result {
	return &result.Result{
		IP:        net.ParseIP(ip),
		Port:      443,
		ProbeMode: "tcp",
		Latencies: []time.Duration{latency},
	}
}

func phase2SelectionHasPrefix(results []*result.Result, prefix string) bool {
	for _, r := range results {
		if strings.HasPrefix(r.IP.String(), prefix) {
			return true
		}
	}
	return false
}

func phase2SelectionIPs(results []*result.Result) []string {
	ips := make([]string, 0, len(results))
	for _, r := range results {
		ips = append(ips, r.IP.String())
	}
	return ips
}

func maxPhase2LatencyForTest(results []*result.Result) time.Duration {
	var max time.Duration
	for _, r := range results {
		if r.Avg() > max {
			max = r.Avg()
		}
	}
	return max
}

func TestSortStabilityResults(t *testing.T) {
	r1 := &result.Result{
		IP:        net.ParseIP("1.1.1.1"),
		Port:      443,
		Latencies: []time.Duration{100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond}, // 0% loss, 0ms jitter, 100ms avg
	}
	r2 := &result.Result{
		IP:        net.ParseIP("1.1.1.2"),
		Port:      443,
		Latencies: []time.Duration{100 * time.Millisecond, 150 * time.Millisecond, 50 * time.Millisecond}, // 0% loss, some jitter, 100ms avg
	}
	r3 := &result.Result{
		IP:        net.ParseIP("1.1.1.3"),
		Port:      443,
		Latencies: []time.Duration{0, 100 * time.Millisecond, 100 * time.Millisecond}, // 33.3% loss, 100ms avg
	}
	r4 := &result.Result{
		IP:        net.ParseIP("1.1.1.4"),
		Port:      443,
		Latencies: []time.Duration{50 * time.Millisecond, 50 * time.Millisecond, 50 * time.Millisecond}, // 0% loss, 0ms jitter, 50ms avg
	}
	r5 := &result.Result{
		IP:        net.ParseIP("1.1.1.5"),
		Port:      443,
		Latencies: []time.Duration{0, 0, 0}, // 100% loss
	}

	results := []*result.Result{r3, r2, r5, r1, r4}
	SortStabilityResults(results)

	if results[0] != r4 {
		t.Errorf("expected index 0 to be r4 (50ms avg, 0 jitter), got %s", results[0].IP)
	}
	if results[1] != r1 {
		t.Errorf("expected index 1 to be r1 (100ms avg, 0 jitter), got %s", results[1].IP)
	}
	if results[2] != r2 {
		t.Errorf("expected index 2 to be r2 (100ms avg, non-zero jitter), got %s", results[2].IP)
	}
	if results[3] != r3 {
		t.Errorf("expected index 3 to be r3 (33%% loss), got %s", results[3].IP)
	}
	if results[4] != r5 {
		t.Errorf("expected index 4 to be r5 (100%% loss), got %s", results[4].IP)
	}
}

func TestConfigurationProfiles(t *testing.T) {
	// 1. Check IP scanner presets
	m := NewApp("test")

	// Default should be Balanced (1)
	if m.configProfileIdx != 1 {
		t.Fatalf("expected default configProfileIdx = 1, got %d", m.configProfileIdx)
	}

	// Change to Fast (0) and apply
	m.configProfileIdx = 0
	m.applyConfigProfile()
	if m.configCountIdx != 1 || m.configWorkersIdx != 2 || m.configTimeoutIdx != 0 {
		t.Errorf("Fast profile didn't set correct values: count=%d workers=%d timeout=%d",
			m.configCountIdx, m.configWorkersIdx, m.configTimeoutIdx)
	}

	// Change count and verify it shifts to Custom (3)
	m.configCountIdx = 2
	m.updateConfigProfileFromSettings()
	if m.configProfileIdx != 3 {
		t.Errorf("expected profile to drop to Custom (3), got %d", m.configProfileIdx)
	}

	// Restore Fast settings manually and verify it auto-detects Fast (0)
	m.configCountIdx = 1
	m.configWorkersIdx = 2
	m.configTimeoutIdx = 0
	m.updateConfigProfileFromSettings()
	if m.configProfileIdx != 0 {
		t.Errorf("expected profile to auto-detect Fast (0), got %d", m.configProfileIdx)
	}

	// 2. Check stability test presets
	// Default should be Balanced (1)
	if m.stabilityProfileIdx != 1 {
		t.Fatalf("expected default stabilityProfileIdx = 1, got %d", m.stabilityProfileIdx)
	}

	// Change to Accurate (2) and apply
	m.stabilityProfileIdx = 2
	m.applyStabilityProfile()
	if m.stabilityTriesIdx != 3 || m.stabilityIntervalIdx != 1 || m.stabilityWorkersIdx != 0 || m.stabilityPortIdx != 0 {
		t.Errorf("Accurate profile didn't set correct values: tries=%d interval=%d workers=%d port=%d",
			m.stabilityTriesIdx, m.stabilityIntervalIdx, m.stabilityWorkersIdx, m.stabilityPortIdx)
	}

	// Change workers and verify it shifts to Custom (3)
	m.stabilityWorkersIdx = 2
	m.updateStabilityProfileFromSettings()
	if m.stabilityProfileIdx != 3 {
		t.Errorf("expected stability profile to drop to Custom (3), got %d", m.stabilityProfileIdx)
	}

	// Restore Balanced settings manually and verify it auto-detects Balanced (1)
	m.stabilityTriesIdx = 1
	m.stabilityIntervalIdx = 1
	m.stabilityWorkersIdx = 1
	m.stabilityPortIdx = 0
	m.updateStabilityProfileFromSettings()
	if m.stabilityProfileIdx != 1 {
		t.Errorf("expected stability profile to auto-detect Balanced (1), got %d", m.stabilityProfileIdx)
	}
}
