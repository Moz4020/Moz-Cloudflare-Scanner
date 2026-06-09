package ui

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/moz/moz-cloudflare-scanner/internal/result"
	"github.com/moz/moz-cloudflare-scanner/internal/xraytest"
)

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

// tickMsg drives banner animation and stat refresh.
type tickMsg time.Time

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

var (
	styleBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#F6821F"))

	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F6821F"))

	styleSelected = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFE066")).
			Background(lipgloss.Color("#1A1A2E"))

	styleNormal = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CCCCCC"))

	styleDim = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))

	styleGood = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#27AE60")).Bold(true)

	styleWarn = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F39C12"))

	styleBad = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E74C3C"))

	styleAccent = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F6821F")).Bold(true)

	styleHint = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#444466")).Italic(true)

	styleHeader = lipgloss.NewStyle().
			Bold(true).Foreground(lipgloss.Color("#888888"))

	styleSep = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#333333"))

	styleColEndpoint = lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0"))
	styleColLoss0    = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	styleColLossBad  = lipgloss.NewStyle().Foreground(lipgloss.Color("#E74C3C")).Bold(true)

	styleColLatencyFast = lipgloss.NewStyle().Foreground(lipgloss.Color("#00E676")).Bold(true)
	styleColLatencyMid  = lipgloss.NewStyle().Foreground(lipgloss.Color("#F39C12"))
	styleColLatencySlow = lipgloss.NewStyle().Foreground(lipgloss.Color("#E74C3C"))

	styleColColo    = lipgloss.NewStyle().Foreground(lipgloss.Color("#9D4EDD")).Bold(true)
	styleColBracket = lipgloss.NewStyle().Foreground(lipgloss.Color("#444466"))
)

type quickPreset struct {
	label string
	value string // empty = custom
}

var quickWorkersPresets = []quickPreset{
	{"Safe 50", "50"},
	{"Balanced 100", "100"},
	{"Fast 200", "200"},
	{"Max 300", "300"},
	{"Custom", ""},
}

var quickTimeoutPresets = []quickPreset{
	{"Fast 2s", "2s"},
	{"Balanced 3s", "3s"},
	{"Safe 5s", "5s"},
	{"Custom", ""},
}

var phase2WorkersPresets = []quickPreset{
	{"Safe 10", "10"},
	{"Balanced 30", "30"},
	{"Fast 60", "60"},
	{"Max 64", "64"},
	{"Custom", ""},
}

func phase2WorkersLabels() []string {
	labels := make([]string, len(phase2WorkersPresets))
	for i, p := range phase2WorkersPresets {
		labels[i] = p.label
	}
	return labels
}

func (m AppModel) isPhase2WorkersCustomSelected() bool {
	return m.configPhase2WorkersIdx == len(phase2WorkersPresets)-1
}

// ---------------------------------------------------------------------------
// AppModel — root Bubble Tea model
// ---------------------------------------------------------------------------

type AppModel struct {
	page   Page
	width  int
	height int

	// animation
	bannerFrame int
	spinner     spinner.Model

	// home menu
	menuIdx int

	// scan state
	scanStarted  time.Time
	scanDuration time.Duration

	// scan with config
	configInput    textinput.Model
	configResults  []*xraytest.ValidationResult
	configScanning bool
	configDone     bool
	configTotal    int
	// v2ray config generator
	generatorInput       textinput.Model
	generatorPrefixInput textinput.Model
	generatorRow         int // 0=config, 1=name prefix, 2=generate
	generatorOutputPath  string
	generatorCount       int
	// config setup options
	configURL      string
	configCountIdx int // index into configCountValues
	configTopNIdx  int // index into configTopNValues
	configSetupRow int // 0=source, 1=count, 2=workers, 3=timeout, 4=ports
	// quick-scan-style pickers for Phase 1
	configWorkersIdx          int
	configTimeoutIdx          int
	configIPMode              int // configIPSource*
	configCustomInput         textinput.Model
	configCustomMode          bool
	configCustomRow           int    // 1=count, 2=workers, 3=timeout, 5=topN custom
	configCountCustom         string // value when Custom count is selected
	configWorkersCustom       string // value when Custom workers is selected
	configTimeoutCustom       string // value when Custom timeout is selected
	configTopNCustom          string // value when Custom top N is selected
	configPhase2WorkersIdx    int    // index into phase2WorkersPresets
	configPhase2WorkersCustom string // value when Custom workers is selected for Phase 2
	configOptionalRow         int    // 0=config URL, 1=validate top N, 2=workers, 3=start
	configPortFocus           int
	configSelectedPorts       map[int]bool
	// phase 1 state
	configPhase1Results     []*result.Result
	configPhase1Done        bool
	configPhase1Only        bool // true when scan stops after Phase 1 (no config URL)
	configPhase1Total       int  // intended IP count for Phase 1 progress display
	configPhase1Neighboring bool // true when scanning neighboring IPs
	liveResultPath          string

	// shared
	statusMsg string
	version   string
}

type menuEntry struct {
	label string
	desc  string
}

var menuEntries = []menuEntry{
	{"Find Working IPs", "scan default Cloudflare or ips.txt ranges"},
	{"Generate V2Ray Configs", "turn ips.txt + one VLESS URL into configs.txt"},
	{"About", ""},
	{"Quit", ""},
}

const menuLabelWidth = 22

const (
	menuFindWorking = 0
	menuGenerate    = 1
	menuAbout       = 2
	menuQuit        = 3
)

var modes = []string{"tls", "tcp", "http"}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func NewApp(version string) AppModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#F6821F"))

	m := AppModel{
		page:                   PageHome,
		spinner:                sp,
		version:                version,
		width:                  120,
		height:                 40,
		scanStarted:            time.Now(),
		configCountIdx:         2,
		configWorkersIdx:       1,
		configTimeoutIdx:       1,
		configPhase2WorkersIdx: 1, // default: Balanced 50
	}

	// Config input for "Scan with Config"
	cfgInput := textinput.New()
	cfgInput.Placeholder = "vless:// or trojan:// share URL"
	cfgInput.CharLimit = 2000
	cfgInput.Width = 58
	cfgInput.Prompt = "› "
	cfgInput.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F6821F")).Bold(true)
	cfgInput.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#CCCCCC"))
	cfgInput.PlaceholderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	m.configInput = cfgInput

	genInput := textinput.New()
	genInput.Placeholder = "paste your working vless:// config"
	genInput.CharLimit = 2000
	genInput.Width = 58
	genInput.Prompt = "› "
	genInput.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F6821F")).Bold(true)
	genInput.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#CCCCCC"))
	genInput.PlaceholderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	m.generatorInput = genInput

	genPrefixInput := textinput.New()
	genPrefixInput.Placeholder = "e.g. Test-fast"
	genPrefixInput.CharLimit = 80
	genPrefixInput.Width = 34
	genPrefixInput.Prompt = "› "
	genPrefixInput.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F6821F")).Bold(true)
	genPrefixInput.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#CCCCCC"))
	genPrefixInput.PlaceholderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	m.generatorPrefixInput = genPrefixInput

	cfgCustom := textinput.New()
	cfgCustom.Placeholder = "enter value"
	cfgCustom.CharLimit = 10
	cfgCustom.Width = 12
	cfgCustom.Prompt = "› "
	cfgCustom.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F6821F")).Bold(true)
	cfgCustom.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#CCCCCC"))
	cfgCustom.PlaceholderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	m.configCustomInput = cfgCustom

	return m
}

// ---------------------------------------------------------------------------
// tea.Model interface
// ---------------------------------------------------------------------------

func (m AppModel) Init() tea.Cmd {
	return tea.Batch(
		tick(),
		m.spinner.Tick,
		textinput.Blink,
		tea.EnableBracketedPaste,
	)
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		m.bannerFrame++
		return m, tick()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case ConfigProgressMsg:
		m.configResults = append(m.configResults, msg.Result)
		m.configTotal = msg.Total
		return m, nil

	case ConfigDoneMsg:
		m.configScanning = false
		m.configDone = true
		m.scanDuration = time.Since(m.scanStarted)
		return m, nil

	case ConfigPhase1ResultMsg:
		m.configPhase1Results = append(m.configPhase1Results, msg.Result)
		return m, nil

	case ConfigPhase1TotalUpdateMsg:
		m.configPhase1Total = msg.Total
		return m, nil

	case ConfigPhase1NeighboringMsg:
		m.configPhase1Neighboring = msg.Neighboring
		return m, nil

	case ConfigPhase1ErrMsg:
		m.configScanning = false
		clearLiveResultWriter()
		m.page = PageScanWithConfig
		m.statusMsg = msg.Err
		return m, nil

	case ConfigPhase1DoneMsg:
		m.configPhase1Done = true
		if strings.TrimSpace(m.configURL) == "" {
			m.configPhase1Only = true
			m.scanDuration = time.Since(m.scanStarted)
			if liveResultWriter != nil {
				liveResultWriter.FinishPhase1Only()
			}
			return m, nil
		}
		topN := m.resolveTopN()
		phase2IPs := selectPhase2Candidates(m.configPhase1Results, topN)
		m.configTotal = len(phase2IPs)
		// If Phase 1 found no healthy IPs, stay on the Phase 1 page and show
		// a clear "no results" message (Phase 2 would have nothing to do).
		if len(phase2IPs) == 0 {
			m.configPhase1Done = true
			m.page = PageConfigPhase2
			m.configScanning = false
			m.configDone = true
			return m, nil
		}
		// Start Phase 2 with candidates spread across latency and IP ranges.
		if liveResultWriter != nil {
			liveResultWriter.BeginPhase2()
		}
		m.page = PageConfigPhase2
		m.scanStarted = time.Now()
		m.configScanning = true
		m.configDone = false
		m.configResults = nil
		return m, m.startConfigPhase2(phase2IPs)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m.updateFormInputs(msg)
}

// ---------------------------------------------------------------------------
// Key handling (dispatched by page)
// ---------------------------------------------------------------------------

func (m AppModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.page {
	case PageHome:
		return m.handleHomeKey(msg)
	case PageAbout:
		if msg.String() == "q" || msg.String() == "esc" || msg.String() == "enter" {
			m.page = PageHome
		}
		return m, nil
	case PageScanWithConfig:
		return m.handleScanWithConfigKey(msg)
	case PageGenerateConfigs:
		return m.handleGenerateConfigsKey(msg)
	case PageConfigOptional:
		return m.handleConfigOptionalKey(msg)
	case PageConfigPhase1:
		return m.handleConfigPhase1Key(msg)
	case PageConfigPhase2:
		return m.handleScanWithConfigKey(msg)
	}
	return m, nil
}

func (m AppModel) handleHomeKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "up", "k":
		if m.menuIdx > 0 {
			m.menuIdx--
		}
	case "down", "j":
		if m.menuIdx < len(menuEntries)-1 {
			m.menuIdx++
		}
	case "enter", " ":
		return m.selectMenuItem()
	}
	return m, nil
}

func (m AppModel) selectMenuItem() (tea.Model, tea.Cmd) {
	switch m.menuIdx {
	case menuFindWorking:
		m.page = PageScanWithConfig
		m.configInput.SetValue("")
		m.configInput.Blur()
		m.configResults = nil
		m.configScanning = false
		m.configDone = false
		m.configSetupRow = 0
		m.configOptionalRow = 0
		m.configCountIdx = 2         // default: Balanced 20k
		m.configTopNIdx = 2          // default: 50 for Phase 2
		m.configWorkersIdx = 1       // default: Balanced 100
		m.configTimeoutIdx = 1       // default: Balanced 3s
		m.configPhase2WorkersIdx = 1 // default: Balanced 50
		m.configPhase2WorkersCustom = ""
		m.configIPMode = configIPSourceDefault // default: random Cloudflare IPs
		m.configPortFocus = 0
		m.configSelectedPorts = nil
		m.configCustomMode = false
		m.configCountCustom = ""
		m.configWorkersCustom = ""
		m.configTimeoutCustom = ""
		m.configTopNCustom = ""
		m.configCustomInput.SetValue("")
		m.configCustomInput.Blur()
		m.configURL = ""
		m.configPhase1Only = false
		m.liveResultPath = ""
		clearLiveResultWriter()
		m.statusMsg = ""
		return m, nil
	case menuGenerate:
		m.page = PageGenerateConfigs
		m.generatorInput.SetValue("")
		m.generatorInput.Focus()
		m.generatorPrefixInput.SetValue("")
		m.generatorPrefixInput.Blur()
		m.generatorRow = 0
		m.generatorOutputPath = ""
		m.generatorCount = 0
		m.statusMsg = ""
		return m, textinput.Blink
	case menuAbout:
		m.page = PageAbout
	case menuQuit:
		return m, tea.Quit
	}
	return m, nil
}

var clipboardWriteAll = clipboard.WriteAll

func (m AppModel) copyWorkingIPs() string {
	endpoints := workingEndpoints(m.configResults)
	if len(endpoints) == 0 {
		return "no working endpoints to copy"
	}
	return copyAndSaveIPs(endpoints)
}

func workingIPs(results []*xraytest.ValidationResult) []string {
	return workingEndpoints(results)
}

func workingEndpoints(results []*xraytest.ValidationResult) []string {
	working := make([]*xraytest.ValidationResult, 0, len(results))
	for _, r := range results {
		if r == nil || !r.Success || r.IP == "" {
			continue
		}
		working = append(working, r)
	}

	sort.SliceStable(working, func(i, j int) bool {
		a, b := working[i], working[j]
		aLatency := validationLatencyRank(a.Latency)
		bLatency := validationLatencyRank(b.Latency)
		if aLatency != bLatency {
			return aLatency < bLatency
		}
		aEndpoint := formatEndpoint(a.IP, a.Port)
		bEndpoint := formatEndpoint(b.IP, b.Port)
		return aEndpoint < bEndpoint
	})

	endpoints := make([]string, 0, len(working))
	seen := make(map[string]struct{})
	for _, r := range working {
		endpoint := formatEndpoint(r.IP, r.Port)
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func validationLatencyRank(latency time.Duration) time.Duration {
	if latency <= 0 {
		return time.Duration(1<<63 - 1)
	}
	return latency
}

func formatEndpoint(ip string, port int) string {
	if port <= 0 {
		return ip
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

const (
	endpointColWidth  = 24
	transportColWidth = 7
	metricColWidth    = 9
	statusColWidth    = 14
)

func endpointHeader(statusLabel string) string {
	return fmt.Sprintf("  %-*s  %7s  %9s  %-6s  %-*s",
		endpointColWidth, "ENDPOINT",
		"LOSS",
		"LATENCY",
		"COLO",
		statusColWidth, statusLabel,
	)
}

func endpointCandidateRow(r *result.Result, status string) string {
	colo := r.Colo
	if colo == "" {
		colo = "---"
	}

	endpointStr := formatEndpoint(r.IP.String(), r.Port)
	endpointFormatted := styleColEndpoint.Render(fmt.Sprintf("%-*s", endpointColWidth, endpointStr))

	lossStr := fmt.Sprintf("%6.1f%%", r.Loss())
	var lossFormatted string
	if r.Loss() == 0 {
		lossFormatted = styleColLoss0.Render(lossStr)
	} else {
		lossFormatted = styleColLossBad.Render(lossStr)
	}

	avg := r.Avg()
	latencyStr := fmt.Sprintf("%8s", formatDurationShort(avg))
	var latencyFormatted string
	if avg <= 0 {
		latencyFormatted = styleDim.Render(latencyStr)
	} else if avg < 300*time.Millisecond {
		latencyFormatted = styleColLatencyFast.Render(latencyStr)
	} else if avg < 500*time.Millisecond {
		latencyFormatted = styleColLatencyMid.Render(latencyStr)
	} else {
		latencyFormatted = styleColLatencySlow.Render(latencyStr)
	}

	coloFormatted := fmt.Sprintf("%s%s%s",
		styleColBracket.Render("["),
		styleColColo.Render(fmt.Sprintf("%-3s", colo)),
		styleColBracket.Render("]"),
	)

	var rawStatus string
	var statusStyle lipgloss.Style
	if !r.IsHealthy() {
		rawStatus = "✗ failed"
		statusStyle = styleColLossBad
	} else {
		rawStatus = "✓ candidate"
		statusStyle = styleColLatencyFast
	}
	statusFormatted := statusStyle.Render(fmt.Sprintf("%-*s", statusColWidth, rawStatus))

	return fmt.Sprintf("  %s  %s  %s  %s  %s",
		endpointFormatted,
		lossFormatted,
		latencyFormatted,
		coloFormatted,
		statusFormatted,
	)
}

func validationHeader() string {
	return fmt.Sprintf("  %-*s  %-*s  %9s  %-*s",
		endpointColWidth, "ENDPOINT",
		transportColWidth, "TYPE",
		"LATENCY",
		statusColWidth, "STATUS",
	)
}

func validationRow(r *xraytest.ValidationResult, status string) string {
	endpointStr := formatEndpoint(r.IP, r.Port)
	endpointFormatted := styleColEndpoint.Render(fmt.Sprintf("%-*s", endpointColWidth, endpointStr))

	typeStr := fmt.Sprintf("%-*s", transportColWidth, r.Transport)
	var typeFormatted string
	switch strings.ToLower(r.Transport) {
	case "ws":
		typeFormatted = lipgloss.NewStyle().Foreground(lipgloss.Color("#00B4D8")).Bold(true).Render(typeStr)
	case "grpc":
		typeFormatted = lipgloss.NewStyle().Foreground(lipgloss.Color("#9D4EDD")).Bold(true).Render(typeStr)
	default:
		typeFormatted = lipgloss.NewStyle().Foreground(lipgloss.Color("#F6821F")).Bold(true).Render(typeStr)
	}

	latencyStr := "-"
	if r.Success {
		latencyStr = formatValidationLatency(r.Latency)
	}
	latencyPadded := fmt.Sprintf("%9s", latencyStr)
	var latencyFormatted string
	if !r.Success {
		latencyFormatted = styleDim.Render(latencyPadded)
	} else if r.Latency < 300*time.Millisecond {
		latencyFormatted = styleColLatencyFast.Render(latencyPadded)
	} else if r.Latency < 500*time.Millisecond {
		latencyFormatted = styleColLatencyMid.Render(latencyPadded)
	} else {
		latencyFormatted = styleColLatencySlow.Render(latencyPadded)
	}

	var rawStatus string
	var statusStyle lipgloss.Style
	if r.Success {
		rawStatus = "✓ working"
		statusStyle = styleColLatencyFast
	} else {
		rawStatus = "✗ failed"
		statusStyle = styleColLossBad
	}
	statusFormatted := statusStyle.Render(fmt.Sprintf("%-*s", statusColWidth, rawStatus))

	return fmt.Sprintf("  %s  %s  %s  %s",
		endpointFormatted,
		typeFormatted,
		latencyFormatted,
		statusFormatted,
	)
}

func tableSeparator(width int) string {
	if width < 40 {
		width = 40
	}
	return "  " + strings.Repeat("─", width)
}

func formatDurationShort(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func truncateMiddle(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	left := (max - 3) / 2
	right := max - 3 - left
	return s[:left] + "..." + s[len(s)-right:]
}



func formatValidationLatency(latency time.Duration) string {
	if latency <= 0 {
		return "—"
	}
	ms := latency.Milliseconds()
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", latency.Seconds())
}

func copyAndSaveIPs(ips []string) string {
	text := strings.Join(ips, "\n") + "\n"
	clipErr := clipboardWriteAll(text)
	path, fileErr := writeIPsBesideExecutable(ips)

	switch {
	case clipErr == nil && fileErr == nil:
		return fmt.Sprintf("copied %d working endpoints; saved to %s", len(ips), path)
	case clipErr != nil && fileErr == nil:
		return fmt.Sprintf("clipboard failed; saved %d working endpoints to %s", len(ips), path)
	case clipErr == nil && fileErr != nil:
		return fmt.Sprintf("copied %d working endpoints; save failed: %v", len(ips), fileErr)
	default:
		return fmt.Sprintf("copy failed: %v; save failed: %v", clipErr, fileErr)
	}
}

func writeIPsBesideExecutable(ips []string) (string, error) {
	exe, err := os.Executable()
	dir := ""
	if err == nil {
		dir = filepath.Dir(exe)
	}
	if dir == "" {
		dir, err = os.Getwd()
		if err != nil {
			dir = "."
		}
	}
	path := filepath.Join(dir, "ips.txt")
	if err := writeIPsFile(path, ips); err == nil {
		return path, nil
	}

	wd, wdErr := os.Getwd()
	if wdErr != nil {
		return path, wdErr
	}
	fallback := filepath.Join(wd, "ips.txt")
	if fallback == path {
		err := writeIPsFile(fallback, ips)
		return fallback, err
	}
	err = writeIPsFile(fallback, ips)
	return fallback, err
}

func writeIPsFile(path string, ips []string) error {
	text := strings.Join(ips, "\n")
	if text != "" {
		text += "\n"
	}
	return os.WriteFile(path, []byte(text), 0644)
}

// updateFormInputs forwards non-key messages (e.g. paste events, resize) to
// every focused text input so they can handle them independently.
func (m AppModel) updateFormInputs(msg tea.Msg) (AppModel, tea.Cmd) {
	var cmds []tea.Cmd

	if m.page == PageScanWithConfig && !m.configScanning && !m.configDone {
		if m.configCustomMode {
			var cmd tea.Cmd
			m.configCustomInput, cmd = m.configCustomInput.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	if m.page == PageConfigOptional {
		if m.configCustomMode {
			var cmd tea.Cmd
			m.configCustomInput, cmd = m.configCustomInput.Update(msg)
			cmds = append(cmds, cmd)
		} else {
			var cmd tea.Cmd
			m.configInput, cmd = m.configInput.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

func (m AppModel) View() string {
	switch m.page {
	case PageHome:
		return m.viewHome()
	case PageAbout:
		return m.viewAbout()
	case PageScanWithConfig:
		return m.viewScanWithConfig()
	case PageGenerateConfigs:
		return m.viewGenerateConfigs()
	case PageConfigOptional:
		return m.viewConfigOptional()
	case PageConfigPhase1:
		return m.viewConfigPhase1()
	case PageConfigPhase2:
		return m.viewScanWithConfig()
	}
	return ""
}

// ---------------------------------------------------------------------------
// Home page
// ---------------------------------------------------------------------------

func (m AppModel) viewHome() string {
	var sb strings.Builder

	sb.WriteRune('\n')
	for _, line := range mainMenuASCII {
		sb.WriteString("  " + gradientText(line, m.bannerFrame/3, []string{
			"#B066FF", "#8F7CFF", "#6C8DFF", "#4B9BFF", "#35B8FF",
		}) + "\n")
	}
	sb.WriteString(styleDim.Render("  Cloudflare endpoint scanner for desktop and VPS"))
	sb.WriteString("\n")
	sb.WriteString(styleAccent.Render("  " + m.version))
	sb.WriteString("\n\n")

	// Menu
	for i, item := range menuEntries {
		cursor := "  "
		labelStyle := styleNormal
		if i == m.menuIdx {
			cursor = styleAccent.Render("▶ ")
			labelStyle = styleSelected
		}

		line := "  " + cursor + labelStyle.Render(fmt.Sprintf("%-*s", menuLabelWidth, item.label))
		if item.desc != "" {
			line += "  " + styleDim.Render(item.desc)
		}
		sb.WriteString(line)
		sb.WriteRune('\n')
	}

	sb.WriteRune('\n')
	sb.WriteString(styleHint.Render("  ↑/↓ navigate   enter select   q quit"))
	sb.WriteRune('\n')

	return sb.String()
}

var mainMenuASCII = []string{
	" __  __  ___  ____",
	"|  \\/  |/ _ \\|_  /",
	"| |\\/| | (_) |/ / ",
	"|_|  |_|\\___//___|",
	" Cloudflare Scanner",
}

func gradientText(text string, frame int, palette []string) string {
	if len(palette) == 0 {
		return text
	}
	var sb strings.Builder
	runes := []rune(text)
	for i, r := range runes {
		idx := i * (len(palette) - 1) / maxInt(len(runes)-1, 1)
		idx = (idx + frame) % len(palette)
		if idx < 0 {
			idx += len(palette)
		}
		sb.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(palette[idx])).
			Render(string(r)))
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// V2Ray config generator
// ---------------------------------------------------------------------------

func (m AppModel) viewGenerateConfigs() string {
	var sb strings.Builder

	sb.WriteString("\n" + styleTitle.Render("  Generate V2Ray Configs") + "\n")
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 76)))))

	rowLabel := func(row int, text string) {
		if m.generatorRow == row {
			sb.WriteString(styleAccent.Render(text))
		} else {
			sb.WriteString(styleDim.Render(text))
		}
	}

	rowLabel(0, "  Config ")
	sb.WriteString(m.generatorInput.View() + "\n")
	if summary := parsedConfigSummary(m.generatorInput.Value()); summary != "" {
		sb.WriteString(styleDim.Render("           "+summary) + "\n\n")
	} else {
		sb.WriteString(styleDim.Render("           paste one working VLESS config; endpoints come from ips.txt") + "\n\n")
	}

	rowLabel(1, "  Prefix ")
	sb.WriteString(m.generatorPrefixInput.View() + "\n")
	prefixPreview := strings.TrimSpace(m.generatorPrefixInput.Value())
	if prefixPreview == "" {
		prefixPreview = "Main-Moz"
	}
	sb.WriteString(styleDim.Render(fmt.Sprintf("           generated remarks look like: %s 1, %s 2, ...", prefixPreview, prefixPreview)) + "\n\n")

	rowLabel(2, "  Create ")
	if m.generatorRow == 2 {
		sb.WriteString(styleAccent.Render("› ") + styleNormal.Render("configs.txt") + "\n")
	} else {
		sb.WriteString(styleDim.Render("› configs.txt") + "\n")
	}
	sb.WriteString(styleDim.Render("           press Enter here to generate one v2rayN import URL per endpoint") + "\n\n")

	gridWidth := minInt(m.width-4, 76)
	if m.generatorCount > 0 {
		path := truncateMiddle(m.generatorOutputPath, gridWidth-12)
		sb.WriteString(styleGood.Render("  ✓ Success! ") + styleNormal.Render(fmt.Sprintf("Generated %d v2rayN configs.", m.generatorCount)) + "\n")
		sb.WriteString(styleDim.Render("    File: ") + styleAccent.Render(path) + "\n\n")
	}

	sb.WriteString(styleDim.Render("  Input   ips.txt next to the exe or current run folder; supports IP or IP:port") + "\n")
	sb.WriteString(styleDim.Render("  Output  configs.txt next to the ips.txt file") + "\n\n")

	if m.statusMsg != "" {
		sb.WriteString(styleWarn.Render("  "+m.statusMsg) + "\n\n")
	}

	hint := "  ↑/↓ row   enter select/generate   esc back"
	if m.generatorRow == 0 {
		hint = "  paste config   enter next   ↓ prefix   esc back"
	} else if m.generatorRow == 1 {
		hint = "  type prefix   enter next   ↑ config   ↓ create"
	}
	sb.WriteString(styleHint.Render(hint))
	sb.WriteRune('\n')
	return sb.String()
}

func (m AppModel) handleGenerateConfigsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type == tea.KeyRunes && msg.Paste {
		m.generatorInput.SetValue(cleanPastedConfigURL(string(msg.Runes)))
		m.generatorInput.CursorEnd()
		m.generatorRow = 1
		m.generatorInput.Blur()
		m.generatorPrefixInput.Focus()
		m.statusMsg = "config pasted — add a prefix or press Enter"
		return m, nil
	}

	if m.generatorRow == 0 {
		m.generatorInput.Focus()
		m.generatorPrefixInput.Blur()
	} else if m.generatorRow == 1 {
		m.generatorPrefixInput.Focus()
		m.generatorInput.Blur()
	} else {
		m.generatorInput.Blur()
		m.generatorPrefixInput.Blur()
	}

	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.page = PageHome
		m.generatorInput.Blur()
		m.generatorPrefixInput.Blur()
		m.statusMsg = ""
		return m, nil
	case "up", "k":
		if m.generatorRow > 0 {
			m.generatorRow--
		}
		return m, nil
	case "down", "j":
		if m.generatorRow < 2 {
			m.generatorRow++
		}
		return m, nil
	case "enter":
		if m.generatorRow < 2 {
			m.generatorRow++
			return m, nil
		}
		path, count, err := generateV2RayConfigs(strings.TrimSpace(m.generatorInput.Value()), strings.TrimSpace(m.generatorPrefixInput.Value()))
		if err != nil {
			m.statusMsg = err.Error()
			m.generatorCount = 0
			m.generatorOutputPath = ""
			return m, nil
		}
		m.generatorCount = count
		m.generatorOutputPath = path
		m.statusMsg = ""
		return m, nil
	}

	var cmd tea.Cmd
	if m.generatorRow == 1 {
		m.generatorPrefixInput, cmd = m.generatorPrefixInput.Update(msg)
	} else if m.generatorRow == 0 {
		m.generatorInput, cmd = m.generatorInput.Update(msg)
	}
	return m, cmd
}

func generateV2RayConfigs(rawURL, prefix string) (string, int, error) {
	if strings.TrimSpace(rawURL) == "" {
		return "", 0, fmt.Errorf("paste a working VLESS config first")
	}
	cfg, err := xraytest.ParseProxyURL(rawURL)
	if err != nil {
		return "", 0, fmt.Errorf("invalid config: %v", err)
	}
	endpoints, ipPath, err := loadDefaultEndpointsFile(cfg.Port)
	if err != nil {
		return "", 0, err
	}
	if len(endpoints) == 0 {
		return "", 0, fmt.Errorf("ips.txt has no valid IPs or endpoints")
	}

	lines := make([]string, 0, len(endpoints))
	for i, endpoint := range endpoints {
		swapped := cfg.WithEndpoint(endpoint.IP.String(), endpoint.Port)
		swapped.Remark = generatedConfigRemark(prefix, cfg.Remark, i+1)
		lines = append(lines, swapped.ToShareURL())
	}

	outPath := filepath.Join(filepath.Dir(ipPath), "configs.txt")
	if err := os.WriteFile(outPath, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		return "", 0, fmt.Errorf("write configs.txt: %v", err)
	}
	return outPath, len(lines), nil
}

func generatedConfigRemark(prefix, fallback string, index int) string {
	base := strings.TrimSpace(prefix)
	if base == "" {
		base = strings.TrimSpace(fallback)
	}
	if base == "" {
		base = "Moz"
	}
	return fmt.Sprintf("%s %d", base, index)
}

// ---------------------------------------------------------------------------
// About page
// ---------------------------------------------------------------------------

func (m AppModel) viewAbout() string {
	var sb strings.Builder

	sb.WriteRune('\n')
	for _, line := range mainMenuASCII {
		sb.WriteString("  " + gradientText(line, m.bannerFrame/3, []string{
			"#B066FF", "#8F7CFF", "#6C8DFF", "#4B9BFF", "#35B8FF",
		}) + "\n")
	}
	sb.WriteString(styleDim.Render("  Cloudflare endpoint scanner for desktop and VPS"))
	sb.WriteString("\n")
	sb.WriteString(styleAccent.Render("  " + m.version))
	sb.WriteString("\n\n")

	sb.WriteString(styleNormal.Render("  Terminal toolkit for Windows desktops and Linux VPS hosts."))
	sb.WriteRune('\n')

	sb.WriteString(styleNormal.Render("  Finds reachable Cloudflare and custom-range endpoints, then validates"))
	sb.WriteRune('\n')

	sb.WriteString(styleNormal.Render("  real VLESS/Trojan configs through embedded xray-core."))
	sb.WriteString("\n\n")

	sb.WriteString(styleDim.Render("  github.com/Moz4020/Moz-Cloudflare-Scanner"))
	sb.WriteString("\n\n")
	sb.WriteString(styleHint.Render("  enter/q → back"))
	return sb.String()
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func tick() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func scanPulse(frame int) string {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	return frames[frame%len(frames)]
}

func scanWave(frame, width int) string {
	if width < 8 {
		width = 8
	}
	pos := frame % width
	var sb strings.Builder
	for i := 0; i < width; i++ {
		switch {
		case i == pos:
			sb.WriteString(styleAccent.Render("●"))
		case (i+1)%4 == 0:
			sb.WriteString(styleDim.Render("·"))
		default:
			sb.WriteString(styleDim.Render("─"))
		}
	}
	return sb.String()
}

func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return "config"
	}
	parts := make([]string, len(ports))
	for i, port := range ports {
		parts[i] = strconv.Itoa(port)
	}
	return strings.Join(parts, ",")
}

func (m AppModel) selectedPortSet() map[int]bool {
	if len(m.configSelectedPorts) == 0 {
		return map[int]bool{0: true}
	}
	out := make(map[int]bool, len(m.configSelectedPorts))
	for port, on := range m.configSelectedPorts {
		if on {
			out[port] = true
		}
	}
	if len(out) == 0 {
		out[0] = true
	}
	return out
}

func (m *AppModel) toggleFocusedConfigPort() {
	if m.configPortFocus < 0 || m.configPortFocus >= len(configPortChoices) {
		return
	}
	port := configPortChoices[m.configPortFocus].port
	if m.configSelectedPorts == nil {
		m.configSelectedPorts = map[int]bool{0: true}
	}
	if port == 0 {
		m.configSelectedPorts = map[int]bool{0: true}
		return
	}
	delete(m.configSelectedPorts, 0)
	m.configSelectedPorts[port] = !m.configSelectedPorts[port]
	if !m.configSelectedPorts[port] {
		delete(m.configSelectedPorts, port)
	}
	if len(m.configSelectedPorts) == 0 {
		m.configSelectedPorts[0] = true
	}
}

// ---------------------------------------------------------------------------
// Scan with Config page
// ---------------------------------------------------------------------------

func (m AppModel) viewScanWithConfig() string {
	var sb strings.Builder

	title := "Find Working IPs"
	if m.configScanning || m.configDone {
		title = "Phase 2 — Xray Validation"
	}
	sb.WriteString("\n" + styleTitle.Render("  " + title) + "\n")
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))

	if !m.configScanning && !m.configDone {
		// helper: render a preset pill row with content-aware selection highlights
		renderPills := func(row int, labels []string, selected int) {
			isRowFocused := (m.configSetupRow == row)
			for i, label := range labels {
				if i == selected {
					if isRowFocused {
						// Active row focus: white text on custom orange background
						sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#F6821F")).Render(" " + label + " "))
					} else {
						// Inactive row selection: simple orange bold text (no background block)
						sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F6821F")).Render("  " + label + "  "))
					}
				} else {
					if isRowFocused {
						sb.WriteString(styleNormal.Render("  " + label + "  "))
					} else {
						sb.WriteString(styleDim.Render("  " + label + "  "))
					}
				}
				if i < len(labels)-1 {
					sb.WriteString(styleDim.Render("│"))
				}
			}
		}

		rowLabel := func(row int, label string) {
			if m.configSetupRow == row {
				sb.WriteString(styleAccent.Render(fmt.Sprintf("  ┃  %-7s  ", label)))
			} else {
				sb.WriteString(styleDim.Render(fmt.Sprintf("  │  %-7s  ", label)))
			}
		}

		renderMultiPorts := func() {
			enabled := m.selectedPortSet()
			for i, choice := range configPortChoices {
				label := choice.label
				if enabled[choice.port] {
					label = "✓ " + label
				} else {
					label = "  " + label
				}
				if i == m.configPortFocus && m.configSetupRow == 4 {
					sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#F6821F")).Render(" " + label + " "))
				} else if enabled[choice.port] {
					if m.configSetupRow == 4 {
						sb.WriteString(styleGood.Render(" " + label + " "))
					} else {
						sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#27AE60")).Render(" " + label + " "))
					}
				} else {
					if m.configSetupRow == 4 {
						sb.WriteString(styleNormal.Render(" " + label + " "))
					} else {
						sb.WriteString(styleDim.Render(" " + label + " "))
					}
				}
				if i < len(configPortChoices)-1 {
					sb.WriteString(styleDim.Render("│"))
				}
			}
		}

		// Row 0: Source
		rowLabel(0, "Source")
		renderPills(0, configIPModeLabels, m.configIPMode)
		sb.WriteString("\n")
		if m.configIPMode == configIPSourceDefault {
			sb.WriteString(styleDim.Render("  │          random sample from official Cloudflare IPv4 ranges") + "\n\n")
		} else {
			sb.WriteString(styleDim.Render("  │          exact IPs and small IPv4 CIDRs from ips.txt") + "\n\n")
		}

		// Row 1: Count
		rowLabel(1, "Count")
		renderPills(1, configCountLabels, m.configCountIdx)
		sb.WriteString("\n")
		if m.configCustomMode && m.configCustomRow == 1 {
			sb.WriteString(styleAccent.Render("  │          custom count: ") + m.configCustomInput.View() + "\n\n")
		} else if configCountValues[m.configCountIdx] == 0 && m.configCountCustom != "" {
			sb.WriteString(styleDim.Render(fmt.Sprintf("  │          IPs to probe in Phase 1  (custom: %s)", m.configCountCustom)) + "\n\n")
		} else if m.configIPMode == configIPSourceFile {
			sb.WriteString(styleDim.Render("  │          ignored when Source is ips.txt — all IPs/CIDRs in ips.txt are used") + "\n\n")
		} else {
			sb.WriteString(styleDim.Render("  │          IPs to probe in Phase 1") + "\n\n")
		}

		// Row 2: Workers
		rowLabel(2, "Workers")
		renderPills(2, quickWorkersLabels(), m.configWorkersIdx)
		sb.WriteString("\n")
		if m.configCustomMode && m.configCustomRow == 2 {
			sb.WriteString(styleAccent.Render("  │          custom workers: ") + m.configCustomInput.View() + "\n\n")
		} else if quickWorkersPresets[m.configWorkersIdx].value == "" && m.configWorkersCustom != "" {
			sb.WriteString(styleDim.Render(fmt.Sprintf("  │          concurrent probes  (custom: %s)", m.configWorkersCustom)) + "\n\n")
		} else {
			sb.WriteString(styleDim.Render("  │          concurrent probes") + "\n\n")
		}

		// Row 3: Timeout
		rowLabel(3, "Timeout")
		renderPills(3, quickTimeoutLabels(), m.configTimeoutIdx)
		sb.WriteString("\n")
		if m.configCustomMode && m.configCustomRow == 3 {
			sb.WriteString(styleAccent.Render("  │          custom timeout: ") + m.configCustomInput.View() + "\n\n")
		} else if quickTimeoutPresets[m.configTimeoutIdx].value == "" && m.configTimeoutCustom != "" {
			sb.WriteString(styleDim.Render(fmt.Sprintf("  │          per-probe deadline  (custom: %s)", m.configTimeoutCustom)) + "\n\n")
		} else {
			sb.WriteString(styleDim.Render("  │          per-probe deadline") + "\n\n")
		}

		// Row 4: Ports
		rowLabel(4, "Ports")
		renderMultiPorts()
		sb.WriteString("\n")
		sb.WriteString(styleDim.Render("  │          space toggles a port; selecting multiple ports multiplies work") + "\n\n")

		hint := "  ↑/↓ row   ←/→ option   enter continue   esc back"
		if m.configCustomMode {
			hint = "  type value   enter confirm   esc cancel"
		}
		sb.WriteString(styleHint.Render(hint) + "\n")
		if m.statusMsg != "" {
			sb.WriteString(styleWarn.Render("  ⚠  "+m.statusMsg) + "\n")
		}
		return sb.String()
	}

	// Stats row — if Phase 1 found no candidates, show a clear message instead
	// of a fake "0/10" counter.
	if m.configTotal == 0 && m.configDone {
		sb.WriteString(fmt.Sprintf("  %s  %s\n\n",
			styleGood.Render("✓"),
			styleBad.Render("No Phase 1 candidates found"),
		))
		sb.WriteString(styleHint.Render("  esc back") + "\n")
		return sb.String()
	}

	done := len(m.configResults)
	total := m.configTotal
	success, failed, skipped := validationOutcomeCounts(m.configResults)
	successRate := validationSuccessRate(success, failed)

	icon := m.spinner.View()
	if m.configDone {
		icon = styleGood.Render("✓")
	}

	elapsedStr := "-"
	etaStr := "-"
	scanRateStr := "-"
	if done > 0 {
		elapsed := time.Since(m.scanStarted)
		if m.configDone && m.scanDuration > 0 {
			elapsed = m.scanDuration
		}
		rate := float64(done) / elapsed.Seconds()
		elapsedStr = formatDurationShort(elapsed)
		scanRateStr = formatRate(rate)
		etaStr = formatETA(done, total, rate, m.configDone)
	}

	gridWidth := minInt(m.width-4, 76)
	if gridWidth < 30 {
		gridWidth = 30
	}

	// Render Phase 2 Metadata Grid
	sb.WriteString(renderPhase2MetadataGrid(
		gridWidth,
		done,
		total,
		success,
		failed,
		skipped,
		successRate,
		elapsedStr,
		etaStr,
		scanRateStr,
	) + "\n\n")

	// Progress Bar
	if total > 0 {
		sb.WriteString(renderProgressBar(gridWidth, done, total) + "\n\n")
	}

	if !m.configDone {
		sb.WriteString(fmt.Sprintf("  %s  xray validating candidates  %s\n\n",
			icon,
			scanWave(m.bannerFrame+5, 32),
		))
	} else if success > 0 {
		sb.WriteString(styleGood.Render("  Ready: copy working endpoints or import generated configs from the V2Ray generator.") + "\n\n")
	}

	sb.WriteString(fmt.Sprintf("%s\n%s\n",
		styleHeader.Render(validationHeader()),
		styleSep.Render(tableSeparator(62)),
	))

	// Results
	maxRows := m.height - 12
	if maxRows < 3 {
		maxRows = 3
	}
	rows := visibleValidationRows(m.configResults, maxRows, m.configDone)

	renderValidationRow := func(r *xraytest.ValidationResult) {
		if r == nil {
			return
		}
		status := "failed"
		if r.Success {
			status = "working"
		} else if isSkippedValidation(r) {
			status = "skipped"
		} else {
			status = r.Error
			if status == "" {
				status = "failed"
			}
		}

		if len(status) > statusColWidth {
			status = status[:statusColWidth-1] + "…"
		}
		sb.WriteString(validationRow(r, status) + "\n")
	}
	if m.configDone {
		for _, r := range rows {
			renderValidationRow(r)
		}
	} else {
		for i := len(rows) - 1; i >= 0; i-- {
			renderValidationRow(rows[i])
		}
	}

	sb.WriteRune('\n')
	if latest := latestConfigFailure(m.configResults); latest != "" {
		sb.WriteString(styleDim.Render("  latest failure: "+truncateMiddle(latest, minInt(maxInt(m.width-22, 30), 110))) + "\n")
	}
	if m.statusMsg != "" {
		sb.WriteString(styleGood.Render("  "+m.statusMsg) + "\n")
	}
	if m.configDone {
		hint := "  c copy working endpoints   q/esc back"
		if m.liveResultPath != "" {
			path := truncateMiddle(m.liveResultPath, minInt(maxInt(m.width-20, 30), 90))
			hint += "\n" + styleDim.Render("  live results: "+path)
		}
		sb.WriteString(styleHint.Render(hint) + "\n")
	} else if m.liveResultPath != "" {
		path := truncateMiddle(m.liveResultPath, minInt(maxInt(m.width-20, 30), 90))
		sb.WriteString(styleDim.Render("  live results: "+path) + "\n")
	}

	return sb.String()
}

func visibleValidationRows(results []*xraytest.ValidationResult, maxRows int, finished bool) []*xraytest.ValidationResult {
	if maxRows <= 0 || len(results) == 0 {
		return nil
	}
	if !finished {
		if len(results) > maxRows {
			return results[len(results)-maxRows:]
		}
		return results
	}

	rows := append([]*xraytest.ValidationResult(nil), results...)
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a == nil || b == nil {
			return b == nil
		}
		if a.Success != b.Success {
			return a.Success
		}
		if a.Success {
			aLatency := validationLatencyRank(a.Latency)
			bLatency := validationLatencyRank(b.Latency)
			if aLatency != bLatency {
				return aLatency < bLatency
			}
		}
		return formatEndpoint(a.IP, a.Port) < formatEndpoint(b.IP, b.Port)
	})
	if len(rows) > maxRows {
		return rows[:maxRows]
	}
	return rows
}

func (m AppModel) configSuccessCount() int {
	success, _, _ := validationOutcomeCounts(m.configResults)
	return success
}

func latestConfigFailure(results []*xraytest.ValidationResult) string {
	for i := len(results) - 1; i >= 0; i-- {
		if results[i] != nil && !results[i].Success && results[i].Error != "" && !isSkippedValidation(results[i]) {
			return results[i].Error
		}
	}
	return ""
}

func (m AppModel) configFailCount() int {
	_, failed, _ := validationOutcomeCounts(m.configResults)
	return failed
}

func validationOutcomeCounts(results []*xraytest.ValidationResult) (success, failed, skipped int) {
	for _, r := range results {
		if r == nil {
			continue
		}
		if r.Success {
			success++
		} else if isSkippedValidation(r) {
			skipped++
		} else {
			failed++
		}
	}
	return success, failed, skipped
}

func validationSuccessRate(success, failed int) float64 {
	total := success + failed
	if total == 0 {
		return 0
	}
	return float64(success) / float64(total) * 100
}

func isSkippedValidation(r *xraytest.ValidationResult) bool {
	return r != nil && strings.HasPrefix(strings.ToLower(r.Error), "skipped:")
}

func formatPercent(v float64) string {
	if v <= 0 {
		return "0%"
	}
	return fmt.Sprintf("%.1f%%", v)
}

func formatRate(v float64) string {
	if v <= 0 || v > 1000000 {
		return "-"
	}
	if v >= 10 {
		return fmt.Sprintf("%.0f/s", v)
	}
	return fmt.Sprintf("%.1f/s", v)
}

func formatETA(done, total int, rate float64, finished bool) string {
	if finished || done >= total {
		return "done"
	}
	if rate <= 0 || total <= 0 || done <= 0 {
		return "-"
	}
	remaining := float64(total-done) / rate
	if remaining < 0 {
		return "done"
	}
	return formatDurationShort(time.Duration(remaining) * time.Second)
}

func (m AppModel) handleScanWithConfigKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// --- Custom input mode: route all keys to the active text input ---
	if m.configCustomMode {
		switch msg.String() {
		case "enter":
			val := strings.TrimSpace(m.configCustomInput.Value())
			switch m.configCustomRow {
			case 1:
				m.configCountCustom = val
			case 2:
				m.configWorkersCustom = val
			case 3:
				m.configTimeoutCustom = val
			}
			m.configCustomMode = false
			m.configCustomInput.Blur()
			return m, nil
		case "esc":
			m.configCustomMode = false
			m.configCustomInput.Blur()
			return m, nil
		}
		var cmd tea.Cmd
		m.configCustomInput, cmd = m.configCustomInput.Update(msg)
		return m, cmd
	}

	// --- Global keys ---
	switch msg.String() {
	case "esc":
		if m.configScanning || m.configDone {
			clearLiveResultWriter()
			m.page = PageHome
			m.configScanning = false
			m.configDone = false
			return m, nil
		}
		m.page = PageHome
		return m, nil
	case "q":
		if m.configDone {
			m.page = PageHome
			m.configDone = false
			return m, nil
		}
	case "c":
		if m.configDone {
			m.statusMsg = m.copyWorkingIPs()
			return m, nil
		}
	}

	if m.configScanning || m.configDone {
		return m, nil
	}

	// --- Setup navigation (Source → Count → Workers → Timeout → Ports) ---
	const maxRow = 4

	configNavLeft := func() {
		switch m.configSetupRow {
		case 0:
			if m.configIPMode > 0 {
				m.configIPMode--
			}
		case 1:
			if m.configCountIdx > 0 {
				m.configCountIdx--
			}
		case 2:
			if m.configWorkersIdx > 0 {
				m.configWorkersIdx--
			}
		case 3:
			if m.configTimeoutIdx > 0 {
				m.configTimeoutIdx--
			}
		case 4:
			if m.configPortFocus > 0 {
				m.configPortFocus--
			}
		}
	}
	configNavRight := func() {
		switch m.configSetupRow {
		case 0:
			if m.configIPMode < len(configIPModeLabels)-1 {
				m.configIPMode++
			}
		case 1:
			if m.configCountIdx < len(configCountValues)-1 {
				m.configCountIdx++
			}
		case 2:
			if m.configWorkersIdx < len(quickWorkersPresets)-1 {
				m.configWorkersIdx++
			}
		case 3:
			if m.configTimeoutIdx < len(quickTimeoutPresets)-1 {
				m.configTimeoutIdx++
			}
		case 4:
			if m.configPortFocus < len(configPortChoices)-1 {
				m.configPortFocus++
			}
		}
	}

	switch msg.String() {
	case "up", "k":
		if m.configSetupRow > 0 {
			m.configSetupRow--
		}
		return m, nil
	case "down", "j":
		if m.configSetupRow < maxRow {
			m.configSetupRow++
		}
		return m, nil
	case "left", "h", "right", "l":
		if msg.String() == "left" || msg.String() == "h" {
			configNavLeft()
		} else {
			configNavRight()
		}
		return m, nil
	case " ":
		if m.configSetupRow == 4 {
			m.toggleFocusedConfigPort()
			return m, nil
		}
	case "enter":
		if m.configSetupRow == 4 {
			m.toggleFocusedConfigPort()
			return m, nil
		}
		if m.configSetupRow == 1 && configCountValues[m.configCountIdx] == 0 {
			m.configCustomMode = true
			m.configCustomRow = 1
			m.configCustomInput.SetValue(m.configCountCustom)
			m.configCustomInput.Placeholder = "e.g. 50000"
			m.configCustomInput.Focus()
			return m, textinput.Blink
		}
		if m.configSetupRow == 2 && quickWorkersPresets[m.configWorkersIdx].value == "" {
			m.configCustomMode = true
			m.configCustomRow = 2
			m.configCustomInput.SetValue(m.configWorkersCustom)
			m.configCustomInput.Placeholder = "e.g. 150"
			m.configCustomInput.Focus()
			return m, textinput.Blink
		}
		if m.configSetupRow == 3 && quickTimeoutPresets[m.configTimeoutIdx].value == "" {
			m.configCustomMode = true
			m.configCustomRow = 3
			m.configCustomInput.SetValue(m.configTimeoutCustom)
			m.configCustomInput.Placeholder = "e.g. 7s"
			m.configCustomInput.Focus()
			return m, textinput.Blink
		}

		m.statusMsg = ""
		m.page = PageConfigOptional
		m.configOptionalRow = 0
		m.configInput.Focus()
		return m, textinput.Blink
	}
	return m, nil
}

func (m AppModel) viewConfigOptional() string {
	var sb strings.Builder
	sb.WriteString(styleTitle.Render("\n  ⚡  Find Working IPs\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))

	rowLabel := func(row int, label string) {
		if m.configOptionalRow == row {
			sb.WriteString(styleAccent.Render(fmt.Sprintf("  ┃  %-7s  ", label)))
		} else {
			sb.WriteString(styleDim.Render(fmt.Sprintf("  │  %-7s  ", label)))
		}
	}

	renderPills := func(row int, labels []string, selected int) {
		isRowFocused := (m.configOptionalRow == row)
		for i, label := range labels {
			if i == selected {
				if isRowFocused {
					sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#F6821F")).Render(" " + label + " "))
				} else {
					sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F6821F")).Render("  " + label + "  "))
				}
			} else {
				if isRowFocused {
					sb.WriteString(styleNormal.Render("  " + label + "  "))
				} else {
					sb.WriteString(styleDim.Render("  " + label + "  "))
				}
			}
			if i < len(labels)-1 {
				sb.WriteString(styleDim.Render("│"))
			}
		}
	}

	rowLabel(0, "Config")
	sb.WriteString(m.configInput.View() + "\n")
	if summary := parsedConfigSummary(m.configInput.Value()); summary != "" {
		sb.WriteString(styleDim.Render("  │          "+summary) + "\n\n")
	} else {
		sb.WriteString(styleDim.Render("  │          optional; leave empty to find healthy endpoints without xray validation") + "\n\n")
	}

	rowLabel(1, "Test N")
	renderPills(1, configTopNLabels, m.configTopNIdx)
	sb.WriteString("\n")
	if m.configCustomMode && m.configCustomRow == 5 {
		sb.WriteString(styleAccent.Render("  │          custom top N: ") + m.configCustomInput.View() + "\n\n")
	} else if m.isTopNCustomSelected() && m.configTopNCustom != "" {
		sb.WriteString(styleDim.Render(fmt.Sprintf("  │          Phase 2 candidates to validate  (custom: %s)", m.configTopNCustom)) + "\n\n")
	} else {
		sb.WriteString(styleDim.Render("  │          Phase 2 picks — used only when a config URL is entered") + "\n\n")
	}

	rowLabel(2, "Workers")
	renderPills(2, phase2WorkersLabels(), m.configPhase2WorkersIdx)
	sb.WriteString("\n")
	if m.configCustomMode && m.configCustomRow == 6 {
		sb.WriteString(styleAccent.Render("  │          custom workers: ") + m.configCustomInput.View() + "\n\n")
	} else if m.isPhase2WorkersCustomSelected() && m.configPhase2WorkersCustom != "" {
		sb.WriteString(styleDim.Render(fmt.Sprintf("  │          Phase 2 xray workers  (custom: %s)", m.configPhase2WorkersCustom)) + "\n\n")
	} else {
		sb.WriteString(styleDim.Render(fmt.Sprintf("  │          Phase 2 xray workers; capped at %d for stability", maxPhase2Workers)) + "\n\n")
	}

	rowLabel(3, "Start")
	mode := "Phase 1 only"
	if strings.TrimSpace(m.configInput.Value()) != "" {
		mode = "Phase 1 + xray validation"
	}
	if m.configOptionalRow == 3 {
		sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#F6821F")).Render(" "+mode+" ") + "\n")
	} else {
		sb.WriteString(styleNormal.Render(mode) + "\n")
	}
	sb.WriteString(styleDim.Render("  │          press Enter here to start") + "\n\n")

	hint := "  ↑/↓ row   ←/→ option   enter select   esc back"
	if m.configOptionalRow == 0 {
		hint = "  paste URL or leave empty   ↓ continue   esc back"
	}
	if m.configCustomMode {
		hint = "  type value   enter confirm   esc cancel"
	}
	sb.WriteString(styleHint.Render(hint) + "\n")
	if m.liveResultPath != "" {
		sb.WriteString(styleDim.Render("  live file: "+m.liveResultPath) + "\n")
	}
	if m.statusMsg != "" {
		sb.WriteString(styleWarn.Render("  ⚠  "+m.statusMsg) + "\n")
	}
	return sb.String()
}

func (m AppModel) handleConfigOptionalKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.configOptionalRow == 0 && msg.Type == tea.KeyRunes && msg.Paste {
		m.configInput.SetValue(cleanPastedConfigURL(string(msg.Runes)))
		m.configInput.CursorEnd()
		m.statusMsg = "config pasted — press Enter to continue"
		return m, nil
	}

	if m.configCustomMode {
		switch msg.String() {
		case "enter":
			if m.configCustomRow == 5 {
				m.configTopNCustom = strings.TrimSpace(m.configCustomInput.Value())
			} else if m.configCustomRow == 6 {
				m.configPhase2WorkersCustom = strings.TrimSpace(m.configCustomInput.Value())
			}
			m.configCustomMode = false
			m.configCustomInput.Blur()
			return m, nil
		case "esc":
			m.configCustomMode = false
			m.configCustomInput.Blur()
			return m, nil
		}
		var cmd tea.Cmd
		m.configCustomInput, cmd = m.configCustomInput.Update(msg)
		return m, cmd
	}

	if m.configOptionalRow == 0 {
		m.configInput.Focus()
		switch msg.String() {
		case "esc":
			m.page = PageScanWithConfig
			m.configInput.Blur()
			return m, nil
		case "down":
			m.configOptionalRow = 1
			m.configInput.Blur()
			return m, nil
		case "enter":
			m.configOptionalRow = 1
			m.configInput.Blur()
			return m, nil
		}
		var cmd tea.Cmd
		m.configInput, cmd = m.configInput.Update(msg)
		return m, cmd
	}

	switch msg.String() {
	case "esc":
		m.page = PageScanWithConfig
		m.configInput.Blur()
		return m, nil
	case "up", "k":
		if m.configOptionalRow > 0 {
			m.configOptionalRow--
			if m.configOptionalRow == 0 {
				m.configInput.Focus()
				return m, textinput.Blink
			}
			m.configInput.Blur()
		}
		return m, nil
	case "down", "j":
		if m.configOptionalRow < 3 {
			m.configOptionalRow++
			m.configInput.Blur()
			return m, nil
		}
		return m, nil
	case "left", "h":
		if m.configOptionalRow == 1 {
			if m.configTopNIdx > 0 {
				m.configTopNIdx--
			}
			return m, nil
		} else if m.configOptionalRow == 2 {
			if m.configPhase2WorkersIdx > 0 {
				m.configPhase2WorkersIdx--
			}
			return m, nil
		}
	case "right", "l":
		if m.configOptionalRow == 1 {
			if m.configTopNIdx < len(configTopNLabels)-1 {
				m.configTopNIdx++
			}
			return m, nil
		} else if m.configOptionalRow == 2 {
			if m.configPhase2WorkersIdx < len(phase2WorkersPresets)-1 {
				m.configPhase2WorkersIdx++
			}
			return m, nil
		}
	case "enter":
		if m.configOptionalRow == 1 {
			if m.isTopNCustomSelected() {
				m.configCustomMode = true
				m.configCustomRow = 5
				m.configCustomInput.SetValue(m.configTopNCustom)
				m.configCustomInput.Placeholder = "e.g. 75"
				m.configCustomInput.Focus()
				return m, textinput.Blink
			}
			m.configOptionalRow = 2
			return m, nil
		}
		if m.configOptionalRow == 2 {
			if m.isPhase2WorkersCustomSelected() {
				m.configCustomMode = true
				m.configCustomRow = 6
				m.configCustomInput.SetValue(m.configPhase2WorkersCustom)
				m.configCustomInput.Placeholder = "e.g. 80"
				m.configCustomInput.Focus()
				return m, textinput.Blink
			}
			m.configOptionalRow = 3
			return m, nil
		}
		return m.launchPhase1FromOptional()
	}

	return m, nil
}

func cleanPastedConfigURL(raw string) string {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\r\n", "\n"))
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func parsedConfigSummary(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	cfg, err := xraytest.ParseProxyURL(raw)
	if err != nil {
		return "invalid URL: " + truncateMiddle(err.Error(), 68)
	}
	host := cfg.Host
	if host == "" {
		host = cfg.SNI
	}
	enc := cfg.Encryption
	if enc == "" {
		enc = "none"
	}
	enc = truncateMiddle(enc, 34)
	return fmt.Sprintf("parsed: %s  %s  host=%s  port=%d  encryption=%s",
		cfg.Protocol, cfg.Network, host, cfg.Port, enc)
}

func (m AppModel) isTopNCustomSelected() bool {
	return m.configTopNIdx == len(configTopNLabels)-1
}

func (m AppModel) launchPhase1FromOptional() (AppModel, tea.Cmd) {
	rawURL := strings.TrimSpace(m.configInput.Value())
	withConfig := rawURL != ""
	if withConfig {
		if _, err := xraytest.ParseProxyURL(rawURL); err != nil {
			m.statusMsg = fmt.Sprintf("invalid URL: %v", err)
			m.configOptionalRow = 0
			m.configInput.Focus()
			return m, textinput.Blink
		}
		m.configURL = rawURL
	} else {
		m.configURL = ""
	}

	writer, path, err := newLiveResultWriter(withConfig)
	if err != nil {
		m.statusMsg = fmt.Sprintf("could not create results file: %v", err)
		return m, nil
	}
	setLiveResultWriter(writer)
	m.liveResultPath = path
	m.statusMsg = ""
	m.configPhase1Only = !withConfig
	m.configPhase1Results = nil
	m.configPhase1Done = false
	m.configPhase1Neighboring = false
	m.page = PageConfigPhase1
	m.scanStarted = time.Now()

	count := configCountValues[m.configCountIdx]
	if count == 0 {
		count, _ = strconv.Atoi(m.configCountCustom)
		if count <= 0 {
			count = 1000
		}
	}
	m.configPhase1Total = m.phase1TargetTotal(count)
	return m, m.startConfigPhase1()
}

func (m AppModel) resolveTopN() int {
	if m.isTopNCustomSelected() {
		n, _ := strconv.Atoi(strings.TrimSpace(m.configTopNCustom))
		if n <= 0 {
			return 50
		}
		return n
	}
	if m.configTopNIdx < 0 || m.configTopNIdx >= len(configTopNValues) {
		return 50
	}
	return configTopNValues[m.configTopNIdx]
}

// ConfigDoneMsg signals Phase 2 validation is complete.
type ConfigDoneMsg struct{}

// ConfigProgressMsg carries a single result during scanning.
type ConfigProgressMsg struct {
	Result *xraytest.ValidationResult
	Done   int
	Total  int
}

// ---------------------------------------------------------------------------
// Config Setup presets
// ---------------------------------------------------------------------------

var configCountValues = []int{1000, 5000, 20000, 50000, 0} // 0 = custom
var configCountLabels = []string{"Quick 1k", "Normal 5k", "Balanced 20k", "Deep 50k", "Custom"}
var configTopNValues = []int{10, 25, 50, 100, 0} // 0 = all
var configTopNLabels = []string{"10", "25", "50", "100", "All", "Custom"}

const (
	configIPSourceDefault = iota
	configIPSourceFile
)

var configIPModeLabels = []string{"Default CF", "ips.txt"}
var configPortChoices = []struct {
	label string
	port  int
}{
	{"Config", 0},
	{"443", 443},
	{"8443", 8443},
	{"2053", 2053},
	{"2083", 2083},
	{"2087", 2087},
	{"2096", 2096},
}

func configPortLabels() []string {
	labels := make([]string, len(configPortChoices))
	for i, p := range configPortChoices {
		labels[i] = p.label
	}
	return labels
}

// quickWorkersLabels and quickTimeoutLabels return the display labels for the
// shared quick-scan preset slices so viewScanWithConfig can use them.
func quickWorkersLabels() []string {
	out := make([]string, len(quickWorkersPresets))
	for i, p := range quickWorkersPresets {
		out[i] = p.label
	}
	return out
}

func quickTimeoutLabels() []string {
	out := make([]string, len(quickTimeoutPresets))
	for i, p := range quickTimeoutPresets {
		out[i] = p.label
	}
	return out
}

// ---------------------------------------------------------------------------
// Config Phase 1 — fast connectivity scan
// ---------------------------------------------------------------------------

type ConfigPhase1ResultMsg struct {
	Result *result.Result
}

// ConfigPhase1ErrMsg is sent when Phase 1 cannot proceed (e.g. ips.txt missing).
type ConfigPhase1ErrMsg struct{ Err string }

type ConfigPhase1DoneMsg struct{}

type ConfigPhase1TotalUpdateMsg struct {
	Total int
}

type ConfigPhase1NeighboringMsg struct {
	Neighboring bool
}

func (m AppModel) viewConfigPhase1() string {
	var sb strings.Builder

	withConfig := strings.TrimSpace(m.configURL) != ""

	sb.WriteString("\n" + styleTitle.Render("  Phase 1 — Candidate Scan") + "\n")
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))

	icon := m.spinner.View()
	if m.configPhase1Done {
		icon = styleGood.Render("✓")
	}

	healthy := 0
	for _, r := range m.configPhase1Results {
		if r.IsHealthy() {
			healthy++
		}
	}

	tested := len(m.configPhase1Results)
	source := "Cloudflare IPs"
	if m.configIPMode == configIPSourceFile {
		source = "ips.txt"
	}
	probe := "Standard HTTP"
	if withConfig {
		probe = "VLESS Config"
	}
	rate := 0.0
	if tested > 0 {
		rate = float64(healthy) / float64(tested) * 100
	}

	elapsedStr := "-"
	etaStr := "-"
	scanRateStr := "-"
	if tested > 0 {
		elapsed := time.Since(m.scanStarted)
		if m.configPhase1Done && m.scanDuration > 0 {
			elapsed = m.scanDuration
		}
		scanRate := float64(tested) / elapsed.Seconds()
		elapsedStr = formatDurationShort(elapsed)
		scanRateStr = formatRate(scanRate)
		etaStr = formatETA(tested, m.configPhase1Total, scanRate, m.configPhase1Done)
	}

	gridWidth := minInt(m.width-4, 76)
	if gridWidth < 30 {
		gridWidth = 30
	}

	// Render Phase 1 Metadata Grid
	sb.WriteString(renderMetadataGrid(
		gridWidth,
		source,
		probe,
		formatPorts(m.resolveConfigPorts()),
		tested,
		healthy,
		m.configPhase1Total,
		rate,
		elapsedStr,
		etaStr,
		scanRateStr,
	) + "\n\n")

	// Progress Bar
	if m.configPhase1Total > 0 {
		sb.WriteString(renderProgressBar(gridWidth, tested, m.configPhase1Total) + "\n\n")
	}

	if !m.configPhase1Done {
		statusText := "discovering reachable candidates"
		if m.configPhase1Neighboring {
			statusText = "probing neighboring IPs of healthy hits"
		}
		sb.WriteString(fmt.Sprintf("  %s  %s  %s\n\n",
			icon,
			statusText,
			scanWave(m.bannerFrame, 28),
		))
	}

	if m.configPhase1Done {
		if m.configPhase1Only {
			sb.WriteString(styleGood.Render(fmt.Sprintf("  Done — %d healthy endpoints found.\n\n", healthy)))
		} else {
			topN := m.resolveTopN()
			label := fmt.Sprintf("%d", topN)
			if topN == 0 {
				label = "all"
			}
			sb.WriteString(styleGood.Render(fmt.Sprintf("  Found %d candidates. Testing %s spread candidates with xray...\n", healthy, label)))
			sb.WriteString(styleDim.Render("  Phase 1 only finds candidates; Phase 2 confirms xray works.\n\n"))
		}
	} else if m.configIPMode == configIPSourceFile {
		sb.WriteString(styleNormal.Render("  Probing IPs and small CIDRs from ips.txt on the selected ports...") + "\n\n")
	} else if !withConfig {
		sb.WriteString(styleNormal.Render("  Scanning random Cloudflare IPv4 IPs (standard HTTP probe)...") + "\n")
		sb.WriteString(styleDim.Render("  healthy hits also explore nearby addresses in the same Cloudflare block") + "\n\n")
	} else {
		sb.WriteString(styleNormal.Render("  Scanning Cloudflare IPs using your config reachability probe...") + "\n")
		sb.WriteString(styleDim.Render("  Phase 1 only finds candidates; Phase 2 confirms xray works.") + "\n\n")
	}

	if m.liveResultPath != "" {
		path := truncateMiddle(m.liveResultPath, minInt(maxInt(m.width-20, 30), 90))
		sb.WriteString(styleDim.Render("  live file: "+path) + "\n\n")
	}

	if len(m.configPhase1Results) > 0 {
		statusLabel := "STATUS"
		if withConfig {
			statusLabel = "PHASE 1"
		}
		sb.WriteString(fmt.Sprintf("%s\n%s\n",
			styleHeader.Render(endpointHeader(statusLabel)),
			styleSep.Render(tableSeparator(76)),
		))

		top := result.TopN(m.configPhase1Results, 20)
		for _, r := range top {
			status := "healthy"
			if withConfig {
				status = "candidate"
			}
			if !r.IsHealthy() {
				status = "failed"
			}
			sb.WriteString(endpointCandidateRow(r, status) + "\n")
		}
		sb.WriteRune('\n')
	}

	if m.statusMsg != "" {
		sb.WriteString(styleGood.Render("  "+m.statusMsg) + "\n")
	}

	if m.configPhase1Done && m.configPhase1Only {
		sb.WriteString(styleHint.Render("  c copy healthy endpoints   q/esc back") + "\n")
	} else if healthy > 0 {
		sb.WriteString(styleHint.Render("  c copy best candidate   q/esc cancel") + "\n")
	} else {
		sb.WriteString(styleHint.Render("  q/esc cancel") + "\n")
	}
	return sb.String()
}

func (m AppModel) handleConfigPhase1Key(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "c":
		if m.configPhase1Done && m.configPhase1Only {
			m.statusMsg = m.copyPhase1HealthyEndpoints()
			return m, nil
		}
		m.statusMsg = m.copyBestPhase1Candidate()
		return m, nil
	case "esc", "q":
		if scanCancel != nil {
			scanCancel()
		}
		clearLiveResultWriter()
		m.page = PageHome
		return m, nil
	}
	return m, nil
}

func (m AppModel) copyBestPhase1Candidate() string {
	top := result.TopN(m.configPhase1Results, 1)
	if len(top) == 0 {
		return "no candidate to copy yet"
	}
	endpoint := formatEndpoint(top[0].IP.String(), top[0].Port)
	if err := clipboardWriteAll(endpoint); err != nil {
		return fmt.Sprintf("clipboard error: %v", err)
	}
	return "copied " + endpoint
}

func (m AppModel) copyPhase1HealthyEndpoints() string {
	top := result.TopN(m.configPhase1Results, 0)
	if len(top) == 0 {
		return "no healthy endpoints to copy"
	}
	endpoints := make([]string, 0, len(top))
	for _, r := range top {
		endpoints = append(endpoints, formatEndpoint(r.IP.String(), r.Port))
	}
	return copyAndSaveIPs(endpoints)
}

// configPhase1Options holds the resolved settings for a Phase 1 engine run.
type configPhase1Options struct {
	count       int
	concurrency int
	timeout     time.Duration
	rawURL      string
	ports       []int
	sourceMode  int
}

func (m AppModel) startConfigPhase1() tea.Cmd {
	opts := m.resolvePhase1Options()
	return func() tea.Msg {
		go runConfigPhase1(opts)
		return nil
	}
}

// resolvePhase1Options reads the current picker state and returns concrete values
// for the Phase 1 engine run.
func (m AppModel) resolvePhase1Options() configPhase1Options {
	// Count
	count := configCountValues[m.configCountIdx]
	if count == 0 {
		count, _ = strconv.Atoi(m.configCountCustom)
		if count <= 0 {
			count = 1000
		}
	}

	concurrency := 0
	if m.configWorkersIdx < len(quickWorkersPresets) {
		wp := quickWorkersPresets[m.configWorkersIdx]
		if wp.value != "" {
			concurrency, _ = strconv.Atoi(wp.value)
		} else {
			concurrency, _ = strconv.Atoi(m.configWorkersCustom)
		}
	}
	if concurrency <= 0 {
		concurrency = 50
	}

	var timeout time.Duration
	if m.configTimeoutIdx < len(quickTimeoutPresets) {
		tp := quickTimeoutPresets[m.configTimeoutIdx]
		if tp.value != "" {
			timeout, _ = time.ParseDuration(tp.value)
		} else {
			timeout, _ = time.ParseDuration(m.configTimeoutCustom)
		}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return configPhase1Options{
		count:       count,
		concurrency: concurrency,
		timeout:     timeout,
		rawURL:      m.configURL,
		ports:       m.resolveConfigPorts(),
		sourceMode:  m.configIPMode,
	}
}

func (m AppModel) phase1TargetTotal(count int) int {
	ports := len(m.resolveConfigPorts())
	if ports <= 0 {
		ports = 1
	}
	if m.configIPMode == configIPSourceFile {
		if ips, err := loadDefaultIPsFile(); err == nil {
			return len(ips) * ports
		}
		return 0
	}
	return count * ports
}

func (m AppModel) resolveConfigPorts() []int {
	selected := m.selectedPortSet()
	var ports []int
	for _, choice := range configPortChoices {
		if choice.port > 0 && selected[choice.port] {
			ports = append(ports, choice.port)
		}
	}
	if len(ports) > 0 {
		return ports
	}
	cfg, err := xraytest.ParseProxyURL(m.configURL)
	if err != nil || cfg.Port <= 0 {
		return []int{443}
	}
	return []int{cfg.Port}
}

// runConfigPhase1 is defined in cmds.go and accepts a configPhase1Options struct.

// selectPhase2Candidates keeps Phase 2 from over-trusting Phase 1 latency.
// Some routes prefer IPs that are merely reachable, not the lowest ping, so we
// sample across latency quantiles and avoid repeating the same IP range first.
func selectPhase2Candidates(results []*result.Result, n int) []*result.Result {
	healthy := result.TopN(results, 0)
	limit := n
	if limit <= 0 || limit > len(healthy) {
		limit = len(healthy)
	}
	if limit == 0 {
		return nil
	}

	const bucketCount = 5
	buckets := make([][]*result.Result, bucketCount)
	for i, r := range healthy {
		bucket := i * bucketCount / len(healthy)
		if bucket >= bucketCount {
			bucket = bucketCount - 1
		}
		buckets[bucket] = append(buckets[bucket], r)
	}

	selected := make([]*result.Result, 0, limit)
	seen := make(map[*result.Result]struct{})
	seenEndpoints := make(map[string]struct{})
	usedRanges := make(map[string]struct{})

	add := func(r *result.Result, allowRangeRepeat bool) bool {
		if r == nil || r.IP == nil {
			return false
		}
		if _, ok := seen[r]; ok {
			return false
		}
		endpoint := formatEndpoint(r.IP.String(), r.Port)
		if _, ok := seenEndpoints[endpoint]; ok {
			return false
		}
		key := phase2RangeKey(r.IP)
		if !allowRangeRepeat && key != "" {
			if _, ok := usedRanges[key]; ok {
				return false
			}
		}
		seen[r] = struct{}{}
		seenEndpoints[endpoint] = struct{}{}
		if key != "" {
			usedRanges[key] = struct{}{}
		}
		selected = append(selected, r)
		return true
	}

	pickFromBucket := func(bucket []*result.Result, allowRangeRepeat bool) bool {
		for _, r := range bucket {
			if add(r, allowRangeRepeat) {
				return true
			}
		}
		return false
	}

	for _, allowRangeRepeat := range []bool{false, true} {
		for len(selected) < limit {
			progress := false
			for _, bucket := range buckets {
				if len(selected) >= limit {
					break
				}
				if pickFromBucket(bucket, allowRangeRepeat) {
					progress = true
				}
			}
			if !progress {
				break
			}
		}
	}

	return selected
}

func phase2RangeKey(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d", ip4[0], ip4[1])
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return ""
	}
	return fmt.Sprintf("%x:%x", ip16[0:2], ip16[2:4])
}

const (
	phase2ValidationTimeout = 7 * time.Second
	maxPhase2Workers        = 64
)

func phase2WorkerCount(total int) int {
	switch {
	case total <= 0:
		return 0
	case total >= 100:
		return 32
	case total >= 30:
		return 16
	default:
		return minInt(8, total)
	}
}

func (m AppModel) resolvePhase2Workers() int {
	if m.configPhase2WorkersIdx < 0 || m.configPhase2WorkersIdx >= len(phase2WorkersPresets) {
		return 50 // default fallback
	}
	wp := phase2WorkersPresets[m.configPhase2WorkersIdx]
	if wp.value == "" {
		n, _ := strconv.Atoi(strings.TrimSpace(m.configPhase2WorkersCustom))
		if n <= 0 {
			return 50
		}
		return clampPhase2Workers(n)
	}
	n, _ := strconv.Atoi(wp.value)
	if n <= 0 {
		return 50
	}
	return clampPhase2Workers(n)
}

func clampPhase2Workers(workers int) int {
	if workers > maxPhase2Workers {
		return maxPhase2Workers
	}
	return workers
}

// ---------------------------------------------------------------------------
// Config Phase 2 — xray validation of selected candidates
// ---------------------------------------------------------------------------

func (m AppModel) startConfigPhase2(topIPs []*result.Result) tea.Cmd {
	url := m.configURL
	workers := m.resolvePhase2Workers()
	return func() tea.Msg {
		go runConfigPhase2(url, topIPs, workers)
		return nil
	}
}

func runConfigPhase2(rawURL string, topIPs []*result.Result, workers int) {
	cfg, err := xraytest.ParseProxyURL(rawURL)
	if err != nil {
		if prog != nil {
			prog.Send(ConfigDoneMsg{})
		}
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	defer cancel()

	topIPs = uniquePhase2Candidates(topIPs)
	total := len(topIPs)
	if workers <= 0 {
		workers = phase2WorkerCount(total)
	}
	workers = minInt(workers, total)
	if workers <= 0 {
		if prog != nil {
			prog.Send(ConfigDoneMsg{})
		}
		return
	}

	jobs := make(chan *result.Result)
	var done atomic.Int64
	var wg sync.WaitGroup

	sendProgress := func(vr *xraytest.ValidationResult) {
		current := int(done.Add(1))
		if liveResultWriter != nil {
			liveResultWriter.AddPhase2(vr)
		}
		if prog != nil {
			prog.Send(ConfigProgressMsg{
				Result: vr,
				Done:   current,
				Total:  total,
			})
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				if r == nil || ctx.Err() != nil {
					continue
				}
				ip := r.IP.String()
				swapped := cfg.WithEndpoint(ip, r.Port)
				vr := xraytest.ValidateConfig(ctx, swapped, phase2ValidationTimeout)
				sendProgress(vr)
			}
		}()
	}

enqueue:
	for _, r := range topIPs {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
			break enqueue
		case jobs <- r:
		}
	}
	close(jobs)
	wg.Wait()
	if liveResultWriter != nil {
		_ = liveResultWriter.flush()
	}

	if prog != nil {
		prog.Send(ConfigDoneMsg{})
	}
}

func uniquePhase2Candidates(rows []*result.Result) []*result.Result {
	out := make([]*result.Result, 0, len(rows))
	seen := make(map[string]struct{})
	for _, r := range rows {
		if r == nil || r.IP == nil {
			continue
		}
		key := formatEndpoint(r.IP.String(), r.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}

func renderProgressBar(width int, current, total int) string {
	if total <= 0 {
		return ""
	}
	pct := float64(current) / float64(total)
	if pct > 1.0 {
		pct = 1.0
	}
	if pct < 0.0 {
		pct = 0.0
	}

	barWidth := width - 9 // leave space for percentage text
	if barWidth < 10 {
		barWidth = 10
	}

	filledWidth := int(pct * float64(barWidth))
	emptyWidth := barWidth - filledWidth

	styleBarFilled := lipgloss.NewStyle().Foreground(lipgloss.Color("#F6821F"))
	styleBarEmpty := lipgloss.NewStyle().Foreground(lipgloss.Color("#222233"))
	stylePct := lipgloss.NewStyle().Foreground(lipgloss.Color("#F6821F")).Bold(true)

	filled := strings.Repeat("█", filledWidth)
	empty := strings.Repeat("░", emptyWidth)

	return fmt.Sprintf("  %s%s  %s",
		styleBarFilled.Render(filled),
		styleBarEmpty.Render(empty),
		stylePct.Render(fmt.Sprintf("%5.1f%%", pct*100)),
	)
}

func renderMetadataGrid(width int, source, probe, ports string, tested, healthy, target int, rate float64, elapsed, eta string, scanRate string) string {
	col1 := fmt.Sprintf(
		"  %s %s\n  %s %s\n  %s %s",
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Source:"), styleNormal.Render(source),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Probe: "), styleNormal.Render(probe),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Ports: "), styleDim.Render(ports),
	)

	col2 := fmt.Sprintf(
		"  %s %s\n  %s %s\n  %s %s",
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Tested:  "), styleAccent.Render(fmt.Sprintf("%d", tested)),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Healthy: "), styleGood.Render(fmt.Sprintf("%d", healthy)),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Target:  "), styleDim.Render(fmt.Sprintf("%d", target)),
	)

	col3 := fmt.Sprintf(
		"  %s %s\n  %s %s\n  %s %s",
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Speed:   "), styleAccent.Render(scanRate),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Hit Rate:"), styleGood.Render(fmt.Sprintf("%.1f%%", rate)),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Time:    "), styleDim.Render(fmt.Sprintf("%s / %s", elapsed, eta)),
	)

	innerWidth := width - 2
	col1Width := 26
	col2Width := 17
	if innerWidth < col1Width+col2Width+15 {
		col1Width = int(float64(innerWidth) * 0.38)
		col2Width = int(float64(innerWidth) * 0.25)
	}
	col3Width := innerWidth - col1Width - col2Width

	styleCol1 := lipgloss.NewStyle().Width(col1Width).Align(lipgloss.Left)
	styleCol2 := lipgloss.NewStyle().Width(col2Width).Align(lipgloss.Left)
	styleCol3 := lipgloss.NewStyle().Width(col3Width).Align(lipgloss.Left)

	c1Rendered := styleCol1.Render(col1)
	c2Rendered := styleCol2.Render(col2)
	c3Rendered := styleCol3.Render(col3)

	grid := lipgloss.JoinHorizontal(lipgloss.Top, c1Rendered, c2Rendered, c3Rendered)

	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#333344")).
		Padding(1, 0, 1, 0).
		Width(width - 2)

	return borderStyle.Render(grid)
}

func renderPhase2MetadataGrid(width int, done, total, success, failed, skipped int, successRate float64, elapsed, eta string, scanRate string) string {
	skippedStr := "-"
	if skipped > 0 {
		skippedStr = fmt.Sprintf("%d", skipped)
	}

	col1 := fmt.Sprintf(
		"  %s %s\n  %s %s\n  %s %s",
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Tested: "), styleAccent.Render(fmt.Sprintf("%d / %d", done, total)),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Success:"), styleGood.Render(fmt.Sprintf("%d", success)),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Failed: "), styleBad.Render(fmt.Sprintf("%d", failed)),
	)

	col2 := fmt.Sprintf(
		"  %s %s\n  %s %s\n  %s %s",
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Rate:   "), styleAccent.Render(scanRate),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Success:"), styleGood.Render(fmt.Sprintf("%.1f%%", successRate)),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Skipped:"), styleDim.Render(skippedStr),
	)

	col3 := fmt.Sprintf(
		"\n  %s %s\n  %s %s",
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("Elapsed:"), styleDim.Render(elapsed),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("ETA:    "), styleDim.Render(eta),
	)

	innerWidth := width - 2
	col1Width := 23
	col2Width := 19
	if innerWidth < col1Width+col2Width+15 {
		col1Width = int(float64(innerWidth) * 0.35)
		col2Width = int(float64(innerWidth) * 0.30)
	}
	col3Width := innerWidth - col1Width - col2Width

	styleCol1 := lipgloss.NewStyle().Width(col1Width).Align(lipgloss.Left)
	styleCol2 := lipgloss.NewStyle().Width(col2Width).Align(lipgloss.Left)
	styleCol3 := lipgloss.NewStyle().Width(col3Width).Align(lipgloss.Left)

	c1Rendered := styleCol1.Render(col1)
	c2Rendered := styleCol2.Render(col2)
	c3Rendered := styleCol3.Render(col3)

	grid := lipgloss.JoinHorizontal(lipgloss.Top, c1Rendered, c2Rendered, c3Rendered)

	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#333344")).
		Padding(1, 0, 1, 0).
		Width(width - 2)

	return borderStyle.Render(grid)
}
