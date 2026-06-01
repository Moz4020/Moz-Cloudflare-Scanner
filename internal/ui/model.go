package ui

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

	"github.com/moz/moz-cloudflare-scanner/internal/banner"
	"github.com/moz/moz-cloudflare-scanner/internal/config"
	"github.com/moz/moz-cloudflare-scanner/internal/result"
	"github.com/moz/moz-cloudflare-scanner/internal/xraytest"
)

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

// ResultMsg carries a completed probe result from the engine.
type ResultMsg struct {
	ScanID int64
	Result *result.Result
}

// StatsMsg carries live engine counters.
type StatsMsg struct {
	ScanID                            int64
	Tested, Healthy, Failed, InFlight int64
}

// DoneMsg signals the scan has finished.
type DoneMsg struct{ ScanID int64 }

// ErrorMsg carries a user-visible background task error.
type ErrorMsg struct {
	ScanID int64
	Text   string
}

// ColosDoneMsg signals the colo discovery finished.
type ColosDoneMsg struct{ ScanID int64 }

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
)

// ---------------------------------------------------------------------------
// ScanConfig holds form state.
// ---------------------------------------------------------------------------

type ScanConfig struct {
	Count       string
	Concurrency string
	Timeout     string
	Tries       string
	Port        string
	Mode        string // tcp|tls|http
	CIDR        string
	OutputFile  string
	ColoFilter  string
	SNI         string
	UseV4       bool
	UseV6       bool
}

func defaultScanConfig() ScanConfig {
	return ScanConfig{
		Count:       strconv.Itoa(config.ScanDefaults.Count),
		Concurrency: strconv.Itoa(config.ScanDefaults.Concurrency),
		Timeout:     config.ScanDefaults.Timeout.String(),
		Tries:       strconv.Itoa(config.ScanDefaults.Tries),
		Port:        strconv.Itoa(config.ScanDefaults.Port),
		Mode:        config.ScanDefaults.Mode,
		UseV4:       config.ScanDefaults.UseV4,
		UseV6:       config.ScanDefaults.UseV6,
	}
}

// ---------------------------------------------------------------------------
// Quick Scan setup rows
// ---------------------------------------------------------------------------

type quickPreset struct {
	label string
	value string // empty = custom
}

var quickCountPresets = []quickPreset{
	{"Quick 5k", "5000"},
	{"Balanced 20k", "20000"},
	{"Deep 100k", "100000"},
	{"Custom", ""},
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

// quickSetupRow identifies which row is focused on the Quick Scan setup page.
type quickSetupRow int

const (
	qRowCount   quickSetupRow = 0
	qRowWorkers quickSetupRow = 1
	qRowTimeout quickSetupRow = 2
)

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

	// quick scan setup (3-row picker)
	quickRow         quickSetupRow
	quickCountIdx    int
	quickWorkersIdx  int
	quickTimeoutIdx  int
	quickCustomInput textinput.Model
	quickCustomRow   quickSetupRow // which row triggered custom input
	quickCustomMode  bool

	// scan config form
	scanCfg    ScanConfig
	formInputs []textinput.Model
	formFocus  int
	modeIdx    int

	// live scan state
	activeScanID int64
	scanResults  []*result.Result
	sortBy       result.SortBy
	sortIdx      int
	scanStats    StatsMsg
	scanDone     bool
	scanStarted  time.Time
	scanTotal    int

	// colos
	colosResults []*result.Result
	colosDone    bool

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
	configWorkersIdx    int
	configTimeoutIdx    int
	configIPMode        int // 0=random Cloudflare IPs, 1=from ips.txt
	configCustomInput   textinput.Model
	configCustomMode    bool
	configCustomRow     int    // 1=count, 2=workers, 3=timeout, 5=topN custom
	configCountCustom   string // value when Custom count is selected
	configWorkersCustom string // value when Custom workers is selected
	configTimeoutCustom string // value when Custom timeout is selected
	configTopNCustom    string // value when Custom top N is selected
	configOptionalRow   int    // 0=config URL, 1=validate top N, 2=start
	configPortFocus     int
	configSelectedPorts map[int]bool
	// phase 1 state
	configPhase1Results []*result.Result
	configPhase1Done    bool
	configPhase1Only    bool // true when scan stops after Phase 1 (no config URL)
	configPhase1Stats   StatsMsg
	configPhase1Total   int // intended IP count for Phase 1 progress display
	liveResultPath      string

	// shared
	statusMsg string
	version   string
}

type menuEntry struct {
	label string
	desc  string
}

var menuEntries = []menuEntry{
	{"Find Working IPs", "scan Cloudflare IPs — config optional"},
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

	customInput := textinput.New()
	customInput.Placeholder = "e.g. 50000"
	customInput.CharLimit = 10
	customInput.Width = 14

	m := AppModel{
		page:             PageHome,
		spinner:          sp,
		scanCfg:          defaultScanConfig(),
		version:          version,
		width:            120,
		height:           40,
		scanStarted:      time.Now(),
		quickCustomInput: customInput,
		quickCountIdx:    1,
		quickWorkersIdx:  1,
		quickTimeoutIdx:  1,
		configCountIdx:   2,
		configWorkersIdx: 1,
		configTimeoutIdx: 1,
	}

	// Config input for "Scan with Config"
	cfgInput := textinput.New()
	cfgInput.Placeholder = "vless:// or trojan:// share URL"
	cfgInput.CharLimit = 2000
	cfgInput.Width = 0 // 0 = no fixed width, grows with content
	m.configInput = cfgInput

	genInput := textinput.New()
	genInput.Placeholder = "paste your working vless:// config"
	genInput.CharLimit = 2000
	genInput.Width = 0
	m.generatorInput = genInput

	genPrefixInput := textinput.New()
	genPrefixInput.Placeholder = "e.g. Test-fast"
	genPrefixInput.CharLimit = 80
	genPrefixInput.Width = 34
	m.generatorPrefixInput = genPrefixInput

	cfgCustom := textinput.New()
	cfgCustom.Placeholder = "enter value"
	cfgCustom.CharLimit = 10
	cfgCustom.Width = 12
	m.configCustomInput = cfgCustom

	m.modeIdx = modeIndex(m.scanCfg.Mode)
	m.buildFormInputs()
	return m
}

func modeIndex(mode string) int {
	for i, candidate := range modes {
		if candidate == mode {
			return i
		}
	}
	return 0
}

func (m *AppModel) buildFormInputs() {
	fields := []struct{ placeholder, value string }{
		{"count (default 500)", m.scanCfg.Count},
		{"concurrency (default 50)", m.scanCfg.Concurrency},
		{"timeout (default 5s)", m.scanCfg.Timeout},
		{"tries per IP (default 4)", m.scanCfg.Tries},
		{"port (default 443)", m.scanCfg.Port},
		{"CIDR filter (e.g. 104.16.0.0/13, empty = all CF)", m.scanCfg.CIDR},
		{"output file (.csv/.json/.txt, empty = none)", m.scanCfg.OutputFile},
		{"colo filter (e.g. FRA,AMS, empty = all)", m.scanCfg.ColoFilter},
		{"SNI override (empty = auto-rotate)", m.scanCfg.SNI},
	}

	inputs := make([]textinput.Model, len(fields))
	for i, f := range fields {
		ti := textinput.New()
		ti.Placeholder = f.placeholder
		ti.SetValue(f.value)
		ti.CharLimit = 80
		ti.Width = 50
		if i == 0 {
			ti.Focus()
		}
		inputs[i] = ti
	}
	m.formInputs = inputs
	m.formFocus = 0
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

	case ResultMsg:
		if msg.ScanID != m.activeScanID || msg.Result == nil {
			return m, nil
		}
		if m.page == PageLiveColos {
			m.colosResults = append(m.colosResults, msg.Result)
		} else {
			m.scanResults = append(m.scanResults, msg.Result)
			result.Sort(m.scanResults, m.sortBy)
		}
		return m, nil

	case StatsMsg:
		if msg.ScanID == m.activeScanID {
			m.scanStats = msg
		}
		return m, nil

	case ErrorMsg:
		if msg.ScanID == m.activeScanID {
			m.statusMsg = msg.Text
		}
		return m, nil

	case DoneMsg:
		if msg.ScanID == m.activeScanID {
			m.scanDone = true
		}
		return m, nil

	case ColosDoneMsg:
		if msg.ScanID == m.activeScanID {
			m.colosDone = true
		}
		return m, nil

	case ConfigProgressMsg:
		m.configResults = append(m.configResults, msg.Result)
		m.configTotal = msg.Total
		return m, nil

	case ConfigDoneMsg:
		m.configScanning = false
		m.configDone = true
		return m, nil

	case ConfigPhase1ResultMsg:
		m.configPhase1Results = append(m.configPhase1Results, msg.Result)
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
	case PageQuickScanCount:
		return m.handleQuickCountKey(msg)
	case PageScanConfig:
		return m.handleConfigKey(msg)
	case PageLiveScan:
		return m.handleLiveScanKey(msg)
	case PageResults:
		return m.handleResultsKey(msg)
	case PageColos, PageLiveColos:
		return m.handleColosKey(msg)
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
		m.configCountIdx = 2   // default: Balanced 20k
		m.configTopNIdx = 2    // default: 50 for Phase 2
		m.configWorkersIdx = 1 // default: Balanced 100
		m.configTimeoutIdx = 1 // default: Balanced 3s
		m.configIPMode = 0     // default: random Cloudflare IPs
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

func (m AppModel) handleQuickCountKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// If the user is typing a custom value, route keys there first.
	if m.quickCustomMode {
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.quickCustomMode = false
			m.quickCustomInput.Blur()
			return m, nil
		case "enter":
			val := strings.TrimSpace(m.quickCustomInput.Value())
			return m.applyCustomValue(val)
		}
		return m.updateFormInputs(msg)
	}

	presets := m.presetsForRow(m.quickRow)
	idx := m.idxForRow(m.quickRow)

	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc", "q":
		m.page = PageHome
	case "up", "k":
		if m.quickRow > 0 {
			m.quickRow--
		}
	case "down", "j":
		if int(m.quickRow) < 2 {
			m.quickRow++
		}
	case "left", "h":
		if idx > 0 {
			m.setIdxForRow(m.quickRow, idx-1)
		}
	case "right", "l":
		if idx < len(presets)-1 {
			m.setIdxForRow(m.quickRow, idx+1)
		}
	case "enter", " ":
		p := presets[idx]
		if p.value == "" {
			// Activate custom input for this row
			m.quickCustomRow = m.quickRow
			m.quickCustomMode = true
			m.quickCustomInput.SetValue("")
			m.quickCustomInput.Placeholder = m.customPlaceholderForRow(m.quickRow)
			m.quickCustomInput.CharLimit = m.customCharLimitForRow(m.quickRow)
			m.quickCustomInput.Focus()
			return m, textinput.Blink
		}
		// If all non-custom rows have a selection, launch
		return m.launchQuickScan()
	}
	return m, nil
}

func (m AppModel) presetsForRow(row quickSetupRow) []quickPreset {
	switch row {
	case qRowWorkers:
		return quickWorkersPresets
	case qRowTimeout:
		return quickTimeoutPresets
	default:
		return quickCountPresets
	}
}

func (m AppModel) idxForRow(row quickSetupRow) int {
	switch row {
	case qRowWorkers:
		return m.quickWorkersIdx
	case qRowTimeout:
		return m.quickTimeoutIdx
	default:
		return m.quickCountIdx
	}
}

func (m *AppModel) setIdxForRow(row quickSetupRow, idx int) {
	switch row {
	case qRowWorkers:
		m.quickWorkersIdx = idx
	case qRowTimeout:
		m.quickTimeoutIdx = idx
	default:
		m.quickCountIdx = idx
	}
}

func (m AppModel) customPlaceholderForRow(row quickSetupRow) string {
	switch row {
	case qRowWorkers:
		return "e.g. 150"
	case qRowTimeout:
		return "e.g. 4s"
	default:
		return "e.g. 50000"
	}
}

func (m AppModel) customCharLimitForRow(row quickSetupRow) int {
	switch row {
	case qRowTimeout:
		return 8
	default:
		return 10
	}
}

// applyCustomValue stores the typed value back into the right row index and
// advances to the next row or launches if on the last row.
func (m AppModel) applyCustomValue(val string) (tea.Model, tea.Cmd) {
	if val == "" {
		// restore placeholder default
		switch m.quickCustomRow {
		case qRowCount:
			val = "5000"
		case qRowWorkers:
			val = "100"
		case qRowTimeout:
			val = "3s"
		}
	}
	// Store in a dedicated custom-value slot by overwriting the last preset's value.
	// We use a simpler approach: just store in scanCfg directly and flag "custom used".
	switch m.quickCustomRow {
	case qRowCount:
		m.scanCfg.Count = val
		m.quickCountIdx = len(quickCountPresets) - 1 // keep "Custom" highlighted
	case qRowWorkers:
		m.scanCfg.Concurrency = val
		m.quickWorkersIdx = len(quickWorkersPresets) - 1
	case qRowTimeout:
		m.scanCfg.Timeout = val
		m.quickTimeoutIdx = len(quickTimeoutPresets) - 1
	}
	m.quickCustomMode = false
	m.quickCustomInput.Blur()
	if m.quickCustomRow < qRowTimeout {
		m.quickRow = m.quickCustomRow + 1
		return m, nil
	}
	m.quickRow = qRowTimeout
	return m.launchQuickScan()
}

func (m AppModel) customValueForRow(row quickSetupRow) string {
	switch row {
	case qRowWorkers:
		return m.scanCfg.Concurrency
	case qRowTimeout:
		return m.scanCfg.Timeout
	default:
		return m.scanCfg.Count
	}
}

func (m AppModel) customLabelForRow(row quickSetupRow) string {
	value := strings.TrimSpace(m.customValueForRow(row))
	if value == "" {
		return "Custom"
	}
	return "Custom: " + value
}

func (m AppModel) customHelpForRow(row quickSetupRow) string {
	switch row {
	case qRowWorkers:
		return "type an integer worker count, e.g. 75 or 150"
	case qRowTimeout:
		return "type a Go duration, e.g. 4s, 1500ms, 8s"
	default:
		return "type an integer IP count, e.g. 50000"
	}
}

func (m AppModel) launchQuickScan() (tea.Model, tea.Cmd) {
	cfg := defaultScanConfig()

	// Count
	cp := quickCountPresets[m.quickCountIdx]
	if cp.value != "" {
		cfg.Count = cp.value
	} else if m.scanCfg.Count != "" {
		cfg.Count = m.scanCfg.Count
	}

	// Workers
	wp := quickWorkersPresets[m.quickWorkersIdx]
	if wp.value != "" {
		cfg.Concurrency = wp.value
	} else if m.scanCfg.Concurrency != "" {
		cfg.Concurrency = m.scanCfg.Concurrency
	}

	// Timeout
	tp := quickTimeoutPresets[m.quickTimeoutIdx]
	if tp.value != "" {
		cfg.Timeout = tp.value
	} else if m.scanCfg.Timeout != "" {
		cfg.Timeout = m.scanCfg.Timeout
	}

	m.scanCfg = cfg
	m.activeScanID = nextScanID()
	m.statusMsg = ""
	m.scanResults = nil
	m.scanDone = false
	m.scanStats = StatsMsg{ScanID: m.activeScanID}
	m.scanStarted = time.Now()
	n, _ := fmt.Sscanf(cfg.Count, "%d", &m.scanTotal)
	if n == 0 {
		m.scanTotal = 0
	}
	m.page = PageLiveScan
	return m, StartScanCmd(cfg, m.activeScanID)
}

func (m AppModel) handleConfigKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.page = PageHome
		return m, nil
	case "tab", "down":
		m.formFocus = (m.formFocus + 1) % len(m.formInputs)
		for i := range m.formInputs {
			if i == m.formFocus {
				m.formInputs[i].Focus()
			} else {
				m.formInputs[i].Blur()
			}
		}
	case "shift+tab", "up":
		m.formFocus = (m.formFocus - 1 + len(m.formInputs)) % len(m.formInputs)
		for i := range m.formInputs {
			if i == m.formFocus {
				m.formInputs[i].Focus()
			} else {
				m.formInputs[i].Blur()
			}
		}
	case "ctrl+left", "ctrl+right":
		if msg.String() == "ctrl+right" {
			m.modeIdx = (m.modeIdx + 1) % len(modes)
		} else {
			m.modeIdx = (m.modeIdx - 1 + len(modes)) % len(modes)
		}
		m.scanCfg.Mode = modes[m.modeIdx]
	case "f2":
		m.scanCfg.UseV4 = !m.scanCfg.UseV4
	case "f3":
		m.scanCfg.UseV6 = !m.scanCfg.UseV6
	case "enter":
		m.saveScanConfig()
		m.activeScanID = nextScanID()
		m.statusMsg = ""
		m.scanResults = nil
		m.scanDone = false
		m.scanStats = StatsMsg{ScanID: m.activeScanID}
		m.scanStarted = time.Now()
		n, _ := fmt.Sscanf(m.scanCfg.Count, "%d", &m.scanTotal)
		if n == 0 {
			m.scanTotal = 0
		}
		m.page = PageLiveScan
		return m, StartScanCmd(m.scanCfg, m.activeScanID)
	}
	return m.updateFormInputs(msg)
}

func (m *AppModel) saveScanConfig() {
	if len(m.formInputs) >= 9 {
		m.scanCfg.Count = m.formInputs[0].Value()
		m.scanCfg.Concurrency = m.formInputs[1].Value()
		m.scanCfg.Timeout = m.formInputs[2].Value()
		m.scanCfg.Tries = m.formInputs[3].Value()
		m.scanCfg.Port = m.formInputs[4].Value()
		m.scanCfg.CIDR = m.formInputs[5].Value()
		m.scanCfg.OutputFile = m.formInputs[6].Value()
		m.scanCfg.ColoFilter = m.formInputs[7].Value()
		m.scanCfg.SNI = m.formInputs[8].Value()
		m.scanCfg.Mode = modes[m.modeIdx]
	}
}

func (m AppModel) handleLiveScanKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "q", "esc":
		if m.scanDone {
			m.page = PageResults
		} else {
			m.page = PageHome
			return m, CancelScanCmd()
		}
	case "s":
		m.sortIdx = (m.sortIdx + 1) % 5
		m.sortBy = result.SortBy(m.sortIdx)
		result.Sort(m.scanResults, m.sortBy)
	case "enter":
		if m.scanDone {
			m.page = PageResults
		}
	case "c":
		m.statusMsg = "use Find Working IPs to copy config-tested IPs"
	}
	return m, nil
}

func (m AppModel) handleResultsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "q", "esc", "enter":
		m.page = PageHome
	case "s":
		m.sortIdx = (m.sortIdx + 1) % 5
		m.sortBy = result.SortBy(m.sortIdx)
		result.Sort(m.scanResults, m.sortBy)
	case "c":
		m.statusMsg = "use Find Working IPs to copy config-tested IPs"
	}
	return m, nil
}

var clipboardWriteAll = clipboard.WriteAll

// copyHealthyIPsToClipboard writes one IP per line to the system clipboard
// and returns a short status message to display to the user.
func (m AppModel) copyHealthyIPsToClipboard() string {
	top := result.TopN(m.scanResults, 0) // all healthy IPs, sorted by avg
	if len(top) == 0 {
		return "no healthy IPs to copy"
	}
	var sb strings.Builder
	for _, r := range top {
		sb.WriteString(r.IP.String())
		sb.WriteRune('\n')
	}
	if err := clipboard.WriteAll(sb.String()); err != nil {
		return fmt.Sprintf("clipboard error: %v", err)
	}
	return fmt.Sprintf("✓ copied %d IPs to clipboard", len(top))
}

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
	var endpoints []string
	seen := make(map[string]struct{})
	for _, r := range results {
		if r == nil || !r.Success || r.IP == "" {
			continue
		}
		endpoint := formatEndpoint(r.IP, r.Port)
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
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
		colo = "-"
	}
	return fmt.Sprintf("  %-*s  %6.1f%%  %8s  %-6s  %-*s",
		endpointColWidth, formatEndpoint(r.IP.String(), r.Port),
		r.Loss(),
		formatDurationShort(r.Avg()),
		colo,
		statusColWidth, status,
	)
}

func validationHeader() string {
	return fmt.Sprintf("  %-*s  %-*s  %9s  %9s  %-*s",
		endpointColWidth, "ENDPOINT",
		transportColWidth, "TYPE",
		"SPEED",
		"LATENCY",
		statusColWidth, "STATUS",
	)
}

func validationRow(r *xraytest.ValidationResult, status string) string {
	speed := "-"
	latency := "-"
	if r.Success {
		speed = formatValidationSpeed(r.Throughput)
		latency = formatValidationLatency(r.Latency)
	}
	return fmt.Sprintf("  %-*s  %-*s  %9s  %9s  %-*s",
		endpointColWidth, formatEndpoint(r.IP, r.Port),
		transportColWidth, r.Transport,
		speed,
		latency,
		statusColWidth, status,
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

func formatValidationSpeed(throughput float64) string {
	if throughput <= 0 {
		return "n/a"
	}
	mbps := throughput * 8 / 1_000_000
	if mbps >= 100 {
		return fmt.Sprintf("%.0f Mbps", mbps)
	}
	return fmt.Sprintf("%.1f Mbps", mbps)
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

func (m AppModel) handleColosKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "q", "esc", "enter":
		if m.colosDone || m.page == PageColos {
			m.page = PageHome
		}
	}
	return m, nil
}

// updateFormInputs forwards non-key messages (e.g. paste events, resize) to
// every focused text input so they can handle them independently.
func (m AppModel) updateFormInputs(msg tea.Msg) (AppModel, tea.Cmd) {
	var cmds []tea.Cmd

	if m.page == PageQuickScanCount && m.quickCustomMode {
		var cmd tea.Cmd
		m.quickCustomInput, cmd = m.quickCustomInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	if m.page == PageScanConfig && len(m.formInputs) > 0 {
		for i := range m.formInputs {
			var cmd tea.Cmd
			m.formInputs[i], cmd = m.formInputs[i].Update(msg)
			cmds = append(cmds, cmd)
		}
	}

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
	case PageQuickScanCount:
		return m.viewQuickScanCount()
	case PageScanConfig:
		return m.viewScanConfig()
	case PageLiveScan:
		return m.viewLiveScan()
	case PageResults:
		return m.viewResults()
	case PageLiveColos:
		return m.viewLiveColos()
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
	sb.WriteString(styleDim.Render("  simple Cloudflare endpoint toolkit"))
	sb.WriteString("\n")
	sb.WriteString(styleAccent.Render("  0.1.0 Beta"))
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

	sb.WriteString(styleTitle.Render("\n  Generate V2Ray Configs\n"))
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
		sb.WriteString(styleDim.Render("         "+summary) + "\n\n")
	} else {
		sb.WriteString(styleDim.Render("         paste one working VLESS config; endpoints come from ips.txt") + "\n\n")
	}

	rowLabel(1, "  Prefix ")
	sb.WriteString(m.generatorPrefixInput.View() + "\n")
	prefixPreview := strings.TrimSpace(m.generatorPrefixInput.Value())
	if prefixPreview == "" {
		prefixPreview = "Main-Moz"
	}
	sb.WriteString(styleDim.Render(fmt.Sprintf("         generated remarks look like: %s 1, %s 2, ...", prefixPreview, prefixPreview)) + "\n\n")

	rowLabel(2, "  Create ")
	sb.WriteString(styleNormal.Render("configs.txt") + "\n")
	sb.WriteString(styleDim.Render("         press Enter here to generate one v2rayN import URL per endpoint") + "\n\n")

	sb.WriteString(styleDim.Render("  Input   ips.txt next to the exe or current run folder; supports IP or IP:port") + "\n")
	sb.WriteString(styleDim.Render("  Output  configs.txt next to the ips.txt file") + "\n\n")

	if m.generatorCount > 0 {
		sb.WriteString(styleGood.Render(fmt.Sprintf("  ✓ Generated %d v2rayN configs successfully\n", m.generatorCount)))
		if m.generatorOutputPath != "" {
			sb.WriteString(styleDim.Render("  "+m.generatorOutputPath) + "\n")
		}
		sb.WriteRune('\n')
	}
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
	case "esc", "q":
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
// Quick Scan setup page (3-row picker: Count / Workers / Timeout)
// ---------------------------------------------------------------------------

func (m AppModel) viewQuickScanCount() string {
	var sb strings.Builder

	separator := fmt.Sprintf("  %v\n\n", strings.Repeat("─", 64))

	sb.WriteString(banner.Render(m.bannerFrame / 2))
	sb.WriteRune('\n')
	sb.WriteString(styleTitle.Render("  ⚡  Quick Scan Setup\n"))
	sb.WriteString(separator)

	type rowDef struct {
		label   string
		presets []quickPreset
		selIdx  int
		row     quickSetupRow
		hint    string
	}

	rows := []rowDef{
		{
			label:   "  Count   ",
			presets: quickCountPresets,
			selIdx:  m.quickCountIdx,
			row:     qRowCount,
			hint:    "number of Cloudflare IPs to probe",
		},
		{
			label:   "  Workers ",
			presets: quickWorkersPresets,
			selIdx:  m.quickWorkersIdx,
			row:     qRowWorkers,
			hint:    "parallel goroutines — higher is faster but harder on slow networks",
		},
		{
			label:   "  Timeout ",
			presets: quickTimeoutPresets,
			selIdx:  m.quickTimeoutIdx,
			row:     qRowTimeout,
			hint:    "per-probe deadline — raise this if you see lots of timeouts",
		},
	}

	for _, r := range rows {
		focused := m.quickRow == r.row
		labelStyle := styleHeader
		if focused {
			labelStyle = styleAccent
		}
		sb.WriteString(labelStyle.Render(r.label))

		// Render preset pills
		for i, p := range r.presets {
			label := strings.SplitN(p.label, " —", 2)[0] // short label only
			// trim trailing spaces
			label = strings.TrimRight(label, " ")
			if p.value == "" {
				label = m.customLabelForRow(r.row)
			}

			if i == r.selIdx {
				if p.value == "" && m.quickCustomMode && m.quickCustomRow == r.row {
					// Active custom input
					sb.WriteString(fmt.Sprintf("%s%s%s",
						styleAccent.Render("["),
						m.quickCustomInput.View(),
						styleAccent.Render("]"),
					))
				} else {
					sb.WriteString(styleSelected.Render(fmt.Sprintf(" %s ", label)))
				}
			} else {
				sb.WriteString(styleDim.Render(fmt.Sprintf(" %s ", label)))
			}
			if i < len(r.presets)-1 {
				sb.WriteString(styleSep.Render(" │ "))
			}
		}
		sb.WriteRune('\n')

		// Show hint only for the focused row
		if focused {
			sb.WriteString(styleHint.Render("    " + r.hint + "\n"))
		}
		sb.WriteRune('\n')
	}

	if m.quickCustomMode {
		sb.WriteString(styleHint.Render("  " + m.customHelpForRow(m.quickCustomRow) + "   enter confirm   esc cancel"))
	} else {
		sb.WriteString(styleHint.Render("  ↑/↓ row   ←/→ option   enter select/start   esc back"))
	}
	sb.WriteRune('\n')
	return sb.String()
}

// ---------------------------------------------------------------------------
// Scan Config page
// ---------------------------------------------------------------------------

func (m AppModel) viewScanConfig() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  ⚙  Custom Scan Configuration\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n",
		styleSep.Render("  "+strings.Repeat("─", 56)),
	))

	labels := []string{
		"Count      ", "Workers    ", "Timeout    ", "Tries      ", "Port       ",
		"CIDR       ", "Output     ", "Colo Filter", "SNI        ",
	}

	for i, inp := range m.formInputs {
		prefix := "  "
		label := styleHeader.Render(labels[i] + "  ")
		if i == m.formFocus {
			prefix = styleAccent.Render("  ▶ ")
			label = styleAccent.Render(labels[i] + "  ")
		}
		sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, label, inp.View()))
	}

	// Mode toggle
	sb.WriteRune('\n')
	sb.WriteString(styleHeader.Render("  Mode        "))
	for i, mode := range modes {
		if i == m.modeIdx {
			sb.WriteString(styleSelected.Render(fmt.Sprintf(" %s ", strings.ToUpper(mode))))
		} else {
			sb.WriteString(styleDim.Render(fmt.Sprintf(" %s ", strings.ToUpper(mode))))
		}
		sb.WriteString("  ")
	}
	sb.WriteString(fmt.Sprintf("%s\n", styleDim.Render("  ←/→ to cycle")))

	// IPv4/v6 toggles
	v4s := styleGood.Render("ON")
	if !m.scanCfg.UseV4 {
		v4s = styleBad.Render("OFF")
	}
	v6s := styleGood.Render("ON")
	if !m.scanCfg.UseV6 {
		v6s = styleBad.Render("OFF")
	}
	sb.WriteString(fmt.Sprintf("%s%s%s\n", styleHeader.Render("  IPv4         "), v4s, styleDim.Render("  F2 toggle")))
	sb.WriteString(fmt.Sprintf("%s%s%s\n", styleHeader.Render("  IPv6         "), v6s, styleDim.Render("  F3 toggle")))

	sb.WriteRune('\n')
	sb.WriteString(styleHint.Render("  tab/↑↓ navigate   enter start scan   esc back"))
	sb.WriteRune('\n')

	return sb.String()
}

// ---------------------------------------------------------------------------
// Live Scan page
// ---------------------------------------------------------------------------

func (m AppModel) viewLiveScan() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  ⚡  Live Scan\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))

	// Stats row
	elapsed := time.Since(m.scanStarted).Round(time.Second)
	rateStr := "—"
	if elapsed.Seconds() > 0 && m.scanStats.Tested > 0 {
		rateStr = fmt.Sprintf("%.0f/s", float64(m.scanStats.Tested)/elapsed.Seconds())
	}

	icon := m.spinner.View()
	if m.scanDone {
		icon = styleGood.Render("✓")
	}

	progBar := ""
	if m.scanTotal > 0 {
		pct := float64(m.scanStats.Tested) / float64(m.scanTotal) * 100
		bw := 22
		filled := int(pct / 100 * float64(bw))
		progBar = "  [" + styleAccent.Render(strings.Repeat("█", filled)) +
			styleDim.Render(strings.Repeat("░", bw-filled)) + "]" +
			fmt.Sprintf(" %.0f%%", pct)
	}

	sb.WriteString(fmt.Sprintf("  %s  tested: %s  healthy: %s  failed: %s  flying: %s  rate: %s  %s%s\n\n",
		icon,
		styleAccent.Render(fmt.Sprintf("%d", m.scanStats.Tested)),
		styleGood.Render(fmt.Sprintf("%d", m.scanStats.Healthy)),
		styleBad.Render(fmt.Sprintf("%d", m.scanStats.Failed)),
		styleDim.Render(fmt.Sprintf("%d", m.scanStats.InFlight)),
		styleDim.Render(rateStr),
		styleDim.Render(elapsed.String()),
		progBar,
	))

	// Table header
	hdr := fmt.Sprintf("  %-18s  %7s  %9s  %8s  %9s  %5s  %-6s",
		"IP", "LOSS", "AVG(ms)", "JTR(ms)", "DL(KB/s)", "TLS", "COLO")
	sb.WriteString(fmt.Sprintf("%s\n%s\n", styleHeader.Render(hdr), styleSep.Render("  "+strings.Repeat("─", 72))))

	maxRows := m.height - 14
	if maxRows < 3 {
		maxRows = 3
	}
	rows := m.scanResults
	if len(rows) > maxRows {
		rows = rows[:maxRows]
	}

	for _, r := range rows {
		tlsIcon := styleBad.Render("✗")
		if r.TLSOk {
			tlsIcon = styleGood.Render("✓")
		}
		colo := r.Colo
		if colo == "" {
			colo = "—"
		}
		line := fmt.Sprintf("  %-18s  %6.1f%%  %9.2f  %8.2f  %9.1f  %5s  %-6s",
			r.IP.String(), r.Loss(),
			float64(r.Avg().Milliseconds()),
			float64(r.Jitter().Milliseconds()),
			r.Throughput/1024,
			tlsIcon, colo)

		switch {
		case r.IsHealthy() && r.Loss() == 0 && r.Avg().Milliseconds() < 200:
			sb.WriteString(fmt.Sprintf("%s\n", styleGood.Render(line)))
		case !r.IsHealthy():
			sb.WriteString(fmt.Sprintf("%s\n", styleBad.Render(line)))
		default:
			sb.WriteString(fmt.Sprintf("%s\n", styleWarn.Render(line)))
		}
	}

	sb.WriteRune('\n')
	sortNames := []string{"avg", "loss", "jitter", "colo", "speed"}
	hint := fmt.Sprintf("  s sort(→%s)   c copy IPs   q/esc back", sortNames[m.sortIdx%5])
	if m.scanDone {
		hint = fmt.Sprintf("  s sort(→%s)   c copy IPs   enter/q → results", sortNames[m.sortIdx%5])
	}
	if m.statusMsg != "" {
		sb.WriteString(styleGood.Render("  "+m.statusMsg) + "\n")
	}
	sb.WriteString(styleHint.Render(hint))
	return sb.String()
}

// ---------------------------------------------------------------------------
// Results page
// ---------------------------------------------------------------------------

func (m AppModel) viewResults() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  ✅  Scan Results\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", 60))))

	top := result.TopN(m.scanResults, 20)
	if len(top) == 0 {
		sb.WriteString(styleWarn.Render("  No healthy IPs found. Try raising timeout, lowering workers, or using a different SNI.\n"))
	} else {
		hdr := fmt.Sprintf("  %-18s  %7s  %9s  %8s  %9s  %5s  %-6s",
			"IP", "LOSS", "AVG(ms)", "JTR(ms)", "DL(KB/s)", "TLS", "COLO")
		sb.WriteString(fmt.Sprintf("%s\n%s\n", styleHeader.Render(hdr), styleSep.Render("  "+strings.Repeat("─", 72))))

		for i, r := range top {
			tlsIcon := "✗"
			if r.TLSOk {
				tlsIcon = "✓"
			}
			colo := r.Colo
			if colo == "" {
				colo = "—"
			}
			rank := styleAccent.Render(fmt.Sprintf(" %2d. ", i+1))
			line := fmt.Sprintf("%-18s  %6.1f%%  %9.2f  %8.2f  %9.1f  %5s  %-6s",
				r.IP.String(), r.Loss(),
				float64(r.Avg().Milliseconds()),
				float64(r.Jitter().Milliseconds()),
				r.Throughput/1024,
				tlsIcon, colo)
			sb.WriteString(fmt.Sprintf("%s%s\n", rank, styleGood.Render(line)))
		}
	}

	total := len(m.scanResults)
	healthy := 0
	for _, r := range m.scanResults {
		if r.IsHealthy() {
			healthy++
		}
	}
	sb.WriteString("\n")
	sb.WriteString(styleDim.Render(fmt.Sprintf("  Total probed: %d   healthy: %d   unhealthy: %d\n", total, healthy, total-healthy)))
	if m.scanCfg.OutputFile != "" {
		sb.WriteString(styleDim.Render(fmt.Sprintf("  Saved → %s\n", m.scanCfg.OutputFile)))
	}
	sb.WriteString("\n")
	if m.statusMsg != "" {
		sb.WriteString(styleGood.Render("  "+m.statusMsg) + "\n")
	}
	sb.WriteString(styleHint.Render("  s sort   c copy IPs   enter/q → home menu"))
	return sb.String()
}

// ---------------------------------------------------------------------------
// Live Colos page
// ---------------------------------------------------------------------------

func (m AppModel) viewLiveColos() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  🌍  Discovering Cloudflare PoPs\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", 56))))

	if !m.colosDone {
		sb.WriteString(fmt.Sprintf("  %s probing IPs via /cdn-cgi/trace…\n\n", m.spinner.View()))
	} else {
		sb.WriteString(styleGood.Render("  ✓ Discovery complete\n\n"))
	}

	PrintColoTableBuf(&sb, m.colosResults)

	sb.WriteRune('\n')
	sb.WriteString(styleHint.Render("  q/esc → home menu"))
	return sb.String()
}

// ---------------------------------------------------------------------------
// About page
// ---------------------------------------------------------------------------

func (m AppModel) viewAbout() string {
	var sb strings.Builder
	sb.WriteString(banner.Render(m.bannerFrame / 2))
	sb.WriteRune('\n')
	sb.WriteString(styleTitle.Render("  Moz Cloudflare Scanner\n"))
	sb.WriteString(styleDim.Render(fmt.Sprintf("  version %s", m.version)))
	sb.WriteString("\n\n")
	sb.WriteString(styleNormal.Render("  Simple Cloudflare endpoint toolkit for Windows."))
	sb.WriteRune('\n')

	sb.WriteString(styleNormal.Render("  Probes Cloudflare's edge nodes via TCP/TLS/HTTP, measures loss,"))
	sb.WriteRune('\n')

	sb.WriteString(styleNormal.Render("  jitter, and identifies the colo (PoP) behind each IP."))
	sb.WriteString("\n\n")

	sb.WriteString(styleDim.Render("  github.com/Moz4020/Moz-Cloudflare-Scanner"))
	sb.WriteString("\n\n")
	sb.WriteString(styleHint.Render("  enter/q → back"))
	return sb.String()
}

// ---------------------------------------------------------------------------
// Exported helpers for non-TUI callers
// ---------------------------------------------------------------------------

// PrintTable prints a sorted results table to stdout.
func PrintTable(results []*result.Result, top int) {
	sorted := make([]*result.Result, len(results))
	copy(sorted, results)
	result.Sort(sorted, result.SortByAvg)
	if top > 0 && top < len(sorted) {
		sorted = sorted[:top]
	}

	hdr := fmt.Sprintf("  %-18s  %7s  %9s  %8s  %9s  %4s  %-5s",
		"IP", "LOSS", "AVG(ms)", "JTR(ms)", "DL(KB/s)", "TLS", "COLO")
	fmt.Println(hdr)
	fmt.Println("  " + strings.Repeat("─", 72))
	for _, r := range sorted {
		tls := "✗"
		if r.TLSOk {
			tls = "✓"
		}
		colo := r.Colo
		if colo == "" {
			colo = "—"
		}
		fmt.Printf("  %-18s  %6.1f%%  %9.2f  %8.2f  %9.1f  %4s  %-5s\n",
			r.IP.String(), r.Loss(),
			float64(r.Avg().Milliseconds()),
			float64(r.Jitter().Milliseconds()),
			r.Throughput/1024,
			tls, colo)
	}
	fmt.Println()
}

// SimpleProgress prints a one-liner progress update.
func SimpleProgress(tested, healthy, total int64) {
	if total > 0 {
		fmt.Printf("\r  tested: %d/%d (%.0f%%)  healthy: %d",
			tested, total, float64(tested)/float64(total)*100, healthy)
	} else {
		fmt.Printf("\r  tested: %d  healthy: %d", tested, healthy)
	}
}

// PrintColoTableBuf writes a colo summary into sb.
func PrintColoTableBuf(sb *strings.Builder, results []*result.Result) {
	type cs struct {
		count  int
		avgSum int64
		bestMS int64
		bestIP string
	}
	byC := map[string]*cs{}
	for _, r := range results {
		if !r.IsHealthy() || r.Colo == "" {
			continue
		}
		s, ok := byC[r.Colo]
		if !ok {
			s = &cs{bestMS: r.Avg().Milliseconds(), bestIP: r.IP.String()}
			byC[r.Colo] = s
		}
		s.count++
		s.avgSum += r.Avg().Milliseconds()
		if r.Avg().Milliseconds() < s.bestMS {
			s.bestMS = r.Avg().Milliseconds()
			s.bestIP = r.IP.String()
		}
	}
	if len(byC) == 0 {
		sb.WriteString(styleDim.Render("  No colos discovered yet…\n"))
		return
	}
	type row struct {
		colo   string
		count  int
		avgMs  float64
		bestMs int64
		bestIP string
	}
	var rows []row
	for colo, s := range byC {
		rows = append(rows, row{colo, s.count, float64(s.avgSum) / float64(s.count), s.bestMS, s.bestIP})
	}
	// sort by bestMs
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j].bestMs < rows[j-1].bestMs; j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
	sb.WriteString(styleHeader.Render(fmt.Sprintf("  %-6s  %6s  %9s  %9s  %s\n",
		"COLO", "COUNT", "AVG(ms)", "BEST(ms)", "BEST IP")))
	sb.WriteString(styleSep.Render("  " + strings.Repeat("─", 52) + "\n"))
	for _, r := range rows {
		line := fmt.Sprintf("  %-6s  %6d  %9.2f  %9d  %s\n",
			r.colo, r.count, r.avgMs, r.bestMs, r.bestIP)
		sb.WriteString(styleGood.Render(line))
	}
}

// ColoTable prints colo summary to stdout.
func ColoTable(results []*result.Result) {
	var sb strings.Builder
	PrintColoTableBuf(&sb, results)
	fmt.Print(sb.String())
}

// ---------------------------------------------------------------------------
// Command factories (implemented in cmds.go)
// ---------------------------------------------------------------------------

// StartScanCmd, CancelScanCmd, StartTestCmd, StartColosCmd are defined in cmds.go.

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
	sb.WriteString(styleTitle.Render("\n  " + title + "\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))

	if !m.configScanning && !m.configDone {
		// helper: render a preset pill row
		renderPills := func(labels []string, selected int) {
			for i, label := range labels {
				if i == selected {
					sb.WriteString(styleSelected.Render(" " + label + " "))
				} else {
					sb.WriteString(styleNormal.Render("  " + label + "  "))
				}
				if i < len(labels)-1 {
					sb.WriteString(styleDim.Render("│"))
				}
			}
		}

		rowLabel := func(row int, text string) {
			if m.configSetupRow == row {
				sb.WriteString(styleAccent.Render(text))
			} else {
				sb.WriteString(styleDim.Render(text))
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
					sb.WriteString(styleSelected.Render(" " + label + " "))
				} else if enabled[choice.port] {
					sb.WriteString(styleGood.Render(" " + label + " "))
				} else {
					sb.WriteString(styleNormal.Render(" " + label + " "))
				}
				if i < len(configPortChoices)-1 {
					sb.WriteString(styleDim.Render("│"))
				}
			}
		}

		// Row 0: Source
		rowLabel(0, "  Source ")
		sb.WriteString(" ")
		renderPills(configIPModeLabels, m.configIPMode)
		sb.WriteString("\n")
		if m.configIPMode == 0 {
			sb.WriteString(styleDim.Render("            random Cloudflare IPv4 IPs") + "\n\n")
		} else {
			sb.WriteString(styleDim.Render("            read custom IPs from ips.txt next to the app or working directory") + "\n\n")
		}

		// Row 1: Count
		rowLabel(1, "  Count  ")
		sb.WriteString(" ")
		renderPills(configCountLabels, m.configCountIdx)
		sb.WriteString("\n")
		if m.configCustomMode && m.configCustomRow == 1 {
			sb.WriteString(styleAccent.Render("            custom count: ") + m.configCustomInput.View() + "\n\n")
		} else if configCountValues[m.configCountIdx] == 0 && m.configCountCustom != "" {
			sb.WriteString(styleDim.Render(fmt.Sprintf("            IPs to probe in Phase 1  (custom: %s)", m.configCountCustom)) + "\n\n")
		} else if m.configIPMode == 1 {
			sb.WriteString(styleDim.Render("            ignored when Source is From File — all IPs in ips.txt are used") + "\n\n")
		} else {
			sb.WriteString(styleDim.Render("            IPs to probe in Phase 1") + "\n\n")
		}

		// Row 2: Workers
		rowLabel(2, "  Workers")
		sb.WriteString(" ")
		renderPills(quickWorkersLabels(), m.configWorkersIdx)
		sb.WriteString("\n")
		if m.configCustomMode && m.configCustomRow == 2 {
			sb.WriteString(styleAccent.Render("            custom workers: ") + m.configCustomInput.View() + "\n\n")
		} else if quickWorkersPresets[m.configWorkersIdx].value == "" && m.configWorkersCustom != "" {
			sb.WriteString(styleDim.Render(fmt.Sprintf("            concurrent probes  (custom: %s)", m.configWorkersCustom)) + "\n\n")
		} else {
			sb.WriteString(styleDim.Render("            concurrent probes") + "\n\n")
		}

		// Row 3: Timeout
		rowLabel(3, "  Timeout")
		sb.WriteString(" ")
		renderPills(quickTimeoutLabels(), m.configTimeoutIdx)
		sb.WriteString("\n")
		if m.configCustomMode && m.configCustomRow == 3 {
			sb.WriteString(styleAccent.Render("            custom timeout: ") + m.configCustomInput.View() + "\n\n")
		} else if quickTimeoutPresets[m.configTimeoutIdx].value == "" && m.configTimeoutCustom != "" {
			sb.WriteString(styleDim.Render(fmt.Sprintf("            per-probe deadline  (custom: %s)", m.configTimeoutCustom)) + "\n\n")
		} else {
			sb.WriteString(styleDim.Render("            per-probe deadline") + "\n\n")
		}

		// Row 4: Ports
		rowLabel(4, "  Ports  ")
		sb.WriteString(" ")
		renderMultiPorts()
		sb.WriteString("\n")
		sb.WriteString(styleDim.Render("            space toggles a port; selecting multiple ports multiplies work") + "\n\n")

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

	// Progress bar
	pct := 0.0
	if total > 0 {
		pct = float64(done) / float64(total) * 100
	}
	bw := 22
	filled := int(pct / 100 * float64(bw))
	progBar := "[" + styleAccent.Render(strings.Repeat("█", filled)) +
		styleDim.Render(strings.Repeat("░", bw-filled)) + "]" +
		fmt.Sprintf(" %.0f%%", pct)

	skippedPart := ""
	if skipped > 0 {
		skippedPart = fmt.Sprintf("  skipped: %s", styleDim.Render(fmt.Sprintf("%d", skipped)))
	}
	sb.WriteString(fmt.Sprintf("  %s  tested: %s  working: %s  failed: %s%s  success: %s  %s\n",
		icon,
		styleAccent.Render(fmt.Sprintf("%d/%d", done, total)),
		styleGood.Render(fmt.Sprintf("%d", success)),
		styleBad.Render(fmt.Sprintf("%d", failed)),
		skippedPart,
		styleGood.Render(formatPercent(successRate)),
		progBar,
	))
	if done > 0 {
		elapsed := time.Since(m.scanStarted)
		rate := float64(done) / elapsed.Seconds()
		sb.WriteString(styleDim.Render(fmt.Sprintf("  elapsed: %s  rate: %s  eta: %s\n",
			formatDurationShort(elapsed),
			formatRate(rate),
			formatETA(done, total, rate, m.configDone),
		)))
	}
	sb.WriteRune('\n')
	if !m.configDone {
		sb.WriteString(fmt.Sprintf("  %s  xray validating candidates  %s\n\n",
			styleAccent.Render(scanPulse(m.bannerFrame)),
			scanWave(m.bannerFrame+5, 32),
		))
	} else if success > 0 {
		sb.WriteString(styleGood.Render("  Ready: copy working endpoints or import generated configs from the V2Ray generator.\n\n"))
	}

	sb.WriteString(fmt.Sprintf("%s\n%s\n",
		styleHeader.Render(validationHeader()),
		styleSep.Render(tableSeparator(76)),
	))

	// Results
	maxRows := m.height - 12
	if maxRows < 3 {
		maxRows = 3
	}
	rows := m.configResults
	if len(rows) > maxRows {
		rows = rows[len(rows)-maxRows:]
	}

	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		if r.Success {
			sb.WriteString(styleGood.Render(validationRow(r, "working")) + "\n")
		} else if isSkippedValidation(r) {
			sb.WriteString(styleDim.Render(validationRow(r, "skipped")) + "\n")
		} else {
			errMsg := r.Error
			if errMsg == "" {
				errMsg = "failed"
			}
			if len(errMsg) > statusColWidth {
				errMsg = errMsg[:statusColWidth-1] + "…"
			}
			sb.WriteString(styleBad.Render(validationRow(r, errMsg)) + "\n")
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
	sb.WriteString(styleTitle.Render("\n  ⚡  Find Working IPs — optional config\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))

	rowLabel := func(row int, text string) {
		if m.configOptionalRow == row {
			sb.WriteString(styleAccent.Render(text))
		} else {
			sb.WriteString(styleDim.Render(text))
		}
	}

	renderPills := func(labels []string, selected int) {
		for i, label := range labels {
			if i == selected {
				sb.WriteString(styleSelected.Render(" " + label + " "))
			} else {
				sb.WriteString(styleNormal.Render("  " + label + "  "))
			}
			if i < len(labels)-1 {
				sb.WriteString(styleDim.Render("│"))
			}
		}
	}

	rowLabel(0, "  Config ")
	sb.WriteString(" " + m.configInput.View() + "\n")
	if summary := parsedConfigSummary(m.configInput.Value()); summary != "" {
		sb.WriteString(styleDim.Render("            "+summary) + "\n\n")
	} else {
		sb.WriteString(styleDim.Render("            optional — leave empty for Phase 1 only") + "\n\n")
	}

	rowLabel(1, "  Test N ")
	sb.WriteString(" ")
	renderPills(configTopNLabels, m.configTopNIdx)
	sb.WriteString("\n")
	if m.configCustomMode && m.configCustomRow == 5 {
		sb.WriteString(styleAccent.Render("            custom top N: ") + m.configCustomInput.View() + "\n\n")
	} else if m.isTopNCustomSelected() && m.configTopNCustom != "" {
		sb.WriteString(styleDim.Render(fmt.Sprintf("            Phase 2 candidates to validate  (custom: %s)", m.configTopNCustom)) + "\n\n")
	} else {
		sb.WriteString(styleDim.Render("            Phase 2 picks — used only when a config URL is entered") + "\n\n")
	}

	rowLabel(2, "  Start  ")
	mode := "Phase 1 only"
	if strings.TrimSpace(m.configInput.Value()) != "" {
		mode = "Phase 1 + xray validation"
	}
	sb.WriteString(" " + styleNormal.Render(mode) + "\n")
	sb.WriteString(styleDim.Render("            press Enter here to start") + "\n\n")

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
		if m.configOptionalRow < 2 {
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
		}
	case "right", "l":
		if m.configOptionalRow == 1 {
			if m.configTopNIdx < len(configTopNLabels)-1 {
				m.configTopNIdx++
			}
			return m, nil
		}
	case "enter":
		if m.configOptionalRow == 1 && m.isTopNCustomSelected() {
			m.configCustomMode = true
			m.configCustomRow = 5
			m.configCustomInput.SetValue(m.configTopNCustom)
			m.configCustomInput.Placeholder = "e.g. 75"
			m.configCustomInput.Focus()
			return m, textinput.Blink
		}
		if m.configOptionalRow == 1 {
			m.configOptionalRow = 2
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
	m.configPhase1Stats = StatsMsg{}
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

// ConfigDoneMsg signals all config validations are complete.
type ConfigDoneMsg struct{}

// ConfigBatchResultMsg is no longer used — results come one by one via ConfigProgressMsg.
type ConfigBatchResultMsg struct {
	Results []*xraytest.ValidationResult
}

// ConfigProgressMsg carries a single result during scanning.
type ConfigProgressMsg struct {
	Result *xraytest.ValidationResult
	Done   int
	Total  int
}

func (m AppModel) startConfigScan(rawURL string) tea.Cmd {
	return func() tea.Msg {
		go runConfigScan(rawURL)
		return nil
	}
}

func runConfigScan(rawURL string) {
	cfg, err := xraytest.ParseProxyURL(rawURL)
	if err != nil {
		if prog != nil {
			prog.Send(ConfigDoneMsg{})
		}
		return
	}

	// Top CF IPs to test
	testIPs := []string{
		"104.18.5.1", "104.17.0.1", "172.66.40.1",
		"172.67.186.127", "104.21.19.146", "104.16.0.1",
		"104.19.229.21", "104.18.10.1", "104.17.100.1",
		"104.16.200.1",
	}

	ctx := context.Background()
	total := len(testIPs)

	for i, ip := range testIPs {
		swapped := cfg.WithAddress(ip)
		r := xraytest.ValidateConfig(ctx, swapped, 20*time.Second)
		if prog != nil {
			prog.Send(ConfigProgressMsg{
				Result: r,
				Done:   i + 1,
				Total:  total,
			})
		}
	}

	if prog != nil {
		prog.Send(ConfigDoneMsg{})
	}
}

// ---------------------------------------------------------------------------
// Config Setup presets
// ---------------------------------------------------------------------------

var configCountValues = []int{1000, 5000, 20000, 0} // 0 = custom
var configCountLabels = []string{"Quick 1k", "Normal 5k", "Balanced 20k", "Custom"}
var configTopNValues = []int{10, 25, 50, 100, 0} // 0 = all
var configTopNLabels = []string{"10", "25", "50", "100", "All", "Custom"}
var configIPModeLabels = []string{"Random IPs", "ips.txt"}
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
// Config Setup page
// ---------------------------------------------------------------------------

func (m AppModel) viewConfigSetup() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  ⚡  Scan with Config — Setup\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))

	sb.WriteString(styleNormal.Render("  Phase 1: Fast connectivity scan to find reachable IPs") + "\n")
	sb.WriteString(styleNormal.Render("  Phase 2: Test a spread of candidates with your actual xray config") + "\n\n")

	// Count row
	countLabel := "  Count   "
	for i, label := range configCountLabels {
		if i == m.configCountIdx && m.configSetupRow == 0 {
			sb.WriteString(styleSelected.Render(" " + label + " "))
		} else {
			sb.WriteString(styleNormal.Render("  " + label + "  "))
		}
		if i < len(configCountLabels)-1 {
			sb.WriteString(styleDim.Render("│"))
		}
	}
	sb.WriteString("\n")
	if m.configSetupRow == 0 {
		sb.WriteString(styleAccent.Render(countLabel) + styleDim.Render("IPs to probe in Phase 1") + "\n\n")
	} else {
		sb.WriteString(styleDim.Render(countLabel+"IPs to probe in Phase 1") + "\n\n")
	}

	// Phase 2 sample size row
	topLabel := "  Test N  "
	for i, label := range configTopNLabels {
		if i == m.configTopNIdx && m.configSetupRow == 1 {
			sb.WriteString(styleSelected.Render(" " + label + " "))
		} else {
			sb.WriteString(styleNormal.Render("  " + label + "  "))
		}
		if i < len(configTopNLabels)-1 {
			sb.WriteString(styleDim.Render("│"))
		}
	}
	sb.WriteString("\n")
	if m.configSetupRow == 1 {
		sb.WriteString(styleAccent.Render(topLabel) + styleDim.Render("candidates to validate, spread across latency and ranges") + "\n\n")
	} else {
		sb.WriteString(styleDim.Render(topLabel+"candidates to validate, spread across latency and ranges") + "\n\n")
	}

	sb.WriteString(styleHint.Render("  ↑/↓ row   ←/→ option   enter start   esc back") + "\n")

	return sb.String()
}

func (m AppModel) handleConfigSetupKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.page = PageScanWithConfig
		return m, nil
	case "up", "k":
		if m.configSetupRow > 0 {
			m.configSetupRow--
		}
	case "down", "j":
		if m.configSetupRow < 1 {
			m.configSetupRow++
		}
	case "left", "h":
		if m.configSetupRow == 0 && m.configCountIdx > 0 {
			m.configCountIdx--
		} else if m.configSetupRow == 1 && m.configTopNIdx > 0 {
			m.configTopNIdx--
		}
	case "right", "l":
		if m.configSetupRow == 0 && m.configCountIdx < len(configCountLabels)-1 {
			m.configCountIdx++
		} else if m.configSetupRow == 1 && m.configTopNIdx < len(configTopNLabels)-1 {
			m.configTopNIdx++
		}
	case "enter":
		// Start Phase 1
		m.page = PageConfigPhase1
		m.configPhase1Results = nil
		m.configPhase1Done = false
		m.configPhase1Stats = StatsMsg{}
		count := configCountValues[m.configCountIdx]
		if count == 0 {
			count, _ = strconv.Atoi(m.configCountCustom)
			if count <= 0 {
				count = 1000
			}
		}
		m.configPhase1Total = count
		return m, m.startConfigPhase1()
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Config Phase 1 — fast connectivity scan
// ---------------------------------------------------------------------------

type ConfigPhase1ResultMsg struct {
	Result *result.Result
}

// ConfigPhase1ErrMsg is sent when Phase 1 cannot proceed (e.g. ips.txt missing).
type ConfigPhase1ErrMsg struct{ Err string }

type ConfigPhase1StatsMsg = StatsMsg

type ConfigPhase1DoneMsg struct{}

func (m AppModel) viewConfigPhase1() string {
	var sb strings.Builder

	withConfig := strings.TrimSpace(m.configURL) != ""

	sb.WriteString(styleTitle.Render("\n  Phase 1 — Candidate Scan\n"))
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
	targetStr := fmt.Sprintf("%d", m.configPhase1Total)
	countLabel := "candidates"
	if !withConfig {
		countLabel = "healthy"
	}
	source := "Random Cloudflare"
	if m.configIPMode == 1 {
		source = "ips.txt"
	}
	probe := "http"
	if withConfig {
		probe = "config aware"
	}
	rate := 0.0
	if tested > 0 {
		rate = float64(healthy) / float64(tested) * 100
	}
	sb.WriteString(fmt.Sprintf("  %s  source %s   probe %s   ports %s\n",
		icon,
		styleNormal.Render(source),
		styleNormal.Render(probe),
		styleDim.Render(formatPorts(m.resolveConfigPorts())),
	))
	sb.WriteString(fmt.Sprintf("     tested %s   %s %s   target %s   hit-rate %s\n",
		styleAccent.Render(fmt.Sprintf("%d", tested)),
		countLabel,
		styleGood.Render(fmt.Sprintf("%d", healthy)),
		styleDim.Render(targetStr),
		styleGood.Render(formatPercent(rate)),
	))
	if tested > 0 {
		elapsed := time.Since(m.scanStarted)
		scanRate := float64(tested) / elapsed.Seconds()
		sb.WriteString(styleDim.Render(fmt.Sprintf("     elapsed %s   rate %s   eta %s\n",
			formatDurationShort(elapsed),
			formatRate(scanRate),
			formatETA(tested, m.configPhase1Total, scanRate, m.configPhase1Done),
		)))
	}
	sb.WriteRune('\n')
	if !m.configPhase1Done {
		sb.WriteString(fmt.Sprintf("  %s  discovering reachable candidates  %s\n\n",
			styleAccent.Render(scanPulse(m.bannerFrame)),
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
	} else if m.configIPMode == 1 {
		sb.WriteString(styleNormal.Render("  Probing IPs from ips.txt on the selected ports...\n\n"))
	} else if !withConfig {
		sb.WriteString(styleNormal.Render("  Scanning random Cloudflare IPv4 IPs (standard HTTP probe)...\n"))
		sb.WriteString(styleDim.Render("  healthy hits also explore nearby addresses in the same Cloudflare block\n\n"))
	} else {
		sb.WriteString(styleNormal.Render("  Scanning Cloudflare IPs using your config reachability probe...\n"))
		sb.WriteString(styleDim.Render("  Phase 1 only finds candidates; Phase 2 confirms xray works.\n\n"))
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
			lineStyle := styleGood
			if !r.IsHealthy() {
				status = "failed"
				lineStyle = styleBad
			}
			sb.WriteString(lineStyle.Render(endpointCandidateRow(r, status)) + "\n")
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
	fromFile    bool
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
		fromFile:    m.configIPMode == 1,
	}
}

func (m AppModel) phase1TargetTotal(count int) int {
	ports := len(m.resolveConfigPorts())
	if ports <= 0 {
		ports = 1
	}
	if m.configIPMode == 1 {
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
	usedRanges := make(map[string]struct{})

	add := func(r *result.Result, allowRangeRepeat bool) bool {
		if r == nil {
			return false
		}
		if _, ok := seen[r]; ok {
			return false
		}
		key := phase2RangeKey(r.IP)
		if !allowRangeRepeat && key != "" {
			if _, ok := usedRanges[key]; ok {
				return false
			}
		}
		seen[r] = struct{}{}
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

const phase2ValidationTimeout = 7 * time.Second

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

// ---------------------------------------------------------------------------
// Config Phase 2 — xray validation of selected candidates
// ---------------------------------------------------------------------------

func (m AppModel) startConfigPhase2(topIPs []*result.Result) tea.Cmd {
	url := m.configURL
	return func() tea.Msg {
		go runConfigPhase2(url, topIPs)
		return nil
	}
}

func runConfigPhase2(rawURL string, topIPs []*result.Result) {
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

	total := len(topIPs)
	workers := phase2WorkerCount(total)
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
