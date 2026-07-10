package ui

// Page identifies the active screen.
type Page int

const (
	PageHome Page = iota
	PageAbout
	PageScanWithConfig // setup: source, count, workers, timeout, ports
	PageGenerateConfigs
	PageConfigPhase1   // xray config - fast connectivity scan
	PageConfigPhase2   // xray config - xray validation
	PageIPInfo
)
