package version

import "fmt"

// These variables are injected at build time via -ldflags.
var (
	Version   = "0.1.2"
	Commit    = "none"
	BuildDate = "unknown"
	BuiltBy   = "source"
)

func String() string {
	return fmt.Sprintf("%s (commit %s, built %s by %s)", Version, Commit, BuildDate, BuiltBy)
}
