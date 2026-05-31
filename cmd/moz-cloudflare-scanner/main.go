package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/moz/moz-cloudflare-scanner/internal/ui"
	"github.com/moz/moz-cloudflare-scanner/pkg/version"
)

func main() {
	// --version flag without launching TUI
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v" || os.Args[1] == "version") {
		fmt.Println("Moz Cloudflare Scanner", version.String())
		return
	}

	model := ui.NewApp(version.Version)

	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	// Give the UI package a reference so background goroutines can send messages.
	ui.SetProgram(p)

	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
