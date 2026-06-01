//go:build windows

package main

import "syscall"

const swMaximize = 3

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	user32               = syscall.NewLazyDLL("user32.dll")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procGetForeground    = user32.NewProc("GetForegroundWindow")
	procShowWindow       = user32.NewProc("ShowWindow")
)

func maximizeConsoleWindow() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		hwnd, _, _ = procGetForeground.Call()
	}
	if hwnd == 0 {
		return
	}
	procShowWindow.Call(hwnd, swMaximize)
}
