#!/usr/bin/env sh
set -eu

binary="moz-cloudflare-scanner"
module="github.com/moz/moz-cloudflare-scanner"
cmd="./cmd/moz-cloudflare-scanner"
commit="none"
build_date="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

if command -v git >/dev/null 2>&1; then
	commit="$(git rev-parse --short HEAD 2>/dev/null || printf '%s' none)"
fi

mkdir -p dist

ldflags="-s -w"
ldflags="$ldflags -X $module/pkg/version.Version=1.1"
ldflags="$ldflags -X $module/pkg/version.Commit=$commit"
ldflags="$ldflags -X $module/pkg/version.BuildDate=$build_date"
ldflags="$ldflags -X $module/pkg/version.BuiltBy=build-linux.sh"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$ldflags" -o "dist/$binary-linux-amd64" "$cmd"

printf 'Built dist/%s-linux-amd64\n' "$binary"
