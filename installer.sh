#!/usr/bin/env sh
set -eu

repo="${MOZ_CLOUDFLARE_SCANNER_REPO:-Moz4020/Moz-Cloudflare-Scanner}"
install_dir="${MOZ_CLOUDFLARE_SCANNER_HOME:-$HOME/moz-cloudflare-scanner}"
bin_dir="${MOZ_CLOUDFLARE_SCANNER_BIN_DIR:-$HOME/.local/bin}"
binary="moz-cloudflare-scanner-linux-amd64"
launcher="moz-cloudflare-scanner"

github_api="https://api.github.com/repos/$repo/releases/latest"

say() {
	printf '%s\n' "$*"
}

need_command() {
	command -v "$1" >/dev/null 2>&1
}

install_apt_dependencies() {
	if ! need_command apt-get || ! need_command sudo; then
		return 1
	fi
	say "Installing required packages with apt..."
	sudo apt-get update
	sudo apt-get install -y ca-certificates curl tar
}

ensure_dependencies() {
	missing=""
	if ! need_command curl && ! need_command wget; then
		missing="$missing curl-or-wget"
	fi
	if ! need_command tar; then
		missing="$missing tar"
	fi

	if [ -n "$missing" ]; then
		if ! install_apt_dependencies; then
			say "Missing required tools:$missing"
			say "Install ca-certificates, curl or wget, and tar, then run this installer again."
			exit 1
		fi
	fi
}

download_to_stdout() {
	url="$1"
	if need_command curl; then
		curl -fsSL "$url"
	else
		wget -qO- "$url"
	fi
}

download_to_file() {
	url="$1"
	path="$2"
	if need_command curl; then
		curl -fL "$url" -o "$path"
	else
		wget -O "$path" "$url"
	fi
}

detect_platform() {
	os="$(uname -s 2>/dev/null || printf unknown)"
	arch="$(uname -m 2>/dev/null || printf unknown)"
	if [ "$os" != "Linux" ]; then
		say "This installer is for Linux VPS hosts. Detected: $os"
		exit 1
	fi
	case "$arch" in
		x86_64|amd64)
			;;
		*)
			say "Unsupported Linux architecture: $arch"
			say "Current release asset supports linux-amd64 only."
			exit 1
			;;
	esac
}

latest_linux_asset_url() {
	release_json="$(download_to_stdout "$github_api")"
	asset_url="$(printf '%s\n' "$release_json" |
		tr -d '\r' |
		sed -n 's/.*"browser_download_url": "\(https:\/\/github.com\/[^"]*moz-cloudflare-scanner-linux-amd64[^"]*\.tar\.gz\)".*/\1/p' |
		head -n 1)"
	if [ -z "$asset_url" ]; then
		say "Could not find a linux-amd64 .tar.gz asset in the latest GitHub release."
		say "Check that the release contains moz-cloudflare-scanner-linux-amd64-*.tar.gz."
		exit 1
	fi
	printf '%s\n' "$asset_url"
}

install_release() {
	asset_url="$1"
	tmp_dir="$(mktemp -d)"
	archive="$tmp_dir/moz-cloudflare-scanner-linux-amd64.tar.gz"
	extract_dir="$tmp_dir/extract"

	cleanup() {
		rm -rf "$tmp_dir"
	}
	trap cleanup EXIT INT TERM

	say "Downloading latest Linux release..."
	download_to_file "$asset_url" "$archive"

	mkdir -p "$extract_dir"
	tar -xzf "$archive" -C "$extract_dir"

	if [ ! -f "$extract_dir/$binary" ]; then
		say "Release archive did not contain $binary"
		exit 1
	fi

	mkdir -p "$install_dir" "$bin_dir"
	cp "$extract_dir/$binary" "$install_dir/$binary"
	chmod +x "$install_dir/$binary"

	if [ -f "$extract_dir/README.md" ]; then
		cp "$extract_dir/README.md" "$install_dir/README.md"
	fi
	if [ -f "$extract_dir/LICENSE" ]; then
		cp "$extract_dir/LICENSE" "$install_dir/LICENSE"
	fi

	cat > "$bin_dir/$launcher" <<EOF
#!/usr/bin/env sh
cd "$install_dir"
exec "$install_dir/$binary" "\$@"
EOF
	chmod +x "$bin_dir/$launcher"
}

main() {
	detect_platform
	ensure_dependencies
	asset_url="$(latest_linux_asset_url)"
	install_release "$asset_url"

	say ""
	say "Moz Cloudflare Scanner installed successfully."
	say "Install dir: $install_dir"
	say "Launcher:    $bin_dir/$launcher"
	say ""
	say "Run it with:"
	say "  $bin_dir/$launcher"
	say ""
	if ! printf '%s' ":$PATH:" | grep -q ":$bin_dir:"; then
		say "Tip: $bin_dir is not in PATH for this shell."
		say "Run directly with:"
		say "  $bin_dir/$launcher"
	fi
	say "Runtime files like ips.txt, configs.txt, and scan result logs will be kept in:"
	say "  $install_dir"
}

main "$@"
