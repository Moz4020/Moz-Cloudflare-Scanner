# Moz Cloudflare Scanner

Simple toolkit for finding Cloudflare endpoints that work with VLESS/Trojan configs, validating them with xray, and generating v2rayN import configs.

## Download

For normal use, download the latest build for your platform from the GitHub **Releases** page.

Recommended release asset:

```text
moz-cloudflare-scanner-windows-amd64.zip
moz-cloudflare-scanner-linux-amd64-0.1.2.tar.gz
```

Extract it, then run:

```powershell
.\moz-cloudflare-scanner.exe
```

Linux:

```bash
tar -xzf moz-cloudflare-scanner-linux-amd64-0.1.2.tar.gz
chmod +x moz-cloudflare-scanner-linux-amd64
./moz-cloudflare-scanner-linux-amd64
```

## Features

- Scan Cloudflare IPs using a config aware Phase 1 probe.
- Validate candidates through xray in Phase 2.
- Copy working `IP:port` endpoints and save them to `ips.txt`.
- Generate `configs.txt` for v2rayN from one working VLESS config plus `ips.txt`.
- Supports Windows desktop usage and Linux amd64 VPS usage, including an optional VPS installer.

## Usage

### Find Working IPs

1. Open **Find Working IPs**.
2. Choose source, count, workers, timeout, and ports.
3. Paste a `vless://` or `trojan://` config.
4. Let Phase 1 find reachable Cloudflare candidates.
5. Let Phase 2 validate candidates through xray.
6. Press `c` to copy working endpoints and save them to `ips.txt`.

Source modes:

```text
Default CF        Scan the default Cloudflare IPv4 ranges.
ips.txt           Scan only IPs/CIDRs from ips.txt.
```

Live scan output is written to:

```text
MozCloudflareScannerResult-YYYYMMDD-HHMMSS.txt
```

### Generate V2Ray Configs

1. Put working endpoints in `ips.txt` next to the exe.
2. Open **Generate V2Ray Configs**.
3. Paste one working VLESS config.
4. Set an optional name prefix, such as `Moz Fast`.
5. Generate `configs.txt`.

For scanning, `ips.txt` supports plain IPs, `IP:port` endpoints, and small IPv4 CIDRs. In scan mode, the Ports row controls which ports are probed.

```text
104.17.122.146
104.18.152.95:8443
45.130.125.0/24
```

Large CIDRs are rejected to avoid accidental huge scans.

For config generation, `ips.txt` supports plain IPs and `IP:port` endpoints. Generated configs preserve endpoint ports from `ips.txt`.

Generated remarks use numbered names:

```text
Moz Fast 1
Moz Fast 2
Moz Fast 3
```

## Build From Source

Requirements:

- Go 1.26.3 or newer

Windows build:

```powershell
.\build.ps1
```

The executable is written to:

```text
dist\moz-cloudflare-scanner.exe
```

Linux build on Ubuntu or another Linux host:

```bash
bash build-linux.sh
```

The executable is written to:

```text
dist/moz-cloudflare-scanner-linux-amd64
```

Cross-compile Linux from Windows PowerShell:

```powershell
$env:CGO_ENABLED='0'
$env:GOOS='linux'
$env:GOARCH='amd64'
go build -trimpath -o dist/moz-cloudflare-scanner-linux-amd64 ./cmd/moz-cloudflare-scanner
```

Run tests:

```powershell
go test -short ./...
```

## Create a Windows Release Zip

Build and package a release zip:

```powershell
.\release.ps1
```

The release zip is written to:

```text
dist\moz-cloudflare-scanner-windows-amd64.zip
```

Upload that zip to a GitHub Release so users do not need to compile the app.

## Create a Linux Release Tarball

Build and package a Linux amd64 release tarball:

```bash
bash release-linux.sh
```

The release tarball is written to:

```text
dist/moz-cloudflare-scanner-linux-amd64-0.1.2.tar.gz
```

## Run on an Ubuntu 24.04 VPS

One-command install from the latest GitHub Linux release:

```bash
curl -fsSL https://raw.githubusercontent.com/Moz4020/Moz-Cloudflare-Scanner/main/installer.sh | sh
```

If `curl` is not installed:

```bash
wget -qO- https://raw.githubusercontent.com/Moz4020/Moz-Cloudflare-Scanner/main/installer.sh | sh
```

Then run:

```bash
~/.local/bin/moz-cloudflare-scanner
```

The installer keeps the app and runtime files in:

```text
~/moz-cloudflare-scanner
```

That is where `ips.txt`, `configs.txt`, and `MozCloudflareScannerResult-*.txt` will be written.

If you use the release tarball, Go is not required on the VPS:

```bash
sudo apt update
sudo apt install -y ca-certificates tar
tar -xzf moz-cloudflare-scanner-linux-amd64-0.1.2.tar.gz
chmod +x moz-cloudflare-scanner-linux-amd64
./moz-cloudflare-scanner-linux-amd64
```

If you build on the VPS instead, install Go 1.26.3 or newer, clone the repo, then run:

```bash
bash build-linux.sh
./dist/moz-cloudflare-scanner-linux-amd64
```

This is a terminal TUI, so run it inside a real SSH terminal. Clipboard copy can fail on headless Linux servers, but successful endpoint lists are still saved to `ips.txt`.

## Notes

- Linux support targets Ubuntu 24.04 amd64 and other modern amd64 Linux hosts.
- Runtime files such as `ips.txt`, generated results, `configs.txt`, and `dist\` builds should not be committed.
- This tool is for testing your own configs and endpoints.

Attribution: this project is a fork of SenPai Scanner.

## License

MIT - see [LICENSE](LICENSE).
