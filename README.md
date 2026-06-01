# Moz Cloudflare Scanner

Simple Windows toolkit for finding Cloudflare endpoints that work with VLESS/Trojan configs, validating them with xray, and generating v2rayN import configs.

## Download

For normal use, download the latest Windows build from the GitHub **Releases** page.

Recommended release asset:

```text
moz-cloudflare-scanner-windows-amd64.zip
```

Extract it, then run:

```powershell
.\moz-cloudflare-scanner.exe
```

## Features

- Scan Cloudflare IPs using a config-aware Phase 1 probe.
- Validate candidates through xray in Phase 2.
- Copy working `IP:port` endpoints and save them to `ips.txt`.
- Generate `configs.txt` for v2rayN from one working VLESS config plus `ips.txt`.
- Supports Windows-focused local usage without CI, installers, or Linux/macOS packaging.

## Usage

### Find Working IPs

1. Open **Find Working IPs**.
2. Choose source, count, workers, timeout, and ports.
3. Paste a `vless://` or `trojan://` config.
4. Let Phase 1 find reachable Cloudflare candidates.
5. Let Phase 2 validate candidates through xray.
6. Press `c` to copy working endpoints and save them to `ips.txt`.

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

`ips.txt` supports plain IPs and `IP:port` endpoints:

```text
104.17.122.146
104.18.152.95:8443
```

Generated remarks use numbered names:

```text
Moz Fast 1
Moz Fast 2
Moz Fast 3
```

## Build From Source

Requirements:

- Windows
- Go installed and available in PowerShell

Build:

```powershell
.\build.ps1
```

The executable is written to:

```text
dist\moz-cloudflare-scanner.exe
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

## Notes

- This project is Windows-only.
- Runtime files such as `ips.txt`, generated results, `configs.txt`, and `dist\` builds should not be committed.
- This tool is for testing your own configs and endpoints.

Tiny attribution: this project is a fork of SenPai Scanner.

## License

MIT - see [LICENSE](LICENSE).
