# Moz Cloudflare Scanner

Find Cloudflare IPs that work with your **VLESS XHTTP** config, then save the working `IP:port` endpoints for v2rayN, NekoRay, Hiddify, or another Xray-based client.

This app is made for people who just want to scan. You do not need Go, coding knowledge, or a terminal build setup if you download the release files.

## Download

From the GitHub **Releases** page, download the file for your system:

```text
Windows: moz-cloudflare-scanner-windows-amd64-1.0.zip
Linux:   moz-cloudflare-scanner-linux-amd64-1.0.tar.gz
```

## Windows

1. Download `moz-cloudflare-scanner-windows-amd64-1.0.zip`.
2. Right-click it and choose **Extract All**.
3. Open the extracted folder.
4. Double-click `moz-cloudflare-scanner.exe`.

If Windows SmartScreen appears, choose **More info** and then **Run anyway**.

## Linux VPS

Upload or download `moz-cloudflare-scanner-linux-amd64-1.0.tar.gz`, then run:

```bash
tar -xzf moz-cloudflare-scanner-linux-amd64-1.0.tar.gz
chmod +x moz-cloudflare-scanner-linux-amd64
./moz-cloudflare-scanner-linux-amd64
```

Run it inside a real SSH terminal. Clipboard copy may not work on some headless VPS systems, but successful endpoints are still saved to `ips.txt`.

## Scan For Working IPs

1. Open **Find Working IPs**.
2. Keep **Default CF** selected unless you already have your own IP list.
3. Choose a scan size:
   - **Fast**: quick first try.
   - **Balanced**: recommended.
   - **Deep**: slower, more complete.
4. Paste one working `vless://` **XHTTP** config.
5. Start the scan.
6. Wait for Phase 1 and Phase 2 to finish.
7. Press `c` to copy and save working endpoints.

The app saves working endpoints to:

```text
ips.txt
```

Example:

```text
104.17.122.146:443
104.18.152.95:8443
```

## What Configs Are Supported?

Supported:

```text
vless://...type=xhttp...
vless://...type=splithttp...
```

Not supported:

```text
trojan://...
vmess://...
vless://...type=ws...
vless://...type=grpc...
```

This is intentional. The scanner is focused on VLESS XHTTP because that is the main target for strict firewall conditions.

## Generate Client Configs

After scanning:

1. Keep the saved `ips.txt` next to the app.
2. Open **Generate V2Ray Configs**.
3. Paste your original working VLESS XHTTP config.
4. Choose a name prefix, such as `Moz Fast`.
5. Generate.

The app writes:

```text
configs.txt
```

Import those generated links into v2rayN or another compatible client.

## Use Your Own IP List

Create an `ips.txt` file next to the app before scanning.

Supported lines:

```text
104.17.122.146
104.18.152.95:8443
45.130.125.0/24
```

Large CIDR ranges are rejected to prevent accidental huge scans.

## Result Files

During scans, a live result file is created:

```text
MozCloudflareScannerResult-YYYYMMDD-HHMMSS.txt
```

You can open this file while the scan is running.

## Notes

- This tool is for testing your own configs and endpoints.
- Phase 1 finds Cloudflare candidates.
- Phase 2 validates candidates with xray and is the result that matters.
- Runtime files such as `ips.txt`, `configs.txt`, scan result files, and `dist` builds should not be committed.

## Build From Source

Normal users do not need this section.

Windows:

```powershell
.\build.ps1
```

Linux:

```bash
sh build-linux.sh
```

Create release packages:

```powershell
.\release.ps1
```

```bash
sh release-linux.sh
```

## License

MIT - see [LICENSE](LICENSE).
