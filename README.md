# Moz Cloudflare Scanner

An easy terminal app for finding Cloudflare `IP:port` endpoints that work with **your VLESS XHTTP configuration**. It is designed for Windows users and Linux VPS users who want to scan, copy the working results, and use them in their client.

## What you need

- A working `vless://` link with `type=xhttp`.
- Windows 10/11 or a Linux VPS.
- Permission to test the configuration and endpoints you use.

No Go installation or coding knowledge is needed when using a release build.

## Quick start (Windows)

1. Download and extract the Windows release zip.
2. Open the extracted folder and run `moz-cloudflare-scanner.exe`.
3. On the main menu, choose **Find Cloudflare IPs**.
4. Keep **Default CF** and **Balanced** selected for your first scan.
5. Paste your working VLESS XHTTP link on the **Config** row.
6. Leave **Upload → Upload test: off** unless you want to compare upload quality. You can choose a 64 KiB sample with a 4 MiB cap or a 128 KiB sample with an 8 MiB cap for the entire scan.
7. On **Files**, choose whether to create a live scan report. Turn it off for an in-memory scan with no report file.
8. Choose **Start** and press Enter.
9. When the scan finishes, press `c` to copy and save the working endpoints.

If Windows SmartScreen appears, use **More info** → **Run anyway** only when you downloaded the file from a source you trust.

## What the scanner does

The scanner has two phases:

1. **Phase 1 — Candidate scan:** quickly checks Cloudflare IPs for reachability using your config's host, path, and port.
2. **Phase 2 — Xray validation:** tests the best candidates through embedded Xray. A saved endpoint must pass **3 out of 3** checks. The optional upload probe measures route quality through the same Xray session; it never changes whether an endpoint passes validation.

Phase 2 is slower by design. Its result is the one that matters.

### Profiles

| Profile | Good for | Phase 1 IPs | Phase 1 tries | Phase 2 candidates |
| --- | --- | ---: | ---: | ---: |
| Quick | A fast first attempt | 5,000 | 1 | 25 |
| Balanced | Most users | 10,000 | 2 | 50 |
| Deep | A longer, broader scan | 20,000 | 3 | 100 |

When a VLESS config is supplied, Phase 1 uses one config-aware reachability
check per endpoint; Phase 2 remains the authoritative 3-of-3 Xray validation.

Use **Advanced** to choose a smaller Top N or **All validated** when you want to test every healthy Phase-1 endpoint. “All validated” can take a long time.

### Optional upload quality

**Upload → Upload test: 64 KB** or **Upload test: 128 KB** sends one small random payload to Cloudflare's edge only after the endpoint passes all three Phase-2 checks. The sample is shown in the Phase-2 **UPLOAD** column, and working endpoints are ordered by measured upload speed when available. The 64 KiB mode reserves at most 4 MiB per scan; the 128 KiB mode reserves at most 8 MiB. Candidates beyond the selected budget are still valid, but show no upload measurement.

## Your results

Successful endpoints are written to `ips.txt` next to the application:

```text
104.17.122.146:443
104.18.152.95:8443
```

The app also creates a live scan report while it runs:

```text
MozCloudflareScannerResult-YYYYMMDD-HHMMSS.txt
```

You can open this report at any time to see progress and failures.

Live reports are optional. Set **Files → Live report: off** before starting a scan if you do not want a report file created. In either mode, `ips.txt` is written only after you press `c` to save the displayed working endpoints.

## Generate client links

After a scan:

1. Leave `ips.txt` next to the application.
2. Choose **VLESS Config Generator** from the main menu.
3. Paste the same working VLESS XHTTP link.
4. Enter an optional name prefix, such as `Moz Fast`.
5. Select **Generate configs.txt**.

The generated `configs.txt` contains one VLESS link per endpoint. Import those links into a compatible Xray client such as v2rayN, NekoRay, or Hiddify.

## Use your own IP list

Create an `ips.txt` file next to the executable, then choose **ips.txt** as the source on the scanner screen.

Each line may be an IP, an `IP:port`, or a small IPv4 CIDR:

```text
104.17.122.146
104.18.152.95:8443
45.130.125.0/24
```

Large CIDR ranges are rejected to prevent accidental very large scans.

## Supported configuration

The scanner intentionally accepts only:

```text
vless://...type=xhttp...
```

It preserves XHTTP settings, ML-KEM 768xplus encryption, XTLS Vision flow, TLS fingerprint, ALPN, and XHTTP extras when it validates or generates links.

It does not accept Trojan, VMess, WebSocket, gRPC, or SplitHTTP links.

## Linux VPS

Extract the Linux release and run it in an interactive SSH terminal:

```bash
tar -xzf moz-cloudflare-scanner-linux-amd64-1.2.tar.gz
chmod +x moz-cloudflare-scanner-linux-amd64
./moz-cloudflare-scanner-linux-amd64
```

Clipboard support may be unavailable on a headless VPS, but results are always written to `ips.txt`.

## Build from source

Most users can skip this section.

```powershell
.\build.ps1
```

```bash
sh build-linux.sh
```

## License

MIT — see [LICENSE](LICENSE).
