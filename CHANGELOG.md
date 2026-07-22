# Changelog

## v1.2 — 2026-07-22

### Iranian route quality and presentation

- Added an opt-in Phase 2 upload-quality probe for comparing endpoints with poor upstream performance.
- Added selectable 64 KiB / 128 KiB samples with 4 MiB / 8 MiB scan-wide caps; upload measurement never affects strict Xray pass/fail results.
- Centered Phase 1 and Phase 2 table headers and values inside their fixed-width columns for easier comparison.
- Updated Windows/Linux build and archive metadata to version 1.2.

## v1.1 — 2026-07-11

### Faster, stricter scanning

- Made the Phase 1 XHTTP prefilter faster by removing its redundant retry.
- Added profile-based Phase 2 candidate caps and an Advanced **All validated** option.
- Kept final results strict: a working endpoint must pass all three Xray checks.
- Preserved ML-KEM 768xplus, XTLS Vision, XHTTP extras, TLS fingerprints, and ALPN when validating and generating VLESS links.
- Fixed generated links dropping `flow=xtls-rprx-vision`.
- Enforced VLESS XHTTP-only input; SplitHTTP and other transports are rejected.

### Better control and privacy

- Added **Files → Live report: on/off** in the scan setup.
- Turning reports off keeps the scan in memory; `ips.txt` is written only when you explicitly press `c` to save results.

### User interface

- Refreshed the main menu, setup screen, Phase 1 and Phase 2 progress screens, generator, IP lookup, and About page.
- Fixed generator input focus when moving between the Config, Prefix, and Create rows.
- Reworked the README into a beginner-friendly quick-start guide.

### Quality

- Added coverage for generator focus navigation, Phase 2 selection behavior, XHTTP parsing, and Vision link preservation.
- Ran `go vet ./...` and `go test ./...`.
