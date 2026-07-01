# Moz Cloudflare Scanner Developer Guidelines

This document outlines the architecture, coding standards, and constraints for developing and maintaining the **Moz Cloudflare Scanner**—a specialized tool tailored for Iranian users to find functional Cloudflare IP/port endpoints for VLESS XHTTP and SplitHTTP configurations.

---

## Codebase Architecture & Domain Context

1. **Target Protocol Focus**:
   - The scanner is **purposefully restricted** to `vless://` configurations with `xhttp` or `splithttp` transports (`type=xhttp` or `type=splithttp`).
   - Do **NOT** add support for VMess, Trojan, or legacy transports (e.g., standard WebSocket or gRPC) unless explicitly requested. This keeps the application performant and targeted at current censorship evasion techniques.

2. **The Two-Phase Scanning Pipeline**:
   - **Phase 1 (TCP/TLS Probing)**:
     - Rapidly tests TCP/TLS connectivity to a list of Cloudflare IPs.
     - Found in [internal/prober](file:///c:/Users/moz/Documents/Moz%20Projects/Moz-Cloudflare-Scanner/internal/prober).
     - Keeps concurrent connection counts high to quickly filter down candidates.
   - **Phase 2 (Xray Validation)**:
     - Validates Phase 1 candidates using real `xray-core` instances.
     - Found in [internal/xraytest](file:///c:/Users/moz/Documents/Moz%20Projects/Moz-Cloudflare-Scanner/internal/xraytest).
     - Measures median First-Byte Latency (TTFB) and Throughput using a 256KB download test from `speed.cloudflare.com`.
     - Validates using a SOCKS5 proxy spun up dynamically for each candidate.

---

## Coding Standards & Technical Guidelines

### 1. In-Memory Xray-Core Execution
- **Rule**: Never write temporary JSON configuration files to disk during scanning. 
- **Rationale**: Disk I/O syscalls severely degrade Phase 2 scan speeds, especially on low-end virtual servers (VPS) or slow HDDs.
- **Practice**: Config templates should be built as JSON in memory and passed straight to `serial.DecodeJSONConfig(bytes.NewReader(configJSON))` to spawn xray instances.

### 2. TUI & Standard Library Logging
- **Rule**: Never log to standard output (`stdout`) or standard error (`stderr`) during execution.
- **Rationale**: The application uses a Bubble Tea TUI with AltScreen buffer. Writing to stdout/stderr will corrupt the interface rendering.
- **Practice**: All standard logger outputs should be discarded (e.g., `log.SetOutput(io.Discard)`) at startup. Save scan outputs/results into physical text files (e.g., `ips.txt`, `configs.txt`) or specific result files rather than writing to stdout/stderr.

### 3. Goroutine Safety and Engine Execution
- **Rule**: The core scanning engine ([internal/engine](file:///c:/Users/moz/Documents/Moz%20Projects/Moz-Cloudflare-Scanner/internal/engine)) relies on dynamic worker pools. Any result processing functions passed to the engine (e.g., `ResultFunc`) must be fully thread-safe.
- **Practice**: Use atomic operations or mutex locks when writing or aggregating stats in the UI or output handlers.

### 4. Memory & Resource Leak Prevention
- **Rule**: Clean up xray instances and release port allocations immediately after validation.
- **Practice**: 
  - Ensure `instance.Close()` is called (typically via `defer`) when validation completes.
  - Dynamically allocate local SOCKS5 proxy ports (using thread-safe atomic counters starting above 20000) to prevent port conflicts during highly concurrent validation runs.

### 5. Robust Network Handling for Restricted Environments
- **Rule**: Configure network probers and validations with robust, configurable timeouts.
- **Rationale**: Networks in Iran often experience high packet drop rates, packet injection, and packet delays. Too short of a timeout will discard slow but working IPs.
- **Practice**: Ensure a floor timeout of at least 10 seconds is used for the final validation checks to give slower paths a fair chance of succeeding.

---

## Testing & Verification

- Every module (ui, engine, prober, ipsrc, result, xraytest) must include corresponding `*_test.go` unit tests.
- When adding or changing configuration parsing, ensure that:
  - Valid VLESS configs parse correctly.
  - Invalid configs, other protocols, or unsupported transport types are gracefully rejected with descriptive errors.
