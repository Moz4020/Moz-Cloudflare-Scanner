# Contributing to Moz Cloudflare Scanner

Thank you for taking the time to improve Moz Cloudflare Scanner. This project exists so that people on slow or restricted networks can find Cloudflare IPs that **actually work with their own config** — without reading docs, memorizing flags, or babysitting a terminal.

Every contribution should move us closer to that goal.

---

## What we optimize for

These priorities are ordered on purpose. When they conflict, resolve them from top to bottom.

| Priority | What it means in practice |
|---|---|
| **Simplicity for users** | Fewer menu items, fewer decisions, sensible defaults. If a feature needs a paragraph of explanation, simplify the feature first. |
| **Low complexity** | Prefer one clear code path over pluggable frameworks. Avoid new abstractions until the same logic appears at least twice. |
| **Clean code** | Small functions, honest names, minimal scope. Match the style of the file you are editing. |
| **Performance** | Scans must stay fast on weak hardware and bad networks. Do not block the UI thread; measure before adding work per IP. |

Moz Cloudflare Scanner is **not** a general-purpose network lab. Resist scope creep: CLI flags, export formats, and power-user toggles only belong here when they serve the main workflow.

---

## What we welcome

- Bug fixes with a clear root cause
- UX improvements that reduce steps or confusion in the TUI
- Probe / validation accuracy on real restricted networks (Iran, corporate filters, high loss)
- Performance wins that do not sacrifice readability
- Tests that lock in non-obvious behaviour (health rules, sorting, config parsing, multi-port logic)
- Documentation that helps ordinary users, not just developers

## What we usually decline

- New top-level menu flows without a strong user story
- Large refactors unrelated to the change at hand
- Dependencies that pull in heavy toolchains for small gains
- Features that require users to understand xray internals
- “Just in case” configuration surface area

When in doubt, open an issue and describe the problem you are solving before writing a large patch.

---

## Before you code

1. **Search existing issues and PRs** — someone may already be working on it.
2. **For non-trivial work**, open an issue first: what problem, who it helps, proposed approach.
3. **For small fixes** (typo, obvious bug, one-file change), a PR alone is fine — reference the behaviour you fixed.

---

## Development setup

**Requirements:** Go version from [`go.mod`](go.mod), Git.

```bash
git clone https://github.com/moz/moz-cloudflare-scanner.git
cd moz-cloudflare-scanner
go mod download
make build          # → ./moz-cloudflare-scanner
make test           # race + coverage
make test-short     # faster, matches CI -short
make vet
make lint           # optional locally; CI runs golangci-lint
```

Run the TUI locally:

```bash
./moz-cloudflare-scanner
# or
make run
```

**Windows:** `powershell -ExecutionPolicy Bypass -File build.ps1` builds all platform binaries into `dist/`.

---

## Project layout

```
cmd/moz-cloudflare-scanner/     entrypoint
internal/
  ui/                  Bubble Tea TUI, pages, commands
  prober/              TCP / TLS / HTTP probes
  engine/              concurrent scan orchestration
  ipsrc/               Cloudflare IP range generation
  result/              metrics, health rules, sorting
  xraytest/            VLESS/Trojan parse, xray config build, validation
  config/              scan defaults
  output/              CSV / JSON / TXT writers (legacy paths)
pkg/version/           ldflags-injected build metadata
```

**Rule of thumb:** UI talks to the engine and xraytest through thin command helpers (`internal/ui/cmds.go`). Keep probe logic out of view functions; keep lipgloss out of probers.

---

## Design guidelines

### User experience

- **Defaults should work** on a restricted connection without tuning.
- **Progress and errors** must be plain language (“ips.txt not found — place it next to the binary or run folder”), not stack traces in the TUI.
- **Keyboard hints** on every setup screen; arrow keys and vim keys where documented in the README.
- **Do not add CLI flags** for scan behaviour unless there is an exceptional maintenance reason.

### Code

- **Minimize diff size** — the best PR is the smallest one that fully fixes the issue.
- **No drive-by refactors** in the same commit as a feature fix.
- **Comments** explain *why* (DPI behaviour, xray quirks, timeout budgeting), not *what* the next line does.
- **Errors** wrap with context (`fmt.Errorf("open %s: %w", path, err)`) in library code; user-facing strings stay short.
- **Concurrency:** respect existing `context` cancellation; never leak goroutines after the user presses Esc.

### Performance

- Phase 1 may probe **IP × port** combinations — avoid extra allocations or redundant TLS handshakes inside hot loops.
- Background work runs in goroutines started from `tea.Cmd` factories; send results back via typed messages.
- Prefer bounded channels and worker pools over unbounded fan-out.

### Tests

- Add tests when behaviour is easy to regress: health criteria, sorting, URL parsing, port selection, file loading.
- Skip tests that only assert mocks or trivial getters.
- Run `go test ./...` before opening a PR; CI also runs `-race` on Linux, macOS, and Windows.

---

## Pull request checklist

- [ ] `go test ./...` passes locally
- [ ] `go vet ./...` passes
- [ ] Change matches an existing issue or includes a one-paragraph description of the user-visible effect
- [ ] README updated if behaviour, menu flow, or defaults changed
- [ ] No unrelated formatting or file churn
- [ ] Screenshots or terminal captures appreciated for TUI changes

### PR title

Use imperative mood, concise scope:

```
fix(ui): show n/a when Phase 2 speed is unavailable
feat(prober): require WS ok for ws-type configs in Phase 1
docs: update Find Working IPs setup table
```

### Commit messages

Same style as PR titles. Body optional; include **why** when the reason is not obvious.

---

## Reporting bugs

Include as much of the following as you can:

| Field | Example |
|---|---|
| OS / arch | Windows 11 amd64 |
| Version | output of `moz-cloudflare-scanner --version` |
| Screen | Find Working IPs → Phase 2 results |
| Config type | VLESS + WS + TLS (no secrets — redact UUID/password) |
| Expected vs actual | “SPEED shows 0.0 Mbps but endpoint works in v2rayN” |
| Steps | numbered, minimal |

Never paste full share URLs with live credentials in public issues.

---

## Security

This tool runs network probes and embeds xray for validation. Report sensitive issues privately to the maintainers if you believe you have found a security problem — do not open a public issue with exploit details until coordinated.

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE) that covers this project.

---

## Questions

Open a [GitHub Discussion](https://github.com/moz/moz-cloudflare-scanner/discussions) or issue if you are unsure whether an idea fits. A quick “is this in scope?” question saves everyone time.

Thank you for helping keep Moz Cloudflare Scanner fast, simple, and reliable for the people who actually need it.
