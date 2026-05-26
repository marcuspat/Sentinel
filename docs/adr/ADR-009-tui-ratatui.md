# ADR-009: Ratatui for the Terminal User Interface

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** UI, Dependencies, Deployment

---

## Context

Sentinel requires a terminal user interface to support the following operator interactions:

- **Session management.** Starting sessions with a stated goal, monitoring session phase transitions (Investigating → Planning → Executing → Verifying), viewing status indicators.
- **Plan review and approval.** Presenting the generated plan in a human-readable, structured format with risk tier indicators, dry-run results, and per-step descriptions. Accepting or rejecting the plan.
- **Step-level editing.** Allowing the operator to modify individual plan step parameters, remove steps, or reorder steps before approval.
- **Execution monitoring.** Showing real-time progress of capability invocations, streaming stdout/stderr output from subprocess capabilities, displaying success/failure indicators.
- **Audit log browsing.** Presenting recent audit events in a scrollable, filterable view.
- **Kill switch controls.** Providing accessible keyboard shortcuts to activate kill switches and halt all High/Critical operations.
- **Fleet overview.** Displaying connected hosts, their status, and current session state for fleet deployments.

The TUI must work in standard terminal emulators (xterm, iTerm2, GNOME Terminal, tmux, screen) on Linux and macOS. It must not require GUI libraries, window managers, or X11.

The implementation is in the `sentinel-tui` crate.

---

## Decision

The `sentinel-tui` crate uses **Ratatui** (version 0.26) with the **crossterm** backend.

Ratatui is a Rust library for building terminal UIs using a retained-mode widget model with an immediate-mode rendering loop. The crossterm backend provides cross-platform terminal control (ANSI escape codes, raw mode input, alternate screen buffer) via the `crossterm` crate.

The key architectural choice is to use Ratatui's **immediate-mode rendering** pattern: on every frame tick (targeting 30–60 fps for active sessions, lower for idle), the application re-renders the complete UI by constructing a layout tree and widget list from current application state. Ratatui computes a diff against the previous frame and emits only the changed terminal cells, minimizing terminal I/O overhead.

Application state is maintained in a central `AppState` struct owned by the TUI event loop. Domain events from `sentinel-agent-llm`, `sentinel-exec`, and `sentinel-audit` are received over an async Tokio channel and applied to `AppState` before the next render cycle.

Input handling uses `crossterm`'s event stream (exposed as a Tokio stream) to receive keyboard and mouse events asynchronously without blocking the render loop.

---

## Rationale

**Pure Rust, no ncurses dependency.** Ratatui has no dependency on ncurses, PDCurses, or any C terminal library. This is essential for the static musl binary (ADR-010): ncurses dynamically links against libc and would break the musl static build. Ratatui's crossterm backend communicates with the terminal entirely through ANSI escape codes, which are supported by all modern terminal emulators and work correctly on musl builds.

**Battle-tested in production Rust TUI applications.** Ratatui is the successor to `tui-rs` and is actively maintained with a large user base (Lazygit, Zellij's layout engine, numerous CLI tools). It has production-quality handling of terminal edge cases (resize events, alternate screen, raw mode cleanup on panic), saving Sentinel from having to solve these problems from scratch.

**Immediate-mode rendering simplifies state management.** In an immediate-mode rendering model, the UI is a pure function of application state: given the same `AppState`, the render function always produces the same UI. This eliminates an entire class of state synchronization bugs common in retained-mode UIs (stale widget states, update ordering issues). The TUI's correctness reduces to the correctness of `AppState` updates.

**Crossterm provides cross-platform terminal support.** The `crossterm` crate abstracts terminal control sequences across Linux, macOS, and Windows. While Sentinel primarily targets Linux, crossterm's portability means that the TUI works for developers on macOS during development without any platform-specific code paths.

**Async-first design matches Sentinel's Tokio runtime.** Crossterm's event stream is natively async and integrates cleanly with Tokio's `select!` macro. The TUI render loop, input event handling, and domain event reception all run on the same Tokio runtime without blocking threads.

**Rich widget library covers all required UI patterns.** Ratatui's built-in widgets (tables, scrollable lists, progress bars, gauges, text paragraphs, block borders, sparklines) cover all of Sentinel's UI requirements without custom widget development. The plan approval view (a scrollable table with risk tier color coding), execution progress (progress bars and scrolling log output), and fleet overview (a table of host states) are all straightforward compositions of built-in widgets.

---

## Consequences

**Positive:**

- No ncurses or C library dependency; the musl static binary constraint is maintained.
- Immediate-mode rendering eliminates widget state synchronization bugs.
- Production-quality terminal handling (resize, alternate screen, raw mode) without Sentinel-specific implementation effort.
- Native async integration with Tokio; no thread blocking in the render loop.
- Rich built-in widget library covers all required UI patterns without custom widget development.
- Active maintenance and community support reduce long-term maintenance burden.

**Negative:**

- Immediate-mode rendering requires a complete re-render on every state change. For very complex UIs with hundreds of widgets, this can create rendering overhead. For Sentinel's UI complexity, this is not a concern at 30 fps with Ratatui's diffing optimization.
- Ratatui provides terminal-only output — there is no path from Ratatui widgets to a web UI or graphical interface. If Sentinel needs a web-based UI in the future, a separate interface layer will be required.
- Terminal emulator compatibility edge cases (e.g., unusual color depth settings, unconventional keyboard encodings, tmux quirks) require testing and occasional workarounds. Ratatui's crossterm backend handles most of these cases, but edge cases exist.
- `crossterm` on some terminal environments has known issues with certain key combinations (e.g., modifier keys in some terminal emulators). Keyboard shortcut design must avoid problematic combinations.
- The alternate screen buffer (used by Ratatui's full-screen mode) means that the TUI erases terminal history while running. Operators who want a scrollable record of session activity should use the audit log export rather than scrolling the terminal.

---

## Alternatives Considered

**`cursive` (ncurses-based TUI framework).** Cursive is a higher-level TUI framework with a retained-mode widget model that abstracts over multiple backends including ncurses and crossterm. The higher-level abstraction would reduce boilerplate for complex UIs. However, cursive's ncurses backend would break the musl static binary constraint, and its crossterm backend is less mature than Ratatui's. The retained-mode model also introduces state synchronization complexity that immediate-mode avoids.

**`termion`.** Termion is a pure-Rust terminal library (like crossterm but Unix-only). It has no Windows support, which is acceptable for a Linux-targeting tool but limits development on macOS. Termion has less momentum than crossterm and fewer high-level widget abstractions. Building a full TUI on raw termion would require significantly more code than using Ratatui.

**Web-based UI (served via embedded HTTP server).** Serving a web UI from Sentinel's process (via embedded axum or warp) would provide a richer graphical interface accessible from any browser. However, it would require JavaScript/HTML/CSS assets bundled with the binary, introduce a web server attack surface, require a browser to use Sentinel, and conflict with the terminal-native use case that is primary for infrastructure tooling. A web UI is a possible future addition but not a replacement for the TUI.

**No TUI (CLI-only with JSON output).** Providing only a CLI interface with structured JSON output and relying on external tools (jq, fzf, custom dashboards) for visualization was considered as the minimal-dependency approach. This would work for automated use cases but fails for the interactive plan review and approval workflow — examining and editing a multi-step plan with risk tiers and dry-run results in raw JSON is a poor operator experience. The TUI is essential for the human-in-the-loop approval workflow.

**`egui` with a terminal backend.** `egui` is a pure-Rust immediate-mode GUI framework, primarily targeting graphical backends (OpenGL, wgpu, web). An experimental terminal backend exists but is not production-quality. Using egui would require either a graphical backend (breaking the terminal-only requirement) or relying on an unmaintained experimental backend. Ratatui, purpose-built for terminal UIs, is the clear choice for this use case.
