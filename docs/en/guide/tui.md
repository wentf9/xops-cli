# Terminal Workbench (TUI)

XOps v2 includes an interactive terminal workbench (`xops tui`) built on **Bubble Tea v2** and **Lipgloss v2**. It brings inventory browsing, live host metrics streaming, remote log streaming, live operation/pool projections, and supervised interactive SSH terminal takeover into a single event-driven interface.

## 1. Launching the Workbench

```bash
# Start with defaults (AltScreen enabled)
xops tui

# Focus a specific node, customize metrics refresh interval, or disable AltScreen
xops tui --node web-01 --refresh 2s
xops tui --no-alt-screen

# Pair with an alternate OpenSSH config, strict security policy, or explicit initial language
xops tui -F ~/.ssh/config.work --policy strict --lang zh
```

| Flag | Description |
| --- | --- |
| `--node <id>` | Initial focused target node ID |
| `--refresh <duration>` | Metrics streaming refresh interval (e.g. `2s`, `5s`) |
| `--no-alt-screen` | Disable the alternate screen buffer |
| `-F <configfile>` | Alternate OpenSSH config file (`none` disables) |
| `--policy <profile>` | Policy profile: `direct_operator` \| `strict` \| `strict_agent` |
| `--lang <en\|zh>` | Initial display language on startup (otherwise auto-detected; toggle live with uppercase `L`) |

> `xops tui` is strictly interactive and rejects `--json`.

## 2. Five Workbench Views

The header displays all 5 view tabs alongside live event counters (`events`, `dropped`, `streams`):

1. **`1:Hosts`**: Displays loaded hosts/nodes (ID, endpoint, user, `origin`, `[tags]`) and the current inventory revision (`rev`), with live filtering and `Enter` interactive SSH takeover.
2. **`2:Metrics`**: Displays live CPU percentage, 1/5/15m load averages, memory usage, mounted disk utilization, and top processes for the selected host, with live CPU/Mem sort toggling.
3. **`3:Logs`**: Streams remote log lines (default `/var/log/syslog`) with scroll navigation, keyword filtering, and explicit `[truncated]` indicators on oversized lines.
4. **`4:Operations`**: Aggregates live operation states (`RUNNING`, `OK`, `FAILED`, `UNKNOWN`), connection pool lease activity, and system diagnostics.
5. **`?:Help`**: Displays the built-in keybinding cheat sheet at any time.

## 3. Complete Keybindings

| Key | Action |
| --- | --- |
| `1` / `2` / `3` / `4` / `?` | Jump directly to Hosts / Metrics / Logs / Operations / Help |
| `Tab` / `Shift+Tab` | Cycle forward / backward through views |
| `j` / `k` or `Down` / `Up` | Move host selection cursor or scroll logs |
| `g` / `Home` and `G` / `End` | Jump to top / bottom of current list |
| `/` | Enter live filter mode (`Enter` apply, `Esc` clear, `Backspace` edit) |
| `r` | Refresh atomic inventory snapshot from the Engine |
| `m` | Switch to Metrics view and start live metrics streaming for the selected host |
| `l` (lowercase) | Switch to Logs view and start live log streaming for the selected host (distinct from uppercase `L`) |
| `x` | Stop all active metrics and log streams |
| `s` | Toggle top-process sorting (`CPU` / `Mem`) in Metrics view |
| `L` (uppercase) | **Live language toggle** (English / Simplified Chinese): immediately re-renders all 5 views, window title, status bar, errors, and safety banners, and syncs `Enter` SSH takeover prompts |
| `Enter` (in Hosts view) | **Supervised SSH takeover**: cleanly drains TUI -> releases terminal to interactive SSH -> automatically restores TUI on exit |
| `q` / `Ctrl+C` | Quit cleanly and deterministically restore terminal state |

### Live Language Toggle (`L`) Behavior

- **Case-Sensitive Distinction**: Uppercase **`L`** toggles display language between English and Simplified Chinese; lowercase **`l`** starts live remote log streaming.
- **Filter-Mode Safe**: While editing a filter after pressing `/`, typing uppercase `L` appends `L` to the filter query instead of switching language. Once you exit filter editing (`Enter` or `Esc`), `L` resumes toggling language.
- **Synced with Interactive SSH Takeover**: Toggling with `L` immediately notifies the host interaction adapter (`OnLocaleChange`), so subsequent `Enter` SSH takeover prompts (such as host-key verification and passphrase prompts) automatically render in the newly selected language, and the selected language persists when returning to the workbench.
- **Session-Scoped & Zero Disk Writes**: The switch applies in-memory for the current TUI session only and does not modify `~/.xops/config.yaml`.

## 4. Real-Time Safety Banners

Two high-visibility safety banners appear automatically above the view body when triggered:

- **Red Circuit-Break Banner (`SECURITY GATE HALTED`)**: Shown immediately if the Engine enters the irreversible `Halted` state (e.g. an audit post-write failure under `strict_agent`), surfacing the exact halt reason.
- **Amber Warning Banner (`WARNING: OutcomeUnknown detected — DO NOT auto-retry`)**: Shown whenever an operation stream records an `OutcomeUnknown` outcome so operators inspect remote state rather than replaying mutations.
