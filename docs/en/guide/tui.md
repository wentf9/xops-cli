# Terminal interface (TUI)

Run `xops tui` to manage nodes interactively—filter hosts, open SSH sessions, view live system metrics, search remote logs, and add or edit nodes from a single terminal window.

```bash
xops tui
```

## Keyboard shortcuts

| Key | Action |
| --- | --- |
| `Enter` | Open an SSH session to the selected node |
| `/` | Filter / search the node list |
| `Space` | Check or uncheck a node (for batch tag operations) |
| `n` / `e` | Add a new node / edit the selected node |
| `g` | Manage tags for checked nodes (or the current node) |
| `m` / `l` | Open live monitoring / open remote log selection |
| `Ctrl+S` / `Esc` (in forms) | Save form / cancel and return to the list |
| `Ctrl+U` / `Ctrl+L` | Unlock the default offline credential store / lock stores opened by this process |
| `Ctrl+Left/Right` | Move cursor by word in filters, forms, log paths, and log searches (including Windows consoles) |

Returning from an SSH session, monitoring view, or log viewer preserves your active filter, checked nodes, and cursor position.

## Common tasks

### 1. Adding and editing nodes

Press `n` to add a node or `e` to edit the current node (`Ctrl+S` saves, `Esc` returns to the list):
- **Verify before saving (default)**: Submitting a new node verifies SSH authentication first. If verification succeeds, the node is saved; if it fails, the failure reason is shown with a `[y/N]` prompt—press `y` to save anyway, or press Enter, `n`, or `Esc` to return to the form without saving (`Ctrl+C` during verification cancels the check).
- **Offline addition**: When adding a host that is not yet reachable, change **Verify before saving** to **Skip verification and save** (this skips only the network check; configuration and credential-store validation still run). Editing an existing node keeps its normal save behavior.
- **Validation feedback**: Duplicate alias errors and field validation messages appear at the bottom of the form, wrapping to the terminal width and scrolling to keep the active input field visible without losing your typed values.

### 2. Managing tags

Check one or more nodes with `Space`, then press `g`:
- **Existing tags**: When your configuration already has tags (including a single tag), press `Tab` to focus **Select existing tags**, use the arrow keys and `Space` to toggle tags, and press `Enter` to move to the new-tag input (if no tags exist yet, focus starts directly in the new-tag input).

### 3. SSH, monitoring, and logs

- Before entering SSH (`Enter`), monitoring (`m`), or logs (`l`), if authentication or vault unlocking is needed, the TUI pauses its own key reader and shows a hidden password prompt, resuming automatically afterward.
- **No background popups**: Live monitoring and log streaming never pop up password or vault-unlock prompts or write credentials back in the background. If credentials fail or the vault is locked, return to the list, press `Ctrl+U` to unlock (or `e` to update credentials), and open the view again.

## Credential saving policy

By default, the TUI uses `credential.remember_prompted` from your configuration (`always` on new installations, saving verified passwords to the offline vault and `credentials.key`). You can override the policy for a single TUI session without modifying your global config:

```bash
xops tui --remember never
xops tui --remember ask
```

- **Save warnings**: If SSH authentication succeeds but saving the credential fails, your connection still proceeds and a persistence warning is shown when you return to the TUI. If the credential persistence service cannot initialize at startup, connections still work with a warning that newly entered secrets cannot be saved (fix directory permissions and restart the TUI; note that read-only `credential doctor` checks do not verify write permissions).
- **Schema version**: Schema v1 compatibility has ended; convert legacy configurations first using the [migration guide](./migration). Submitting a credential form is an explicit management action, and existing saved passwords are never echoed back into form fields.

## Terminal display and resizing

- **Alternate screen**: The TUI runs in the terminal's alternate screen and restores your original terminal buffer and input mode on exit or `Ctrl+C`.
- **Automatic light/dark palette**: At startup, the TUI queries the terminal background color and adapts lists and forms to a matching light or dark palette (falling back to the dark palette if the terminal does not reply; checked tags stay highlighted in green while unselected items adjust for contrast).
- **Resizing and paste**: Filters, forms, log paths, and search inputs all accept terminal paste. Resizing the terminal window (including on Windows) reflows layouts, error messages, and scroll positions immediately without altering credentials while a save is in progress.
