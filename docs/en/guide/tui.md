# Terminal interface (TUI)

```bash
xops tui
```

The interface uses the alternate screen and restores the original terminal contents on exit. Node filters, forms, log paths, and log searches accept terminal paste. The layout adjusts when the terminal is resized, including on Windows, without requiring a keypress or reopening the interface. At startup, the interface queries the terminal background color. Node lists, log lists, and forms use the light or dark palette matching the reply; refreshed lists retain that palette. Lists keep the default dark palette if the terminal does not reply. Unselected options in the tag form use a contrasting foreground for the background; selected tags retain their green highlight.

Ctrl+Left/Right moves the cursor by word in text inputs, including node filters, forms, log paths, and log searches on Windows consoles.

Before SSH sessions or credential-unlock prompts, the interface stops reading terminal input and resumes after returning. Ctrl+C or cancellation closes input reading and restores the terminal state.

New installations use the offline credential store with key-file. Enter opens SSH, `m` opens monitoring, and `l` opens log selection. Follow the prompts to verify the host fingerprint and enter a password or private-key passphrase. Verified credentials are saved according to your policy. Returning to the UI preserves your filter, checked items, and current selection.

Automatic saving covers authentication prompts initiated and successfully verified by XOps. Background monitoring and log collection cannot open authentication/unlock prompts or automatically write credentials.

## Remember policy

The default inherits `credential.remember_prompted`; new installations use `always`. `ask` requests confirmation after authentication, and declining still permits the session. `never` disables automatic saving. Override it for one invocation with:

```bash
xops tui --remember never
```

This also disables automatic migration for that invocation without changing global configuration. Explicit credential-form submissions and explicit migration are separate management actions. Existing passwords are never filled back into forms.

A save failure retains the connection, and a persistence warning remains visible after the UI resumes. If automatic persistence cannot initialize at startup, connections remain available with an explicit warning that new credentials cannot be saved. Fix configuration or credential-directory permissions and restart the TUI. Passing read-only doctor checks does not establish write permissions.

## Common actions

The new-node form selects verification by default. On submission, it verifies SSH authentication before saving. If verification fails, the TUI reports the reason and asks whether to save anyway. Press `y` to save; Enter, `n`, or Esc leaves the node unsaved and returns to the form for correction. Ctrl+C during verification cancels the operation.

While awaiting that decision, the interface prioritizes the question and `[y/N]` over editing shortcut help. Completed forms give their space to the failure details. Saving uses the submitted values; resizing the terminal during a save does not change the credentials being saved.

For an offline addition, explicitly select **Skip verification and save** in the **Verify before saving** field. This skips only the connection check; configuration and credential-store validation still run. Editing an existing node keeps its existing save behavior.

Press `Ctrl+S` to save a node form or `Esc` to return to the list. If an alias belongs to another node, the error remains visible below the form. Entered values are retained for correction and retry. Footer messages wrap to the terminal width while preserving space for the focused input. Long messages show an ellipsis; enlarge the terminal to see the full text.

Validation errors triggered by Tab or arrow-key navigation appear in the same feedback area. When feedback appears or the terminal is resized, the form adjusts its scroll position to keep the focused input visible, including the final Tags field.

| Key | Action |
| --- | --- |
| `Enter` | Open SSH for the current node |
| `/` | Filter nodes |
| `Space` | Select or deselect a node |
| `n` / `e` | Add or edit a node |
| `g` | Manage tags |
| `m` / `l` | Open monitoring or log selection |
| `Ctrl+L` | Lock offline stores opened by this process |
| `Ctrl+U` | Unlock the default offline store |

Authentication prompts appear before entering SSH, monitoring, or logs. Password input is hidden. Connection errors appear in the status area. Editing a target takes effect on the next connection.

Background monitoring and log collection do not prompt for passwords. If credentials become unavailable, return to the list, unlock the store or fix the credentials, then open the operation again.
