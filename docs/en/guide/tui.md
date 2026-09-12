# TUI credentials

::: info Unreleased
This page describes the working branch. Final native-platform acceptance is pending.
:::

```bash
xops tui
```

New installations use the offline credential store with key-file. Enter opens SSH, `m` opens monitoring, and `l` opens log selection. The UI releases its terminal before host-fingerprint, password, or private-key passphrase prompts. Successful authentication records credential references according to the remember policy. Returning to the UI preserves filtering, checked items, and the selected node while refreshing updated references.

Automatic saving covers authentication prompts initiated and successfully verified by XOps. Background monitoring and log collection cannot open authentication/unlock prompts or automatically write credentials.

## Remember policy

The default inherits `credential.remember_prompted`; new installations use `always`. `ask` requests confirmation after authentication, and declining still permits the session. `never` disables automatic saving. Override it for one invocation with:

```bash
xops tui --remember never
```

This also disables automatic migration for that invocation without changing global configuration. Explicit credential-form submissions and explicit migration are separate management actions. Existing passwords are never filled back into forms.

A save failure retains the connection, and a persistence warning remains visible after the UI resumes. If automatic persistence cannot initialize at startup, connections remain available with an explicit warning that new credentials cannot be saved. Fix configuration or credential-directory permissions and restart the TUI. Passing read-only doctor checks does not establish write permissions.

## Terminal and connection ownership

Connection, monitoring, and log entry points authenticate only after the UI releases its terminal. SSH sessions run in-process and share the form's configuration repository; they no longer depend on a child process waiting for Enter. Errors return to the TUI status area.

Each user-initiated connection action creates a fresh connector and closes the preceding one, preventing reuse of a previous target after TUI edits. Monitoring and logs may retain authenticated connections, with prompting and automatic writeback disabled after terminal handoff. Cancellation and shutdown wait for pending authentication and input work to stop.

`Ctrl+L` locks the process's offline vault sessions. `Ctrl+U` releases the terminal before unlocking the default vault. Background operations remain non-interactive.
