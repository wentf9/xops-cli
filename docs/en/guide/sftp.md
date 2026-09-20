# SFTP and file transfer

In batch mode, `lls`/`lll` and remote `ls`/`ll` fail on missing paths or directory read errors. A listing failure in any wildcard match stops the remaining matches and subsequent commands.

Piped or file input automatically uses batch mode: the first command failure stops execution with a nonzero exit status, without running later commands or writing interactive history. Batch `exec` uses no PTY; `exec` and `lexec` receive EOF on stdin so they cannot consume subsequent SFTP commands. `shell/lshell` require a terminal. Operations requiring confirmation fail unless an existing force/no-clobber option resolves it. Commands are limited to 1 MiB per line. Interactive command errors allow correction and continuation; connection or output failures still terminate the session.

```bash
xops sftp web-01
```

Run `help` inside the SFTP shell for all commands. Common operations:

```text
pwd
ls
cd /var/tmp
put ./report.txt
get report.txt
exec date
exit
```

`exec` runs a command in the current remote directory with a PTY for terminal programs, then returns to the SFTP prompt. `shell` opens a remote shell and `lexec` runs a local command. Exit the interactive program before entering more SFTP commands.

Use SCP for batch file distribution:

```bash
xops scp ./config.conf --tag web --dest /etc/app/
```

Check target directory permissions and avoid overwriting files unintentionally. If the connection is lost, the SFTP shell exits with a failure status instead of accepting further invalid operations.

## Interactive input and shortcuts

The SFTP prompt supports line editing, command history, and local and remote path completion. Long commands scroll horizontally within the input area. Cursor positions use visible display cells, including wide characters, combining marks, and emoji, and adjust when the terminal is resized. Commands typed ahead are read in order by subsequent prompts instead of being discarded when the preceding command is submitted.

| Key | Behavior |
| --- | --- |
| Delete | Delete the character after the cursor; do nothing on an empty line or at the end |
| Ctrl+D | Exit on an empty line; otherwise delete the character after the cursor |
| Ctrl+C | Cancel the current input; stop processing remaining files in the command at a confirmation prompt |
| Home/End, Ctrl+A/E | Move to the beginning/end of the line |
| Ctrl+U/K/W | Delete before the cursor/after the cursor/the previous word |
| ↑/↓, Ctrl+P/N | Browse history; returning to the newest position restores the draft |
| Ctrl+R | Search history backward; press again for an earlier match |
| Enter / Esc (history search) | Accept the match and return to editing without executing it |
| Ctrl+G (history search) | Cancel the search and restore the draft |
| Tab / Shift+Tab | Request completion, then cycle forward/backward through candidates, turning pages automatically |
| PageUp / PageDown (completion menu) | Move by a page while retaining the selection position where possible; stop at the first/last page |
| Enter (completion menu) | Accept the selected candidate and return to editing without executing; default to the first match if none is selected |
| Esc | Dismiss completion candidates |

A unique match is inserted immediately. After completing a directory, press Tab again to complete its contents without typing another character. With multiple matches, Tab / Shift+Tab cycles through the current candidates. The selected item uses reverse highlighting and a `>` marker; the panel arranges columns to fit the terminal width, showing at most six candidate rows and a footer with the page and candidate counts. Short terminals show fewer rows. Resizing keeps the selected item visible. The marker remains when colors are disabled. Enter accepts the selection and closes the menu. After accepting a directory, press Tab to complete its contents. Press Enter again after leaving candidate selection to execute the command. Type a more specific prefix and press Tab to narrow the results. Only the current page is rendered.

Pasted newlines and tabs become spaces, and control characters are removed. Pasting does not execute commands; press Enter to submit. Path completion runs in the background with a two-second timeout. Editing the input or leaving the prompt cancels the request; stale results never replace newer input. After cancellation or timeout, remote completion can be requested again without running another command first. Pasting during history search appends to the search query rather than editing the displayed history entry.

If the history or lock file is unavailable at startup, a warning is displayed and the shell uses session-only history. Readable existing entries remain available, but this fallback does not write to disk. Normally, command history is stored in `~/.xops_sftp_history`, retaining up to 500 recent entries and ignoring empty input and consecutive duplicates. Confirmation answers and batch commands are not recorded. Confirmation prompts disable command completion and history browsing. History write failures are reported while retaining the command in the current session. Once writing recovers, pending entries are merged with disk history, retaining the most recent 500 entries.

Before executing commands or entering a local/remote interactive program, the prompt stops reading and restores the terminal. The SFTP prompt resumes when the program finishes. Connection loss or cancellation ends pending input and completion tasks.

At an overwrite or removal confirmation, answering `n` skips only the current item; Ctrl+C stops the rest of the command and returns to the prompt. File operations already completed are not rolled back.
