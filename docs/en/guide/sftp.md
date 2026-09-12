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
