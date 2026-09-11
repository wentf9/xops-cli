# SFTP and file transfer

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
