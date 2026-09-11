# Troubleshooting

## System credential store unavailable

Run `xops credential doctor`. Linux requires `secret-tool`, a user D-Bus session, and Secret Service. Install `libsecret-tools` on Ubuntu/Debian if the tool is missing. Start your desktop keyring service if it is inactive.

Doctor forbids service auto-start. An interactive migration dry-run through `secret-tool` may activate the service, explaining why doctor can fail initially and pass afterward. Passing a read check does not prove write permissions.

## New host fingerprint prompt cannot be submitted

Use a build containing the Windows prompt fix. Ordinary text prompts should echo input, accept Enter, and support Backspace. Hidden password input is expected. `context canceled` indicates cancellation and does not by itself prove network authentication failed.

## SFTP exec consumes the next prompt's first character

Use a build containing the Windows stdin handoff fix. Run `exec date`, then enter `pwd`. The first character should remain, with no `read stdin failed: EOF` error. If it persists, record your OS, terminal, and XOps version.

## exec -x shows a prompt and command echo

Current code executes commands through SSH exec requests, including sudo/su execution, without injecting commands into an outer shell. Update older builds. Output deliberately printed by remote startup scripts is not filtered.

## Report a problem

Include command structure, version, OS/terminal, expected behavior, and sanitized errors. Do not share passwords, private keys, unlock material, or full production configuration.

## Old Linux kernel: identify vault mount / function not implemented

Some CentOS 7 kernels based on Linux 3.10 do not implement `statx`. Current builds prefer its mount ID and fall back to `mnt_id` from `/proc/self/fdinfo/<fd>` for the already-open handle when the syscall or field is unsupported. Cross-mount checks remain enforced.

The fallback requires accessible procfs and a valid `mnt_id`. Missing mount identity remains an error; the device number alone is insufficient. Offline vaults also require locking, atomic publication, and synchronization. Passing this check does not establish that every maintenance operation works on the target system.
