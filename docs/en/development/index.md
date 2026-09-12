# Development

Use **Go 1.26+**. Update tests and relevant documentation with logic changes. Before opening a PR, run:

```bash
go build ./...
go test ./...
golangci-lint run ./...
```

Reusable packages wrap and return errors; the CLI presents them. Network operations need timeouts, and resources and goroutines need defined cleanup paths. Cross-compilation alone is not native Windows validation.

## Architecture and historical records

Historical engineering records are grouped under `docs/development/archive/`. These links open GitHub; the records are currently primarily in Chinese:

- [Historical development archive](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/README.md)
- [Credential backend ADR](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/adr/0001-credential-persistence-backends.md)
- [Offline store ADR](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/adr/0002-offline-encrypted-credential-store.md)
- [Credential implementation design](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/design/credential-persistence.md)

Historical implementation records describe validation at the time; they do not imply current validation on every platform. See [Writing documentation](./docs) for contribution instructions.

## Accepted design, pending implementation

- [Zero-configuration credential design](./credential-experience-design)
- [Credential experience implementation plan](./credential-experience-plan)
- [Release-note draft](./credential-experience-release)
