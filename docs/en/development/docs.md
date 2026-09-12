# Writing documentation

## Local development

Requires Node.js 22+ and Go 1.26+. From the repository root:

```bash
npm ci
npm run docs:dev
```

Build and preview:

```bash
npm run docs:build
npm run docs:preview
```

CLI reference pages are generated from source before building into `reference/commands/` and `en/reference/commands/`. Generated files are not committed. The script only invokes `--help` with a temporary configuration directory; it does not read production configuration or connect to hosts.

## Bilingual conventions

Chinese pages use the root path; English mirrors them under `en/` with identical filenames. Update both languages when editing guides. `npm run docs:check` checks path parity and generator tests; the VitePress build checks internal links. Automated checks do not assess translation accuracy.

Do not edit generated command pages. Update CLI i18n strings and help instead. Existing ADRs, designs, and implementation records are grouped under `docs/development/archive/` and are linked as engineering records, not presented as untranslated English user guides.

## GitHub Pages

In repository Settings → Pages → Build and deployment → Source, select **GitHub Actions**. The deployment URL is `https://wentf9.github.io/xops-cli/`; append `en/` for English.

PRs run build checks. Pushes to `master` upload and deploy through the `github-pages` environment. Manual dispatch from master is also supported. Builds require no secrets; deployment uses workflow Pages and OIDC permissions.

If renaming the repository or using a custom domain, update `base` in `.vitepress/config.mts`. This site follows master without multiple version snapshots; mark unreleased functionality explicitly.

## Build dependencies

VitePress 1.6.4 defaults to Vite 5, which has security advisories. `package.json` pins Vite to 6.4.3, supported by the Vue plugin and verified with a site build. Review this override when upgrading VitePress and run `npm audit`.

Documentation builds default to Go/esbuild parallelism of 2 and page-rendering concurrency of 2 for smaller development environments. Avoid simultaneous builds and stop the preview server with Ctrl+C when finished.
