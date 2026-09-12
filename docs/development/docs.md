# 文档维护

## 本地开发

需要 Node.js 22+ 和 Go 1.26+。在仓库根目录运行：

```bash
npm ci
npm run docs:dev
```

构建和预览：

```bash
npm run docs:build
npm run docs:preview
```

CLI 参考在构建前从源码生成，输出目录为 `reference/commands/` 与 `en/reference/commands/`，不提交生成文件。脚本只调用 `--help`，使用临时配置目录，不读取生产配置或连接主机。

## 双语约定

中文页面位于根路径，英文镜像位于 `en/`；两种语言保持相同文件名。修改指南时同时更新两种语言。`npm run docs:check` 检查目录对齐与生成器测试；VitePress 构建检查站内链接。自动检查不能判断译文是否准确。

不要手工编辑自动命令参考，应修改 CLI 中的 i18n 文案和帮助信息。开发资料保留在仓库的 `docs/development/` 和 `docs/en/development/` 中，不参与用户文档站点构建或站内搜索。面向用户的操作说明应放入双语使用指南。

## GitHub Pages

仓库 Settings → Pages → Build and deployment → Source 选择 **GitHub Actions**。发布地址为 `https://wentf9.github.io/xops-cli/`，英文入口追加 `en/`。

PR 执行构建检查；推送到 `master` 后，工作流上传站点并通过 `github-pages` 环境部署。也可在 master 上手动触发。构建不需要密钥，部署使用工作流的 Pages 和 OIDC 权限。

修改仓库名或使用独立域名时，同步调整 `.vitepress/config.mts` 中的 `base`。本站不维护多版本快照，内容跟随 master；未发布功能必须注明状态。

## 构建依赖

VitePress 1.6.4 默认依赖的 Vite 5 存在安全通告；`package.json` 将 Vite 固定为 6.4.3。该版本在 Vue 插件支持范围内，已验证站点构建。升级 VitePress 时重新检查此覆盖项，并运行 `npm audit`。

文档构建默认限制 Go/esbuild 并行度为 2，页面渲染并发为 2，适合内存较小的开发环境。不要同时运行多个构建；预览完成后用 Ctrl+C 停止服务。
