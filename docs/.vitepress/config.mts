import { defineConfig } from 'vitepress'

const repo = 'https://github.com/wentf9/xops-cli'
function sidebar(en = false) {
  const prefix = en ? '/en' : ''
  const item = (zh: string, english: string, path: string) => ({ text: en ? english : zh, link: `${prefix}/${path}` })
  return [
    { text: en ? 'Get started' : '开始使用', items: [item('安装与初始化', 'Installation and setup', 'guide/getting-started'), item('主机与身份', 'Hosts and identities', 'guide/hosts')] },
    { text: en ? 'Guides' : '使用指南', items: [item('SSH 与提权', 'SSH and privilege escalation', 'guide/ssh'), item('SFTP 与文件传输', 'SFTP and file transfer', 'guide/sftp'), item('命令执行', 'Command execution', 'guide/exec'), item('凭据存储', 'Credential storage', 'guide/credentials'), item('离线凭据库', 'Offline credential storage', 'guide/offline-store'), item('凭据迁移', 'Credential migration', 'guide/migration'), item('终端管理界面', 'Terminal interface', 'guide/tui'), item('Playbook 与 MCP', 'Playbooks and MCP', 'guide/automation')] },
    { text: en ? 'Reference and support' : '参考与支持', items: [item('命令参考', 'Command reference', 'reference/'), item('完整命令列表', 'All commands', 'reference/commands/'), item('故障排查', 'Troubleshooting', 'troubleshooting/')] }
  ]
}
export default defineConfig({
  title: 'XOps CLI',
  description: 'SSH、SFTP、批量执行与凭据管理 / SSH, SFTP, automation and credential management',
  base: '/xops-cli/',
  lastUpdated: true,
  buildConcurrency: 2,
  // Keep engineering records out of the user documentation site and search.
  srcExclude: ['development/**', 'en/development/**'],
  locales: {
    root: { label: '简体中文', lang: 'zh-CN', themeConfig: { nav: [{ text: '指南', link: '/guide/getting-started' }, { text: '命令参考', link: '/reference/' }], sidebar: sidebar(), outline: { label: '本页目录' }, docFooter: { prev: '上一页', next: '下一页' }, editLink: { pattern: `${repo}/edit/master/docs/:path`, text: '在 GitHub 上编辑此页' }, lastUpdated: { text: '最后更新' } } },
    en: { label: 'English', lang: 'en', description: 'SSH, SFTP, automation and credential management', themeConfig: { nav: [{ text: 'Guide', link: '/en/guide/getting-started' }, { text: 'Reference', link: '/en/reference/' }], sidebar: sidebar(true), editLink: { pattern: `${repo}/edit/master/docs/:path`, text: 'Edit this page on GitHub' } } }
  },
  themeConfig: {
    logo: '/logo.svg',
    socialLinks: [{ icon: 'github', link: repo }],
    search: { provider: 'local', options: { locales: { root: { translations: { button: { buttonText: '搜索文档', buttonAriaLabel: '搜索文档' }, modal: { noResultsText: '未找到结果', resetButtonTitle: '清除搜索', footer: { selectText: '选择', navigateText: '切换', closeText: '关闭' } } } } } } },
    footer: { message: 'MIT License', copyright: 'XOps CLI contributors' }
  }
})
