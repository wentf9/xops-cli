import { defineConfig } from 'vitepress'

const repo = 'https://github.com/wentf9/xops-cli'
function sidebar(en = false) {
  const prefix = en ? '/en' : ''
  const item = (zh: string, english: string, path: string) => ({ text: en ? english : zh, link: `${prefix}/${path}` })
  return [
    {
      text: en ? 'Get started' : '开始使用',
      items: [
        item('安装与快速开始', 'Installation and quick start', 'guide/getting-started'),
        item('主机资产与配置导入', 'Hosts, inventory, and imports', 'guide/hosts'),
        item('Agent Skill 与 AI 集成概览', 'Agent Skill and AI overview', 'guide/agent-skill')
      ]
    },
    {
      text: en ? 'Guides' : '使用指南',
      items: [
        item('SSH、隧道与多路复用', 'SSH, tunnels, and multiplexing', 'guide/ssh'),
        item('命令执行与批量并发', 'Command execution and batch runs', 'guide/exec'),
        item('SFTP 与 SCP 文件传输', 'SFTP and SCP file transfers', 'guide/sftp'),
        item('凭据路由与密钥管理', 'Credential routing and vault', 'guide/credentials'),
        item('离线加密凭据库 (AEAD)', 'Offline encrypted vault (AEAD)', 'guide/offline-store'),
        item('终端工作台 (TUI)', 'Terminal workbench (TUI)', 'guide/tui'),
        item('Playbook v2、护栏与审计', 'Playbooks v2, guardrails, and audit', 'guide/automation'),
        item('MCP 服务与 HTTP 流式传输', 'MCP server and HTTP streaming', 'guide/mcp-http'),
        item('MCP 隧道与多路复用工具', 'MCP tunnel and mux tools', 'guide/mcp-tunnels')
      ]
    },
    {
      text: en ? 'Reference and support' : '参考与支持',
      items: [
        item('CLI 命令参考', 'CLI command reference', 'reference/'),
        item('配置 Schema v2 参考', 'Config schema v2 reference', 'reference/config'),
        item('MCP 7 工具协议参考', 'MCP 7-tool protocol reference', 'reference/mcp'),
        item('故障排查', 'Troubleshooting', 'troubleshooting/')
      ]
    }
  ]
}
export default defineConfig({
  title: 'XOps CLI',
  description: 'XOps v2 — 单二进制 SSH/SFTP、终端工作台、安全护栏与受控 MCP 运维平台 / Single-binary SSH/SFTP, TUI workbench, guardrails, and MCP operations platform',
  base: '/xops-cli/',
  lastUpdated: true,
  buildConcurrency: 2,
  // Keep engineering records out of the user documentation site and search.
  srcExclude: ['development/**', 'en/development/**'],
  locales: {
    root: {
      label: '简体中文',
      lang: 'zh-CN',
      themeConfig: {
        nav: [
          { text: '快速开始', link: '/guide/getting-started' },
          { text: 'CLI 参考', link: '/reference/' },
          { text: '配置 Schema', link: '/reference/config' },
          { text: 'MCP 参考', link: '/reference/mcp' }
        ],
        sidebar: sidebar(),
        outline: { label: '本页目录' },
        docFooter: { prev: '上一页', next: '下一页' },
        editLink: { pattern: `${repo}/edit/master/docs/:path`, text: '在 GitHub 上编辑此页' },
        lastUpdated: { text: '最后更新' }
      }
    },
    en: {
      label: 'English',
      lang: 'en',
      description: 'Single-binary SSH/SFTP, TUI workbench, guardrails, and MCP operations platform',
      themeConfig: {
        nav: [
          { text: 'Quick Start', link: '/en/guide/getting-started' },
          { text: 'CLI Reference', link: '/en/reference/' },
          { text: 'Config Schema', link: '/en/reference/config' },
          { text: 'MCP Reference', link: '/en/reference/mcp' }
        ],
        sidebar: sidebar(true),
        editLink: { pattern: `${repo}/edit/master/docs/:path`, text: 'Edit this page on GitHub' }
      }
    }
  },
  themeConfig: {
    logo: '/logo.svg',
    socialLinks: [{ icon: 'github', link: repo }],
    search: {
      provider: 'local',
      options: {
        locales: {
          root: {
            translations: {
              button: { buttonText: '搜索文档', buttonAriaLabel: '搜索文档' },
              modal: {
                noResultsText: '未找到结果',
                resetButtonTitle: '清除搜索',
                footer: { selectText: '选择', navigateText: '切换', closeText: '关闭' }
              }
            }
          }
        }
      }
    },
    footer: { message: 'MIT License', copyright: 'XOps CLI contributors' }
  }
})
