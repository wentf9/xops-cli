---
layout: home
hero:
  name: XOps CLI v2
  text: 一个二进制，统筹远程运维与安全 AI 自动化
  tagline: OpenSSH 兼容 CLI、并行 SFTP/SCP、Bubble Tea v2 终端工作台、AEAD 加密凭据库、声明式 Playbook v2 与 7 工具沙箱 MCP 服务端。
  image:
    src: /logo.svg
    alt: XOps CLI
  actions:
    - theme: brand
      text: 快速开始
      link: /guide/getting-started
    - theme: alt
      text: CLI 命令参考
      link: /reference/
    - theme: alt
      text: 配置 Schema v2
      link: /reference/config
features:
  - title: OpenSSH 兼容与多路复用
    details: 支持四层 OpenSSH 选项求解、跳板 DAG 校验、ControlMaster/ControlPersist 守护、-L/-R/-D/StreamLocal/TUN 转发与交互式终端。
  - title: 零明文加密凭据路由
    details: 内置 Argon2id + XChaCha20-Poly1305 离线加密库，支持 Windows/macOS/Linux 原生钥匙串与外部 JSON v2 凭据助手，全链路零明文配置。
  - title: 批量并发与 Playbook v2
    details: 多节点并发执行、多方言启动配置、单步/交互式 SFTP 与可续传 SCP、以及带三态结果追踪与幂等 ensure 的声明式 Playbook v2。
  - title: 强护栏、审计与沙箱 MCP
    details: 能力门控 + O(1) 进程锁审计对账 + strict_agent 熔断；7 大判别式 MCP 工具支持 stdio 与 Streamable HTTP 10 GiB 流式传输，物理隔离宿主机读权限。
---

本站面向 **XOps v2**（YAML Schema `version: 2`，Go 1.27+）维护。已安装二进制支持的精确选项请以 `xops <command> --help` 为准。
