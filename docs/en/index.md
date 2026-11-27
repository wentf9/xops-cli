---
layout: home
hero:
  name: XOps CLI v2
  text: One binary for remote operations and guardrailed AI automation
  tagline: OpenSSH-compatible CLI, resumable SFTP/SCP, Bubble Tea v2 terminal workbench, AEAD encrypted vault, declarative Playbook v2, and a 7-tool sandboxed MCP server.
  image:
    src: /logo.svg
    alt: XOps CLI
  actions:
    - theme: brand
      text: Quick start
      link: /en/guide/getting-started
    - theme: alt
      text: CLI reference
      link: /en/reference/
    - theme: alt
      text: Config schema v2
      link: /en/reference/config
features:
  - title: OpenSSH Compatibility & Multiplexing
    details: Deterministic 4-layer OpenSSH option resolution, Tarjan jump-DAG validation, ControlMaster/ControlPersist daemon, and -L/-R/-D/StreamLocal/TUN tunnels.
  - title: Zero-Plaintext Encrypted Vault
    details: Built-in Argon2id + XChaCha20-Poly1305 offline vault, native Windows/macOS/Linux keychains, and external JSON v2 credential helpers with zero plaintext config fields.
  - title: Batch Runs & Playbook v2
    details: Concurrent multi-node exec, explicit launch dialects, atomic single-shot/interactive SFTP, resumable parallel SCP, and declarative Playbook v2 with idempotent ensure steps.
  - title: Guardrails, Audit & Sandboxed MCP
    details: Capability-gated authorization, O(1) crash-lock audit reconciliation, strict_agent circuit breaking, and 7 discriminated MCP tools over stdio & Streamable HTTP with zero OperatorReadFS.
---

This documentation targets **XOps v2** (YAML schema `version: 2`, Go 1.27+). Always consult `xops <command> --help` for the exact flags of your installed binary.
