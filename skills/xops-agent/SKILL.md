---
name: xops-agent
description: Automate server O&M, execute batch commands, test network connectivity, transfer files, and manage host assets using the XOps CLI toolkit. Triggers when managing server clusters, performing concurrent tasks across multiple machines, checking network ports, or synchronizing configuration files.
---

# XOps CLI (IT Operations Automation Tool) Skill Guide

This skill empowers you to manage server clusters, execute batch tasks, and perform network security diagnostics via the XOps command-line tool (`xops`).

## 🎯 Environment Self-Check & Bootstrap Installation

Before attempting any operations, please run `xops --version` to check if the tool is installed.
If you receive a `command not found` error, instruct the user to execute the following installation command:

```bash
curl -sSL https://raw.githubusercontent.com/wentf9/xops-cli/main/install.sh | bash
```

## 🎯 Core Capabilities & Precise Command Usage

### 1. Host & Asset Management (`xops host`)
Manage the inventory of servers, credentials, and grouping tags.

- **List All Hosts**:
  ```bash
  xops host list
  ```
- **View All Unique Tags**:
  ```bash
  xops host tags
  ```
- **Add a New Host**:
  ```bash
  xops host add --name "web-01" --address "192.168.1.10" --user "root" --password "your_pass" --tag "web"
  ```
- **Batch Load Hosts from CSV**:
  ```bash
  xops loadHost hosts.csv --tag "production"
  ```

### 2. Batch Execution (`xops exec`)
Run commands or local scripts concurrently across multiple targets.

- **Execute Command via Tag**:
  ```bash
  xops exec --tag "web" -c "uptime"
  ```
- **Run Local Script Remotely**:
  ```bash
  xops exec --tag "db" --shell "./backup.sh" --task 5
  ```

### 3. Distributed File Transfer (`xops scp`)
Transfer files or directories between local and remote hosts.

- **Upload to Tagged Hosts**:
  ```bash
  xops scp ./config.conf --tag "web" --dest "/etc/app/"
  ```

### 4. Unified Firewall Management (`xops firewall`)
Abstracts different firewall backends (firewalld, ufw, iptables, nftables).

- **List Rules for a Host**:
  ```bash
  xops firewall list -H "web-01"
  ```
- **Manage Ports**:
  ```bash
  #open port 80/tcp,81/tcp and reload firewall
  xops firewall port 80,81 -H "web-01" --reload
  #remove port 80/udp
  xops firewall port 80 --remove --proto udp -H "web-01"
  #allow port 80/tcp from source 192.168.0.1
  xops firewall rule 80 192.168.0.1 -H "web-01" 
  ```

### 5. Network & Security Tools
- **Smart Ping** (Supports ICMP and TCP port checks):
  ```bash
  xops ping 1.1.1.1           # ICMP
  xops ping 1.1.1.1 443       # TCP Port Check
  ```
- **Netcat (nc)** (Port scanning):
  ```bash
  #listen on local port 8080 and print requests to stdout
  xops nc -l 8080
  #send "scan me" to local port 8080
  echo "scan me" | xops nc 127.0.0.1 8080
  ```
- **DNS Diagnostics**:
  ```bash
  xops dns "google.com"
  ```
- **Data Encoding**:
  ```bash
  xops encode base64 "hello"
  xops encode base64 --decode "aGVsbG8="
  ```

## 🛠️ Execution Principles & Safety Guardrails

1. **Host Verification**: Before executing batch tasks on a tag, run `xops host list` to verify which hosts will be affected.
2. **Non-Interactive Preference**: Always prefer `xops exec` and `xops scp` over `xops ssh` or `xops tui` for automation.
3. **High-Risk Operations**: You MUST obtain explicit user confirmation via `ask_user` before running destructive commands (e.g., `rm -rf`, `format`, `systemctl stop`) on multiple hosts.
4. **Credential Protection**: NEVER print or log passwords/keys used in `xops host add` commands.
