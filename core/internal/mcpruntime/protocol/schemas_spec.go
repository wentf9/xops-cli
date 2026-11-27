package protocol

import (
	"encoding/json/jsontext"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// 7 个强类型判别式 MCP 工具名称常量（对应 RFC §4.2 / Plan P3-T5）。
const (
	ToolNameNodes           = "nodes"
	ToolNameTerminalExec    = "terminal_exec"
	ToolNameTerminalSession = "terminal_session"
	ToolNameFile            = "file"
	ToolNameTransfer        = "transfer"
	ToolNameTunnel          = "tunnel"
	ToolNameGUI             = "gui"
)

// sharedApprovalSchemaFrag 为所有 7 个判别式工具共享的两步审批回执 JSON Schema 片段。
const sharedApprovalSchemaFrag = `"approval":{"type":"object","additionalProperties":false,"required":["verdict","envelope_digest"],"properties":{"verdict":{"type":"string","enum":["allow","deny"]},"envelope_digest":{"type":"string"},"envelope":{"type":"object"},"comment":{"type":"string"}}}`

const schemaNodes = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["action"],
  "properties": {
    "action": {
      "type": "string",
      "enum": [
        "list_hosts", "get_host", "create_host", "update_host", "delete_host",
        "list_identities", "get_identity", "create_identity", "update_identity", "delete_identity",
        "list_nodes", "get_node", "create_node", "update_node", "delete_node",
        "resolve", "validate_dag", "doctor",
        "list_import_formats", "plan_import", "apply_import"
      ]
    },
    "id": {"type": "string"},
    "target": {"type": "string"},
    "host": {"type": "object"},
    "identity": {"type": "object"},
    "node": {"type": "object"},
    "expected_revision": {"type": "string"},
    "gc_unreferenced_old_secrets": {"type": "boolean"},
    "delete_unused_secrets": {"type": "boolean"},
    "require_secrets_unreferenced": {"type": "boolean"},
    "check_vault_secrets": {"type": "boolean"},
    "check_private_keys": {"type": "boolean"},
    "format": {"type": "string"},
    "source_name": {"type": "string"},
    "content": {"type": "string"},
    "bundle": {"type": "object"},
    "dry_run": {"type": "boolean"},
    "scope_summary": {"type": "string"},
    "risk": {"type": "string", "enum": ["safe", "moderate", "dangerous"]},
    ` + sharedApprovalSchemaFrag + `
  }
}`

const schemaTerminalExec = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["action"],
  "properties": {
    "action": {
      "type": "string",
      "enum": ["exec", "exec_privileged", "probe_shell", "batch_exec", "run_playbook"]
    },
    "target": {"type": "string"},
    "targets": {"type": "array", "items": {"type": "string"}},
    "selector": {"type": "object"},
    "exclude_nodes": {"type": "array", "items": {"type": "string"}},
    "exclude_tags": {"type": "array", "items": {"type": "string"}},
    "command": {"type": "string"},
    "work_dir": {"type": "string"},
    "env": {"type": "object", "additionalProperties": {"type": "string"}},
    "stdin": {"type": "string"},
    "timeout": {"type": "string"},
    "max_output_bytes": {"type": "integer", "minimum": 1},
    "pty": {"type": "boolean"},
    "term": {"type": "string"},
    "privilege_method": {"type": "string", "enum": ["sudo", "su", "doas"]},
    "target_user": {"type": "string"},
    "non_interactive": {"type": "boolean"},
    "password_ref": {"type": "string"},
    "paths": {"type": "array", "items": {"type": "string"}},
    "recursive_paths": {"type": "array", "items": {"type": "string"}},
    "concurrency": {"type": "integer", "minimum": 1},
    "fail_fast": {"type": "boolean"},
    "playbook": {"type": "object"},
    "extra_vars": {"type": "object", "additionalProperties": {"type": "string"}},
    "risk": {"type": "string", "enum": ["safe", "moderate", "dangerous"]},
    ` + sharedApprovalSchemaFrag + `
  }
}`

const schemaTerminalSession = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["action"],
  "properties": {
    "action": {
      "type": "string",
      "enum": ["open", "read", "write", "resize", "signal", "inspect", "close"]
    },
    "target": {"type": "string"},
    "handle": {"type": "object"},
    "handle_token": {"type": "string"},
    "term": {"type": "string"},
    "cols": {"type": "integer", "minimum": 1, "maximum": 65535},
    "rows": {"type": "integer", "minimum": 1, "maximum": 65535},
    "max_buffer_bytes": {"type": "integer", "minimum": 1},
    "max_bytes": {"type": "integer", "minimum": 1},
    "wait": {"type": "boolean"},
    "data": {"type": "string"},
    "data_b64": {"type": "string"},
    "signal": {"type": "string"},
    "risk": {"type": "string", "enum": ["safe", "moderate", "dangerous"]},
    ` + sharedApprovalSchemaFrag + `
  }
}`

const schemaFile = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["action", "target"],
  "properties": {
    "action": {
      "type": "string",
      "enum": ["read", "write", "patch", "stat", "rename", "list", "mkdir", "remove", "removedir"]
    },
    "target": {"type": "string"},
    "path": {"type": "string"},
    "old_path": {"type": "string"},
    "new_path": {"type": "string"},
    "content": {"type": "string"},
    "content_b64": {"type": "string"},
    "edits": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["old_text", "new_text"],
        "properties": {
          "old_text": {"type": "string"},
          "new_text": {"type": "string"},
          "replace_all": {"type": "boolean"}
        }
      }
    },
    "perm": {"type": "integer", "minimum": 1, "maximum": 511},
    "no_clobber": {"type": "boolean"},
    "create_parents": {"type": "boolean"},
    "follow_symlinks": {"type": "boolean"},
    "max_bytes": {"type": "integer", "minimum": 1},
    "expected_anchor": {"type": "object"},
    "expected_digest": {"type": "string"},
    "risk": {"type": "string", "enum": ["safe", "moderate", "dangerous"]},
    ` + sharedApprovalSchemaFrag + `
  }
}`

const schemaTransfer = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["action"],
  "properties": {
    "action": {
      "type": "string",
      "enum": ["start", "chunk", "pull", "commit", "abort", "resume", "recover", "inspect"]
    },
    "target": {"type": "string"},
    "direction": {"type": "string", "enum": ["upload", "download"]},
    "transfer_id": {"type": "string"},
    "handle": {"type": "object"},
    "handle_token": {"type": "string"},
    "remote_path": {"type": "string"},
    "local_dest": {"type": "string"},
    "total_bytes": {"type": "integer", "minimum": 0},
    "expected_digest": {"type": "string"},
    "offset": {"type": "integer", "minimum": 0},
    "data_b64": {"type": "string"},
    "max_chunk_bytes": {"type": "integer", "minimum": 1},
    "reason": {"type": "string"},
    "start_next_gen": {"type": "boolean"},
    "prune_superseded": {"type": "boolean"},
    "all": {"type": "boolean"},
    "no_clobber": {"type": "boolean"},
    "preserve_times": {"type": "boolean"},
    "perm": {"type": "integer", "minimum": 1, "maximum": 511},
    "expected_anchor": {"type": "object"},
    "risk": {"type": "string", "enum": ["safe", "moderate", "dangerous"]},
    ` + sharedApprovalSchemaFrag + `
  }
}`

const schemaTunnel = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["action"],
  "properties": {
    "action": {
      "type": "string",
      "enum": [
        "start_forward", "inspect_forward", "stop_forward",
        "start_mux", "inspect_mux", "stop_mux", "probe_mux", "control_mux"
      ]
    },
    "target": {"type": "string"},
    "handle": {"type": "object"},
    "handle_token": {"type": "string"},
    "direction": {"type": "string", "enum": ["local", "remote", "dynamic", "tun"]},
    "bind_kind": {"type": "string", "enum": ["tcp", "unix"]},
    "bind_addr": {"type": "string"},
    "target_kind": {"type": "string", "enum": ["tcp", "unix"]},
    "target_addr": {"type": "string"},
    "tun_mode": {"type": "string", "enum": ["point_to_point", "ethernet"]},
    "tun_local_unit": {"type": "integer", "minimum": 0},
    "tun_remote_unit": {"type": "integer", "minimum": 0},
    "socket_path": {"type": "string"},
    "control_master": {"type": "string"},
    "control_persist": {"type": "string"},
    "mux_action": {"type": "string", "enum": ["check", "forward", "cancel", "exit", "stop"]},
    "risk": {"type": "string", "enum": ["safe", "moderate", "dangerous"]},
    ` + sharedApprovalSchemaFrag + `
  }
}`

const schemaGUI = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["action"],
  "properties": {
    "action": {
      "type": "string",
      "enum": ["exec", "open_session", "inspect_session", "close_session"]
    },
    "target": {"type": "string"},
    "handle": {"type": "object"},
    "handle_token": {"type": "string"},
    "gui_action": {
      "type": "string",
      "enum": ["screenshot", "click", "double_click", "right_click", "move", "drag", "scroll", "type", "key"]
    },
    "display": {"type": "string"},
    "wayland_display": {"type": "string"},
    "x": {"type": "integer", "minimum": 0, "maximum": 1000},
    "y": {"type": "integer", "minimum": 0, "maximum": 1000},
    "start_x": {"type": "integer", "minimum": 0, "maximum": 1000},
    "start_y": {"type": "integer", "minimum": 0, "maximum": 1000},
    "end_x": {"type": "integer", "minimum": 0, "maximum": 1000},
    "end_y": {"type": "integer", "minimum": 0, "maximum": 1000},
    "clicks": {"type": "integer", "minimum": 1, "maximum": 100},
    "direction": {"type": "string", "enum": ["up", "down", "left", "right"]},
    "text": {"type": "string"},
    "key": {"type": "string"},
    "include_shot": {"type": "boolean"},
    "artifact_file": {"type": "string"},
    "timeout": {"type": "string"},
    "session_kind": {"type": "string", "enum": ["x11", "vnc"]},
    "display_num": {"type": "integer", "minimum": 0, "maximum": 99},
    "use_unix_socket": {"type": "boolean"},
    "allow_non_loopback_bind": {"type": "boolean"},
    "local_bind_host": {"type": "string"},
    "local_bind_port": {"type": "integer", "minimum": 0, "maximum": 65535},
    "risk": {"type": "string", "enum": ["safe", "moderate", "dangerous"]},
    ` + sharedApprovalSchemaFrag + `
  }
}`

type rawToolSchema struct {
	name string
	desc string
	raw  string
}

// ToolDescriptors 返回全部 7 个强类型判别式 MCP 工具的标准描述符与规范化 JSON Schema（零可变全局状态）。
func ToolDescriptors() ([]ToolDescriptor, error) {
	specs := []rawToolSchema{
		{ToolNameNodes, "Inventory query, CAS CRUD, Tarjan DAG validation, read-only doctor, target resolution, and unified import.", schemaNodes},
		{ToolNameTerminalExec, "Gate-authorized remote one-shot execution, privilege escalation, two-phase shell probing, concurrent batch execution, and Playbook vNext runs.", schemaTerminalExec},
		{ToolNameTerminalSession, "Managed persistent PTY session lifecycle across requests (open/read/write/resize/signal/inspect/close).", schemaTerminalSession},
		{ToolNameFile, "Remote SFTP atomic file read/write, FSTAT-anchored patch, rename, directory listing, and workspace mutations (zero OperatorReadFS).", schemaFile},
		{ToolNameTransfer, "Resumable streaming transfer control plane up to 10 GiB (start/chunk/pull/commit/abort/resume/recover/inspect) with HTTP streaming bindings.", schemaTransfer},
		{ToolNameTunnel, "SSH port forwarding (-L/-R/-D/StreamLocal/TUN) and managed ControlMaster multiplexing control.", schemaTunnel},
		{ToolNameGUI, "POSIX-validated remote GUI actions, pure-Go bomb-safe screenshot compression, and managed X11/VNC tunnel sessions (zero OperatorReadFS).", schemaGUI},
	}
	out := make([]ToolDescriptor, 0, len(specs))
	for _, sp := range specs {
		val := jsontext.Value(sp.raw)
		if err := val.Canonicalize(); err != nil {
			return nil, domi18n.WrapS(ErrInvalidSchema, err, domi18n.KeyMCPProtoSchemaCanonFailed, domi18n.BoundStr("tool", sp.name))
		}
		out = append(out, ToolDescriptor{
			Name:        sp.name,
			Description: sp.desc,
			InputSchema: val,
		})
	}
	return out, nil
}
