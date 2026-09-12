import { test } from 'node:test';
import assert from 'node:assert/strict';
import { childCommands } from './help.mjs';

test('discovers commands without treating flags or examples as children', () => {
  assert.deepEqual(childCommands(`Usage:
  xops [command]

Available Commands:
  host        管理主机
  exec        Run a command
  help        Help

Flags:
  -h, --help  help
Examples:
  xops ssh example
`), ['host', 'exec']);
});

test('supports additional command groups and leaves', () => {
  assert.deepEqual(childCommands('Additional Commands:\n  completion  Generate completion\n'), ['completion']);
  assert.deepEqual(childCommands('Usage:\n  xops ssh host\n\nFlags:\n  --host string\n'), []);
});
