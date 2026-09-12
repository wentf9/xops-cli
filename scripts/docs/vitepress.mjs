import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Bound esbuild's Go workers on small development machines. Existing explicit
// GOMAXPROCS settings take precedence. Use Node directly for Windows support.
const cli = fileURLToPath(new URL('../../node_modules/vitepress/bin/vitepress.js', import.meta.url));
const [command, ...args] = process.argv.slice(2);
if (!['build', 'dev', 'preview'].includes(command)) throw new Error('Expected build, dev, or preview');
const result = spawnSync(process.execPath, [cli, command, 'docs', ...args], {
  stdio: 'inherit',
  env: { ...process.env, GOMAXPROCS: process.env.GOMAXPROCS || '2' }
});
if (result.error) throw result.error;
process.exitCode = result.status ?? (result.signal === 'SIGINT' ? 130 : 1);
