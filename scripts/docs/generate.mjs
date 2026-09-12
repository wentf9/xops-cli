import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { childCommands } from './help.mjs';

const temporary = mkdtempSync(join(tmpdir(), 'xops-docs-'));
const binary = join(temporary, process.platform === 'win32' ? 'xops.exe' : 'xops');
try {
  execFileSync('go', ['build', '-p=2', '-o', binary, './cmd/cli'], {
    stdio: 'inherit', timeout: 300000,
    env: { ...process.env, GOMAXPROCS: process.env.GOMAXPROCS || '2' }
  });
  for (const [language, prefix] of [['zh', ''], ['en', 'en/']]) {
    const output = resolve('docs', prefix, 'reference/commands');
    rmSync(output, { recursive: true, force: true });
    mkdirSync(output, { recursive: true });
    const index = [];
    const visit = (parts) => {
      const help = execFileSync(binary, [...parts, '--help'], {
        encoding: 'utf8', timeout: 15000, maxBuffer: 2 * 1024 * 1024,
        env: { ...process.env, XOPS_LANG: language, NO_COLOR: '1',
          XOPS_CONFIG_DIR: join(temporary, 'config'), XOPS_JOURNAL_DIR: join(temporary, 'journals') }
      }).trim();
      const name = ['xops', ...parts].join(' ');
      const filename = ['xops', ...parts].join('-');
      index.push(`- [\`${name}\`](./${filename})`);
      const note = language === 'zh'
        ? '由当前源码的 Cobra 帮助自动生成，请勿手动编辑。参数以安装版本的 `--help` 为准。'
        : 'Generated from Cobra help in the current source tree. Do not edit. Use `--help` for your installed version.';
      writeFileSync(join(output, `${filename}.md`), `---\neditLink: false\nlastUpdated: false\n---\n\n# ${name}\n\n${note}\n\n~~~text\n${help}\n~~~\n`);
      for (const child of childCommands(help)) visit([...parts, child]);
    };
    visit([]);
    writeFileSync(join(output, 'index.md'), `---\neditLink: false\nlastUpdated: false\n---\n\n# ${language === 'zh' ? '完整命令参考' : 'Complete command reference'}\n\n${index.join('\n')}\n`);
    console.log(`${language}: generated ${index.length} command pages`);
  }
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
