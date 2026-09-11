import { readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import assert from 'node:assert/strict';

function pages(root, directory = root) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    if (['commands', 'archive'].includes(entry.name)) return [];
    const path = join(directory, entry.name);
    return entry.isDirectory() ? pages(root, path) : entry.name.endsWith('.md') ? [relative(root, path)] : [];
  }).sort();
}
for (const section of ['guide', 'reference', 'troubleshooting', 'development']) {
  assert.deepEqual(pages(`docs/${section}`), pages(`docs/en/${section}`), `Missing translation in ${section}`);
}
console.log('Chinese and English page paths match');
