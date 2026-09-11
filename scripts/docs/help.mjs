// Cobra emits these headings independently of the application's translations.
export function childCommands(help) {
  const names = [];
  let listing = false;
  for (const line of help.split('\n')) {
    if (/^(Available|Additional) Commands:$/.test(line)) {
      listing = true;
      continue;
    }
    if (line && !/^\s/.test(line)) listing = false;
    if (!listing) continue;
    const match = line.match(/^  ([a-z][a-z0-9-]*)\s{2,}/);
    if (match && match[1] !== 'help') names.push(match[1]);
  }
  return [...new Set(names)];
}
