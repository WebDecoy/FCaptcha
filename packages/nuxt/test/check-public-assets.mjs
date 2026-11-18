import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

const root = new URL('./fixture/.output/public/', import.meta.url);
let checked = 0;
async function inspect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const file = join(directory, entry.name);
    if (entry.isDirectory()) await inspect(file);
    else {
      checked++;
      if ((await readFile(file)).includes(Buffer.from('server-only-build-fixture'))) {
        throw new Error(`Server-only fixture secret leaked into ${file}`);
      }
    }
  }
}
await inspect(root.pathname);
if (!checked) throw new Error('No browser assets found');
console.log(`Checked ${checked} browser assets: no private fixture marker`);
