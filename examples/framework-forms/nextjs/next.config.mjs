import path from 'node:path';
import { fileURLToPath } from 'node:url';
export default { agentRules: false, turbopack: { root: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..') } };
