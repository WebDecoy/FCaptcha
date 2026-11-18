import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
export default defineConfig({
  resolve: { alias: { '#app': fileURLToPath(new URL('./test/runtime-config.mjs', import.meta.url)) } },
  test: { environment: 'jsdom', include: ['test/*.test.mjs'] },
});
