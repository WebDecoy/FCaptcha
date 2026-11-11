// @vitest-environment node
import { expect, it } from 'vitest';

it('can be imported without browser globals', async () => {
  const module = await import('./index.js');
  expect(module.FCaptcha).toBeTypeOf('function');
});
