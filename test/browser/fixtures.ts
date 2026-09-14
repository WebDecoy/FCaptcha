import { test as base } from '@playwright/test';
import { randomBytes } from 'node:crypto';

// Each independent browser test represents a different visitor behind the
// local trusted proxy. Keep production quotas enabled while isolating tests.
export const test = base.extend<{ sourceIdentity: void }>({
  sourceIdentity: [async ({ context }, use) => {
    const suffix = randomBytes(12).toString('hex').match(/.{4}/g)!.join(':');
    await context.setExtraHTTPHeaders({ 'x-forwarded-for': `2001:db8:${suffix}` });
    await use();
  }, { auto: true }],
});
export { expect, type Page } from '@playwright/test';
