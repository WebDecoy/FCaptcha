import { defineConfig, devices } from '@playwright/test';

// These tests assume an FCaptcha server (Node, Python, or Go) is already
// running on http://localhost:3000. Start one with `npm start` from
// server-node/, or run server-go/server, before invoking `npm test`.
export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  reporter: 'list',
  webServer: process.env.CI ? {
    command: 'node ../../server-node/server.js',
    url: 'http://127.0.0.1:3000/ready',
    reuseExistingServer: process.env.FCAPTCHA_REUSE_SERVER === '1',
    env: { FCAPTCHA_SECRET: 'browser-ci-secret-0123456789abcdef0123456789abcdef' },
  } : undefined,
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
