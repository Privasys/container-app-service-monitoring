// Copyright (c) Privasys. Licensed under the AGPL-3.0.

import { defineConfig, devices } from '@playwright/test';
import { BASE_URL } from './monitor';

// Two browsers, because the page's claim is that a reader can check a
// proof in their own browser, and "their own browser" is not always the
// one we tested in. The signature check needs Ed25519 in WebCrypto and
// the suite reports it as unavailable rather than failing where it is
// missing; the proof arithmetic runs everywhere.
export default defineConfig({
  testDir: '.',
  timeout: 180_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] }, testIgnore: /screenshots\./ },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] }, testIgnore: /screenshots\./ },
    {
      name: 'screenshots',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 900 } },
      testMatch: /screenshots\.capture\.ts/,
    },
  ],
});
