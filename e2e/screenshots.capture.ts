// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// Generates the screenshots in docs/screenshots from a live monitor
// watching a live service. Nothing here is drawn: an outage is caused,
// a window is declared, a report is issued, and the pages are
// photographed as they came out.
//
//   cd e2e && npm run screenshots

import { test, expect } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { AUTH, api, breakTarget, healTarget, start, waitForReadings, type Harness } from './monitor';

const out = resolve(new URL('../docs/screenshots', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
let harness: Harness;

test.beforeAll(async () => {
  mkdirSync(out, { recursive: true });
  harness = await start();
  await waitForReadings(2);
});

test.afterAll(() => harness?.stop());

test('capture the pages', async ({ page }) => {
  // An outage, so the page has something to show.
  await breakTarget(80);
  await expect.poll(async () => {
    const { incidents } = await api('/api/v1/incidents?limit=5');
    return (incidents || []).length;
  }, { timeout: 150_000, intervals: [5000] }).toBeGreaterThan(0);

  await page.goto('/status');
  await expect(page.locator('#banner')).toHaveClass(/major|minor/);
  await page.screenshot({ path: `${out}/status-outage.png`, fullPage: true });

  await healTarget();
  await expect.poll(async () => {
    const { incidents } = await api('/api/v1/incidents?limit=1');
    return incidents?.[0]?.status;
  }, { timeout: 150_000, intervals: [5000] }).toBe('resolved');

  await page.goto('/status');
  await page.screenshot({ path: `${out}/status.png`, fullPage: true });

  // The verification panel, open, with the checks the page ran.
  const bars = page.locator('.component').first().locator('.bar');
  await bars.last().click();
  await expect(page.locator('.component').first().locator('.verify .check').first()).toBeVisible();
  await page.locator('.component').first().screenshot({ path: `${out}/verify.png` });

  // The same panel after a byte was changed in flight.
  await page.route('**/api/v1/public/evidence/bucket**', async (route) => {
    const response = await route.fetch();
    const bundle = await response.json();
    bundle.statement = 'something else entirely';
    await route.fulfill({ json: bundle });
  });
  await page.goto('/status');
  await page.locator('.component').first().locator('.bar').last().click();
  await expect(page.locator('.check.fail').first()).toBeVisible();
  await page.locator('.component').first().screenshot({ path: `${out}/verify-tampered.png` });
  await page.unroute('**/api/v1/public/evidence/bucket**');

  // The explorer: the log, and a report with its coverage.
  await page.goto('/explorer');
  await page.locator('#token').fill(AUTH.replace('Bearer ', ''));
  await page.locator('#connect').click();
  await expect(page.locator('#panel-log .row').first()).toBeVisible();
  await page.screenshot({ path: `${out}/log.png`, fullPage: true });

  await page.locator('.tabs button[data-tab="reports"]').click();
  await page.locator('#panel-reports button', { hasText: 'Issue a report' }).click();
  await expect(page.locator('#panel-reports pre').first()).toBeVisible({ timeout: 60_000 });
  await page.screenshot({ path: `${out}/report.png`, fullPage: true });

  await page.locator('.tabs button[data-tab="credentials"]').click();
  await expect(page.locator('#panel-credentials .row').first()).toBeVisible();
  await page.screenshot({ path: `${out}/credentials.png`, fullPage: true });
});
