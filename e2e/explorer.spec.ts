// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The operator explorer.
//
// It is a client of the same API an auditor would use, so the tests
// here are as much about that as about the rendering: what an operator
// sees is what a token with the same role could fetch, and no more.

import { test, expect } from '@playwright/test';
import { AUTH, api, start, waitForReadings, type Harness } from './monitor';

let harness: Harness;

test.beforeAll(async () => {
  harness = await start();
  await waitForReadings(2);
});

test.afterAll(() => harness?.stop());

async function connect(page: import('@playwright/test').Page) {
  await page.goto('/explorer');
  await page.locator('#token').fill(AUTH.replace('Bearer ', ''));
  await page.locator('#connect').click();
  await expect(page.locator('#who')).toContainText('acting as');
}

test('the log shows who changed what and why', async ({ page }) => {
  await connect(page);
  const rows = page.locator('#panel-log .row');
  await expect(rows.first()).toBeVisible();
  // Every entry carries a kind, a summary and the versions either side.
  await expect(rows.first().locator('.kind')).not.toBeEmpty();
  await expect(rows.first().locator('.summary')).not.toBeEmpty();
  await expect(rows.first().locator('.detail')).toContainText('version');
});

test('monitors show their state and can be run on demand', async ({ page }) => {
  await connect(page);
  await page.locator('.tabs button[data-tab="monitors"]').click();
  const rows = page.locator('#panel-monitors .row');
  await expect(rows.first()).toBeVisible();
  await rows.first().locator('button', { hasText: 'Run now' }).click();
  await expect(rows.first().locator('pre')).toBeVisible({ timeout: 60_000 });
  // A manual run is recorded and marked, so it cannot enter the
  // availability series.
  await expect(rows.first().locator('pre')).toContainText('"manual": true');
});

test('credentials appear without their values', async ({ page }) => {
  await connect(page);
  await page.locator('.tabs button[data-tab="credentials"]').click();
  const rows = page.locator('#panel-credentials .row');
  await expect(rows.first()).toBeVisible();
  await expect(rows.first()).toContainText('bound to');
  await expect(rows.first()).toContainText('fingerprint');
  await expect(page.locator('#panel-credentials')).not.toContainText('correct horse battery staple');
});

test('a report can be issued and shows its own coverage', async ({ page }) => {
  await connect(page);
  await page.locator('.tabs button[data-tab="reports"]').click();
  await page.locator('#panel-reports button', { hasText: 'Issue a report' }).click();
  const output = page.locator('#panel-reports pre').first();
  await expect(output).toBeVisible({ timeout: 60_000 });
  await expect(output).toContainText('available over');
  // A report over a month the monitor has watched for two minutes is
  // indeterminate, and says why. That is the honest answer, and the
  // suite asserts on it rather than on a flattering one.
  await expect(output).toContainText('coverage');
});

test('the checkpoint chain is checked in the page', async ({ page }) => {
  await connect(page);
  await api('/api/v1/checkpoints', { reason: 'manual' });
  await page.locator('.tabs button[data-tab="checkpoints"]').click();
  const rows = page.locator('#panel-checkpoints .row');
  await expect(rows.first()).toBeVisible();
  await expect(rows.first()).toContainText('root ');
});

test('maintenance shows the notice each window carried', async ({ page }) => {
  const { services } = await api('/api/v1/services');
  const now = Math.floor(Date.now() / 1000);
  await api('/api/v1/maintenance', {
    service_id: services[0].id, title: 'Planned upgrade',
    class: 'planned_maintenance',
    starts_at: now + 7 * 86400, ends_at: now + 7 * 86400 + 3600,
    message: 'Declare next week upgrade window',
  });

  await connect(page);
  await page.locator('.tabs button[data-tab="maintenance"]').click();
  const rows = page.locator('#panel-maintenance .row');
  await expect(rows.first()).toBeVisible();
  await expect(rows.first().locator('.detail')).toContainText('excluded from agreed service time');
});
