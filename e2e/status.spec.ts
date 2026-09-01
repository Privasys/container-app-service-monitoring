// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The status page, driven in a real browser against a real monitor.
//
// Most of this file is about one claim: that a reader can check a
// figure on the page rather than take it. So the suite edits the
// evidence in flight and requires the page to notice, which is the only
// way to know the verification is verification rather than decoration.

import { test, expect, type Page } from '@playwright/test';
import { api, breakTarget, healTarget, start, waitForReadings, type Harness } from './monitor';

let harness: Harness;

test.beforeAll(async () => {
  harness = await start();
  await waitForReadings(2);
});

test.afterAll(() => harness?.stop());

test('the page shows the service, its components and their uptime', async ({ page }) => {
  await page.goto('/status');
  await expect(page.locator('#service-name')).toHaveText('Example SaaS');
  await expect(page.locator('#headline')).not.toHaveText('Loading');
  await expect(page.locator('.component').first()).toBeVisible();
  await expect(page.locator('.component-name').first()).toHaveText('Order API');
  // Ninety bars, one per day, and the last one is today.
  const bars = page.locator('.component').first().locator('.bar');
  await expect(bars).toHaveCount(90);
});

test('the page names the build that drew it', async ({ page }) => {
  await page.goto('/status');
  const attestation = page.locator('#attestation');
  await expect(attestation).toContainText('Ledger root');
  await expect(attestation).toContainText('Signing key');
  const root = await attestation.locator('dd').nth(2).textContent();
  expect(root?.trim().length).toBeGreaterThan(0);
});

// The load-bearing test. A reader clicks a bar; the page fetches the
// proof behind it and checks it here, not on the server.
test('a reader can check a figure in their own browser', async ({ page }) => {
  await page.goto('/status');
  await clickTodaysBar(page);

  const panel = page.locator('.component').first().locator('.verify');
  await expect(panel).toContainText('folded intervals');
  await expect(panel.locator('.check')).not.toHaveCount(0);

  const proof = panel.locator('.check', { hasText: 'Merkle proof' });
  await expect(proof).toHaveClass(/pass/);
});

// The same page, with one byte changed between the monitor and the
// reader. The proof still folds, because the tree was not touched; the
// row no longer matches what was signed, and the page has to say so.
test('an edited proof is refused in the page', async ({ page }) => {
  await page.route('**/api/v1/public/evidence/bucket**', async (route) => {
    const response = await route.fetch();
    const bundle = await response.json();
    bundle.statement = 'something else entirely';
    await route.fulfill({ json: bundle });
  });

  await page.goto('/status');
  await clickTodaysBar(page);

  const panel = page.locator('.component').first().locator('.verify');
  await expect(panel.locator('.check.fail, .check.unknown')).not.toHaveCount(0);
  const signature = panel.locator('.check', { hasText: 'Monitor signature' });
  await expect(signature).not.toHaveClass(/pass/);
});

// A day with no readings is drawn as unknown, not as a good day.
test('a day nobody watched is not drawn as a good day', async ({ page }) => {
  await page.goto('/status');
  const first = page.locator('.component').first().locator('.bar').first();
  await expect(first).toHaveClass(/unknown/);
  await expect(first).toHaveAttribute('title', /nothing was observed/);
});

test('an outage reaches the page as an incident', async ({ page }) => {
  await breakTarget(80);
  // Two consecutive failures at a thirty second interval, plus the
  // rollup lag.
  await expect.poll(async () => {
    const { incidents } = await api('/api/v1/incidents?limit=5');
    return (incidents || []).length;
  }, { timeout: 150_000, intervals: [5000] }).toBeGreaterThan(0);
  await healTarget();

  await page.goto('/status');
  await expect(page.locator('#incidents')).toBeVisible();
  await expect(page.locator('.incident h3').first()).toContainText('Order API');
  await expect(page.locator('#banner')).toHaveClass(/major|minor/);
});

// A window declared after the outage is shown as exactly that, on the
// page, in words a customer reads.
test('a retrospective maintenance window says so on the page', async ({ page }) => {
  const { services } = await api('/api/v1/services');
  const now = Math.floor(Date.now() / 1000);
  await api('/api/v1/maintenance', {
    service_id: services[0].id,
    title: 'Retrospective window',
    class: 'planned_maintenance',
    starts_at: now - 600,
    ends_at: now + 600,
    message: 'Declare a window over something that already began',
  });

  await page.goto('/status');
  const declared = page.locator('.declared').first();
  await expect(declared).toBeVisible();
  await expect(declared).toContainText('after it began');
  await expect(declared).toHaveClass(/late/);
});

test('the status surface answers without a token', async ({ request }) => {
  const summary = await request.get('/api/v2/summary.json');
  expect(summary.ok()).toBeTruthy();
  const body = await summary.json();
  expect(body.status.indicator).toBeTruthy();
  expect(body.components.length).toBeGreaterThan(0);
  // The shape existing consumers parse, plus the fields that make this
  // one checkable.
  expect(body.attestation.root).toBeTruthy();

  const wellKnown = await request.get('/.well-known/privasys-monitor.json');
  expect((await wellKnown.json()).signing_key.public_key).toBeTruthy();

  const feed = await request.get('/history.atom');
  expect(feed.headers()['content-type']).toContain('atom');
});

test('the authenticated API refuses an anonymous caller', async ({ request }) => {
  const response = await request.get('/api/v1/log');
  expect(response.status()).toBe(401);
});

async function clickTodaysBar(page: Page) {
  const bars = page.locator('.component').first().locator('.bar');
  await expect(bars.last()).toBeVisible();
  await bars.last().click();
}
