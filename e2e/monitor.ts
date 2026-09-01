// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The harness: a real monitor watching a real service.
//
// Nothing here is mocked. The suite builds both binaries, starts the
// target service, starts the monitor against it, delivers the
// credentials the reference journey needs, and waits for actual
// readings to accumulate. A status page tested against a fixture would
// prove that the page renders; this proves that what it renders is what
// the monitor measured.

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

export const MONITOR_PORT = 18090;
export const TARGET_PORT = 18081;
export const BASE_URL = `http://127.0.0.1:${MONITOR_PORT}`;
export const TARGET_URL = `http://127.0.0.1:${TARGET_PORT}`;
export const AUTH = 'Bearer dev:owner-1:Owner:monitoring:owner';

const repo = resolve(new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));

export interface Harness {
  stop(): void;
  dataDir: string;
}

function build(target: string, output: string) {
  const result = spawnSync('go', ['build', '-o', output, target], {
    cwd: repo, encoding: 'utf8', shell: process.platform === 'win32',
  });
  if (result.status !== 0) {
    throw new Error(`could not build ${target}: ${result.stderr || result.stdout}`);
  }
}

async function waitFor(url: string, seconds = 60) {
  for (let i = 0; i < seconds * 2; i++) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`${url} never answered`);
}

export async function start(): Promise<Harness> {
  const exe = process.platform === 'win32' ? '.exe' : '';
  const bin = mkdtempSync(join(tmpdir(), 'monitor-bin-'));
  const dataDir = mkdtempSync(join(tmpdir(), 'monitor-data-'));

  build('./tools/target', join(bin, `target${exe}`));
  build('./cmd/monitor', join(bin, `monitor${exe}`));

  const children: ChildProcess[] = [];
  children.push(spawn(join(bin, `target${exe}`), [], {
    env: { ...process.env, TARGET_PORT: String(TARGET_PORT) },
    stdio: 'ignore',
  }));
  await waitFor(`${TARGET_URL}/health`);

  children.push(spawn(join(bin, `monitor${exe}`), [], {
    cwd: repo,
    env: {
      ...process.env,
      PORT: String(MONITOR_PORT),
      MONITOR_DATA_DIR: dataDir,
      MONITOR_DEV_AUTH: '1',
      MONITOR_SELF_CONFIGURE: '1',
      MONITOR_PACK: 'example-saas',
      MONITOR_ROLLUP_LAG: '5s',
    },
    stdio: 'ignore',
  }));
  await waitFor(`${BASE_URL}/health`);

  // The credentials the reference journey logs in with. They are bound
  // to the target's host and are refused anywhere else.
  await api('/api/v1/secrets', {
    name: 'example_user', value: 'monitor', hosts: ['127.0.0.1'],
    message: 'Store the monitoring account',
  });
  await api('/api/v1/secrets', {
    name: 'example_password', value: 'correct horse battery staple', hosts: ['127.0.0.1'],
    message: 'Store the monitoring password',
  });

  return {
    dataDir,
    stop() {
      for (const child of children) child.kill();
      try { rmSync(bin, { recursive: true, force: true }); } catch { /* windows holds the exe */ }
    },
  };
}

export async function api(path: string, body?: unknown): Promise<any> {
  const response = await fetch(`${BASE_URL}${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined
      ? { authorization: AUTH }
      : { authorization: AUTH, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`${path} answered ${response.status}: ${text}`);
  return text ? JSON.parse(text) : {};
}

// waitForReadings blocks until the monitor has taken readings AND folded
// them into intervals.
//
// The folded interval is what the page draws and what a proof is about,
// so waiting only for readings would race the folder and leave the bar
// for today drawn as unknown.
export async function waitForReadings(minimum = 2, seconds = 180) {
  const services = await api('/api/v1/services');
  const serviceID = services.services[0].id;
  for (let i = 0; i < seconds; i++) {
    const { samples } = await api('/api/v1/samples?limit=20');
    if ((samples || []).length >= minimum) {
      const { buckets } = await api(
        `/api/v1/buckets?service_id=${serviceID}&width=60&from=0&to=9999999999`);
      if ((buckets || []).length > 0) return samples;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error('the monitor took no readings, or never folded them');
}

export async function breakTarget(seconds: number) {
  await fetch(`${TARGET_URL}/admin/break`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ seconds }),
  });
}

export async function healTarget() {
  await fetch(`${TARGET_URL}/admin/heal`, { method: 'POST' });
}
