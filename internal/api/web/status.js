// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The status page.
//
// It is an ordinary status page in every respect but one: each bar on
// the uptime chart is a folded interval that exists as a row in an
// append-only ledger, so clicking one fetches its inclusion proof and
// checks it here, in the reader's browser, against a key fetched once
// from the service. Nothing on this page has to be taken on trust
// because the service said so.

const $ = (sel) => document.querySelector(sel);

const slug = (() => {
  const parts = location.pathname.split('/').filter(Boolean);
  return parts[0] === 'status' && parts[1] ? parts[1] : '';
})();

const api = (path) => fetch(path, { headers: { accept: 'application/json' } }).then((r) => {
  if (!r.ok) throw new Error(`${path} answered ${r.status}`);
  return r.json();
});

let publicKey = null;
let page = null;

async function load() {
  try {
    const wellKnown = await api('/.well-known/privasys-monitor.json');
    publicKey = wellKnown.signing_key ? wellKnown.signing_key.public_key : null;
  } catch (err) {
    // The page still renders without it; the verification section will
    // say the key could not be fetched rather than claiming a pass.
  }
  page = await api(slug ? `/api/v1/public/status/${encodeURIComponent(slug)}` : '/api/v1/public/status');
  render();
}

function render() {
  document.title = `${page.service} status`;
  $('#service-name').textContent = page.service;
  $('#service-description').textContent = page.description || '';

  const banner = $('#banner');
  banner.className = `banner ${page.indicator}`;
  $('#headline').textContent = page.headline;
  $('#updated').textContent = `updated ${formatTime(page.updated_at)}`;

  renderIncidents();
  renderMaintenance();
  renderComponents();
  renderHistory();
  renderAttestation();
}

function renderIncidents() {
  const section = $('#incidents');
  const list = $('#incident-list');
  list.innerHTML = '';
  if (!page.incidents || page.incidents.length === 0) { section.hidden = true; return; }
  section.hidden = false;
  for (const inc of page.incidents) list.appendChild(incidentCard(inc));
}

function renderHistory() {
  const section = $('#history');
  const list = $('#history-list');
  list.innerHTML = '';
  if (!page.history || page.history.length === 0) { section.hidden = true; return; }
  section.hidden = false;
  for (const inc of page.history.slice(0, 10)) list.appendChild(incidentCard(inc));
}

function incidentCard(inc) {
  const el = document.createElement('article');
  el.className = 'incident';
  const opened = formatTime(inc.opened_at);
  const resolved = inc.resolved_at ? `, resolved ${formatTime(inc.resolved_at)}` : '';
  el.innerHTML = `
    <h3></h3>
    <p class="meta"></p>
  `;
  el.querySelector('h3').textContent = inc.title;
  el.querySelector('.meta').textContent =
    `${inc.impact} impact, ${inc.status}${resolved} (opened ${opened}${inc.auto ? ', detected automatically' : ''})`;
  for (const update of inc.updates || []) {
    const u = document.createElement('div');
    u.className = 'update';
    const status = document.createElement('div');
    status.className = 'status';
    status.textContent = `${update.status} — ${formatTime(update.created_at)}`;
    const body = document.createElement('div');
    body.textContent = update.body;
    u.append(status, body);
    el.appendChild(u);
  }
  return el;
}

function renderMaintenance() {
  const section = $('#maintenance');
  const list = $('#maintenance-list');
  list.innerHTML = '';
  if (!page.maintenance || page.maintenance.length === 0) { section.hidden = true; return; }
  section.hidden = false;
  for (const w of page.maintenance) {
    const el = document.createElement('article');
    el.className = 'window';
    const title = document.createElement('h3');
    title.textContent = w.title;
    const meta = document.createElement('p');
    meta.className = 'meta';
    meta.textContent = `${formatTime(w.starts_at)} to ${formatTime(w.ends_at)}`;
    const declared = document.createElement('p');
    // The notice a window carried is shown, not implied. A window
    // declared after the outage it covers reads as exactly that.
    const late = w.lead_time < 0;
    declared.className = `declared${late ? ' late' : ''}`;
    declared.textContent = late
      ? `Declared ${formatDuration(-w.lead_time)} after it began, so it is not excluded from availability.`
      : `Declared ${formatDuration(w.lead_time)} in advance` +
        (w.excluded ? ', and excluded from availability.' : ', which is not enough notice to exclude it.');
    el.append(title, meta, declared);
    if (w.description) {
      const body = document.createElement('p');
      body.textContent = w.description;
      el.appendChild(body);
    }
    list.appendChild(el);
  }
}

function renderComponents() {
  const host = $('#components');
  host.innerHTML = '';
  for (const c of page.components || []) {
    const el = document.createElement('article');
    el.className = 'component';

    const head = document.createElement('div');
    head.className = 'component-head';
    const name = document.createElement('span');
    name.className = 'component-name';
    name.textContent = c.name;
    const status = document.createElement('span');
    status.className = `component-status status-${c.status}`;
    status.textContent = c.status.replace(/_/g, ' ');
    head.append(name, status);
    el.appendChild(head);

    if (c.description) {
      const desc = document.createElement('p');
      desc.className = 'muted';
      desc.textContent = c.description;
      el.appendChild(desc);
    }

    const bars = document.createElement('div');
    bars.className = 'bars';
    for (const day of c.days || []) {
      const bar = document.createElement('div');
      bar.className = `bar ${day.status}`;
      bar.title = day.uptime_ppm < 0
        ? `${day.date}: nothing was observed`
        : `${day.date}: ${formatPPM(day.uptime_ppm)}` +
          (day.downtime_seconds ? `, ${formatDuration(day.downtime_seconds)} down` : '');
      bar.addEventListener('click', () => verifyDay(c, day, el));
      bars.appendChild(bar);
    }
    el.appendChild(bars);

    const legend = document.createElement('div');
    legend.className = 'bar-legend';
    const first = document.createElement('span');
    first.textContent = `${(c.days || []).length} days ago`;
    const uptime = document.createElement('span');
    uptime.className = 'uptime';
    uptime.textContent = `${formatPPM(c.uptime_ppm)} uptime`;
    const last = document.createElement('span');
    last.textContent = 'today';
    legend.append(first, uptime, last);
    el.appendChild(legend);

    host.appendChild(el);
  }
}

// verifyDay fetches the proof behind one bar and checks it here.
//
// A bar is drawn from folded readings; the ledger holds those readings
// as rows, and any row can be returned with an inclusion proof. So a
// reader who does not believe the bar can ask for the arithmetic.
async function verifyDay(component, day, host) {
  let panel = host.querySelector('.verify');
  if (!panel) {
    panel = document.createElement('div');
    panel.className = 'verify';
    host.appendChild(panel);
  }
  panel.textContent = `Fetching the readings behind ${day.date}…`;

  try {
    const from = day.start;
    const to = day.start + 86400;
    // Hours where the day is closed, minutes where it is not: the hour
    // in progress has not been folded to an hour yet, and the bar for
    // today is drawn from its minutes.
    let buckets = [];
    for (const width of ['3600', '60']) {
      const params = new URLSearchParams({ from, to, width });
      if (slug) params.set('service', slug);
      const uptime = await api(`/api/v1/public/uptime/${encodeURIComponent(page.slug)}?${params}`);
      buckets = (uptime.buckets || []).filter((b) => b.component_id === component.id);
      if (buckets.length > 0) break;
    }
    if (buckets.length === 0) {
      panel.textContent = `No readings are held for ${day.date}. A day with no readings is drawn as unknown, ` +
        'not as a good day.';
      return;
    }
    // The bar's own arithmetic, recomputed from the rows.
    const observed = buckets.filter((b) => b.up + b.degraded + b.down > 0);
    const down = observed.filter((b) => b.verdict === 'down');
    const recomputed = observed.length === 0 ? -1
      : Math.round(((observed.length - down.length) / observed.length) * 1000000);

    const target = buckets[0];
    const bundle = await api(`/api/v1/public/evidence/bucket?monitor=${encodeURIComponent(target.monitor_id)}` +
      `&width=${target.width}&start=${target.start}`);
    const checks = await window.MonitorVerify.verifyBundle(bundle, publicKey);

    panel.innerHTML = '';
    const intro = document.createElement('p');
    intro.textContent = `${day.date}: ${observed.length} folded intervals, ${down.length} of them down, ` +
      `which is ${formatPPM(recomputed)} for the day. One of those intervals was fetched with its proof:`;
    panel.appendChild(intro);
    for (const check of checks) {
      const row = document.createElement('div');
      row.className = `check ${check.state}`;
      const mark = document.createElement('span');
      mark.className = 'mark';
      mark.textContent = check.state === 'pass' ? '✓' : check.state === 'fail' ? '✗' : '?';
      const text = document.createElement('span');
      text.textContent = `${check.name}: ${check.why}`;
      row.append(mark, text);
      panel.appendChild(row);
    }
  } catch (err) {
    panel.textContent = `The proof could not be checked: ${err.message}`;
  }
}

function renderAttestation() {
  const dl = $('#attestation');
  dl.innerHTML = '';
  const att = page.attestation || {};
  const rows = [
    ['Instance', att.instance],
    ['Vantage point', att.vantage],
    ['Workload measurement', att.image_digest || 'not running under the platform'],
    ['Ledger root', att.root],
    ['Ledger version', String(att.version)],
    ['Signing key', att.key_id],
  ];
  for (const [label, value] of rows) {
    if (!value) continue;
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    dd.textContent = value;
    dl.append(dt, dd);
  }
}

function formatPPM(ppm) {
  if (ppm === undefined || ppm === null || ppm < 0) return 'no data';
  return `${(ppm / 10000).toFixed(3)}%`;
}

function formatDuration(seconds) {
  seconds = Math.round(seconds);
  if (seconds >= 86400) return `${Math.round(seconds / 86400)} days`;
  if (seconds >= 3600) return `${Math.round(seconds / 3600)} hours`;
  if (seconds >= 60) return `${Math.round(seconds / 60)} minutes`;
  return `${seconds} seconds`;
}

function formatTime(unix) {
  if (!unix) return '';
  return new Date(unix * 1000).toLocaleString();
}

load().catch((err) => {
  $('#headline').textContent = 'The status page could not be loaded';
  $('#updated').textContent = err.message;
});
