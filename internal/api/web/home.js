// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The landing page: the apps whose teams publish their status page, each
// with where it is now. Built with text nodes only, never innerHTML, so a
// service name is shown and never run.

const LABEL = {
  none: 'Operational',
  minor: 'Degraded',
  major: 'Partial outage',
  critical: 'Major outage',
  maintenance: 'Maintenance',
};

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

async function load() {
  const banner = document.getElementById('banner');
  const headline = document.getElementById('headline');
  let apps = [];
  try {
    const r = await fetch('/api/v1/public/apps', { headers: { accept: 'application/json' } });
    if (!r.ok) throw new Error(`answered ${r.status}`);
    apps = (await r.json()).apps || [];
  } catch (err) {
    headline.textContent = 'The status list could not be loaded.';
    return;
  }

  const order = ['critical', 'major', 'minor', 'maintenance', 'none'];
  const worst = apps.reduce((w, a) => {
    const i = order.indexOf(a.indicator || 'none');
    return i >= 0 && i < order.indexOf(w) ? a.indicator : w;
  }, 'none');
  banner.className = `banner ${worst}`;
  const affected = apps.filter((a) => a.indicator && a.indicator !== 'none').length;
  headline.textContent = apps.length === 0 ? 'No published pages yet'
    : affected === 0 ? 'All published apps are operational'
      : `${affected} of ${apps.length} published apps are affected`;

  const list = document.getElementById('apps');
  document.getElementById('empty').hidden = apps.length > 0;
  for (const a of apps) {
    const row = el('div', 'component');
    const head = el('div', 'component-head');
    const name = el('a', 'component-name', a.service);
    name.href = a.page;
    head.appendChild(name);
    const status = el('span', 'component-status');
    const kind = a.indicator === 'none' || !a.indicator ? 'operational'
      : a.indicator === 'minor' || a.indicator === 'maintenance' ? 'degraded_performance' : 'major_outage';
    status.classList.add(`status-${kind}`);
    status.textContent = LABEL[a.indicator] || 'Unknown';
    head.appendChild(status);
    row.appendChild(head);
    if (a.headline) row.appendChild(el('div', 'muted', a.headline));
    list.appendChild(row);
  }
}

load();
