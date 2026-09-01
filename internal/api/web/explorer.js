// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The operator explorer.
//
// It reads the same API an auditor would, with the caller's own bearer
// token, so nothing it shows is privileged rendering: every panel here
// is a view of transactions, readings, incidents and anchors that any
// holder of the right role can fetch for themselves.

const $ = (sel) => document.querySelector(sel);
const state = { token: '', service: null, publicKey: null };

function api(path, options = {}) {
  const headers = Object.assign({ accept: 'application/json' }, options.headers || {});
  if (state.token) headers.authorization = `Bearer ${state.token}`;
  if (options.body) headers['content-type'] = 'application/json';
  return fetch(path, Object.assign({}, options, { headers })).then(async (r) => {
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || `${path} answered ${r.status}`);
    return body;
  });
}

$('#connect').addEventListener('click', connect);
$('#token').addEventListener('keydown', (e) => { if (e.key === 'Enter') connect(); });

for (const button of document.querySelectorAll('.tabs button')) {
  button.addEventListener('click', () => {
    for (const b of document.querySelectorAll('.tabs button')) b.classList.toggle('active', b === button);
    for (const panel of document.querySelectorAll('.panel')) {
      panel.hidden = panel.id !== `panel-${button.dataset.tab}`;
    }
    render(button.dataset.tab);
  });
}

async function connect() {
  state.token = $('#token').value.trim();
  try {
    const me = await api('/api/v1/me');
    $('#who').textContent = `${me.display || me.sub} acting as ${me.acting}`;
    const services = await api('/api/v1/services');
    state.service = (services.services || [])[0] || null;
    const key = await api('/api/v1/checkpoints/key');
    state.publicKey = key.public_key;
    render('log');
  } catch (err) {
    $('#who').textContent = err.message;
    $('#who').className = 'error';
  }
}

function render(tab) {
  const panel = $(`#panel-${tab}`);
  panel.innerHTML = '<p class="muted">Loading…</p>';
  const renderers = {
    log: renderLog, monitors: renderMonitors, incidents: renderIncidents,
    maintenance: renderMaintenance, reports: renderReports,
    checkpoints: renderCheckpoints, credentials: renderCredentials,
  };
  renderers[tab](panel).catch((err) => {
    panel.innerHTML = '';
    const p = document.createElement('p');
    p.className = 'error';
    p.textContent = err.message;
    panel.appendChild(p);
  });
}

// The log is the spine of the record: every change, with who made it,
// when, why, and the ledger version it produced.
async function renderLog(panel) {
  const { log } = await api('/api/v1/log?limit=150');
  panel.innerHTML = '';
  for (const entry of log || []) {
    const row = document.createElement('div');
    row.className = 'row';
    const top = document.createElement('div');
    top.className = 'top';
    const kind = document.createElement('span');
    kind.className = 'kind';
    kind.textContent = entry.envelope.kind;
    const summary = document.createElement('span');
    summary.className = 'summary';
    summary.textContent = entry.envelope.message.split('\n')[0];
    const when = document.createElement('span');
    when.className = 'when';
    when.textContent = formatTime(entry.envelope.timestamp);
    top.append(kind, summary, when);
    const detail = document.createElement('div');
    detail.className = 'detail';
    detail.textContent = `${entry.envelope.author.display || entry.envelope.author.sub}` +
      ` as ${entry.envelope.author.role} — version ${entry.version_before} to ${entry.version_after}`;
    const hash = document.createElement('div');
    hash.className = 'hash';
    hash.textContent = entry.txid;
    row.append(top, detail, hash);
    panel.appendChild(row);
  }
}

async function renderMonitors(panel) {
  const { monitors } = await api('/api/v1/monitors');
  panel.innerHTML = '';
  for (const entry of monitors || []) {
    const mon = entry.monitor;
    const st = entry.state;
    const row = document.createElement('div');
    row.className = 'row';
    const top = document.createElement('div');
    top.className = 'top';
    const name = document.createElement('span');
    name.className = 'summary';
    name.textContent = mon.name;
    const verdict = document.createElement('span');
    verdict.className = `verdict-${st ? st.verdict : 'error'}`;
    verdict.textContent = st ? st.verdict : 'no readings yet';
    const when = document.createElement('span');
    when.className = 'when';
    when.textContent = `v${mon.version}, every ${mon.interval_seconds}s`;
    top.append(name, verdict, when);

    const detail = document.createElement('div');
    detail.className = 'detail';
    detail.textContent = `${mon.steps.length} steps, ${mon.failure_threshold} failures to declare down, ` +
      `${mon.recovery_threshold} passes to recover` +
      (mon.latency_budget_ms ? `, ${mon.latency_budget_ms}ms budget` : '');

    const actions = document.createElement('div');
    actions.className = 'actions';
    const run = document.createElement('button');
    run.textContent = 'Run now';
    run.addEventListener('click', async () => {
      run.disabled = true;
      run.textContent = 'Running…';
      try {
        const result = await api(`/api/v1/monitors/${mon.id}/run`, { method: 'POST', body: '{}' });
        const out = document.createElement('pre');
        out.textContent = JSON.stringify(result.sample, null, 2);
        row.appendChild(out);
      } catch (err) {
        const out = document.createElement('p');
        out.className = 'error';
        out.textContent = err.message;
        row.appendChild(out);
      }
      run.disabled = false;
      run.textContent = 'Run now';
    });
    actions.appendChild(run);

    row.append(top, detail, actions);
    panel.appendChild(row);
  }
}

async function renderIncidents(panel) {
  const params = state.service ? `?service_id=${encodeURIComponent(state.service.id)}` : '';
  const { incidents } = await api(`/api/v1/incidents${params}`);
  panel.innerHTML = '';
  for (const inc of incidents || []) {
    const row = document.createElement('div');
    row.className = 'row';
    const top = document.createElement('div');
    top.className = 'top';
    const title = document.createElement('span');
    title.className = 'summary';
    title.textContent = inc.title;
    const status = document.createElement('span');
    status.className = 'kind';
    status.textContent = inc.status;
    const when = document.createElement('span');
    when.className = 'when';
    when.textContent = formatTime(inc.opened_at);
    top.append(title, status, when);
    row.appendChild(top);
    for (const update of inc.updates || []) {
      const u = document.createElement('div');
      u.className = 'detail';
      u.textContent = `${update.status}: ${update.body} (${update.author.display || update.author.sub})`;
      row.appendChild(u);
    }
    panel.appendChild(row);
  }
}

async function renderMaintenance(panel) {
  const params = state.service ? `?service_id=${encodeURIComponent(state.service.id)}` : '';
  const { maintenance } = await api(`/api/v1/maintenance${params}`);
  panel.innerHTML = '';
  for (const w of maintenance || []) {
    const row = document.createElement('div');
    row.className = 'row';
    const top = document.createElement('div');
    top.className = 'top';
    const title = document.createElement('span');
    title.className = 'summary';
    title.textContent = w.title;
    const kind = document.createElement('span');
    kind.className = 'kind';
    kind.textContent = w.class;
    const when = document.createElement('span');
    when.className = 'when';
    when.textContent = `${formatTime(w.starts_at)} to ${formatTime(w.ends_at)}`;
    top.append(title, kind, when);
    const detail = document.createElement('div');
    detail.className = 'detail';
    // The two facts a dispute turns on, side by side.
    detail.textContent = `declared ${formatTime(w.declared_at)} (${w.lead_time < 0 ? 'after it began' :
      formatDuration(w.lead_time) + ' ahead'}) — ` +
      (w.excluded ? 'excluded from agreed service time' : 'left in the agreed service time');
    row.append(top, detail);
    panel.appendChild(row);
  }
}

async function renderReports(panel) {
  panel.innerHTML = '';
  const actions = document.createElement('div');
  actions.className = 'actions';
  const window_ = document.createElement('select');
  for (const [value, label] of [
    ['calendar_month', 'This month'], ['calendar_week', 'This week'],
    ['calendar_quarter', 'This quarter'], ['rolling_30d', 'Rolling 30 days'],
  ]) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    window_.appendChild(option);
  }
  const generate = document.createElement('button');
  generate.textContent = 'Issue a report';
  actions.append(window_, generate);
  panel.appendChild(actions);

  const list = document.createElement('div');
  panel.appendChild(list);

  generate.addEventListener('click', async () => {
    generate.disabled = true;
    try {
      const result = await api('/api/v1/reports', {
        method: 'POST',
        body: JSON.stringify({
          service_id: state.service ? state.service.id : '',
          window: window_.value, include_proofs: true,
        }),
      });
      const pre = document.createElement('pre');
      pre.textContent = result.summary + '\n\n' + JSON.stringify(result.report, null, 2);
      list.prepend(pre);
    } catch (err) {
      const p = document.createElement('p');
      p.className = 'error';
      p.textContent = err.message;
      list.prepend(p);
    }
    generate.disabled = false;
  });

  const params = state.service ? `?service_id=${encodeURIComponent(state.service.id)}` : '';
  const { reports } = await api(`/api/v1/reports${params}`);
  for (const report of reports || []) {
    const row = document.createElement('div');
    row.className = 'row';
    const top = document.createElement('div');
    top.className = 'top';
    const label = document.createElement('span');
    label.className = 'summary';
    label.textContent = `${report.service_name} — ${report.period.label}`;
    const value = document.createElement('span');
    value.textContent = formatPPM(report.results.availability_ppm);
    const when = document.createElement('span');
    when.className = 'when';
    when.textContent = `coverage ${formatPPM(report.results.coverage_ppm)}`;
    top.append(label, value, when);
    const detail = document.createElement('div');
    detail.className = 'detail';
    detail.textContent = (report.objectives || [])
      .map((o) => `${o.name}: ${o.result}`).join(', ') || 'no objectives declared';
    row.append(top, detail);
    list.appendChild(row);
  }
}

// The checkpoint chain, with each link checked here rather than taken
// from the service.
async function renderCheckpoints(panel) {
  const { checkpoints } = await api('/api/v1/checkpoints?limit=100');
  panel.innerHTML = '';
  for (const signed of checkpoints || []) {
    const cp = signed.checkpoint;
    const row = document.createElement('div');
    row.className = 'row';
    const top = document.createElement('div');
    top.className = 'top';
    const version = document.createElement('span');
    version.className = 'summary';
    version.textContent = `version ${cp.version}`;
    const reason = document.createElement('span');
    reason.className = 'kind';
    reason.textContent = cp.reason;
    const when = document.createElement('span');
    when.className = 'when';
    when.textContent = formatTime(cp.issued_at);
    top.append(version, reason, when);
    const hash = document.createElement('div');
    hash.className = 'hash';
    hash.textContent = `root ${cp.root}`;
    const check = document.createElement('div');
    check.className = 'detail';
    row.append(top, hash, check);
    panel.appendChild(row);

    const result = await window.MonitorVerify.verifyBundle(
      { root: cp.root, path: '', proof: '', present: true, signature: signed.signature,
        key_id: signed.key_id, version: cp.version, checkpoint: signed },
      state.publicKey,
    ).catch(() => null);
    if (result) {
      const signature = result.find((c) => c.name === 'Monitor signature');
      check.textContent = signature ? `signature: ${signature.state}` : '';
    }
  }
}

// Credentials, as the record holds them: names and bindings, never
// values. The list is a check that the bindings are what somebody
// intended, which is the point of having them.
async function renderCredentials(panel) {
  const { secrets } = await api('/api/v1/secrets');
  panel.innerHTML = '';
  if (!secrets || secrets.length === 0) {
    panel.innerHTML = '<p class="muted">No credentials have been delivered.</p>';
    return;
  }
  for (const secret of secrets) {
    const row = document.createElement('div');
    row.className = 'row';
    const top = document.createElement('div');
    top.className = 'top';
    const name = document.createElement('span');
    name.className = 'summary';
    name.textContent = secret.name;
    const when = document.createElement('span');
    when.className = 'when';
    when.textContent = secret.destroyed_at ? 'destroyed' : `created ${formatTime(secret.created_at)}`;
    top.append(name, when);
    const detail = document.createElement('div');
    detail.className = 'detail';
    detail.textContent = `bound to ${(secret.hosts || []).join(', ')}` +
      (secret.description ? ` — ${secret.description}` : '');
    const hash = document.createElement('div');
    hash.className = 'hash';
    hash.textContent = `fingerprint ${secret.fingerprint}`;
    row.append(top, detail, hash);
    panel.appendChild(row);
  }
}

function formatPPM(ppm) {
  if (ppm === undefined || ppm === null || ppm < 0) return 'no data';
  return `${(ppm / 10000).toFixed(3)}%`;
}

function formatDuration(seconds) {
  seconds = Math.round(Math.abs(seconds));
  if (seconds >= 86400) return `${Math.round(seconds / 86400)} days`;
  if (seconds >= 3600) return `${Math.round(seconds / 3600)} hours`;
  if (seconds >= 60) return `${Math.round(seconds / 60)} minutes`;
  return `${seconds} seconds`;
}

function formatTime(unix) {
  if (!unix) return '';
  return new Date(unix * 1000).toLocaleString();
}
