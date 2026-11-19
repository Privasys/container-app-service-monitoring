// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The support site. A person signs in with their Privasys Wallet, which
// attests this enclave and opens an encrypted session to it, and everything
// they write travels inside that session. Text is always placed with text
// nodes, never as markup, so what someone wrote is shown and never run.

const parts = location.pathname.split('/').filter(Boolean);
const app = (parts[0] === 'support' || parts[0] === 'apps') && parts[1] ? decodeURIComponent(parts[1]) : '';
const onSupportHost = location.hostname.startsWith('support.');
const isTest = location.hostname.includes('.test.');

const STATUS = {
  new: 'Received', triaged: 'Received', assigned: 'With the team', in_progress: 'With the team',
  waiting: 'Waiting for your reply', resolved: 'Resolved', closed: 'Closed',
};

let frame = null;
let sealed = null;
let token = '';
let info = null;

const $ = (id) => document.getElementById(id);
const view = $('view');

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function say(text, isError) {
  const m = $('message');
  m.hidden = !text;
  m.textContent = text || '';
  m.className = isError ? 'notice error' : 'notice';
}

function when(unix) {
  return new Date(unix * 1000).toLocaleString();
}

function button(text, cls, onClick) {
  const b = el('button', cls, text);
  b.type = 'button';
  b.addEventListener('click', onClick);
  return b;
}

function field(label, control) {
  const l = el('label', 'field', label);
  l.appendChild(control);
  return l;
}

// call reaches the desk inside the encrypted session. The session carries
// the channel; the person's token says who is asking.
async function call(method, path, body) {
  const res = await sealed.request(method, path, body, { headers: { 'X-App-Auth': token } });
  const text = res.body && res.body.byteLength ? new TextDecoder().decode(res.body) : '';
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (err) { data = null; }
  if (res.status < 200 || res.status >= 300) {
    throw new Error((data && data.error) || `The request failed (${res.status}).`);
  }
  return data;
}

const desk = () => `/api/v1/apps/${encodeURIComponent(app)}/tickets`;

// Runs an action, turning any failure into a message on the page.
async function attempt(action) {
  say('');
  try {
    await action();
  } catch (err) {
    say(err.message || 'That did not work. Please try again.', true);
  }
}

function statusURL() {
  const page = `/apps/${encodeURIComponent(app)}/`;
  return onSupportHost ? `https://status.${location.hostname.slice('support.'.length)}${page}` : page;
}

async function landing() {
  $('title').textContent = 'Support';
  $('subtitle').textContent = 'Choose the app you need help with.';
  const r = await fetch('/api/v1/public/support', { headers: { accept: 'application/json' } });
  const apps = r.ok ? ((await r.json()).apps || []) : [];
  view.replaceChildren();
  if (apps.length === 0) {
    view.appendChild(el('p', 'muted', 'No app is taking support requests here yet.'));
    return;
  }
  for (const a of apps) {
    const link = el('a', 'ticket-row');
    link.href = `${onSupportHost ? '/apps' : '/support'}/${encodeURIComponent(a.name || a.app)}/`;
    link.appendChild(el('div', 'ticket-subject', a.display_name || a.name || a.app));
    view.appendChild(link);
  }
}

function signInPanel() {
  view.replaceChildren();
  const p = el('div', 'panel');
  p.appendChild(el('h2', '', 'Sign in to continue'));
  p.appendChild(el('p', 'muted', 'Sign in with your Privasys Wallet to open a request and follow the replies.'));
  p.appendChild(button('Sign in with the Privasys Wallet', 'button primary', signIn));
  view.appendChild(p);
}

async function signIn() {
  await attempt(async () => {
    if (!window.Privasys || !window.Privasys.AuthFrame) throw new Error('The sign-in could not be loaded.');
    if (!frame) {
      frame = new window.Privasys.AuthFrame({
        apiBase: isTest ? 'https://api.developer.test.privasys.org' : 'https://api.developer.privasys.org',
        authOrigin: 'https://privasys.id',
        rpId: 'privasys.id',
        clientId: 'privasys-platform',
        appName: 'Privasys Support',
        brokerUrl: 'wss://relay.privasys.org/relay',
        // The name shows the team who is asking; nothing else is requested.
        scope: ['openid', 'profile', 'offline_access'],
        methods: ['wallet'],
        container: $('gate'),
        presentation: 'page',
        sessionRelay: { appHost: location.hostname },
      });
      frame.onSessionRenewed = (_rp, fresh) => { if (fresh) token = fresh; };
    }
    view.replaceChildren(el('p', 'muted', 'Waiting for your wallet…'));
    const res = await frame.connect();
    $('gate').replaceChildren();
    if (!res.session) throw new Error('Your wallet signed you in, but the encrypted session did not open.');
    sealed = res.session;
    token = res.accessToken;
    await showList();
  });
  if (!sealed) signInPanel();
}

async function showList() {
  const data = await call('GET', desk());
  view.replaceChildren();
  const bar = el('div', 'actions');
  bar.appendChild(button('New request', 'button primary', showNew));
  view.appendChild(bar);
  const list = el('div', 'panel');
  list.appendChild(el('h2', '', 'Your requests'));
  const rows = data.tickets || [];
  if (rows.length === 0) list.appendChild(el('p', 'muted', 'You have no requests here yet.'));
  for (const row of rows) {
    const t = row.ticket;
    const b = button('', 'ticket-row', () => attempt(() => showTicket(t.number)));
    b.appendChild(el('div', 'ticket-subject', `T-${t.number}: ${t.subject}`));
    b.appendChild(el('div', 'ticket-meta', `${STATUS[t.status] || t.status} · ${when(t.updated_at)}`));
    list.appendChild(b);
  }
  view.appendChild(list);
}

function showNew() {
  say('');
  view.replaceChildren();
  const form = el('form', 'panel');
  form.appendChild(el('h2', '', 'New request'));
  const subject = el('input');
  subject.required = true;
  subject.maxLength = 200;
  form.appendChild(field('Subject', subject));
  let category = null;
  if (info.categories && info.categories.length > 0) {
    category = el('select');
    category.appendChild(new Option('Choose a category (optional)', ''));
    for (const c of info.categories) category.appendChild(new Option(c, c));
    form.appendChild(field('Category', category));
  }
  const body = el('textarea');
  body.required = true;
  body.maxLength = 20000;
  form.appendChild(field('What happened, and what did you expect?', body));
  const bar = el('div', 'actions');
  const send = el('button', 'button primary', 'Send request');
  send.type = 'submit';
  bar.append(send, button('Cancel', 'linkish', () => attempt(showList)));
  form.appendChild(bar);
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    send.disabled = true;
    attempt(async () => {
      const out = await call('POST', desk(), {
        subject: subject.value, body: body.value, category: category ? category.value : '',
      });
      await showTicket(out.ticket.number);
      say('Your request was sent.');
    }).finally(() => { send.disabled = false; });
  });
  view.appendChild(form);
  subject.focus();
}

async function showTicket(number) {
  const { ticket: t } = await call('GET', `${desk()}/${number}`);
  view.replaceChildren();
  view.appendChild(button('← Your requests', 'linkish', () => attempt(showList)));

  const head = el('div', 'panel');
  head.appendChild(el('h2', '', `T-${t.number}: ${t.subject}`));
  head.appendChild(el('div', 'ticket-meta', `${STATUS[t.status] || t.status} · opened ${when(t.created_at)}`));
  head.appendChild(el('p', 'written', t.body));
  for (const c of t.comments || []) {
    const r = el('div', c.team ? 'reply team' : 'reply');
    r.appendChild(el('div', 'ticket-meta', `${c.team ? `${c.author_name || 'Support'} (support team)` : 'You'} · ${when(c.at)}`));
    r.appendChild(el('p', 'written', c.body));
    head.appendChild(r);
  }
  view.appendChild(head);

  if (t.status === 'closed') {
    view.appendChild(el('p', 'muted', 'This request is closed. Open a new one if you need more help.'));
    return;
  }
  const form = el('form', 'panel');
  const reply = el('textarea');
  reply.required = true;
  reply.maxLength = 20000;
  form.appendChild(field('Your reply', reply));
  const bar = el('div', 'actions');
  const send = el('button', 'button primary', 'Send reply');
  send.type = 'submit';
  bar.append(send, button('Close this request', 'linkish', () => attempt(async () => {
    await call('POST', `${desk()}/${t.number}/close`, {});
    await showTicket(t.number);
  })));
  form.appendChild(bar);
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    send.disabled = true;
    attempt(async () => {
      await call('POST', `${desk()}/${t.number}/comments`, { body: reply.value });
      await showTicket(t.number);
    }).finally(() => { send.disabled = false; });
  });
  view.appendChild(form);
}

async function start() {
  if (!app) {
    await landing();
    return;
  }
  const r = await fetch(`/api/v1/public/apps/${encodeURIComponent(app)}/support`, { headers: { accept: 'application/json' } });
  if (!r.ok) {
    $('title').textContent = 'Support';
    $('subtitle').textContent = '';
    say('This app is not taking support requests here.');
    return;
  }
  info = await r.json();
  const name = info.display_name || info.name || app;
  document.title = `${name} support`;
  $('title').textContent = `${name} support`;
  $('subtitle').textContent = `Ask the ${name} team for help.`;
  const link = $('status-link');
  link.href = statusURL();
  link.hidden = false;
  signInPanel();
}

start().catch(() => say('This page could not be loaded. Please try again.', true));
