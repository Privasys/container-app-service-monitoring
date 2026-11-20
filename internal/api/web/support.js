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

// How a request's state reads to the person who opened it, and its colour.
const STATUS = {
  new: ['Received', 'open'], triaged: ['Received', 'open'],
  assigned: ['With the team', 'open'], in_progress: ['With the team', 'open'],
  waiting: ['Waiting for your reply', 'waiting'],
  resolved: ['Resolved', 'done'], closed: ['Closed', ''],
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

function pill(status) {
  const [label, tone] = STATUS[status] || [status, ''];
  return el('span', `pill ${tone}`.trim(), label);
}

// The person's name, from the token their sign-in gave the page.
function nameIn(jwt) {
  try {
    const claims = JSON.parse(atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return claims.name || claims.email || '';
  } catch (err) {
    return '';
  }
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
  const panel = el('div', 'panel');
  panel.appendChild(el('h2', '', 'Apps taking requests'));
  if (apps.length === 0) {
    panel.appendChild(el('p', 'empty', 'No app is taking support requests here yet.'));
  } else {
    const list = el('div', 'ticket-list');
    for (const a of apps) {
      const link = el('a', 'ticket-row');
      link.href = `/support/${encodeURIComponent(a.name || a.app)}/`;
      const main = el('div', 'ticket-main');
      main.appendChild(el('div', 'ticket-subject', a.display_name || a.name || a.app));
      link.appendChild(main);
      list.appendChild(link);
    }
    panel.appendChild(list);
  }
  view.appendChild(panel);
}

function signInPanel() {
  view.replaceChildren();
  const p = el('div', 'panel sign-in');
  p.appendChild(el('h2', '', 'Sign in to continue'));
  p.appendChild(el('p', '', 'Sign in with your Privasys Wallet to open a request and follow the replies. Your wallet checks this service before anything is sent.'));
  p.appendChild(button('Sign in with the Privasys Wallet', 'primary', signIn));
  view.appendChild(p);
}

function showWho() {
  const name = nameIn(token);
  $('who-name').textContent = name ? `Signed in as ${name}` : 'Signed in';
  $('who').hidden = false;
}

async function signOut() {
  try {
    if (frame) await frame.clearSession();
  } catch (err) {
    // Signing out of this page still happens below.
  }
  sealed = null;
  token = '';
  $('who').hidden = true;
  say('You are signed out.');
  signInPanel();
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
    view.replaceChildren(el('div', 'panel', 'Waiting for your wallet…'));
    const res = await frame.connect();
    $('gate').replaceChildren();
    if (!res.session) throw new Error('Your wallet signed you in, but the encrypted session did not open.');
    sealed = res.session;
    token = res.accessToken;
    showWho();
    await showList();
  });
  if (!sealed) signInPanel();
}

async function showList() {
  const data = await call('GET', desk());
  view.replaceChildren();
  const panel = el('div', 'panel');
  const head = el('div', 'panel-head');
  head.append(el('h2', '', 'Your requests'), button('New request', 'primary small', showNew));
  panel.appendChild(head);
  const rows = data.tickets || [];
  if (rows.length === 0) {
    panel.appendChild(el('p', 'empty', 'You have no requests here yet.'));
  } else {
    const list = el('div', 'ticket-list');
    for (const row of rows) {
      const t = row.ticket;
      const b = button('', 'ticket-row', () => attempt(() => showTicket(t.number)));
      const main = el('div', 'ticket-main');
      main.appendChild(el('div', 'ticket-subject', t.subject));
      main.appendChild(el('div', 'ticket-meta', `T-${t.number} · updated ${when(t.updated_at)}`));
      b.append(main, pill(t.status));
      list.appendChild(b);
    }
    panel.appendChild(list);
  }
  view.appendChild(panel);
}

function backLink() {
  const b = button('← Your requests', 'linkish back', () => attempt(showList));
  return b;
}

function showNew() {
  say('');
  view.replaceChildren(backLink());
  const form = el('form', 'panel');
  form.appendChild(el('h2', '', 'New request'));
  form.appendChild(el('p', '', 'Describe the problem. The team replies here, and your wallet tells you when they do.'));
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
  const send = el('button', 'primary', 'Send request');
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
  view.replaceChildren(backLink());

  const head = el('div', 'panel');
  const title = el('div', 'panel-head');
  title.append(el('h2', '', t.subject), pill(t.status));
  head.appendChild(title);
  head.appendChild(el('div', 'ticket-meta', `T-${t.number} · opened ${when(t.created_at)}${t.category ? ` · ${t.category}` : ''}`));
  head.appendChild(el('p', 'written', t.body));
  const thread = el('div', 'thread');
  for (const c of t.comments || []) {
    const r = el('div', c.team ? 'reply team' : 'reply');
    r.appendChild(el('div', 'ticket-meta', `${c.team ? `${c.author_name || 'Support'} · support team` : 'You'} · ${when(c.at)}`));
    r.appendChild(el('p', 'written', c.body));
    thread.appendChild(r);
  }
  head.appendChild(thread);
  view.appendChild(head);

  if (t.status === 'closed') {
    view.appendChild(el('p', 'empty', 'This request is closed. Open a new one if you need more help.'));
    return;
  }
  const form = el('form', 'panel');
  const reply = el('textarea');
  reply.required = true;
  reply.maxLength = 20000;
  form.appendChild(field('Your reply', reply));
  const bar = el('div', 'actions');
  const send = el('button', 'primary', 'Send reply');
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
  $('sign-out').addEventListener('click', signOut);
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
