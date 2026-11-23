// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The header shared by the status and support sites. Both are one app
// answering under two names, so where each link points depends on the name
// the page was opened under, and on the account whose pages these are
// (/@<account>/ on either site).

(() => {
  const host = location.hostname;
  const site = document.body.dataset.site;
  // /@/<account>/ is the address the site links to; /@<account>/ the older form.
  const joinAccount = (p) => (p[0] === '@' && p[1] ? ['@' + p[1], ...p.slice(2)] : p);
  const parts = joinAccount(location.pathname.split('/').filter(Boolean));
  const rest = joinAccount(parts[0] === 'support' ? parts.slice(1) : parts);
  const account = rest[0] && rest[0].startsWith('@') ? rest[0] : '';

  // On the support name every page is a support page. The server answers
  // that way when it can see the name; where a proxy in front hides it, the
  // browser, which always knows its own address, takes the reader there.
  if (host.startsWith('support.') && site !== 'support') {
    const app = (parts[0] === 'apps' || account) && parts[1] ? parts[1] : '';
    location.replace(app ? `/support/${app}/` : account ? `/support/${account}/` : '/support/');
    return;
  }

  const onStatus = host.startsWith('status.');
  const onSupport = host.startsWith('support.');
  const base = onStatus ? host.slice('status.'.length) : onSupport ? host.slice('support.'.length) : '';
  const accountPath = account ? `@/${account.slice(1)}/` : '';
  let statusHome = `/${accountPath}`;
  let supportHome = account ? `/support/${account}/` : '/support/';
  if (onStatus) {
    supportHome = `https://support.${base}/${account ? accountPath : 'support/'}`;
  } else if (onSupport) {
    statusHome = `https://status.${base}/${accountPath}`;
    supportHome = account ? `/${accountPath}` : '/support/';
  }
  const links = { status: document.getElementById('nav-status'), support: document.getElementById('nav-support') };
  if (links.status) links.status.href = statusHome;
  if (links.support) links.support.href = supportHome;
  if (links[site]) links[site].classList.add('active');
  const brand = document.getElementById('brand');
  if (brand) brand.href = site === 'support' ? supportHome : statusHome;
  const product = document.getElementById('brand-product');
  if (product) product.textContent = site === 'support' ? 'Support' : 'Status';
})();
