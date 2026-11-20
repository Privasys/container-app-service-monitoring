// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The header shared by the status and support sites. Both are one app
// answering under two names, so where each link points depends on the name
// the page was opened under.

(() => {
  const host = location.hostname;
  const site = document.body.dataset.site;
  // On the support name every page is a support page. The server answers
  // that way when it can see the name; where a proxy in front hides it, the
  // browser, which always knows its own address, takes the reader there.
  if (host.startsWith('support.') && site !== 'support') {
    const parts = location.pathname.split('/').filter(Boolean);
    const app = parts[0] === 'apps' && parts[1] ? parts[1] : '';
    location.replace(app ? `/support/${app}/` : '/support/');
    return;
  }
  let statusHome = '/';
  let supportHome = '/support/';
  if (host.startsWith('status.')) {
    supportHome = `https://support.${host.slice('status.'.length)}/support/`;
  } else if (host.startsWith('support.')) {
    statusHome = `https://status.${host.slice('support.'.length)}/`;
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
