// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The header shared by the status and support sites. Both are one app
// answering under two names, so where each link points depends on the name
// the page was opened under.

(() => {
  const host = location.hostname;
  let statusHome = '/';
  let supportHome = '/support/';
  if (host.startsWith('status.')) {
    supportHome = `https://support.${host.slice('status.'.length)}/`;
  } else if (host.startsWith('support.')) {
    statusHome = `https://status.${host.slice('support.'.length)}/`;
    supportHome = '/';
  }
  const site = document.body.dataset.site;
  const links = { status: document.getElementById('nav-status'), support: document.getElementById('nav-support') };
  if (links.status) links.status.href = statusHome;
  if (links.support) links.support.href = supportHome;
  if (links[site]) links[site].classList.add('active');
  const brand = document.getElementById('brand');
  if (brand) brand.href = site === 'support' ? supportHome : statusHome;
  const product = document.getElementById('brand-product');
  if (product) product.textContent = site === 'support' ? 'Support' : 'Status';
})();
