'use strict';
(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const TOKEN_KEY = 'certstore.adminToken';

  let token = '';
  try { token = sessionStorage.getItem(TOKEN_KEY) || ''; } catch {}
  let state = { certs: [], creds: [], keys: [] };
  let pollTimer;

  /* ---------- helpers ---------- */

  /** Build DOM safely (all text goes through textContent). */
  function h(tag, attrs = {}, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  function toast(msg, isErr = false) {
    const t = $('#toast');
    t.textContent = msg;
    t.className = 'toast' + (isErr ? ' err' : '');
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => t.classList.add('hidden'), 4000);
  }

  async function api(method, path, body) {
    const res = await fetch('/api/admin' + path, {
      method,
      headers: { Authorization: 'Bearer ' + token, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 401) { logout(); throw new Error('Session expired'); }
    if (res.status === 204) return null;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Request failed (' + res.status + ')');
    return data;
  }

  const fmtDate = (s) => (s ? new Date(s).toLocaleString() : '—');
  const daysLeft = (s) => Math.floor((new Date(s).getTime() - Date.now()) / 86400000);
  const ago = (s) => {
    if (!s) return 'never';
    const m = Math.round((Date.now() - new Date(s).getTime()) / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return m + ' min ago';
    if (m < 1440) return Math.round(m / 60) + ' h ago';
    return Math.round(m / 1440) + ' d ago';
  };

  /* ---------- auth ---------- */

  function showLogin() {
    $('#app').classList.add('hidden');
    $('#login').classList.remove('hidden');
    $('#login-token').focus();
  }

  function logout() {
    token = '';
    try { sessionStorage.removeItem(TOKEN_KEY); } catch {}
    clearInterval(pollTimer);
    showLogin();
  }

  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    token = $('#login-token').value.trim();
    $('#login-error').textContent = '';
    try {
      const res = await fetch('/api/admin/settings', { headers: { Authorization: 'Bearer ' + token } });
      if (!res.ok) throw new Error(res.status === 429 ? 'Too many attempts, try later' : 'Invalid token');
      try { sessionStorage.setItem(TOKEN_KEY, token); } catch {}
      $('#login-token').value = '';
      start();
    } catch (err) {
      $('#login-error').textContent = err.message;
    }
  });
  $('#logout').addEventListener('click', logout);

  /* ---------- tabs ---------- */

  $$('#tabs button').forEach((b) =>
    b.addEventListener('click', () => {
      $$('#tabs button').forEach((x) => x.classList.toggle('active', x === b));
      $$('[data-panel]').forEach((p) => p.classList.toggle('hidden', p.dataset.panel !== b.dataset.tab));
      if (b.dataset.tab === 'audit') loadAudit();
      if (b.dataset.tab === 'settings') loadSettings();
    }),
  );

  /* ---------- dialogs ---------- */

  $$('[data-open]').forEach((b) => b.addEventListener('click', () => openDialog(b.dataset.open)));
  $$('[data-close]').forEach((b) => b.addEventListener('click', () => b.closest('dialog').close()));

  function openDialog(id, prepare) {
    const dlg = $('#' + id);
    const form = $('form', dlg);
    if (form) { form.reset(); const err = $('[data-error]', form); if (err) err.textContent = ''; }
    if (id === 'dlg-cert') fillCredSelect($('select[name=credentialId]', dlg));
    if (id === 'dlg-cred') prepareCredDialog(null);
    if (id === 'dlg-key') prepareKeyDialog();
    if (prepare) prepare(dlg);
    dlg.showModal();
  }

  /** Submit handler that keeps the dialog open on error. */
  function onSubmit(form, fn) {
    form.addEventListener('submit', async (e) => {
      if (e.submitter && e.submitter.value === 'cancel') return;
      e.preventDefault();
      const btn = $('button[type=submit]', form);
      const err = $('[data-error]', form);
      btn.disabled = true;
      if (err) err.textContent = '';
      try {
        await fn(new FormData(form));
        form.closest('dialog').close();
      } catch (ex) {
        if (err) err.textContent = ex.message;
      } finally {
        btn.disabled = false;
      }
    });
  }

  /* ---------- certificates ---------- */

  function fillCredSelect(sel, selected) {
    sel.replaceChildren(
      ...(state.creds.length
        ? state.creds.map((c) => h('option', { value: c.id, selected: c.id === selected }, c.name + ' (' + c.hint + ')'))
        : [h('option', { value: '' }, 'Add a Cloudflare token first')]),
    );
  }

  function renderCerts() {
    const body = $('#certs-body');
    if (!state.certs.length) {
      body.replaceChildren(h('tr', {}, h('td', { colspan: 6, class: 'empty' }, 'No certificates yet.')));
      return;
    }
    body.replaceChildren(
      ...state.certs.map((c) => {
        let exp = '—';
        if (c.notAfter) {
          const d = daysLeft(c.notAfter);
          exp = h('span', { class: d < 0 ? 'exp-past' : d < 14 ? 'exp-soon' : '', title: fmtDate(c.notAfter) },
            d < 0 ? 'expired' : d + ' days');
        }
        return h('tr', {},
          h('td', { class: 'domains' }, c.domains.map((d) => h('div', {}, d))),
          h('td', {},
            h('span', { class: 'badge ' + c.status }, c.status),
            c.lastError ? h('div', { class: 'err-detail', title: c.lastError }, c.lastError.slice(0, 220)) : null,
            c.nextAttemptAt && c.lastError ? h('div', { class: 'muted' }, 'retry ' + fmtDate(c.nextAttemptAt)) : null,
          ),
          h('td', {}, exp),
          h('td', {}, c.credentialName),
          h('td', {}, c.acmeEnv === 'staging' ? h('span', { class: 'badge staging' }, 'staging') : 'production',
            h('div', { class: 'muted' }, c.email)),
          h('td', { class: 'actions-cell' },
            h('button', { class: 'small', disabled: c.status === 'issuing', onclick: () => renewCert(c) }, 'Renew now'),
            h('button', { class: 'small', onclick: () => editCert(c) }, 'Edit'),
            h('button', { class: 'small danger', onclick: () => deleteCert(c) }, 'Delete'),
          ),
        );
      }),
    );
  }

  onSubmit($('#cert-form'), async (fd) => {
    const domains = String(fd.get('domains')).split(/[\s,]+/).filter(Boolean);
    await api('POST', '/certs', {
      domains,
      credentialId: fd.get('credentialId'),
      email: fd.get('email') || undefined,
      acmeEnv: fd.get('acmeEnv'),
      keyType: fd.get('keyType'),
    });
    toast('Certificate created — issuance started');
    await refresh();
  });

  let editing = null;
  function editCert(c) {
    editing = c;
    openDialog('dlg-edit-cert', (dlg) => {
      $('[data-title]', dlg).textContent = c.id;
      fillCredSelect($('select[name=credentialId]', dlg), c.credentialId);
      $('select[name=acmeEnv]', dlg).value = c.acmeEnv;
      $('select[name=keyType]', dlg).value = c.keyType;
      $('input[name=email]', dlg).value = c.email || '';
    });
  }
  onSubmit($('#edit-cert-form'), async (fd) => {
    await api('PUT', '/certs/' + encodeURIComponent(editing.id), {
      credentialId: fd.get('credentialId'),
      email: fd.get('email'),
      acmeEnv: fd.get('acmeEnv'),
      keyType: fd.get('keyType'),
    });
    toast('Saved');
    await refresh();
  });

  async function renewCert(c) {
    try {
      await api('POST', '/certs/' + encodeURIComponent(c.id) + '/renew');
      toast('Renewal started for ' + c.id);
      await refresh();
    } catch (e) { toast(e.message, true); }
  }

  async function deleteCert(c) {
    if (!confirm('Delete certificate ' + c.id + '? Servers using it will no longer be able to download it.')) return;
    try { await api('DELETE', '/certs/' + encodeURIComponent(c.id)); toast('Deleted'); await refresh(); }
    catch (e) { toast(e.message, true); }
  }

  /* ---------- credentials ---------- */

  function renderCreds() {
    const body = $('#creds-body');
    if (!state.creds.length) {
      body.replaceChildren(h('tr', {}, h('td', { colspan: 6, class: 'empty' }, 'No Cloudflare tokens yet.')));
      return;
    }
    body.replaceChildren(
      ...state.creds.map((c) =>
        h('tr', {},
          h('td', {}, h('b', {}, c.name)),
          h('td', {}, h('code', {}, c.hint)),
          h('td', {}, c.zones.length ? c.zones.join(', ') : h('span', { class: 'muted' }, 'none visible')),
          h('td', {}, c.certificates + ' cert' + (c.certificates === 1 ? '' : 's')),
          h('td', { title: fmtDate(c.lastVerifiedAt) }, ago(c.lastVerifiedAt)),
          h('td', { class: 'actions-cell' },
            h('button', { class: 'small', onclick: () => verifyCred(c) }, 'Verify'),
            h('button', { class: 'small', onclick: () => openDialog('dlg-cred', () => prepareCredDialog(c)) }, 'Edit'),
            h('button', { class: 'small danger', onclick: () => deleteCred(c) }, 'Delete'),
          ),
        ),
      ),
    );
  }

  function prepareCredDialog(c) {
    const f = $('#cred-form');
    $('[data-title]', f).textContent = c ? 'Edit ' + c.name : 'Add Cloudflare token';
    f.elements.id.value = c ? c.id : '';
    f.elements.name.value = c ? c.name : '';
    f.elements.token.required = !c;
    f.elements.token.value = '';
    $('[data-token-hint]', f).textContent = c ? '(leave blank to keep ' + c.hint + ')' : '';
  }

  onSubmit($('#cred-form'), async (fd) => {
    const id = fd.get('id');
    const body = { name: fd.get('name') };
    if (fd.get('token')) body.token = fd.get('token');
    const res = id ? await api('PUT', '/credentials/' + id, body) : await api('POST', '/credentials', body);
    toast('Token verified — ' + res.zones.length + ' zone(s) accessible');
    await refresh();
  });

  async function verifyCred(c) {
    try {
      const r = await api('POST', '/credentials/' + c.id + '/verify');
      toast('OK — zones: ' + (r.credential.zones.join(', ') || 'none'));
      await refresh();
    } catch (e) { toast(e.message, true); }
  }

  async function deleteCred(c) {
    if (!confirm('Delete Cloudflare token "' + c.name + '"?')) return;
    try { await api('DELETE', '/credentials/' + c.id); toast('Deleted'); await refresh(); }
    catch (e) { toast(e.message, true); }
  }

  /* ---------- API keys ---------- */

  function renderKeys() {
    const body = $('#keys-body');
    if (!state.keys.length) {
      body.replaceChildren(h('tr', {}, h('td', { colspan: 7, class: 'empty' }, 'No API keys yet.')));
    } else {
      body.replaceChildren(
        ...state.keys.map((k) => {
          const expired = k.expiresAt && new Date(k.expiresAt) < new Date();
          return h('tr', {},
            h('td', {}, h('b', {}, k.name)),
            h('td', {}, h('code', {}, k.prefix + '…')),
            h('td', {}, k.domains.includes('*') ? h('i', {}, 'all') : k.domains.join(', ')),
            h('td', {}, k.allowedIps.length ? k.allowedIps.join(', ') : h('span', { class: 'muted' }, 'any')),
            h('td', { title: fmtDate(k.lastUsedAt) }, ago(k.lastUsedAt), k.lastUsedIp ? h('div', { class: 'muted' }, k.lastUsedIp) : null),
            h('td', { class: expired ? 'exp-past' : '' }, k.expiresAt ? fmtDate(k.expiresAt) : 'never'),
            h('td', { class: 'actions-cell' }, h('button', { class: 'small danger', onclick: () => revokeKey(k) }, 'Revoke')),
          );
        }),
      );
    }
    const origin = location.origin;
    const example = (state.certs[0] && state.certs[0].id) || 'api.example.com';
    $('#usage').textContent =
      '# List certificates this key can access\n' +
      'curl -H "Authorization: Bearer $CERTSTORE_KEY" ' + origin + '/api/v1/certs\n\n' +
      '# Download individual PEM files\n' +
      'curl -fsS -H "Authorization: Bearer $CERTSTORE_KEY" ' + origin + '/api/v1/certs/' + example + '/fullchain.pem -o fullchain.pem\n' +
      'curl -fsS -H "Authorization: Bearer $CERTSTORE_KEY" ' + origin + '/api/v1/certs/' + example + '/privkey.pem -o privkey.pem\n' +
      '# also: cert.pem, chain.pem, bundle.pem (key + fullchain, for HAProxy)\n\n' +
      '# Everything as JSON\n' +
      'curl -H "Authorization: Bearer $CERTSTORE_KEY" ' + origin + '/api/v1/certs/' + example + '\n\n' +
      '# Automatic sync + reload (cron): see scripts/certstore-sync.sh\n' +
      'CERTSTORE_URL=' + origin + ' CERTSTORE_KEY=... DOMAIN=' + example + ' \\\n' +
      '  DEST=/etc/ssl/' + example + ' RELOAD_CMD="systemctl reload nginx" ./certstore-sync.sh';
  }

  function prepareKeyDialog() {
    $('#key-domains').replaceChildren(
      ...(state.certs.length
        ? state.certs.map((c) => h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'domain', value: c.id }), c.id))
        : [h('span', { class: 'muted' }, 'No certificates yet — choose “All certificates”.')]),
    );
  }

  onSubmit($('#key-form'), async (fd) => {
    const domains = fd.get('all') ? ['*'] : fd.getAll('domain');
    const res = await api('POST', '/keys', {
      name: fd.get('name'),
      domains,
      allowedIps: fd.get('allowedIps'),
      expiresInDays: fd.get('expiresInDays') || undefined,
    });
    await refresh();
    setTimeout(() => {
      $('#new-key').textContent = res.key;
      $('#dlg-key-created').showModal();
    });
  });

  $('#copy-key').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($('#new-key').textContent); toast('Copied'); }
    catch { toast('Copy failed — select the key manually', true); }
  });

  async function revokeKey(k) {
    if (!confirm('Revoke API key "' + k.name + '"? Servers using it will lose access immediately.')) return;
    try { await api('DELETE', '/keys/' + k.id); toast('Revoked'); await refresh(); }
    catch (e) { toast(e.message, true); }
  }

  /* ---------- settings ---------- */

  async function loadSettings() {
    const s = await api('GET', '/settings');
    const f = $('#settings-form');
    f.elements.renewBeforeDays.value = s.renewBeforeDays;
  }
  $('#settings-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      await api('PUT', '/settings', { renewBeforeDays: Number(f.elements.renewBeforeDays.value) });
      $('#settings-msg').textContent = 'Saved.';
      setTimeout(() => ($('#settings-msg').textContent = ''), 2500);
    } catch (ex) { toast(ex.message, true); }
  });

  /* ---------- audit ---------- */

  async function loadAudit() {
    const rows = await api('GET', '/audit');
    $('#audit-body').replaceChildren(
      ...(rows.length
        ? rows.map((r) =>
            h('tr', {},
              h('td', {}, fmtDate(r.at)),
              h('td', {}, r.actor),
              h('td', {}, h('span', { class: r.ok ? '' : 'exp-past' }, r.action)),
              h('td', {}, r.target || ''),
              h('td', {}, r.ip || ''),
              h('td', { class: 'err-detail' }, r.detail || ''),
            ))
        : [h('tr', {}, h('td', { colspan: 6, class: 'empty' }, 'No entries.'))]),
    );
  }
  $('#audit-refresh').addEventListener('click', loadAudit);

  /* ---------- boot ---------- */

  async function refresh() {
    const [certs, creds, keys] = await Promise.all([api('GET', '/certs'), api('GET', '/credentials'), api('GET', '/keys')]);
    state = { certs, creds, keys };
    renderCerts();
    renderCreds();
    renderKeys();
  }

  function start() {
    $('#login').classList.add('hidden');
    $('#app').classList.remove('hidden');
    refresh().catch((e) => toast(e.message, true));
    clearInterval(pollTimer);
    pollTimer = setInterval(() => {
      if (!document.hidden) refresh().catch(() => {});
    }, 5000);
  }

  if (token) start();
  else showLogin();
})();
