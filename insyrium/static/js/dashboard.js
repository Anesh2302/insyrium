/* Insyrium Portal — dashboard shell */
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (v) => Insyrium.escapeHtml(v);

  let me = null;

  /* ── Role → modules ── */
  const MODULES = {
    overview: { label: 'Overview', icon: '◈' },
    profile: { label: 'My Profile', icon: '👤' },
    inbox: { label: 'Support Inbox', icon: '✉' },
    content: { label: 'Content Publishing', icon: '✍' },
    users: { label: 'User Management', icon: '☰' },
    sessions: { label: 'Active Sessions', icon: '📡' },
    admins: { label: 'Admin Management', icon: '🛡' },
    config: { label: 'System Config', icon: '⚙' },
    billing: { label: 'Billing', icon: '◷' },
    audit: { label: 'Audit Logs', icon: '📜' },
  };

  function modulesFor(role) {
    switch (role) {
      case 'supreme_admin':
        return ['overview', 'profile', 'inbox', 'content', 'users', 'sessions', 'admins', 'config', 'billing', 'audit'];
      case 'admin_platform':
        return ['overview', 'profile', 'inbox', 'content', 'users', 'sessions', 'audit'];
      case 'admin_content':
        return ['overview', 'profile', 'inbox', 'content'];
      case 'admin_support':
        return ['overview', 'profile', 'inbox', 'users'];
      default:
        return ['overview', 'profile'];
    }
  }

  /* ── Boot ── */
  async function init() {
    const ok = await Insyrium.restore();
    if (!ok) { location.href = '/login'; return; }

    try {
      const r = await Insyrium.api('/api/auth/me');
      if (!r.ok) throw new Error('no me');
      me = r.data.user;
      Insyrium.user = () => me;
    } catch {
      location.href = '/login';
      return;
    }

    renderNav();
    renderSidebar();
    showModule('overview');

    wireTopbar();
    wireModals();

    const splash = $('#splash');
    $('#app').hidden = false;
    splash.classList.add('fade-out');
    setTimeout(() => splash.remove(), 500);

    setInterval(() => { const c = $('#clock'); if (c) c.textContent = new Date().toLocaleTimeString(); }, 1000);
  }

  /* ── Nav ── */
  function renderNav() {
    const nav = $('#nav-side');
    nav.innerHTML = modulesFor(me.role)
      .map((m) => `<button class="nav-item" data-mod="${m}">
          <span class="nav-icon">${MODULES[m].icon}</span><span>${esc(MODULES[m].label)}</span></button>`)
      .join('')
      + `<a class="nav-item" href="/community"><span class="nav-icon">💬</span><span>Community</span></a>`;
    $$('.nav-item', nav).forEach((b) => b.addEventListener('click', (e) => {
      if (b.dataset.mod) showModule(b.dataset.mod);
      else if (e.target.tagName !== 'A') location.href = '/community';
    }));
  }

  function renderSidebar() {
    $('#sidebar-avatar').textContent = (me.name || '?')[0].toUpperCase();
    $('#sidebar-name').textContent = me.name;
    $('#sidebar-role').textContent = me.role.replace(/_/g, ' ').toUpperCase();
  }

  /* ── Module switching ── */
  function showModule(name) {
    $$('.mod').forEach((s) => {
      s.hidden = s.id !== `mod-${name}`;
      if (!s.hidden) {
        s.classList.remove('mod-in');
        void s.offsetWidth;
        s.classList.add('mod-in');
      }
    });
    $('#module-title').textContent = MODULES[name].label;
    $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.mod === name));
    $('#sidebar').classList.remove('open');
    loaders[name] && loaders[name]();
  }

  /* ── Topbar / modals wiring ── */
  function wireTopbar() {
    $('#logout-btn').addEventListener('click', () => Insyrium.logout());
    $('#menu-btn').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  }

  function wireModals() {
    $$('[data-close]').forEach((el) =>
      el.addEventListener('click', () => closeModal(el.dataset.close)));
    $('#stepup-form').addEventListener('submit', onStepUpSubmit);
    $('#confirm-ok').addEventListener('click', runConfirmed);
  }

  function closeModal(name) {
    $(`#${name}-modal`).hidden = true;
    if (name === 'stepup') resetStepUp();
  }
  function openModal(name) { $(`#${name}-modal`).hidden = false; }

  /* ── Confirm ── */
  let confirmTask = null;
  function confirmAction(title, text, task) {
    $('#confirm-title').textContent = title;
    $('#confirm-text').textContent = text;
    confirmTask = task;
    openModal('confirm');
  }
  async function runConfirmed() {
    if (!confirmTask) return;
    const task = confirmTask;
    confirmTask = null;
    closeModal('confirm');
    try { await task(); } catch (_) {}
  }

  /* ── Step-up ── */
  let stepUpTask = null;
  let stepUpState = { password: '', otpVisible: false };

  function openStepUp(task) {
    stepUpTask = task;
    stepUpState = { password: '', otpVisible: false };
    resetStepUp();
    openModal('stepup');
    setTimeout(() => $('#stepup-password').focus(), 50);
  }

  function resetStepUp() {
    stepUpState = { password: '', otpVisible: false };
    $('#stepup-password').value = '';
    $('#stepup-otp').value = '';
    $('#stepup-otp-wrap').hidden = true;
    $('#stepup-error').hidden = true;
    $('#stepup-submit').textContent = 'Authorise';
  }

  async function onStepUpSubmit(ev) {
    ev.preventDefault();
    const password = $('#stepup-password').value;
    const err = $('#stepup-error');
    const btn = $('#stepup-submit');
    err.hidden = true;

    const body = { password };
    if (stepUpState.otpVisible) body.otp = $('#stepup-otp').value;

    btn.disabled = true;
    btn.textContent = 'Checking…';
    try {
      const r = await Insyrium.api('/api/auth/step-up', { method: 'POST', body });
      if (r.status === 202 && r.data.otp_required) {
        stepUpState.otpVisible = true;
        $('#stepup-otp-wrap').hidden = false;
        $('#stepup-otp-dest').textContent = `→ sent to ${r.data.masked_target || 'your inbox'}`;
        btn.textContent = 'Verify & authorise';
        setTimeout(() => $('#stepup-otp').focus(), 50);
        return;
      }
      if (r.ok && r.data.step_up_token) {
        closeModal('stepup');
        const task = stepUpTask;
        stepUpTask = null;
        await task(r.data.step_up_token);
        return;
      }
      err.textContent = r.data.error || 'Verification failed.';
      err.hidden = false;
    } catch {
      err.textContent = 'Network error. Please try again.';
      err.hidden = false;
    } finally {
      btn.disabled = false;
    }
  }

  /* ════════════════════════════════════════════════════════
     MODULE LOADERS
  ════════════════════════════════════════════════════════ */
  const loaders = {
    /* ── Overview ── */
    async overview() {
      const r = await Insyrium.api('/admin/stats');
      if (!r.ok) { $('#stat-grid').innerHTML = '<div class="empty">Could not load stats.</div>'; return; }
      const d = r.data;

      $('#welcome-sub').textContent = `Signed in as ${me.role.replace(/_/g, ' ')}`;
      $('#welcome-title').textContent = `Welcome back, ${me.name.split(' ')[0]}`;
      $('#welcome-text').textContent = `Last login ${Insyrium.humanDate(me.last_login_at)} · ${me.email}`;
      $('#welcome-badge').innerHTML = Insyrium.badgeHtml(me.role);

      const cards = [
        { label: 'Active users', value: d.totals.active_users, suffix: '' },
        { label: 'Admins', value: d.totals.admins, suffix: '' },
        { label: 'Published resources', value: d.content.published, suffix: '' },
        { label: 'New enquiries', value: d.enquiries.new, suffix: '' },
      ];
      $('#stat-grid').innerHTML = cards.map((c, i) => `
        <div class="stat-card" style="animation-delay:${i * 60}ms">
          <span class="stat-label">${esc(c.label)}</span>
          <span class="stat-value" data-count="${c.value}">0</span>
          <span class="stat-spark"></span>
        </div>`).join('');
      $$('.stat-value').forEach((el) => Insyrium.countUp(el, +el.dataset.count, ''));

      $('#activity-list').innerHTML = d.activity.length
        ? d.activity.map((a) => `
            <div class="activity-row">
              <span class="a-icon">${esc(a.icon)}</span>
              <span class="a-label">${esc(a.label)}</span>
              <span class="a-count">${a.count}</span>
            </div>`).join('')
        : '<div class="empty">No activity yet.</div>';

      const max = Math.max(1, ...d.weekly.map((w) => w.value));
      $('#bar-chart').innerHTML = d.weekly.map((w) => `
        <div class="bar-col" title="${esc(w.day)}: ${w.value}">
          <div class="bar-fill" style="height:${Math.max(4, (w.value / max) * 100)}%"></div>
          <span class="bar-day">${esc(w.day[0])}</span>
        </div>`).join('');

      const qa = [];
      if (me.rank >= 1) qa.push(['✉', 'Open support inbox', 'inbox']);
      if (me.rank >= 2) qa.push(['✍', 'Write a resource', 'content']);
      if (me.rank >= 3) qa.push(['☰', 'Manage users', 'users']);
      if (me.rank === 4) qa.push(['⚙', 'System config', 'config']);
      qa.push(['👤', 'My profile', 'profile']);
      $('#quick-actions').innerHTML = qa.map(([i, label, mod]) => `
        <button class="qa-btn" data-mod="${mod}"><span class="qa-icon">${i}</span>${esc(label)}</button>`).join('');
      $$('.qa-btn').forEach((b) => b.addEventListener('click', () => showModule(b.dataset.mod)));
    },

    /* ── Profile ── */
    async profile() {
      const a = $('#profile-avatar');
      a.textContent = (me.name || '?')[0].toUpperCase();
      $('#profile-name').textContent = me.name;
      $('#profile-email').textContent = me.email;
      $('#profile-badges').innerHTML = `${Insyrium.badgeHtml(me.role)} ${Insyrium.statusPill(me.status)}`;
      $('#profile-badges').innerHTML += `
        <span class="muted">· member since ${Insyrium.humanDateShort(me.created_at)}</span>`;

      const btn = $('#mfa-toggle');
      btn.textContent = me.mfa_enabled ? 'Disable 2FA' : 'Enable 2FA';
      btn.classList.toggle('danger-outline', me.mfa_enabled);
      btn.onclick = () => openStepUp(async (token) => {
        const r = await Insyrium.api('/api/auth/profile/mfa', {
          method: 'POST',
          body: { enabled: !me.mfa_enabled },
          stepUpToken: token,
        });
        if (r.ok) {
          me = r.data.user;
          Insyrium.user = () => me;
          Insyrium.toast(me.mfa_enabled ? 'Two-factor authentication enabled.' : 'Two-factor authentication disabled.', 'success');
          loaders.profile();
        } else {
          Insyrium.toast(r.data.error || 'Could not update MFA.', 'error');
        }
      });

      $('#logout-all-btn').onclick = () => confirmAction(
        'Sign out everywhere?',
        'This revokes every active session for your account, including this one.',
        async () => {
          const r = await Insyrium.api('/api/auth/logout-all', { method: 'POST' });
          if (r.ok) { Insyrium.toast(`Signed out ${r.data.devices_revoked || 0} device(s).`, 'success'); Insyrium.logout(); }
          else Insyrium.toast('Could not revoke sessions.', 'error');
        });

      $('#pw-form').onsubmit = async (ev) => {
        ev.preventDefault();
        const r = await Insyrium.api('/api/auth/change-password', {
          method: 'POST',
          body: { current: $('#pw-current').value, new: $('#pw-new').value },
        });
        if (r.ok) {
          Insyrium.toast('Password updated.', 'success');
          $('#pw-form').reset();
        } else {
          Insyrium.toast(r.data.error || 'Could not update password.', 'error');
        }
      };
    },

    /* ── Support Inbox ── */
    async inbox() {
      const filter = $('#inbox-filters .chip.active')?.dataset.status || '';
      const r = await Insyrium.api(`/admin/enquiries?status=${encodeURIComponent(filter)}`);
      const rows = r.ok ? r.data.enquiries : [];
      $('#inbox-body').innerHTML = rows.length
        ? rows.map((e) => `
          <tr>
            <td><strong>${esc(e.name)}</strong><br><span class="muted">${esc(e.email)}</span></td>
            <td>${esc(e.subject)}</td>
            <td class="trunc">${esc(e.message)}</td>
            <td>${Insyrium.statusPill(e.status)}</td>
            <td class="muted">${Insyrium.humanDate(e.created_at)}</td>
            <td>
              <select class="mini-select" data-enq="${e.id}" data-cur="${e.status}">
                ${['new', 'open', 'responded', 'closed'].map((s) => `<option ${s === e.status ? 'selected' : ''}>${s}</option>`).join('')}
              </select>
            </td>
          </tr>`).join('')
        : '<tr class="empty-row"><td colspan="6">No enquiries found.</td></tr>';
      $$('#inbox-body .mini-select').forEach((sel) =>
        sel.addEventListener('change', async () => {
          const r2 = await Insyrium.api(`/admin/enquiries/${sel.dataset.enq}/status`, {
            method: 'PATCH', body: { status: sel.value },
          });
          if (r2.ok) { Insyrium.toast('Enquiry updated.', 'success'); loaders.inbox(); }
          else Insyrium.toast(r2.data.error || 'Failed.', 'error');
        }));
      $$('#inbox-filters .chip').forEach((c) =>
        c.onclick = () => { $$('#inbox-filters .chip').forEach((x) => x.classList.remove('active')); c.classList.add('active'); loaders.inbox(); });
    },

    /* ── Content Publishing ── */
    async content() {
      const filter = $('#content-filters .chip.active')?.dataset.status || '';
      const r = await Insyrium.api(`/admin/content?status=${encodeURIComponent(filter)}`);
      const items = r.ok ? r.data.content : [];
      $('#content-list').innerHTML = items.length
        ? items.map((c) => `
          <div class="content-item">
            <div class="content-meta">
              <span class="pill pill-type">${esc(c.type.replace(/_/g, ' '))}</span>
              ${Insyrium.statusPill(c.status)}
              <span class="muted">· ${esc(c.product)}</span>
            </div>
            <h4>${esc(c.title)}</h4>
            <p class="muted">${esc((c.body || '').slice(0, 120))}${(c.body || '').length > 120 ? '…' : ''}</p>
            <div class="content-foot">
              <span class="muted">by ${esc(c.author || '?')} · ${Insyrium.humanDate(c.created_at)}</span>
              <span class="actions">
                ${c.status !== 'published' ? `<button class="mini-btn ok" data-id="${c.id}" data-s="published">Publish</button>` : ''}
                ${c.status !== 'rejected' ? `<button class="mini-btn warn" data-id="${c.id}" data-s="rejected">Reject</button>` : ''}
                ${c.status === 'published' ? `<button class="mini-btn" data-id="${c.id}" data-s="draft">Unpublish</button>` : ''}
              </span>
            </div>
          </div>`).join('')
        : '<div class="empty">No resources here yet.</div>';

      $$('#content-list .mini-btn').forEach((b) =>
        b.addEventListener('click', async () => {
          const r2 = await Insyrium.api(`/admin/content/${b.dataset.id}/status`, {
            method: 'PATCH', body: { status: b.dataset.s },
          });
          if (r2.ok) { Insyrium.toast('Content updated.', 'success'); loaders.content(); }
          else Insyrium.toast(r2.data.error || 'Failed.', 'error');
        }));

      $$('#content-filters .chip').forEach((c) =>
        c.onclick = () => { $$('#content-filters .chip').forEach((x) => x.classList.remove('active')); c.classList.add('active'); loaders.content(); });

      $('#content-form').onsubmit = async (ev) => {
        ev.preventDefault();
        const body = {
          type: $('#content-type').value,
          product: $('#content-product').value,
          title: $('#content-title').value,
          body: $('#content-body').value,
          file_url: $('#content-file').value || null,
        };
        const r3 = await Insyrium.api('/admin/content', { method: 'POST', body });
        if (r3.ok) {
          Insyrium.toast('Resource submitted for review.', 'success');
          $('#content-form').reset();
          loaders.content();
        } else Insyrium.toast(r3.data.error || 'Could not submit.', 'error');
      };
    },

    /* ── User Management ── */
    async users() {
      const q = $('#users-search').value.trim();
      const status = $('#users-filters .chip.active')?.dataset.status || '';
      const r = await Insyrium.api(`/admin/users?q=${encodeURIComponent(q)}&status=${encodeURIComponent(status)}`);
      const users = r.ok ? r.data.users : [];

      const canEdit = me.rank >= 3;
      $('#users-actions-th').textContent = canEdit ? 'Actions' : '';
      $('#users-body').innerHTML = users.length
        ? users.map((u) => `
          <tr>
            <td><strong>${esc(u.name)}</strong><br><span class="muted">${esc(u.email)}</span></td>
            <td>${Insyrium.badgeHtml(u.role)}${u.scopes && u.scopes.length ? `<br><span class="muted scopes">${esc(u.scopes.join(' · '))}</span>` : ''}</td>
            <td>${Insyrium.statusPill(u.status)}</td>
            <td class="muted">${esc(u.organization || '—')}</td>
            <td>
              <div class="mono">${Insyrium.humanDate(u.last_login_at)}</div>
              <div class="mono">${esc(u.last_login_ip || '—')}</div>
              <div class="mono muted">${esc(u.last_login_mac || '—')}</div>
            </td>
            <td>
              ${canEdit && u.role !== 'supreme_admin' && u.id !== me.id
                ? `<div class="row-gap">
                    <select class="mini-select" data-id="${u.id}" data-role="${u.role}" data-status="${u.status}">
                      <option value="active" ${u.status === 'active' ? 'selected' : ''}>Active</option>
                      <option value="suspended" ${u.status === 'suspended' ? 'selected' : ''}>Suspended</option>
                    </select>
                    ${me.rank === 4 ? `<button class="mini-btn warn" data-role-btn="${u.id}" title="Change role">Role</button>` : ''}
                  </div>`
                : ''}
            </td>
          </tr>`).join('')
        : '<tr class="empty-row"><td colspan="6">No users found.</td></tr>';

      $$('#users-body .mini-select').forEach((sel) =>
        sel.addEventListener('change', async () => {
          const r2 = await Insyrium.api(`/admin/users/${sel.dataset.id}`, {
            method: 'PATCH', body: { status: sel.value },
          });
          if (r2.ok) { Insyrium.toast('User updated.', 'success'); loaders.users(); }
          else Insyrium.toast(r2.data.error || 'Failed.', 'error');
        }));

      $$('#users-body [data-role-btn]').forEach((b) =>
        b.addEventListener('click', () => {
          const uid = b.dataset.roleBtn;
          openStepUp(async (token) => {
            const role = prompt('New role (user / admin_support / admin_content / admin_platform):');
            if (!role) return;
            const r3 = await Insyrium.api(`/admin/users/${uid}/role`, {
              method: 'PATCH', body: { role }, stepUpToken: token,
            });
            if (r3.ok) { Insyrium.toast('Role updated.', 'success'); loaders.users(); }
            else Insyrium.toast(r3.data.error || 'Failed.', 'error');
          });
        }));

      let t;
      $('#users-search').addEventListener('input', () => {
        clearTimeout(t);
        t = setTimeout(() => loaders.users(), 350);
      });
      $$('#users-filters .chip').forEach((c) =>
        c.onclick = () => { $$('#users-filters .chip').forEach((x) => x.classList.remove('active')); c.classList.add('active'); loaders.users(); });
    },

    /* ── Active Sessions ── */
    async sessions() {
      const q = $('#sessions-search').value.trim().toLowerCase();
      const r = await Insyrium.api('/admin/sessions');
      if (!r.ok) { $('#sessions-body').innerHTML = '<tr class="empty-row"><td colspan="7">Could not load sessions.</td></tr>'; return; }
      let rows = r.data.sessions || [];
      if (q) {
        rows = rows.filter((s) =>
          (s.user_name || '').toLowerCase().includes(q)
          || (s.user_email || '').toLowerCase().includes(q)
          || (s.ip_address || '').toLowerCase().includes(q)
          || (s.mac_address || '').toLowerCase().includes(q));
      }
      $('#sessions-body').innerHTML = rows.length
        ? rows.map((s) => `
          <tr class="${s.expired ? 'dim' : ''}">
            <td><strong>${esc(s.user_name)}</strong><br><span class="muted">${esc(s.user_email)}</span></td>
            <td class="mono">${esc(s.ip_address || '—')}</td>
            <td class="mono muted">${esc(s.mac_address || '—')}</td>
            <td class="trunc muted" title="${esc(s.user_agent)}">${esc(s.user_agent || '—')}</td>
            <td class="muted">${Insyrium.humanDate(s.created_at)}</td>
            <td class="muted">${s.expired ? 'expired' : Insyrium.humanDate(s.expires_at)}</td>
            <td><button class="mini-btn danger" data-revoke="${s.id}" data-name="${esc(s.user_name)}">Revoke</button></td>
          </tr>`).join('')
        : '<tr class="empty-row"><td colspan="7">No active sessions found.</td></tr>';

      $$('#sessions-body [data-revoke]').forEach((b) =>
        b.addEventListener('click', () => {
          confirmAction(
            `Revoke session for ${b.dataset.name}?`,
            'The user will be signed out of that device immediately.',
            async () => {
              const r2 = await Insyrium.api(`/admin/sessions/${b.dataset.revoke}`, { method: 'DELETE' });
              if (r2.ok) { Insyrium.toast(r2.data.message || 'Session revoked.', 'success'); loaders.sessions(); }
              else Insyrium.toast(r2.data.error || 'Could not revoke.', 'error');
            });
        }));

      $('#sessions-refresh').onclick = () => loaders.sessions();
      let st;
      $('#sessions-search').addEventListener('input', () => {
        clearTimeout(st);
        st = setTimeout(() => loaders.sessions(), 350);
      });
    },

    /* ── Admin Management ── */
    async admins() {
      $('#admin-products').innerHTML = ['insyrium', 'sape_tqm', 'decisium', 'mirads_builder']
        .map((p) => `<label class="check"><input type="checkbox" value="${p}"> ${p}</label>`).join('');

      const r = await Insyrium.api('/admin/admins');
      const admins = r.ok ? r.data.admins : [];
      $('#admin-list').innerHTML = admins.length
        ? admins.map((a) => `
          <div class="admin-card">
            <div class="admin-avatar">${esc((a.name || '?')[0].toUpperCase())}</div>
            <div class="admin-meta">
              <strong>${esc(a.name)}</strong>
              <span class="muted">${esc(a.email)}</span>
              <div class="badges">${Insyrium.badgeHtml(a.role)} ${a.scopes && a.scopes.length ? `<span class="scopes">${esc(a.scopes.join(' · '))}</span>` : '<span class="scopes">all products</span>'} ${Insyrium.statusPill(a.status)}</div>
              ${a.job_title || a.department || a.organization || a.country || a.phone_number ? `
                <div class="admin-detail">
                  ${[a.job_title, a.department].filter(Boolean).join(' · ') ? `<span>${esc([a.job_title, a.department].filter(Boolean).join(' · '))}</span>` : ''}
                  ${a.organization ? `<span>${esc(a.organization)}</span>` : ''}
                  ${a.country ? `<span>${esc(a.country)}</span>` : ''}
                  ${a.phone_number ? `<span class="mono">${esc(a.phone_number)}</span>` : ''}
                </div>` : ''}
            </div>
            <div class="actions">
              ${a.role !== 'supreme_admin' && a.id !== me.id ? `
                <button class="mini-btn" data-edit="${a.id}">Edit</button>
                <button class="mini-btn danger" data-del="${a.id}">Remove</button>` : ''}
            </div>
          </div>`).join('')
        : '<div class="empty">No admins yet.</div>';

      $$('#admin-list [data-edit]').forEach((b) =>
        b.addEventListener('click', () => {
          const target = admins.find((a) => a.id === Number(b.dataset.edit));
          editAdmin(target.id, target);
        }));

      $$('#admin-list [data-del]').forEach((b) =>
        b.addEventListener('click', () => {
          const target = admins.find((a) => a.id === Number(b.dataset.del));
          confirmAction(
            `Remove ${target.name}?`,
            `This permanently deletes the ${target.role} account and revokes all sessions.`,
            () => openStepUp(async (token) => {
              const r2 = await Insyrium.api(`/admin/admins/${target.id}`, { method: 'DELETE', stepUpToken: token });
              if (r2.ok) { Insyrium.toast(r2.data.message || 'Admin removed.', 'success'); loaders.admins(); }
              else Insyrium.toast(r2.data.error || 'Failed.', 'error');
            }),
          );
        }));

      $('#admin-form').onsubmit = async (ev) => {
        ev.preventDefault();
        const products = $$('#admin-products input:checked').map((i) => i.value);
        const body = {
          name: $('#admin-name').value,
          email: $('#admin-email').value,
          role: $('#admin-role').value,
          password: $('#admin-password').value,
          products,
          phone_number: $('#admin-phone').value,
          job_title: $('#admin-jobtitle').value,
          department: $('#admin-department').value,
          organization: $('#admin-org').value,
          country: $('#admin-country').value,
        };
        openStepUp(async (token) => {
          const r2 = await Insyrium.api('/admin/admins', { method: 'POST', body, stepUpToken: token });
          if (r2.ok) {
            Insyrium.toast(`Admin ${body.role} created.`, 'success');
            $('#admin-form').reset();
            loaders.admins();
          } else Insyrium.toast(r2.data.error || 'Could not create admin.', 'error');
        });
      };
    },

    /* ── Config ── */
    async config() {
      const r = await Insyrium.api('/admin/config');
      if (!r.ok) { Insyrium.toast(r.data.error || 'Could not load config.', 'error'); return; }
      const c = r.data.config;
      $('#cfg-portal-name').value = c.portal_name || '';
      $('#cfg-alert-email').value = c.alert_email || '';
      $('#cfg-register').checked = !!c.allow_registration;
      $('#cfg-maintenance').checked = !!c.maintenance_mode;
      $('#cfg-mfa').checked = !!c.default_mfa_for_admins;

      $('#config-form').onsubmit = async (ev) => {
        ev.preventDefault();
        const body = {
          portal_name: $('#cfg-portal-name').value,
          alert_email: $('#cfg-alert-email').value,
          allow_registration: $('#cfg-register').checked,
          maintenance_mode: $('#cfg-maintenance').checked,
          default_mfa_for_admins: $('#cfg-mfa').checked,
        };
        openStepUp(async (token) => {
          const r2 = await Insyrium.api('/admin/config', { method: 'PATCH', body, stepUpToken: token });
          if (r2.ok) Insyrium.toast('Settings saved.', 'success');
          else Insyrium.toast(r2.data.error || 'Could not save.', 'error');
        });
      };
    },

    /* ── Billing ── */
    async billing() {
      const r = await Insyrium.api('/admin/billing');
      if (!r.ok) { $('#billing-body').innerHTML = '<tr class="empty-row"><td colspan="5">Could not load billing.</td></tr>'; return; }
      const b = r.data.billing;
      $('#billing-totals').innerHTML = [
        { label: 'Paid', value: b.totals.paid },
        { label: 'Pending', value: b.totals.pending },
        { label: 'This month', value: b.totals.this_month },
      ].map((t) => `<div class="stat-card"><span class="stat-label">${esc(t.label)}</span><span class="stat-value">$${t.value.toLocaleString()}</span></div>`).join('');

      $('#billing-body').innerHTML = b.invoices.map((inv) => `
        <tr>
          <td class="mono">${esc(inv.id)}</td>
          <td>${esc(inv.description)}</td>
          <td class="mono">$${inv.amount.toLocaleString()}</td>
          <td>${Insyrium.statusPill(inv.status)}</td>
          <td class="muted">${esc(inv.due)}</td>
        </tr>`).join('');
    },

    /* ── Audit Logs ── */
    async audit() {
      const action = $('#audit-action').value.trim();
      const from = $('#audit-from').value;
      const to = $('#audit-to').value;
      const qs = new URLSearchParams();
      if (action) qs.set('action', action);
      if (from) qs.set('from', from);
      if (to) qs.set('to', to);

      const r = await Insyrium.api(`/admin/audit-logs?${qs.toString()}`);
      const logs = r.ok ? r.data.logs : [];
      $('#audit-body').innerHTML = logs.length
        ? logs.map((l) => `
          <tr>
            <td class="mono muted">#${l.id}</td>
            <td class="muted">${Insyrium.humanDate(l.created_at)}</td>
            <td>${esc(l.actor_name || 'system')}</td>
            <td><span class="mono pill-${l.action === 'login_failed' || l.action === 'otp_failed' ? 'danger' : 'soft'}">${esc(l.action)}</span></td>
            <td class="mono muted">${l.target_id ? '#' + l.target_id : '—'}</td>
            <td class="trunc muted">${esc(l.metadata ? JSON.stringify(l.metadata) : '')}</td>
          </tr>`).join('')
        : '<tr class="empty-row"><td colspan="6">No log entries found.</td></tr>';

      $('#audit-apply').onclick = () => loaders.audit();
      $('#audit-action').addEventListener('keydown', (e) => { if (e.key === 'Enter') loaders.audit(); });
    },
  };

  let editingAdminId = null;

  function editAdmin(id, admin) {
    editingAdminId = id;
    $('#edit-admin-sub').textContent = admin ? admin.email : '';
    $('#ea-name').value = admin?.name || '';
    $('#ea-role').value = admin?.role || 'admin_support';
    $('#ea-status').value = admin?.status || 'active';
    $('#ea-mfa').value = admin?.mfa_enabled ? 'true' : 'false';
    $('#ea-phone').value = admin?.phone_number || '';
    $('#ea-jobtitle').value = admin?.job_title || '';
    $('#ea-department').value = admin?.department || '';
    $('#ea-org').value = admin?.organization || '';
    $('#ea-country').value = admin?.country || '';
    $('#ea-products').innerHTML = ['insyrium', 'sape_tqm', 'decisium', 'mirads_builder']
      .map((p) => `<label class="check"><input type="checkbox" value="${p}" ${(admin?.scopes || []).includes(p) ? 'checked' : ''}> ${p}</label>`).join('');
    openModal('editadmin');
  }

  $('#edit-admin-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (editingAdminId === null) return;
    const products = $$('#ea-products input:checked').map((i) => i.value);
    const body = {
      name: $('#ea-name').value,
      role: $('#ea-role').value,
      status: $('#ea-status').value,
      mfa_enabled: $('#ea-mfa').value === 'true',
      products,
      phone_number: $('#ea-phone').value,
      job_title: $('#ea-jobtitle').value,
      department: $('#ea-department').value,
      organization: $('#ea-org').value,
      country: $('#ea-country').value,
    };
    openStepUp(async (token) => {
      const r = await Insyrium.api(`/admin/admins/${editingAdminId}`, { method: 'PATCH', body, stepUpToken: token });
      if (r.ok) {
        Insyrium.toast('Admin updated.', 'success');
        closeModal('editadmin');
        editingAdminId = null;
        loaders.admins();
      } else Insyrium.toast(r.data.error || 'Failed.', 'error');
    });
  });

  window.InsyriumDashboard = { showModule, loaders };
  init();
})();
