/* Insyrium Portal — shared client library */
const Insyrium = (() => {
  const TOKEN_KEY = 'insyrium_access';
  const USER_KEY = 'insyrium_user';

  function getCookie(name) {
    const m = document.cookie.split('; ').find((c) => c.startsWith(name + '='));
    return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
  }

  function escapeHtml(v) {
    if (v === null || v === undefined) return '';
    return String(v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function humanDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  }

  function humanDateShort(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  /* ── API client with refresh-once on expired access token ── */
  async function api(path, opts = {}) {
    const { method = 'GET', body, silent = false, stepUpToken } = opts;
    const headers = {
      'X-CSRF-Token': getCookie('insyrium_csrf') || '',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}),
      ...(stepUpToken ? { 'X-Step-Up-Token': stepUpToken } : {}),
    };

    let res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    let json = {};
    try { json = await res.json(); } catch (_) {}

    // Access token expired → silently rotate via the refresh cookie, retry once.
    if (res.status === 401 && (json.code === 'token_expired' || json.code === 'no_token' || json.code === 'bad_token')) {
      const ok = await refresh();
      if (ok) {
        const h2 = { ...headers, Authorization: `Bearer ${getToken()}` };
        res = await fetch(path, { method, headers: h2, body: body ? JSON.stringify(body) : undefined });
        try { json = await res.json(); } catch (_) {}
      }
    }
    return { ok: res.ok, status: res.status, data: json };
  }

  async function refresh() {
    const res = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'X-CSRF-Token': getCookie('insyrium_csrf') || '' },
    });
    const json = await res.json().catch(() => ({}));
    if (res.ok && json.access_token) {
      setToken(json.access_token);
      if (json.user) setUser(json.user);
      return true;
    }
    clearSession();
    return false;
  }

  function setToken(t) { sessionStorage.setItem(TOKEN_KEY, t); }
  function getToken() { return sessionStorage.getItem(TOKEN_KEY); }
  function setUser(u) { sessionStorage.setItem(USER_KEY, JSON.stringify(u)); }
  function getUser() { try { return JSON.parse(sessionStorage.getItem(USER_KEY)); } catch (_) { return null; } }
  function clearSession() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
  }

  async function restore() {
    if (getToken()) return true;
    return refresh();
  }

  async function logout() {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCookie('insyrium_csrf') || '' },
      });
    } catch (_) {}
    clearSession();
    location.href = '/login';
  }

  /* ── Toasts ── */
  function toast(message, type = 'info') {
    const wrap = document.getElementById('toasts') || document.body;
    let host = document.getElementById('toasts');
    if (!host) {
      host = document.createElement('div');
      host.id = 'toasts';
      document.body.appendChild(host);
    }
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `<span class="toast-dot"></span><span>${escapeHtml(message)}</span>`;
    host.appendChild(el);
    requestAnimationFrame(() => el.classList.add('in'));
    setTimeout(() => {
      el.classList.remove('in');
      setTimeout(() => el.remove(), 350);
    }, 3800);
  }

  /* ── Password visibility toggles ── */
  function wirePwToggles() {
    document.querySelectorAll('.pw-toggle').forEach((btn) => {
      btn.addEventListener('click', () => {
        const input = document.getElementById(btn.dataset.target);
        if (!input) return;
        input.type = input.type === 'password' ? 'text' : 'password';
        btn.textContent = input.type === 'password' ? '👁' : '🙈';
      });
    });
  }

  function badgeHtml(role) {
    const map = {
      supreme_admin: 'Supreme Admin', admin_platform: 'Platform Admin',
      admin_content: 'Content Admin', admin_support: 'Support Admin', user: 'User',
    };
    return `<span class="badge badge-${role}">${escapeHtml(map[role] || role)}</span>`;
  }

  function statusPill(status) {
    return `<span class="pill pill-${status}">${escapeHtml(status.replace(/_/g, ' '))}</span>`;
  }

  function countUp(el, target, suffix = '') {
    const start = performance.now();
    const dur = 900;
    function tick(now) {
      const p = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(target * eased) + suffix;
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  return {
    api, refresh, restore, logout,
    auth: {
      complete(accessToken, user) {
        setToken(accessToken);
        setUser(user);
        location.href = '/dashboard';
      },
    },
    token: getToken,
    user: getUser,
    getCookie, escapeHtml, humanDate, humanDateShort,
    toast, wirePwToggles, badgeHtml, statusPill, countUp,
  };
})();

document.addEventListener('DOMContentLoaded', () => Insyrium.wirePwToggles());
