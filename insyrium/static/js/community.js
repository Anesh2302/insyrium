/* Insyrium Community — realtime chat, voice channels and calls.
 * REST for persistence/moderation + Socket.IO for live delivery and
 * WebRTC signaling. Media flows peer-to-peer (server is control plane).
 */
(function () {
  const P = {
    VIEW: 1, READ: 2, SEND: 4, EMBED: 8, ATTACH: 16, CREATE_INVITE: 32,
    MENTION_ALL: 64, MANAGE_MESSAGES: 128, MANAGE_CHANNELS: 256,
    MANAGE_ROLES: 512, MANAGE_SERVER: 1024, KICK: 2048, BAN: 4096,
    MUTE: 8192, MODERATE: 16384, MANAGE_BOTS: 32768, VIEW_AUDIT: 65536,
  };
  const PERM_NAMES = {
    view: 'View channels', read: 'Read messages', send: 'Send messages',
    embed: 'Post links', attach: 'Upload files', create_invite: 'Create invites',
    mention_all: 'Mention everyone', manage_messages: 'Manage messages',
    manage_channels: 'Manage channels', manage_roles: 'Manage roles',
    manage_server: 'Manage server', kick: 'Kick members', ban: 'Ban members',
    mute: 'Mute members', moderate: 'Moderate', manage_bots: 'Manage bots',
    view_audit: 'View audit log',
  };

  const state = {
    user: null, servers: [], server: null, channel: null,
    dmThread: null, dmList: [], lastId: 0, members: [], voice: {},
    pollTimer: null,
    // ── realtime ──
    socket: null, connected: false, online: new Set(),
    typingTimers: {},
    // voice channel state
    voiceChannel: null, voiceStream: null, voicePeers: new Map(),
    voiceMuted: false, voiceDeafened: false,
    // direct call state
    call: null,
  };

  const ICE = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
  ];

  const $ = (id) => document.getElementById(id);
  const esc = (v) => Insyrium.escapeHtml(v);
  const hasPerm = (bit) => state.server && (state.server.my_permissions & bit);
  const myId = () => state.user && state.user.id;

  async function api(path, opts) {
    const r = await Insyrium.api(path, opts);
    if (r.status === 403) {
      // Re-pull server info so the UI reflects permission changes.
      if (state.server && !path.startsWith('/api/community/servers/')) {
        await selectServer(state.server.id, { silent: true });
      }
    }
    return r;
  }

  // ── Boot ──────────────────────────────────────────────────────────────
  async function init() {
    if (!(await Insyrium.restore())) { location.href = '/login'; return; }
    state.user = Insyrium.user();

    const qs = new URLSearchParams(location.search);
    const invite = qs.get('invite');
    if (invite) {
      const r = await api(`/api/community/invite/${encodeURIComponent(invite)}`, { method: 'POST' });
      Insyrium.toast(r.ok ? 'Joined the server' : (r.data.error || 'Invalid invite'), r.ok ? 'success' : 'error');
      history.replaceState({}, '', '/community');
    }

    wire();
    connectSocket();
    await loadServers();
    if (state.servers.length && !state.server) {
      await selectServer(state.servers[0].id);
    }
    await Promise.all([loadDms(), updateNotifBadge()]);
    startPolling();
  }

  function wire() {
    $('logout-btn').addEventListener('click', () => Insyrium.logout());
    $('new-server-btn').addEventListener('click', showCreateServer);
    $('nav-dms').addEventListener('click', (e) => { e.preventDefault(); $('chat-head').textContent = 'Select a conversation'; state.server = null; state.channel = null; state.dmThread = null; $('channels-col').style.display = 'none'; $('members-col').style.display = 'none'; leaveRooms(); });
    $('add-channel-btn').addEventListener('click', showCreateChannel);
    $('invite-copy').addEventListener('click', copyInvite);
    $('roles-btn').addEventListener('click', showRoles);
    $('reports-btn').addEventListener('click', showReports);
    $('message-form').onsubmit = handleSend;
    $('notif-btn').addEventListener('click', toggleNotifications);
    $('message-input').addEventListener('input', onTypingInput);
    $('voice-mute-btn').addEventListener('click', toggleVoiceMute);
    $('voice-deafen-btn').addEventListener('click', toggleVoiceDeafen);
    $('voice-leave-btn').addEventListener('click', () => leaveVoice(true));
    $('modal-overlay').addEventListener('click', (e) => {
      if (e.target === $('modal-overlay') || e.target.closest('[data-close]')) $('modal-overlay').hidden = true;
    });
  }

  // ── Realtime socket ───────────────────────────────────────────────────
  function connectSocket() {
    if (state.socket) state.socket.disconnect();
    const socket = io({
      auth: { token: Insyrium.token() },
      reconnection: true,
      reconnectionDelay: 1000,
    });
    state.socket = socket;

    socket.on('connect', () => {
      state.connected = true;
      joinRooms();
    });
    socket.on('disconnect', () => { state.connected = false; });
    socket.on('connect_error', async () => {
      // Access token may have expired — rotate and reconnect with the new one.
      const ok = await Insyrium.refresh();
      if (ok) {
        socket.auth = { token: Insyrium.token() };
        socket.connect();
      } else {
        Insyrium.toast('Realtime connection lost', 'error');
      }
    });

    socket.on('presence:init', (d) => { state.online = new Set(d.online || []); renderMembers(); });
    socket.on('presence:set', (d) => {
      if (d.online) state.online.add(d.user_id); else state.online.delete(d.user_id);
      renderMembers();
    });

    socket.on('chat:new', (m) => {
      if (state.channel && m.channel_id === state.channel.id) {
        appendMessage(m);
      } else if (state.channel && m.channel_id !== state.channel.id) {
        flashChannel(m.channel_id);
      }
    });
    socket.on('chat:delete', (d) => {
      if (state.channel && d.channel_id === state.channel.id) {
        document.querySelector(`.msg[data-id="${d.message_id}"]`)?.remove();
      }
    });
    socket.on('dm:new', (d) => {
      if (state.dmThread && d.thread_id === state.dmThread.id) {
        appendDmMessage(d.message);
      } else {
        flashDm(d.thread_id);
      }
    });
    socket.on('notif:new', () => updateNotifBadge());
    socket.on('typing:set', onTypingSet);
    socket.on('voice:update', onVoiceUpdate);
    socket.on('voice:state', onVoiceState);
    socket.on('signal', onSignal);
  }

  function joinedChannel() { return state.channel ? state.channel.id : null; }
  function joinedDm() { return state.dmThread ? state.dmThread.id : null; }

  function joinRooms() {
    if (!state.connected) return;
    const cid = joinedChannel(); if (cid) state.socket.emit('channel:join', { channel_id: cid });
    const tid = joinedDm(); if (tid) state.socket.emit('dm:join', { thread_id: tid });
  }

  function leaveRooms() {
    if (!state.connected) return;
    const cid = joinedChannel(); if (cid) state.socket.emit('channel:leave', { channel_id: cid });
    const tid = joinedDm(); if (tid) state.socket.emit('dm:leave', { thread_id: tid });
  }

  // ── Servers ───────────────────────────────────────────────────────────
  async function loadServers() {
    const r = await api('/api/community/servers');
    state.servers = r.data.servers || [];
    renderServerButtons();
  }

  function renderServerButtons() {
    const list = $('server-list');
    list.innerHTML = '';
    state.servers.forEach((s) => {
      const b = document.createElement('button');
      b.className = 'server-btn' + (state.server && state.server.id === s.id ? ' active' : '');
      b.innerHTML = `${esc(s.name)} <span class="server-count">${s.members}</span>${s.is_verified ? ' <span title="Verified server">✔</span>' : ''}`;
      b.addEventListener('click', () => selectServer(s.id));
      list.appendChild(b);
    });
  }

  async function selectServer(id, opts = {}) {
    leaveRooms();
    const r = await api(`/api/community/servers/${id}`);
    if (!r.ok) { Insyrium.toast(r.data.error || 'Could not open server', 'error'); return; }
    state.server = r.data.server;
    state.server.channels = r.data.channels || [];
    state.server.roles = r.data.roles || [];
    state.server.my_permissions = r.data.my_permissions;
    state.members = r.data.members || [];
    state.dmThread = null;
    state.channel = null;
    state.lastId = 0;
    renderServerButtons();
    $('server-title').textContent = state.server.name + (state.server.is_verified ? ' ✔' : '');
    $('channels-col').style.display = '';
    $('members-col').style.display = '';
    renderChannels();
    renderMembers();
    renderVoicePresence();
    const showAdmin = hasPerm(P.MANAGE_CHANNELS) || hasPerm(P.MANAGE_ROLES) || hasPerm(P.MODERATE);
    $('server-actions').hidden = !showAdmin;
    $('add-channel-btn').hidden = !hasPerm(P.MANAGE_CHANNELS);
    const first = (state.server.channels || []).find((c) => c.kind === 'text');
    if (first) selectChannel(first.id);
    else { $('chat-head').textContent = 'No channels yet'; $('chat-messages').innerHTML = ''; }
  }

  function renderChannels() {
    const text = $('text-channels'); const voice = $('voice-channels');
    text.innerHTML = ''; voice.innerHTML = '';
    (state.server.channels || []).forEach((c) => {
      const b = document.createElement('button');
      b.className = 'ch-item' + (state.channel && state.channel.id === c.id ? ' active' : '');
      b.dataset.cid = c.id;
      b.innerHTML = (c.kind === 'voice' ? '🔊 ' : '# ') + esc(c.name);
      if (c.slow_mode_seconds > 0) b.innerHTML += ` <span class="ch-slow">(${c.slow_mode_seconds}s)</span>`;
      if (c.kind === 'voice') {
        b.addEventListener('click', () => toggleVoice(c));
        voice.appendChild(b);
      } else {
        b.addEventListener('click', () => selectChannel(c.id));
        text.appendChild(b);
      }
    });
  }

  function flashChannel(cid) {
    const btn = [...document.querySelectorAll('#text-channels .ch-item')]
      .find((b) => b.dataset.cid === String(cid));
    if (btn) {
      btn.classList.add('unread');
      setTimeout(() => btn.classList.remove('unread'), 2500);
    }
  }

  function flashDm(tid) {
    const btn = [...document.querySelectorAll('.dm-btn')]
      .find((b) => b.dataset.tid === String(tid));
    if (btn) btn.classList.add('unread');
    updateNotifBadge();
  }

  // ── Channels / messages ───────────────────────────────────────────────
  async function selectChannel(cid) {
    leaveRooms();
    const r = await api(`/api/community/servers/${state.server.id}`);
    if (!r.ok) return;
    state.server = r.data.server;
    state.server.channels = r.data.channels || [];
    state.server.roles = r.data.roles || [];
    state.server.my_permissions = r.data.my_permissions;
    state.members = r.data.members || [];
    state.channel = (state.server.channels || []).find((c) => c.id === cid) || null;
    state.dmThread = null;
    state.lastId = 0;
    if (!state.channel) return;
    renderChannels();
    renderMembers();
    $('chat-head').textContent = `# ${state.channel.name} — ${state.channel.topic || 'channel'}`;
    joinRooms();
    await loadMessages(true);
  }

  async function loadMessages(reset) {
    if (reset) { $('chat-messages').innerHTML = ''; state.lastId = 0; }
    const cid = state.channel ? state.channel.id : null;
    const tid = state.dmThread ? state.dmThread.id : null;
    if (!cid && !tid) return;
    const url = cid
      ? `/api/community/channels/${cid}/messages?after=${state.lastId}`
      : `/api/community/dms/${tid}/messages?after=${state.lastId}`;
    const r = await api(url);
    const msgs = r.data.messages || [];
    if (!msgs.length) return;
    msgs.forEach((m) => appendMessage(m));
    state.lastId = Math.max(state.lastId, ...msgs.map((m) => m.id));
    const box = $('chat-messages');
    if (!reset) box.scrollTop = box.scrollHeight;
  }

  function appendMessage(m) {
    const box = $('chat-messages');
    if (box.querySelector(`[data-id="${m.id}"]`)) return;
    const el = document.createElement('div');
    el.className = 'msg' + (m.kind === 'system' ? ' msg-system' : '') + (m.flagged ? ' msg-flagged' : '');
    el.dataset.id = m.id;
    const mine = m.author_id != null ? m.author_id === myId() : m.sender_id === myId();
    const author = m.author_name || (mine ? 'You' : 'Them');
    const canMod = hasPerm(P.MANAGE_MESSAGES);
    let body = esc(m.body).replace(/\n/g, '<br>');
    if (m.attachment_name) body += `<div class="msg-file">📎 ${esc(m.attachment_name)}</div>`;
    const actions = (m.author_id != null && (mine || canMod))
      ? `<span class="msg-actions"><button data-act="del" title="Delete">✕</button></span>` : '';
    el.innerHTML = `
      <div class="msg-head"><span class="msg-author">${esc(author)}</span>
        <span class="msg-time">${Insyrium.humanDate(m.created_at)}</span>
        ${m.link_status === 'flagged' ? '<span class="pill pill-flagged">links flagged</span>' : ''}${actions}</div>
      <div class="msg-body">${body}</div>`;
    el.querySelector('[data-act="del"]')?.addEventListener('click', () => deleteMessage(m.id));
    box.appendChild(el);
    box.scrollTop = box.scrollHeight;
  }

  async function sendMessage(ev) {
    ev.preventDefault();
    const input = $('message-input');
    const text = input.value.trim();
    if (!text || !state.channel) return;
    const cid = state.channel.id;
    const r = await api(`/api/community/channels/${cid}/messages`, { method: 'POST', body: { body: text } });
    if (r.ok) {
      appendMessage(r.data.message);
      state.lastId = Math.max(state.lastId, r.data.message.id);
      input.value = '';
      socketTypingStop();
    } else {
      Insyrium.toast(r.data.error || r.data.message?.error || 'Could not send', 'error');
      if (r.data.blocked) input.value = '';
    }
  }

  function handleSend(ev) {
    if (state.dmThread) return sendDm(ev);
    return sendMessage(ev);
  }

  async function sendDm(ev) {
    ev.preventDefault();
    const input = $('message-input');
    const text = input.value.trim();
    if (!text || !state.dmThread) return;
    const rr = await api(`/api/community/dms/${state.dmThread.id}/messages`, { method: 'POST', body: { body: text } });
    if (rr.ok) {
      appendDmMessage(rr.data.message);
      input.value = '';
      socketTypingStop();
    } else Insyrium.toast(rr.data.error || 'Blocked by security filter', 'error');
  }

  function appendDmMessage(m) {
    const box = $('chat-messages');
    if (box.querySelector(`[data-id="${m.id}"]`)) return;
    const el = document.createElement('div');
    el.className = 'msg' + (m.sender_id === myId() ? ' mine' : '');
    el.dataset.id = m.id;
    el.innerHTML = `<div class="msg-head"><span class="msg-author">${m.sender_id === myId() ? 'You' : 'Them'}</span>
      <span class="msg-time">${Insyrium.humanDate(m.created_at)}</span></div>
      <div class="msg-body">${esc(m.body).replace(/\n/g, '<br>')}</div>`;
    box.appendChild(el);
    box.scrollTop = box.scrollHeight;
  }

  async function deleteMessage(mid) {
    const r = await api(`/api/community/messages/${mid}`, { method: 'DELETE' });
    if (r.ok) document.querySelector(`.msg[data-id="${mid}"]`)?.remove();
    else Insyrium.toast(r.data.error || 'Could not delete', 'error');
  }

  // ── Typing indicators ─────────────────────────────────────────────────
  function socketTypingStop() {
    const cid = joinedChannel();
    if (state.connected && cid) state.socket.emit('typing:stop', { channel_id: cid });
  }

  let typingThrottle = 0;
  function onTypingInput() {
    const cid = joinedChannel();
    if (!state.connected || !cid) return;
    const now = Date.now();
    if (now - typingThrottle > 1500) {
      typingThrottle = now;
      state.socket.emit('typing', { channel_id: cid });
    }
  }

  function onTypingSet(d) {
    if (d.user_id === myId()) return;
    if (state.channel && d.channel_id !== state.channel.id) return;
    const host = $('chat-typing');
    host.hidden = false;
    host.textContent = `${esc(d.name)} is typing…`;
    clearTimeout(state.typingTimers[d.channel_id]);
    state.typingTimers[d.channel_id] = setTimeout(() => { host.hidden = true; }, 2500);
  }

  // ── Members / moderation ──────────────────────────────────────────────
  function renderMembers() {
    const host = $('member-list');
    const title = $('members-title');
    title.textContent = `Members — ${state.members.length}`;
    host.innerHTML = '';
    state.members.forEach((m) => {
      const row = document.createElement('div');
      row.className = 'm-row';
      const online = state.online.has(m.user_id);
      const role = (state.server.roles || []).find((r) => r.id === m.role_id);
      const c = role ? `style="color:${role.color}"` : '';
      const callBtn = online ? `<button class="com-mini-btn m-call" title="Call ${esc(m.nickname || m.username || '')}">📞</button>` : '';
      row.innerHTML = `<span class="m-dot ${online ? 'on' : ''}"></span><span class="m-name" ${c}>${esc(m.nickname || m.username || m.email)}</span>${callBtn}`;
      row.addEventListener('click', (e) => {
        if (e.target.closest('.m-call')) return startCall(m, 'audio');
        memberMenu(m);
      });
      host.appendChild(row);
    });
  }

  function memberMenu(member) {
    const title = member.nickname || member.username || member.email;
    let html = `<p class="muted">${esc(member.email || '')}</p>`;
    if (hasPerm(P.MANAGE_ROLES)) {
      html += `<label class="muted">Role</label><select id="role-select">`;
      (state.server.roles || []).forEach((r) => {
        html += `<option value="${r.id}" ${r.id === member.role_id ? 'selected' : ''}>${esc(r.name)}</option>`;
      });
      html += `</select><button class="btn small block" id="save-role">Apply role</button>`;
    }
    if (hasPerm(P.MUTE)) html += `<button class="btn small block" data-mute>Mute 10 min</button>`;
    if (hasPerm(P.KICK)) html += `<button class="btn small block warn" data-kick>Kick</button>`;
    if (hasPerm(P.BAN)) html += `<button class="btn small block danger" data-ban>Ban</button>`;
    html += `<button class="btn small block" data-dm>Message</button>`;
    html += `<button class="btn small block" data-call-audio>📞 Voice call</button>`;
    html += `<button class="btn small block" data-call-video>📹 Video call</button>`;
    openModal('Member — ' + esc(title), html);
    $('save-role')?.addEventListener('click', async () => {
      const r = await api(`/api/community/servers/${state.server.id}/members/${member.user_id}/role`, {
        method: 'POST', body: { role_id: parseInt($('role-select').value, 10) },
      });
      Insyrium.toast(r.ok ? 'Role updated' : r.data.error, r.ok ? 'success' : 'error');
      if (r.ok) selectServer(state.server.id);
    });
    const act = (sel, path) => document.querySelector(sel)?.addEventListener('click', async () => {
      const r = await api(`/api/community/servers/${state.server.id}/members/${member.user_id}/${path}`, { method: 'POST', body: {} });
      Insyrium.toast(r.ok ? 'Done' : (r.data.error || 'Action failed'), r.ok ? 'success' : 'error');
      if (r.ok) { $('modal-overlay').hidden = true; selectServer(state.server.id); }
    });
    act('[data-mute]', 'mute');
    act('[data-kick]', 'kick');
    act('[data-ban]', 'ban');
    document.querySelector('[data-dm]')?.addEventListener('click', async () => {
      const r = await api('/api/community/dms', { method: 'POST', body: { user_id: member.user_id } });
      if (r.ok) { $('modal-overlay').hidden = true; openDm(r.data.thread_id); }
    });
    document.querySelector('[data-call-audio]')?.addEventListener('click', () => { $('modal-overlay').hidden = true; startCall(member, 'audio'); });
    document.querySelector('[data-call-video]')?.addEventListener('click', () => { $('modal-overlay').hidden = true; startCall(member, 'video'); });
  }

  // ── DMs ───────────────────────────────────────────────────────────────
  async function loadDms() {
    const r = await api('/api/community/dms');
    state.dmList = r.data.threads || [];
    const list = $('dm-list');
    list.innerHTML = '';
    state.dmList.forEach((t) => {
      const b = document.createElement('button');
      b.className = 'dm-btn' + (state.dmThread && state.dmThread.id === t.id ? ' active' : '');
      b.dataset.tid = t.id;
      b.textContent = '💬 ' + (t.username || t.email);
      b.addEventListener('click', () => openDm(t.id));
      list.appendChild(b);
    });
  }

  async function openDm(tid) {
    leaveRooms();
    const r = await api(`/api/community/dms/${tid}/messages`);
    if (!r.ok) { Insyrium.toast(r.data.error || 'Could not open', 'error'); return; }
    state.dmThread = { id: tid };
    state.channel = null;
    state.lastId = 0;
    $('chat-head').textContent = 'Private messages — encrypted at rest';
    $('channels-col').style.display = 'none';
    $('members-col').style.display = 'none';
    document.querySelectorAll('.dm-btn').forEach((b) => b.classList.remove('active'));
    const msgs = r.data.messages || [];
    $('chat-messages').innerHTML = '';
    msgs.forEach((m) => appendDmMessage(m));
    state.lastId = msgs.length ? Math.max(...msgs.map((m) => m.id)) : 0;
    $('chat-messages').scrollTop = $('chat-messages').scrollHeight;
    joinRooms();
  }

  // ── Notifications ─────────────────────────────────────────────────────
  async function updateNotifBadge() {
    const r = await api('/api/community/poll');
    state.voice = r.data.voice || {};
    renderVoicePresence();
    const n = r.data.unread_notifications || 0;
    const badge = $('notif-badge');
    badge.hidden = n === 0;
    badge.textContent = n > 99 ? '99+' : n;
    return n;
  }

  async function toggleNotifications() {
    const panel = $('notif-panel');
    const r = await api('/api/community/notifications?unread=1');
    const items = r.data.notifications || [];
    panel.hidden = !panel.hidden;
    if (panel.hidden) return;
    panel.innerHTML = items.length
      ? items.map((n) => `<a class="notif" href="${esc(n.link || '#')}" data-id="${n.id}"><b>${esc(n.title)}</b><span>${esc(n.body)}</span></a>`).join('')
      : '<div class="notif empty">No new notifications</div>';
    panel.querySelectorAll('.notif').forEach((a) => a.addEventListener('click', () => { panel.hidden = true; }));
    await api('/api/community/notifications/read', { method: 'POST' });
    updateNotifBadge();
  }

  // ── Voice presence (live) ─────────────────────────────────────────────
  function renderVoicePresence() {
    const host = $('voice-presence');
    host.innerHTML = '';
    if (!state.server) return;
    const vc = (state.server.channels || []).filter((c) => c.kind === 'voice');
    vc.forEach((c) => {
      const users = state.voice[c.id] || [];
      const div = document.createElement('div');
      div.className = 'voice-row';
      const joined = state.voiceChannel === c.id;
      div.innerHTML = `<span class="voice-name">🔊 ${esc(c.name)}</span>
        <span class="voice-count">${users.length ? `${users.length} connected` : 'idle'}</span>
        <button class="com-mini-btn ${joined ? 'active' : ''}">${joined ? 'Leave' : 'Join'}</button>`;
      div.querySelector('button').addEventListener('click', () => toggleVoice(c));
      host.appendChild(div);
    });
  }

  function onVoiceUpdate(d) {
    if (d.server_id !== (state.server && state.server.id)) return;
    const next = {};
    Object.entries(d.channels || {}).forEach(([cid, users]) => { next[cid] = users; });
    state.voice = next;
    renderVoicePresence();
    // Connect/disconnect WebRTC peers to match the new roster.
    syncVoicePeers();
  }

  function onVoiceState(d) {
    if (state.voiceChannel !== d.channel_id) return;
    const users = state.voice[d.channel_id] || [];
    const u = users.find((x) => x.user_id === d.user_id);
    if (u) { u.muted = d.muted; u.deafened = d.deafened; }
    renderVoiceBar();
  }

  // ── Voice channels (WebRTC) ───────────────────────────────────────────
  async function toggleVoice(channel) {
    if (state.voiceChannel === channel.id) return leaveVoice(true);
    await leaveVoice(false);
    await joinVoice(channel);
  }

  async function joinVoice(channel) {
    try {
      state.voiceStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch (err) {
      Insyrium.toast('Microphone unavailable: ' + (err.message || err), 'error');
      return;
    }
    const r = await api(`/api/community/channels/${channel.id}/voice`, { method: 'POST' });
    if (!r.ok) {
      state.voiceStream.getTracks().forEach((t) => t.stop());
      state.voiceStream = null;
      Insyrium.toast(r.data.error || 'Could not join voice channel', 'error');
      return;
    }
    state.voiceChannel = channel.id;
    state.voiceMuted = false;
    state.voiceDeafened = false;
    if (state.connected) state.socket.emit('voice:join', { channel_id: channel.id });
    renderVoiceBar();
    renderVoicePresence();
    renderChannels();
    // Pull the current roster so we can initiate peer connections.
    await refreshVoiceRoster();
    syncVoicePeers();
  }

  async function refreshVoiceRoster() {
    if (!state.voiceChannel || !state.server) return;
    const r = await api(`/api/community/servers/${state.server.id}`);
    // voice presence comes via live voice:update; also poll for safety.
    await updateNotifBadge();
  }

  function syncVoicePeers() {
    if (!state.voiceChannel || !state.voiceStream) return;
    const roster = new Set((state.voice[state.voiceChannel] || []).map((u) => u.user_id));
    // Close peers for members who left.
    state.voicePeers.forEach((pc, uid) => {
      if (uid !== myId() && !roster.has(uid)) {
        pc.close();
        state.voicePeers.delete(uid);
        document.querySelector(`[data-vpeer="${uid}"]`)?.remove();
      }
    });
    // Ensure a peer exists for every other member (offer created via negotiationneeded).
    roster.forEach((uid) => { if (uid !== myId()) ensureVoicePeer(uid); });
    renderVoiceBar();
  }

  function ensureVoicePeer(uid) {
    if (state.voicePeers.has(uid)) return state.voicePeers.get(uid);
    const pc = makePeer(uid, true);
    state.voicePeers.set(uid, pc);
    attachLocalTracks(pc);
    return pc;
  }

  function makePeer(uid, polite) {
    const pc = new RTCPeerConnection({ iceServers: ICE });
    pc.polite = polite;
    pc.makingOffer = false;
    pc.ignoreOffer = false;
    pc.peerUid = uid;

    pc.onnegotiationneeded = async () => {
      try {
        pc.makingOffer = true;
        await pc.setLocalDescription();
        sendSignal(uid, { kind: 'offer', sdp: pc.localDescription, call: { channel_id: state.voiceChannel } });
      } catch (err) {
        console.error('offer failed', err);
      } finally {
        pc.makingOffer = false;
      }
    };

    pc.onicecandidate = (e) => {
      if (e.candidate) sendSignal(uid, { kind: 'candidate', candidate: e.candidate, call: { channel_id: state.voiceChannel } });
    };

    pc.ontrack = (e) => {
      const el = document.createElement('audio');
      el.autoplay = true;
      el.dataset.vpeer = uid;
      el.srcObject = e.streams[0];
      document.getElementById('voice-bar-members')?.appendChild(el);
    };

    pc.onconnectionstatechange = () => {
      if (['disconnected', 'failed', 'closed'].includes(pc.connectionState)) {
        pc.close();
        state.voicePeers.delete(uid);
      }
    };
    return pc;
  }

  function attachLocalTracks(pc) {
    (state.voiceStream ? state.voiceStream.getTracks() : []).forEach((t) => pc.addTrack(t, state.voiceStream));
  }

  async function handleSignal(d) {
    // Direct calls
    if (d.call && d.call.direct) return handleCallSignal(d);
    // Voice channel signaling
    if (!d.call || !d.call.channel_id) return;
    if (d.call.channel_id !== state.voiceChannel) return;
    if (state.voicePeers.has(d.from)) {
      const pc = state.voicePeers.get(d.from);
      await negotiate(pc, d);
    } else if (d.kind === 'offer') {
      const pc = makePeer(d.from, d.from < myId());  // lower id is polite
      state.voicePeers.set(d.from, pc);
      attachLocalTracks(pc);
      await negotiate(pc, d);
    }
  }

  async function negotiate(pc, d) {
    try {
      if (d.kind === 'offer') {
        const offerCollision = pc.makingOffer || pc.signalingState !== 'stable';
        pc.ignoreOffer = !pc.polite && offerCollision;
        if (pc.ignoreOffer) return;
        await pc.setRemoteDescription(d.sdp);
        await pc.setLocalDescription();
        sendSignal(pc.peerUid, { kind: 'answer', sdp: pc.localDescription, call: { channel_id: state.voiceChannel } });
      } else if (d.kind === 'answer') {
        await pc.setRemoteDescription(d.sdp);
      } else if (d.kind === 'candidate') {
        try { await pc.addIceCandidate(d.candidate); } catch (_) {}
      }
    } catch (err) {
      console.error('negotiation failed', err);
    }
  }

  async function leaveVoice(notifyServer) {
    if (state.connected && notifyServer && state.voiceChannel) {
      state.socket.emit('voice:state', { channel_id: state.voiceChannel, muted: true, deafened: false });
    }
    state.voicePeers.forEach((pc) => pc.close());
    state.voicePeers.clear();
    if (state.voiceStream) {
      state.voiceStream.getTracks().forEach((t) => t.stop());
      state.voiceStream = null;
    }
    if (state.voiceChannel) {
      await api(`/api/community/channels/${state.voiceChannel}/voice`, { method: 'DELETE' }).catch(() => {});
    }
    state.voiceChannel = null;
    document.querySelectorAll('[data-vpeer]').forEach((el) => el.remove());
    $('voice-bar').hidden = true;
    $('voice-self').hidden = true;
    renderVoicePresence();
    renderChannels();
  }

  function renderVoiceBar() {
    const bar = $('voice-bar');
    if (!state.voiceChannel) { bar.hidden = true; return; }
    bar.hidden = false;
    const ch = (state.server.channels || []).find((c) => c.id === state.voiceChannel);
    $('voice-bar-channel').textContent = ch ? ch.name : '';
    $('voice-mute-btn').textContent = state.voiceMuted ? '🔇' : '🎙';
    $('voice-mute-btn').title = state.voiceMuted ? 'Unmute' : 'Mute';
    $('voice-deafen-btn').textContent = state.voiceDeafened ? '🙈' : '🔇';
    $('voice-bar-members').innerHTML = '';
    const users = state.voice[state.voiceChannel] || [];
    $('voice-bar-members').innerHTML = users
      .filter((u) => u.user_id !== myId())
      .map((u) => `<span class="vpeer-name">${esc(u.name)}${u.muted ? ' 🔇' : ''}</span>`)
      .join(' ');
    const selfHost = $('voice-self');
    selfHost.hidden = false;
    selfHost.innerHTML = `<div class="m-head">Voice connected</div>
      <div class="voice-row"><span class="m-dot on"></span><span>${esc(state.user.name)} ${state.voiceMuted ? '🔇' : ''}</span></div>`;
  }

  function toggleVoiceMute() {
    state.voiceMuted = !state.voiceMuted;
    state.voiceStream?.getAudioTracks().forEach((t) => { t.enabled = !state.voiceMuted; });
    if (state.connected && state.voiceChannel) {
      state.socket.emit('voice:state', { channel_id: state.voiceChannel, muted: state.voiceMuted, deafened: state.voiceDeafened });
    }
    renderVoiceBar();
  }

  function toggleVoiceDeafen() {
    state.voiceDeafened = !state.voiceDeafened;
    if (state.voiceDeafened) {
      state.voiceStream?.getAudioTracks().forEach((t) => { t.enabled = false; });
    } else {
      state.voiceStream?.getAudioTracks().forEach((t) => { t.enabled = !state.voiceMuted; });
    }
    if (state.connected && state.voiceChannel) {
      state.socket.emit('voice:state', { channel_id: state.voiceChannel, muted: state.voiceMuted || state.voiceDeafened, deafened: state.voiceDeafened });
    }
    renderVoiceBar();
  }

  // ── Direct calls (WebRTC) ─────────────────────────────────────────────
  function sendSignal(to, payload) {
    if (state.connected) state.socket.emit('signal', Object.assign({ to }, payload));
  }

  // Ringtone generated with WebAudio (two-tone pattern) so no audio asset is needed.
  let ringCtx = null, ringOscs = [], ringTimer = null;
  function playRingtone() {
    try {
      if (ringCtx) return;
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return;
      ringCtx = new AC();
      const gain = ringCtx.createGain();
      gain.gain.value = 0.12;
      gain.connect(ringCtx.destination);
      const chime = () => {
        if (!ringCtx) return;
        const now = ringCtx.currentTime;
        [440, 554].forEach((f, i) => {
          const o = ringCtx.createOscillator();
          o.type = 'sine';
          o.frequency.value = f;
          o.connect(gain);
          o.start(now + i * 0.5);
          o.stop(now + 0.9);
          ringOscs.push(o);
        });
      };
      chime();
      ringTimer = setInterval(chime, 1200);
    } catch (_) {}
  }
  function stopRingtone() {
    ringOscs.forEach((o) => { try { o.stop(); } catch (_) {} });
    ringOscs = [];
    clearInterval(ringTimer);
    ringTimer = null;
    if (ringCtx) { ringCtx.close().catch(() => {}); ringCtx = null; }
  }

  async function startCall(member, mode) {
    if (state.call) { Insyrium.toast('You are already in a call', 'error'); return; }
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: mode === 'video' });
    } catch (err) {
      Insyrium.toast('Media unavailable: ' + (err.message || err), 'error');
      return;
    }
    const call = {
      id: `call-${myId()}-${member.user_id}-${Date.now()}`,
      peerId: member.user_id,
      mode,
      stream,
      pc: null,
      incoming: false,
    };
    state.call = call;
    renderCallUI(call);
    sendSignal(call.peerId, { kind: 'ring', mode, callId: call.id, call: { direct: true } });
    Insyrium.toast(`Calling ${member.nickname || member.username || member.email}…`, 'info');
  }

  async function handleCallSignal(d) {
    const call = state.call;
    if (d.kind === 'ring') {
      if (call) { sendSignal(d.from, { kind: 'decline', callId: d.callId, call: { direct: true } }); return; }
      const incoming = {
        id: d.callId,
        peerId: d.from,
        mode: d.mode || 'audio',
        incoming: true,
        pc: null,
        stream: null,
      };
      state.call = incoming;
      renderIncomingCall(d);
      return;
    }
    if (!call) return;
    if (d.callId && d.callId !== call.id) return;

    if (d.kind === 'ring') {
      // already handled above
    } else if (d.kind === 'accept') {
      if (call.incoming) return;
      // Callee accepted: establish the connection (we are the offerer).
      call.pc = makeCallPeer(call.peerId);
      attachLocalTracks(call.pc);
      call.pc.onnegotiationneeded();
      renderCallUI(call);
    } else if (d.kind === 'decline') {
      Insyrium.toast(`${esc(d.from_name || 'They')} declined the call`, 'error');
      endCall(false, false);
    } else if (d.kind === 'hangup') {
      Insyrium.toast('Call ended', 'info');
      endCall(false, false);
    } else if (d.kind === 'offer') {
      if (call.incoming) {
        // We accepted; callee now answers this offer.
        call.pc = makeCallPeer(call.peerId);
        attachLocalTracks(call.pc);
      }
      if (call.pc) await negotiateCall(call.pc, d);
    } else if (d.kind === 'answer') {
      if (call.pc) await negotiateCall(call.pc, d);
    } else if (d.kind === 'candidate') {
      if (call.pc) { try { await call.pc.addIceCandidate(d.candidate); } catch (_) {} }
    }
  }

  function makeCallPeer(uid) {
    const pc = new RTCPeerConnection({ iceServers: ICE });
    pc.polite = false;
    pc.makingOffer = false;
    pc.peerUid = uid;
    pc.onicecandidate = (e) => {
      if (e.candidate) sendSignal(uid, { kind: 'candidate', candidate: e.candidate, callId: state.call.id, call: { direct: true } });
    };
    pc.ontrack = (e) => {
      const card = $('call-card');
      const video = card.querySelector('#call-remote-video');
      if (video) { video.srcObject = e.streams[0]; video.hidden = false; }
      const audio = card.querySelector('#call-remote-audio');
      if (audio) audio.srcObject = e.streams[0];
    };
    pc.onconnectionstatechange = () => {
      if (['failed', 'disconnected', 'closed'].includes(pc.connectionState)) {
        endCall(false, false);
      }
    };
    return pc;
  }

  async function negotiateCall(pc, d) {
    try {
      if (d.kind === 'offer') {
        await pc.setRemoteDescription(d.sdp);
        await pc.setLocalDescription();
        sendSignal(pc.peerUid, { kind: 'answer', sdp: pc.localDescription, callId: state.call.id, call: { direct: true } });
      } else if (d.kind === 'answer') {
        await pc.setRemoteDescription(d.sdp);
      }
    } catch (err) { console.error('call negotiation failed', err); }
  }

  function acceptCall() {
    const call = state.call;
    if (!call || !call.incoming) return;
    call.incoming = false;
    sendSignal(call.peerId, { kind: 'accept', callId: call.id, call: { direct: true } });
    renderCallUI(call);
  }

  function declineCall() {
    const call = state.call;
    if (!call) return;
    if (call.incoming) sendSignal(call.peerId, { kind: 'decline', callId: call.id, call: { direct: true } });
    endCall(false, false);
  }

  function endCall(sendHangup, withToast) {
    const call = state.call;
    if (!call) return;
    if (sendHangup && state.connected) {
      sendSignal(call.peerId, { kind: 'hangup', callId: call.id, call: { direct: true } });
    }
    if (call.pc) call.pc.close();
    if (call.stream) call.stream.getTracks().forEach((t) => t.stop());
    state.call = null;
    stopRingtone();
    $('call-overlay').hidden = true;
    $('call-card').innerHTML = '';
  }

  function renderIncomingCall(d) {
    const card = $('call-card');
    card.innerHTML = `
      <div class="call-remote-info">
        <div class="call-avatar">${esc((d.from_name || '?').slice(0, 1).toUpperCase())}</div>
        <div class="call-name">${esc(d.from_name || 'Incoming call')}</div>
        <div class="call-status">Incoming ${d.mode === 'video' ? 'video' : 'voice'} call</div>
      </div>
      <div class="call-controls">
        <button class="call-btn decline" id="call-decline">Decline</button>
        <button class="call-btn accept" id="call-accept">Accept</button>
      </div>
    `;
    $('call-overlay').hidden = false;
    $('call-decline').addEventListener('click', declineCall);
    $('call-accept').addEventListener('click', async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: state.call.mode === 'video' });
        state.call.stream = stream;
      } catch (err) {
        Insyrium.toast('Media unavailable', 'error');
        declineCall();
        return;
      }
      acceptCall();
    });
    playRingtone();
  }

  function renderCallUI(call) {
    const card = $('call-card');
    const isVideo = call.mode === 'video';
    stopRingtone();
    card.innerHTML = `
      <div class="call-remote-video-wrap">
        <video id="call-remote-video" autoplay playsinline ${isVideo ? '' : 'hidden'}></video>
        <audio id="call-remote-audio" autoplay></audio>
        <div class="call-remote-info">
          <div class="call-name">${esc(state.user.name)}</div>
          <div class="call-status">${call.incoming ? 'Incoming call…' : 'Connecting…'}</div>
        </div>
      </div>
      ${isVideo ? `<video id="call-local-video" autoplay playsinline muted class="call-local-video"></video>` : ''}
      <div class="call-controls">
        <button class="call-btn" id="call-mute" title="Mute microphone">🎙</button>
        ${isVideo ? `<button class="call-btn" id="call-cam" title="Toggle camera">📹</button>` : ''}
        <button class="call-btn hangup" id="call-end" title="End call">End</button>
      </div>
    `;
    $('call-overlay').hidden = false;
    if (isVideo) {
      const local = $('call-local-video');
      local.srcObject = call.stream;
      local.muted = true;
    }
    $('call-mute')?.addEventListener('click', () => {
      const on = state.call.stream.getAudioTracks().every((t) => t.enabled);
      state.call.stream.getAudioTracks().forEach((t) => { t.enabled = !on; });
      $('call-mute').textContent = on ? '🔇' : '🎙';
    });
    $('call-cam')?.addEventListener('click', () => {
      const tracks = state.call.stream.getVideoTracks();
      tracks.forEach((t) => { t.enabled = !t.enabled; });
    });
    $('call-end')?.addEventListener('click', () => endCall(true, true));
  }

  // ── Polling fallback ──────────────────────────────────────────────────
  function startPolling() {
    clearInterval(state.pollTimer);
    state.pollTimer = setInterval(async () => {
      // Live messages arrive over the socket; keep a light fallback when it drops.
      if (!state.connected) {
        if (state.channel) await loadMessages(false);
        else if (state.dmThread) await loadMessages(false);
      }
      await updateNotifBadge();
    }, 4000);
  }

  // ── Modals ────────────────────────────────────────────────────────────
  function openModal(title, html) {
    $('modal-title').textContent = title;
    $('modal-body').innerHTML = html;
    $('modal-overlay').hidden = false;
  }

  function showCreateServer() {
    openModal('Create a server',
      `<label class="muted">Server name</label><input id="ns-name" maxlength="80">
       <label class="muted">Description</label><textarea id="ns-desc" rows="3"></textarea>
       <button class="btn primary block" id="ns-go">Create</button>`);
    $('ns-go').addEventListener('click', async () => {
      const r = await api('/api/community/servers', {
        method: 'POST', body: { name: $('ns-name').value, description: $('ns-desc').value },
      });
      if (r.ok) { $('modal-overlay').hidden = true; await loadServers(); selectServer(r.data.server.id); }
      else Insyrium.toast(r.data.error || 'Could not create', 'error');
    });
  }

  function showCreateChannel() {
    openModal('Create a channel',
      `<label class="muted">Name</label><input id="nc-name" placeholder="announcements" maxlength="40">
       <label class="muted">Type</label><select id="nc-kind"><option value="text">Text</option><option value="voice">Voice</option></select>
       <label class="muted">Slow mode (seconds)</label><input id="nc-slow" type="number" min="0" max="3600" value="0">
       <label class="muted">Topic</label><input id="nc-topic" maxlength="300">
       <button class="btn primary block" id="nc-go">Create</button>`);
    $('nc-go').addEventListener('click', async () => {
      const r = await api(`/api/community/servers/${state.server.id}/channels`, {
        method: 'POST',
        body: { name: $('nc-name').value.trim().toLowerCase().replace(/\s+/g, '-'), kind: $('nc-kind').value, slow_mode_seconds: parseInt($('nc-slow').value || '0', 10), topic: $('nc-topic').value },
      });
      if (r.ok) { $('modal-overlay').hidden = true; selectServer(state.server.id); }
      else Insyrium.toast(r.data.error || 'Could not create', 'error');
    });
  }

  function showRoles() {
    const roles = (state.server.roles || []).slice();
    let html = roles.map((r) => `
      <div class="role-card">
        <div class="role-head"><input class="role-name" value="${esc(r.name)}"><input class="role-color" type="color" value="${esc(r.color)}">
        <span class="muted">rank ${r.rank}</span>
        <button class="btn small" data-role-save="${r.id}">Save</button></div>
        <div class="perm-grid">${permCheckboxes(r)}</div>
      </div>`).join('');
    html += `<h3>New role</h3><div class="role-card">
      <div class="role-head"><input id="nr-name" placeholder="Moderator"><input id="nr-color" type="color" value="#99aab5"></div>
      <div class="perm-grid">${permCheckboxes(null)}</div>
      <button class="btn primary block" id="nr-go">Create role</button></div>`;
    openModal('Roles &amp; permissions', html);
    document.querySelectorAll('[data-role-save]').forEach((btn) => btn.addEventListener('click', async () => {
      const rid = parseInt(btn.dataset.roleSave, 10);
      const perms = [...btn.closest('.role-card').querySelectorAll('input[type=checkbox]:checked')].map((c) => c.dataset.perm);
      const name = btn.closest('.role-card').querySelector('.role-name')?.value || '';
      const color = btn.closest('.role-card').querySelector('.role-color')?.value || '#99aab5';
      const r = await api(`/api/community/servers/${state.server.id}/roles/${rid}`, { method: 'PATCH', body: { name, color, permissions: perms } });
      Insyrium.toast(r.ok ? 'Saved' : r.data.error, r.ok ? 'success' : 'error');
      if (r.ok) { $('modal-overlay').hidden = true; selectServer(state.server.id); }
    }));
    $('nr-go').addEventListener('click', async () => {
      const perms = [...document.querySelectorAll('#modal-body input[data-perm][data-role-new]:checked')].map((c) => c.dataset.perm);
      const r = await api(`/api/community/servers/${state.server.id}/roles`, {
        method: 'POST', body: { name: $('nr-name').value, color: $('nr-color').value, permissions: perms },
      });
      Insyrium.toast(r.ok ? 'Role created' : r.data.error, r.ok ? 'success' : 'error');
      if (r.ok) { $('modal-overlay').hidden = true; selectServer(state.server.id); }
    });
  }

  function permCheckboxes(role) {
    const current = role ? (role.permissions || 0) : 0;
    return Object.entries(PERM_NAMES).map(([key, label]) => {
      const bit = P[key.toUpperCase()];
      const checked = current & bit ? 'checked' : '';
      return `<label class="perm"><input type="checkbox" data-perm="${key}" ${checked} ${role ? '' : 'data-role-new'}> ${label}</label>`;
    }).join('');
  }

  function showReports() {
    openModal('Reports queue', '<p class="muted">Loading…</p>');
    api(`/api/community/servers/${state.server.id}/reports`).then((r) => {
      const reports = r.data.reports || [];
      $('modal-body').innerHTML = reports.length
        ? reports.map((rep) => `<div class="report-card">
            <b>#${rep.id}</b> ${esc(rep.reporter_name)} <span class="pill pill-${rep.status}">${rep.status}</span>
            <p>${esc(rep.reason)}</p>
            <button class="btn small" data-resolve="${rep.id}">Resolve</button>
            <button class="btn small ghost" data-dismiss="${rep.id}">Dismiss</button></div>`).join('')
        : '<p class="muted">No reports.</p>';
      document.querySelectorAll('[data-resolve]').forEach((b) => b.addEventListener('click', async () => {
        await api(`/api/community/reports/${b.dataset.resolve}/resolve`, { method: 'POST' });
        showReports();
      }));
      document.querySelectorAll('[data-dismiss]').forEach((b) => b.addEventListener('click', async () => {
        await api(`/api/community/reports/${b.dataset.dismiss}`, { method: 'DELETE' });
        showReports();
      }));
    });
  }

  async function copyInvite() {
    const url = `${location.origin}/community?invite=${state.server.invite_code}`;
    try {
      await navigator.clipboard.writeText(url);
      Insyrium.toast('Invite link copied', 'success');
    } catch {
      Insyrium.toast(url, 'info');
    }
  }

  // ── Reactions ───────────────────────────────────────────────────────
  async function addReaction(mid, emoji) {
    await api(`/api/community/messages/${mid}/reactions`, { method: 'POST', body: { emoji } });
    const el = document.querySelector(`.msg[data-id="${mid}"]`);
    if (el) loadReactions(mid, el.querySelector('.msg-reactions'));
  }

  async function removeReaction(mid, emoji) {
    await api(`/api/community/messages/${mid}/reactions/${encodeURIComponent(emoji)}`, { method: 'DELETE' });
    const el = document.querySelector(`.msg[data-id="${mid}"]`);
    if (el) loadReactions(mid, el.querySelector('.msg-reactions'));
  }

  async function loadReactions(mid, container) {
    if (!container) return;
    const r = await api(`/api/community/messages/${mid}/reactions`);
    const grouped = r.data.reactions || {};
    container.innerHTML = '';
    Object.entries(grouped).forEach(([emoji, users]) => {
      const mine = users.includes(myId());
      const chip = document.createElement('button');
      chip.className = 'reaction-chip' + (mine ? ' mine' : '');
      chip.textContent = `${emoji} ${users.length}`;
      chip.addEventListener('click', () => mine ? removeReaction(mid, emoji) : addReaction(mid, emoji));
      container.appendChild(chip);
    });
  }

  function showEmojiPicker(msgEl, mid) {
    const picker = $('emoji-picker');
    if (!picker.hidden && picker.dataset.mid === String(mid)) { picker.hidden = true; return; }
    picker.dataset.mid = mid;
    const builtIn = ['👍','❤️','😂','😮','😢','🔥','✅','🎉','👀','💯'];
    const serverEmoji = (state.server && state.server._emojiCache) || [];
    let html = builtIn.map((e) => `<button class="emoji-btn" data-emoji="${e}">${e}</button>`).join('');
    serverEmoji.forEach((e) => { html += `<button class="emoji-btn" data-emoji=":${esc(e.name)}:"><img src="${esc(e.url)}" alt="${esc(e.name)}" width="20" height="20"></button>`; });
    $('emoji-grid').innerHTML = html;
    const rect = msgEl.getBoundingClientRect();
    picker.style.top = Math.min(rect.top, window.innerHeight - 300) + 'px';
    picker.style.left = Math.min(rect.left + 40, window.innerWidth - 250) + 'px';
    picker.hidden = false;
    picker.querySelectorAll('.emoji-btn').forEach((btn) => btn.addEventListener('click', () => {
      addReaction(mid, btn.dataset.emoji);
      picker.hidden = true;
    }));
  }

  // ── Threads ────────────────────────────────────────────────────────
  async function createThread(channelId, name) {
    const r = await api('/api/community/threads', { method: 'POST', body: { name, channel_id: channelId } });
    if (r.ok) { $('thread-create-modal').hidden = true; loadThreads(state.server.id); openThread(r.data.thread.id); }
    else Insyrium.toast(r.data.error || 'Could not create thread', 'error');
  }

  async function openThread(threadId) {
    const r = await api(`/api/community/threads/${threadId}`);
    if (!r.ok) { Insyrium.toast(r.data.error || 'Thread not found', 'error'); return; }
    const thread = r.data.thread;
    const panel = $('thread-panel');
    panel.hidden = false;
    $('thread-panel-title').textContent = thread.name;
    $('thread-parent-msg').innerHTML = '';
    const msgs = await api(`/api/community/threads/${threadId}/messages`);
    const box = $('thread-messages');
    box.innerHTML = '';
    (msgs.data.messages || []).forEach((m) => {
      const el = document.createElement('div');
      el.className = 'msg';
      el.dataset.id = m.id;
      const author = m.author_id === myId() ? 'You' : (m.author_name || 'Them');
      el.innerHTML = `<div class="msg-head"><span class="msg-author">${esc(author)}</span><span class="msg-time">${Insyrium.humanDate(m.created_at)}</span></div><div class="msg-body">${esc(m.body).replace(/\n/g, '<br>')}</div>`;
      box.appendChild(el);
    });
    box.scrollTop = box.scrollHeight;
    state._activeThread = threadId;
  }

  function closeThread() {
    $('thread-panel').hidden = true;
    state._activeThread = null;
  }

  async function loadThreads(serverId) {
    const r = await api(`/api/community/servers/${serverId}/threads`);
    const list = $('thread-list');
    const threads = r.data.threads || [];
    list.innerHTML = '';
    list.hidden = threads.length === 0;
    threads.forEach((t) => {
      const b = document.createElement('button');
      b.className = 'ch-item';
      b.textContent = '🧵 ' + t.name;
      b.addEventListener('click', () => openThread(t.id));
      list.appendChild(b);
    });
  }

  async function sendThreadMessage(threadId, text) {
    const r = await api(`/api/community/threads/${threadId}/messages`, { method: 'POST', body: { body: text } });
    if (r.ok) {
      const box = $('thread-messages');
      const m = r.data.message;
      const el = document.createElement('div');
      el.className = 'msg';
      el.dataset.id = m.id;
      el.innerHTML = `<div class="msg-head"><span class="msg-author">You</span><span class="msg-time">${Insyrium.humanDate(m.created_at)}</span></div><div class="msg-body">${esc(m.body).replace(/\n/g, '<br>')}</div>`;
      box.appendChild(el);
      box.scrollTop = box.scrollHeight;
    }
  }

  // ── Categories ─────────────────────────────────────────────────────
  function loadCategories(serverId, channels) {
    const host = $('channel-categories');
    host.innerHTML = '';
    const grouped = {};
    const uncategorized = [];
    channels.forEach((c) => {
      if (c.category_id) { (grouped[c.category_id] = grouped[c.category_id] || []).push(c); }
      else uncategorized.push(c);
    });
    const categories = (state.server._categories || []).sort((a, b) => (a.position || 0) - (b.position || 0));
    categories.forEach((cat) => {
      const header = document.createElement('div');
      header.className = 'cat-header';
      header.innerHTML = `<span class="cat-toggle" data-cat="${cat.id}">▾</span> ${esc(cat.name)}`;
      header.querySelector('.cat-toggle').addEventListener('click', () => toggleCategory(cat.id));
      host.appendChild(header);
      const wrap = document.createElement('div');
      wrap.className = 'cat-channels';
      wrap.dataset.catId = cat.id;
      (grouped[cat.id] || []).forEach((c) => {
        const b = document.createElement('button');
        b.className = 'ch-item' + (state.channel && state.channel.id === c.id ? ' active' : '');
        b.dataset.cid = c.id;
        b.innerHTML = (c.kind === 'voice' ? '🔊 ' : '# ') + esc(c.name);
        b.addEventListener('click', () => c.kind === 'voice' ? toggleVoice(c) : selectChannel(c.id));
        wrap.appendChild(b);
      });
      host.appendChild(wrap);
    });
    if (uncategorized.length) {
      const label = document.createElement('div');
      label.className = 'cat-header';
      label.textContent = 'Channels';
      host.appendChild(label);
      const wrap = document.createElement('div');
      wrap.className = 'cat-channels';
      uncategorized.forEach((c) => {
        const b = document.createElement('button');
        b.className = 'ch-item' + (state.channel && state.channel.id === c.id ? ' active' : '');
        b.dataset.cid = c.id;
        b.innerHTML = (c.kind === 'voice' ? '🔊 ' : '# ') + esc(c.name);
        b.addEventListener('click', () => c.kind === 'voice' ? toggleVoice(c) : selectChannel(c.id));
        wrap.appendChild(b);
      });
      host.appendChild(wrap);
    }
  }

  async function createCategory(serverId, name) {
    const r = await api(`/api/community/servers/${serverId}/categories`, { method: 'POST', body: { name } });
    if (r.ok) selectServer(serverId);
    else Insyrium.toast(r.data.error || 'Could not create category', 'error');
  }

  function toggleCategory(catId) {
    const wrap = $('channel-categories').querySelector(`.cat-channels[data-cat-id="${catId}"]`);
    if (wrap) wrap.hidden = !wrap.hidden;
    const toggle = $('channel-categories').querySelector(`.cat-toggle[data-cat="${catId}"]`);
    if (toggle) toggle.textContent = wrap && wrap.hidden ? '▸' : '▾';
  }

  async function moveChannelToCategory(channelId, catId) {
    await api(`/api/community/channels/${channelId}/category`, { method: 'PATCH', body: { category_id: catId } });
    if (state.server) selectServer(state.server.id);
  }

  // ── Pins ───────────────────────────────────────────────────────────
  async function pinMessage(mid) {
    if (!state.channel) return;
    const r = await api(`/api/community/channels/${state.channel.id}/pins/${mid}`, { method: 'POST' });
    Insyrium.toast(r.ok ? 'Message pinned' : (r.data.error || 'Could not pin'), r.ok ? 'success' : 'error');
  }

  async function unpinMessage(mid) {
    if (!state.channel) return;
    const r = await api(`/api/community/channels/${state.channel.id}/pins/${mid}`, { method: 'DELETE' });
    Insyrium.toast(r.ok ? 'Unpinned' : (r.data.error || 'Could not unpin'), r.ok ? 'success' : 'error');
  }

  async function loadPins(channelId) {
    const cid = channelId || (state.channel && state.channel.id);
    if (!cid) return;
    const r = await api(`/api/community/channels/${cid}/pins`);
    const pins = r.data.pins || [];
    const list = $('pins-list');
    list.innerHTML = pins.length ? pins.map((p) => `
      <div class="pin-card" data-mid="${p.message.id}">
        <div class="pin-author">${esc(p.message.author_name || 'Unknown')}</div>
        <div class="pin-body">${esc(p.message.body).replace(/\n/g, '<br>')}</div>
        <div class="pin-time">${Insyrium.humanDate(p.message.created_at)}</div>
        ${hasPerm(P.MANAGE_MESSAGES) ? `<button class="btn small ghost" data-unpin="${p.message.id}">Unpin</button>` : ''}
      </div>`).join('') : '<p class="muted">No pinned messages.</p>';
    list.querySelectorAll('[data-unpin]').forEach((b) => b.addEventListener('click', async () => {
      await unpinMessage(parseInt(b.dataset.unpin, 10));
      loadPins(cid);
    }));
    $('pins-modal').hidden = false;
  }

  // ── Custom Emoji ───────────────────────────────────────────────────
  async function loadServerEmoji(serverId) {
    const r = await api(`/api/community/servers/${serverId}/emoji`);
    state.server._emojiCache = r.data.emoji || [];
    return r.data.emoji || [];
  }

  function renderEmojiPicker(serverId) {
    const picker = $('emoji-picker');
    const builtIn = ['👍','❤️','😂','😮','😢','🔥','✅','🎉','👀','💯','🤔','👏','🚀','💀','🥳'];
    let html = builtIn.map((e) => `<button class="emoji-btn" data-emoji="${e}">${e}</button>`).join('');
    const custom = (state.server && state.server._emojiCache) || [];
    custom.forEach((e) => { html += `<button class="emoji-btn" data-emoji=":${esc(e.name)}:"><img src="${esc(e.url)}" alt="${esc(e.name)}" width="20" height="20"> :${esc(e.name)}:</button>`; });
    $('emoji-grid').innerHTML = html;
  }

  // ── Channel Permission Overrides ──────────────────────────────────
  async function loadOverrides(channelId) {
    const r = await api(`/api/community/channels/${channelId}/overrides`);
    return r.data.overrides || [];
  }

  async function setOverride(channelId, data) {
    return api(`/api/community/channels/${channelId}/overrides`, { method: 'POST', body: data });
  }

  async function removeOverride(channelId, oid) {
    return api(`/api/community/channels/${channelId}/overrides/${oid}`, { method: 'DELETE' });
  }

  // ── User Status ────────────────────────────────────────────────────
  async function setUserStatus(status, customStatus) {
    return api('/api/community/status', { method: 'PATCH', body: { status, custom_status: customStatus } });
  }

  async function getUserStatus(userId) {
    const r = await api(`/api/community/users/${userId}/status`);
    return r.data;
  }

  function renderStatusDot(status) {
    const colors = { online: '#43b581', idle: '#faa61a', dnd: '#f04747', invisible: '#747f8d' };
    return `<span class="status-dot" style="background:${colors[status] || colors.online}"></span>`;
  }

  // ── Scheduled Events ──────────────────────────────────────────────
  async function createEvent(serverId, data) {
    const r = await api(`/api/community/servers/${serverId}/events`, { method: 'POST', body: data });
    if (r.ok) { $('event-modal').hidden = true; loadEvents(serverId); }
    else Insyrium.toast(r.data.error || 'Could not create event', 'error');
  }

  async function loadEvents(serverId) {
    const sid = serverId || (state.server && state.server.id);
    if (!sid) return;
    const r = await api(`/api/community/servers/${sid}/events`);
    const events = r.data.events || [];
    const list = $('events-list');
    list.innerHTML = events.length ? events.map((e) => `
      <div class="event-card" data-eid="${e.id}">
        <div class="event-name">${esc(e.name)}</div>
        <div class="event-desc muted">${esc(e.description || '')}</div>
        <div class="event-time">${Insyrium.humanDate(e.start_at)}${e.end_at ? ' — ' + Insyrium.humanDate(e.end_at) : ''}</div>
        <div class="event-actions">
          <button class="btn small" data-rsvp="${e.id}">RSVP</button>
          ${hasPerm(P.MANAGE_SERVER) ? `<button class="btn small ghost" data-cancel-event="${e.id}">Cancel</button>` : ''}
        </div>
      </div>`).join('') : '<p class="muted">No upcoming events.</p>';
    list.querySelectorAll('[data-rsvp]').forEach((b) => b.addEventListener('click', async () => {
      const r = await api(`/api/community/events/${b.dataset.rsvp}/rsvp`, { method: 'POST' });
      Insyrium.toast(r.ok ? 'RSVP confirmed' : (r.data.error || 'Already RSVPed'), r.ok ? 'success' : 'error');
    }));
    list.querySelectorAll('[data-cancel-event]').forEach((b) => b.addEventListener('click', async () => {
      if (!confirm('Cancel this event?')) return;
      await api(`/api/community/events/${b.dataset.cancelEvent}`, { method: 'DELETE' });
      loadEvents(sid);
    }));
    $('events-modal').hidden = false;
  }

  async function rsvpEvent(eventId) {
    const r = await api(`/api/community/events/${eventId}/rsvp`, { method: 'POST' });
    Insyrium.toast(r.ok ? 'RSVP confirmed' : (r.data.error || 'Already RSVPed'), r.ok ? 'success' : 'error');
  }

  async function cancelEvent(eventId) {
    const r = await api(`/api/community/events/${eventId}`, { method: 'DELETE' });
    if (r.ok && state.server) loadEvents(state.server.id);
  }

  // ── Auto-Moderation ────────────────────────────────────────────────
  async function createAutoMod(serverId, data) {
    const r = await api(`/api/community/servers/${serverId}/automod`, { method: 'POST', body: data });
    if (r.ok) loadAutoMod(serverId);
    else Insyrium.toast(r.data.error || 'Could not create rule', 'error');
  }

  async function loadAutoMod(serverId) {
    const sid = serverId || (state.server && state.server.id);
    if (!sid) return;
    const r = await api(`/api/community/servers/${sid}/automod`);
    const rules = r.data.rules || [];
    const list = $('automod-rules');
    list.innerHTML = rules.length ? rules.map((rule) => `
      <div class="automod-card" data-rid="${rule.id}">
        <div class="automod-name">${esc(rule.name)}</div>
        <div class="automod-trigger muted">Trigger: ${esc(rule.trigger_type)} ${rule.trigger_value ? `(${esc(rule.trigger_value)})` : ''}</div>
        <div class="automod-action muted">Action: ${esc(rule.action_type)}${rule.action_duration_minutes ? ` for ${rule.action_duration_minutes} min` : ''}</div>
        <div class="automod-actions">
          <button class="btn small" data-toggle-automod="${rule.id}" data-enabled="${rule.enabled ? '0' : '1'}">${rule.enabled ? 'Disable' : 'Enable'}</button>
          <button class="btn small ghost danger" data-del-automod="${rule.id}">Delete</button>
        </div>
      </div>`).join('') : '<p class="muted">No AutoMod rules configured.</p>';
    list.querySelectorAll('[data-toggle-automod]').forEach((b) => b.addEventListener('click', () => {
      toggleAutoMod(parseInt(b.dataset.toggleAutomod, 10), b.dataset.enabled === '1');
    }));
    list.querySelectorAll('[data-del-automod]').forEach((b) => b.addEventListener('click', async () => {
      if (!confirm('Delete this rule?')) return;
      await deleteAutoMod(parseInt(b.dataset.delAutomod, 10));
      loadAutoMod(sid);
    }));
    $('automod-modal').hidden = false;
  }

  async function deleteAutoMod(ruleId) {
    await api(`/api/community/automod/${ruleId}`, { method: 'DELETE' });
  }

  async function toggleAutoMod(ruleId, enabled) {
    await api(`/api/community/automod/${ruleId}`, { method: 'PATCH', body: { enabled } });
  }

  // ── Webhooks ───────────────────────────────────────────────────────
  async function createWebhook(serverId, name, channelId) {
    const r = await api(`/api/community/servers/${serverId}/webhooks`, { method: 'POST', body: { name, channel_id: channelId } });
    if (r.ok) {
      Insyrium.toast('Webhook created. Token: ' + r.data.webhook.token, 'success', 10000);
      loadWebhooks(serverId);
    } else Insyrium.toast(r.data.error || 'Could not create webhook', 'error');
  }

  async function loadWebhooks(serverId) {
    const sid = serverId || (state.server && state.server.id);
    if (!sid) return;
    const r = await api(`/api/community/servers/${sid}/webhooks`);
    const webhooks = r.data.webhooks || [];
    const list = $('webhook-list');
    list.innerHTML = webhooks.length ? webhooks.map((w) => `
      <div class="webhook-card" data-wid="${w.id}">
        <div class="webhook-name">${esc(w.name)}</div>
        <div class="webhook-ch muted">Channel: #${esc(w.channel_name || w.channel_id)}</div>
        <button class="btn small ghost danger" data-del-webhook="${w.id}">Delete</button>
      </div>`).join('') : '<p class="muted">No webhooks configured.</p>';
    list.querySelectorAll('[data-del-webhook]').forEach((b) => b.addEventListener('click', async () => {
      await deleteWebhook(parseInt(b.dataset.delWebhook, 10));
      loadWebhooks(sid);
    }));
    $('webhook-modal').hidden = false;
  }

  async function deleteWebhook(wid) {
    await api(`/api/community/webhooks/${wid}`, { method: 'DELETE' });
  }

  // ── Stickers ───────────────────────────────────────────────────────
  async function loadStickers(serverId) {
    const sid = serverId || (state.server && state.server.id);
    if (!sid) return;
    const r = await api(`/api/community/servers/${sid}/stickers`);
    const stickers = r.data.stickers || [];
    const grid = $('sticker-grid');
    grid.innerHTML = stickers.length ? stickers.map((s) => `
      <div class="sticker-card" data-stid="${s.id}">
        <img src="${esc(s.url)}" alt="${esc(s.name)}" class="sticker-img">
        <div class="sticker-name">${esc(s.name)}</div>
        <div class="sticker-tags muted">${esc(s.tags || '')}</div>
        <div class="sticker-actions">
          <button class="btn small" data-use-sticker="${esc(s.url)}">Use</button>
          <button class="btn small ghost danger" data-del-sticker="${s.id}">Delete</button>
        </div>
      </div>`).join('') : '<p class="muted">No stickers yet.</p>';
    grid.querySelectorAll('[data-use-sticker]').forEach((b) => b.addEventListener('click', () => insertSticker(b.dataset.useSticker)));
    grid.querySelectorAll('[data-del-sticker]').forEach((b) => b.addEventListener('click', async () => {
      await deleteSticker(parseInt(b.dataset.delSticker, 10));
      loadStickers(sid);
    }));
    $('sticker-modal').hidden = false;
  }

  async function createSticker(serverId, name, url, tags) {
    const r = await api(`/api/community/servers/${serverId}/stickers`, { method: 'POST', body: { name, url, tags } });
    if (r.ok) loadStickers(serverId);
    else Insyrium.toast(r.data.error || 'Could not upload sticker', 'error');
  }

  async function deleteSticker(stid) {
    await api(`/api/community/stickers/${stid}`, { method: 'DELETE' });
  }

  function insertSticker(url) {
    const input = $('message-input');
    input.value += (input.value ? ' ' : '') + url;
    input.focus();
  }

  // ── Server Templates ──────────────────────────────────────────────
  async function createTemplate(serverId, name, desc) {
    const r = await api(`/api/community/servers/${serverId}/templates`, { method: 'POST', body: { name, description: desc } });
    if (r.ok) { Insyrium.toast('Template saved', 'success'); loadTemplates(serverId); }
    else Insyrium.toast(r.data.error || 'Could not create template', 'error');
  }

  async function loadTemplates(serverId) {
    const sid = serverId || (state.server && state.server.id);
    if (!sid) return;
    const r = await api(`/api/community/servers/${sid}/templates`);
    const templates = r.data.templates || [];
    const list = $('template-list');
    list.innerHTML = templates.length ? templates.map((t) => `
      <div class="template-card" data-tid="${t.id}">
        <div class="template-name">${esc(t.name)}</div>
        <div class="template-desc muted">${esc(t.description || '')}</div>
        <div class="template-meta muted">Used ${t.use_count || 0} times</div>
        <button class="btn small" data-use-template="${t.id}">Use Template</button>
      </div>`).join('') : '<p class="muted">No templates saved.</p>';
    list.querySelectorAll('[data-use-template]').forEach((b) => b.addEventListener('click', async () => {
      const r = await useTemplate(parseInt(b.dataset.useTemplate, 10));
      if (r && r.ok) { $('template-modal').hidden = true; await loadServers(); selectServer(r.data.server.id); }
    }));
    $('template-modal').hidden = false;
  }

  async function useTemplate(templateId) {
    return api(`/api/community/templates/${templateId}/use`, { method: 'POST', body: {} });
  }

  // ── Message Search ────────────────────────────────────────────────
  async function searchMessages(serverId, query) {
    const sid = serverId || (state.server && state.server.id);
    if (!sid || !query.trim()) return;
    const r = await api(`/api/community/servers/${sid}/search?q=${encodeURIComponent(query.trim())}`);
    const msgs = r.data.messages || [];
    const panel = $('search-results-panel');
    const list = $('search-results-list');
    list.innerHTML = msgs.length ? msgs.map((m) => `
      <div class="search-result-msg" data-mid="${m.id}" data-channel-id="${m.channel_id}">
        <div class="search-result-head"><b>${esc(m.author_name || 'Unknown')}</b> — ${Insyrium.humanDate(m.created_at)}</div>
        <div class="search-result-body">${esc(m.body).substring(0, 300)}</div>
      </div>`).join('') : '<p class="muted">No results found.</p>';
    list.querySelectorAll('.search-result-msg').forEach((el) => el.addEventListener('click', () => {
      const cid = el.dataset.channelId;
      if (cid) { hideSearch(); selectChannel(parseInt(cid, 10)); }
    }));
    panel.hidden = false;
  }

  function showSearch() { $('chat-search-bar').hidden = false; $('search-input').focus(); }
  function hideSearch() { $('chat-search-bar').hidden = true; $('search-results-panel').hidden = true; }

  // ── Message Forwarding ────────────────────────────────────────────
  async function forwardMessage(msgId, targetChannelId) {
    const r = await api('/api/community/messages/forward', { method: 'POST', body: { message_id: msgId, channel_id: targetChannelId } });
    Insyrium.toast(r.ok ? 'Message forwarded' : (r.data.error || 'Could not forward'), r.ok ? 'success' : 'error');
    if (r.ok) $('forward-modal').hidden = true;
  }

  function showForwardModal(msgId) {
    if (!state.server) return;
    const channels = (state.server.channels || []).filter((c) => c.kind === 'text');
    const sel = $('forward-channel-select');
    sel.innerHTML = channels.map((c) => `<option value="${c.id}">#${esc(c.name)}</option>`).join('');
    $('forward-preview').innerHTML = '<p class="muted">Select a channel to forward this message to.</p>';
    $('forward-modal').hidden = false;
    $('forward-go').onclick = () => forwardMessage(msgId, parseInt(sel.value, 10));
    state._forwardMsgId = msgId;
  }

  // ── Link Previews / Embeds ────────────────────────────────────────
  function renderEmbed(msg) {
    if (!msg.embed_json) return '';
    let embeds;
    try { embeds = JSON.parse(msg.embed_json); } catch (_) { return ''; }
    if (!Array.isArray(embeds) || !embeds.length) return '';
    return embeds.map((e) => {
      if (!e.url) return '';
      return `<div class="msg-embed">
        ${e.title ? `<div class="embed-title">${esc(e.title)}</div>` : ''}
        ${e.description ? `<div class="embed-desc">${esc(e.description).substring(0, 500)}</div>` : ''}
        ${e.image ? `<img class="embed-img" src="${esc(e.image)}" alt="" loading="lazy">` : ''}
        <a class="embed-url" href="${esc(e.url)}" target="_blank" rel="noopener">${esc(e.url)}</a>
      </div>`;
    }).join('');
  }

  // ── User Profile ──────────────────────────────────────────────────
  async function showProfile(userId) {
    const r = await api(`/api/community/users/${userId}/status`);
    const statusData = r.data;
    const member = (state.members || []).find((m) => m.user_id === userId);
    $('profile-name').textContent = member ? (member.nickname || member.username || member.email) : 'User';
    $('profile-status').innerHTML = renderStatusDot(statusData.status) + ' ' + esc(statusData.status) + (statusData.custom_status ? ' — ' + esc(statusData.custom_status) : '');
    $('profile-avatar').innerHTML = (member ? (member.nickname || member.username || '?').charAt(0).toUpperCase() : '?');
    const role = member ? (state.server.roles || []).find((rl) => rl.id === member.role_id) : null;
    $('profile-roles').innerHTML = role ? `<span class="role-pill" style="border-color:${esc(role.color)}">${esc(role.name)}</span>` : '';
    $('profile-member-since').textContent = member && member.joined_at ? 'Joined ' + Insyrium.humanDate(member.joined_at) : '';
    $('profile-popup').hidden = false;
  }

  function closeProfile() { $('profile-popup').hidden = true; }

  // ── Server Discovery ──────────────────────────────────────────────
  async function loadDiscover() {
    const r = await api('/api/community/discover');
    const servers = r.data.servers || [];
    const grid = $('discover-grid');
    grid.innerHTML = servers.length ? servers.map((s) => `
      <div class="discover-card">
        <div class="discover-name">${esc(s.name)}${s.is_verified ? ' ✔' : ''}</div>
        <div class="discover-desc muted">${esc(s.description || '')}</div>
        <div class="discover-meta muted">${s.members || 0} members</div>
        <button class="btn primary small" data-join-discover="${esc(s.invite_code || '')}">Join</button>
      </div>`).join('') : '<p class="muted">No discoverable servers yet.</p>';
    grid.querySelectorAll('[data-join-discover]').forEach((b) => b.addEventListener('click', async () => {
      await joinDiscovered(b.dataset.joinDiscover);
    }));
    $('discover-modal').hidden = false;
  }

  async function joinDiscovered(inviteCode) {
    const r = await api(`/api/community/invite/${encodeURIComponent(inviteCode)}`, { method: 'POST' });
    Insyrium.toast(r.ok ? 'Joined server' : (r.data.error || 'Invalid invite'), r.ok ? 'success' : 'error');
    if (r.ok) { await loadServers(); $('discover-modal').hidden = true; }
  }

  // ── Wire new feature event listeners ───────────────────────────────
  function wireNewFeatures() {
    const discoverBtn = $('discover-btn');
    if (discoverBtn) discoverBtn.addEventListener('click', loadDiscover);

    const searchBtn = $('chat-search-btn');
    if (searchBtn) searchBtn.addEventListener('click', showSearch);

    const searchClose = $('chat-search-bar')?.querySelector('[data-close="search"]');
    if (searchClose) searchClose.addEventListener('click', hideSearch);

    const searchForm = $('search-form');
    if (searchForm) searchForm.addEventListener('submit', (e) => {
      e.preventDefault();
      searchMessages(state.server && state.server.id, $('search-input').value);
    });

    const pinsBtn = $('chat-pins-btn');
    if (pinsBtn) pinsBtn.addEventListener('click', () => loadPins(state.channel && state.channel.id));

    const eventsBtn = $('chat-events-btn');
    if (eventsBtn) eventsBtn.addEventListener('click', () => loadEvents(state.server && state.server.id));

    const eventCreateBtn = $('event-create-btn');
    if (eventCreateBtn) eventCreateBtn.addEventListener('click', () => {
      if (!state.server) return;
      const chSel = $('event-channel');
      chSel.innerHTML = (state.server.channels || []).map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join('');
      $('event-modal').hidden = false;
    });

    const eventCreateGo = $('event-create-go');
    if (eventCreateGo) eventCreateGo.addEventListener('click', () => {
      createEvent(state.server.id, {
        name: $('event-name').value,
        description: $('event-desc').value,
        channel_id: parseInt($('event-channel').value, 10) || null,
        start_at: $('event-start').value,
        end_at: $('event-end').value || null,
      });
    });

    const addCategoryBtn = $('add-category-btn');
    if (addCategoryBtn) addCategoryBtn.addEventListener('click', () => {
      $('category-name-input').value = '';
      $('category-modal').hidden = false;
    });

    const categorySave = $('category-save');
    if (categorySave) categorySave.addEventListener('click', () => {
      if (state.server) createCategory(state.server.id, $('category-name-input').value.trim());
      $('category-modal').hidden = true;
    });

    const automodBtn = $('automod-btn');
    if (automodBtn) automodBtn.addEventListener('click', () => loadAutoMod(state.server && state.server.id));

    const automodAdd = $('automod-add-rule');
    if (automodAdd) automodAdd.addEventListener('click', () => {
      openModal('New AutoMod Rule',
        `<label class="muted">Name</label><input id="ar-name" maxlength="50">
         <label class="muted">Trigger type</label><select id="ar-trigger"><option value="keyword">Keyword</option><option value="spam">Spam</option><option value="mention_flood">Mention flood</option><option value="link_filter">Link filter</option></select>
         <label class="muted">Trigger value</label><input id="ar-value" maxlength="200">
         <label class="muted">Action</label><select id="ar-action"><option value="block">Block</option><option value="flag">Flag</option><option value="mute">Mute</option><option value="warn">Warn</option></select>
         <label class="muted">Duration (minutes)</label><input id="ar-duration" type="number" min="0" value="0">
         <button class="btn primary block" id="ar-go">Create Rule</button>`);
      $('ar-go').addEventListener('click', () => {
        createAutoMod(state.server.id, {
          name: $('ar-name').value,
          trigger_type: $('ar-trigger').value,
          trigger_value: $('ar-value').value,
          action_type: $('ar-action').value,
          action_duration_minutes: parseInt($('ar-duration').value || '0', 10),
        });
        $('modal-overlay').hidden = true;
      });
    });

    const webhooksBtn = $('webhooks-btn');
    if (webhooksBtn) webhooksBtn.addEventListener('click', () => loadWebhooks(state.server && state.server.id));

    const webhookCreate = $('webhook-create');
    if (webhookCreate) webhookCreate.addEventListener('click', () => {
      if (!state.server) return;
      openModal('New Webhook',
        `<label class="muted">Name</label><input id="wh-name" maxlength="80">
         <label class="muted">Channel</label><select id="wh-channel">${(state.server.channels || []).filter((c) => c.kind === 'text').map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join('')}</select>
         <button class="btn primary block" id="wh-go">Create</button>`);
      $('wh-go').addEventListener('click', () => {
        createWebhook(state.server.id, $('wh-name').value.trim(), parseInt($('wh-channel').value, 10));
        $('modal-overlay').hidden = true;
      });
    });

    const stickersBtn = $('stickers-btn');
    if (stickersBtn) stickersBtn.addEventListener('click', () => loadStickers(state.server && state.server.id));

    const stickerUpload = $('sticker-upload');
    if (stickerUpload) stickerUpload.addEventListener('click', () => {
      if (!state.server) return;
      openModal('Upload Sticker',
        `<label class="muted">Name</label><input id="st-name" maxlength="50">
         <label class="muted">Image URL</label><input id="st-url" maxlength="500" placeholder="https://...">
         <label class="muted">Tags</label><input id="st-tags" maxlength="128" placeholder="funny, reaction">
         <button class="btn primary block" id="st-go">Upload</button>`);
      $('st-go').addEventListener('click', () => {
        createSticker(state.server.id, $('st-name').value.trim(), $('st-url').value.trim(), $('st-tags').value.trim());
        $('modal-overlay').hidden = true;
      });
    });

    const templatesBtn = $('templates-btn');
    if (templatesBtn) templatesBtn.addEventListener('click', () => loadTemplates(state.server && state.server.id));

    const templateCreate = $('template-create');
    if (templateCreate) templateCreate.addEventListener('click', () => {
      if (!state.server) return;
      openModal('Save as Template',
        `<label class="muted">Template name</label><input id="tpl-name" maxlength="80">
         <label class="muted">Description</label><textarea id="tpl-desc" rows="3" maxlength="500"></textarea>
         <button class="btn primary block" id="tpl-go">Save</button>`);
      $('tpl-go').addEventListener('click', () => {
        createTemplate(state.server.id, $('tpl-name').value.trim(), $('tpl-desc').value.trim());
        $('modal-overlay').hidden = true;
      });
    });

    const threadPanelClose = $('thread-panel-close');
    if (threadPanelClose) threadPanelClose.addEventListener('click', closeThread);

    const threadForm = $('thread-form');
    if (threadForm) threadForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const input = $('thread-input');
      const text = input.value.trim();
      if (!text || !state._activeThread) return;
      sendThreadMessage(state._activeThread, text);
      input.value = '';
    });

    const replyCancel = $('reply-cancel');
    if (replyCancel) replyCancel.addEventListener('click', () => {
      $('reply-bar').hidden = true;
      state._replyTo = null;
    });

    document.addEventListener('click', (e) => {
      if (!e.target.closest('#emoji-picker') && !e.target.closest('.msg-actions-react')) {
        const picker = $('emoji-picker');
        if (picker) picker.hidden = true;
      }
      if (!e.target.closest('#profile-popup') && !e.target.closest('.m-row')) {
        closeProfile();
      }
    });

    const msgBox = $('chat-messages');
    if (msgBox) {
      msgBox.addEventListener('mouseover', (e) => {
        const msgEl = e.target.closest('.msg');
        if (!msgEl || msgEl.querySelector('.msg-hover-actions')) return;
        const mid = parseInt(msgEl.dataset.id, 10);
        if (!mid) return;
        const actions = document.createElement('div');
        actions.className = 'msg-hover-actions';
        actions.innerHTML = `<button class="com-mini-btn msg-actions-react" title="React">😀</button>${hasPerm(P.MANAGE_MESSAGES) ? `<button class="com-mini-btn" title="Pin" data-act="pin">📌</button>` : ''}<button class="com-mini-btn" title="Forward" data-act="forward">↪</button>`;
        actions.style.position = 'absolute';
        actions.style.top = '0';
        actions.style.right = '8px';
        msgEl.style.position = 'relative';
        msgEl.appendChild(actions);
        actions.querySelector('.msg-actions-react')?.addEventListener('click', (ev) => { ev.stopPropagation(); showEmojiPicker(msgEl, mid); });
        actions.querySelector('[data-act="pin"]')?.addEventListener('click', () => pinMessage(mid));
        actions.querySelector('[data-act="forward"]')?.addEventListener('click', () => showForwardModal(mid));
      });
      msgBox.addEventListener('mouseout', (e) => {
        const msgEl = e.target.closest('.msg');
        if (msgEl && !msgEl.matches(':hover')) {
          const ha = msgEl.querySelector('.msg-hover-actions');
          if (ha) ha.remove();
        }
      });
    }

    const discoverSearch = $('discover-search-input');
    if (discoverSearch) {
      discoverSearch.addEventListener('input', async () => {
        const q = discoverSearch.value.trim();
        if (!q) { loadDiscover(); return; }
        const r = await api(`/api/community/discover?q=${encodeURIComponent(q)}`);
        const servers = r.data.servers || [];
        const grid = $('discover-grid');
        grid.innerHTML = servers.map((s) => `
          <div class="discover-card">
            <div class="discover-name">${esc(s.name)}${s.is_verified ? ' ✔' : ''}</div>
            <div class="discover-desc muted">${esc(s.description || '')}</div>
            <div class="discover-meta muted">${s.members || 0} members</div>
            <button class="btn primary small" data-join-discover="${esc(s.invite_code || '')}">Join</button>
          </div>`).join('') || '<p class="muted">No results.</p>';
        grid.querySelectorAll('[data-join-discover]').forEach((b) => b.addEventListener('click', () => joinDiscovered(b.dataset.joinDiscover)));
      });
    }

    const settingsBtn = $('chat-settings-btn');
    if (settingsBtn) {
      settingsBtn.addEventListener('click', () => {
        if (!state.channel || !hasPerm(P.MANAGE_CHANNELS)) return;
        loadOverrides(state.channel.id).then((overrides) => {
          openModal('Channel Permission Overrides',
            overrides.map((o) => `<div class="override-card"><span>${o.role_id ? 'Role #' + o.role_id : 'User #' + o.user_id}</span> — allow: ${o.allow || 0}, deny: ${o.deny || 0} <button class="btn small ghost danger" data-del-ov="${o.id}">Remove</button></div>`).join('') +
            `<button class="btn primary block" id="add-override">+ Add Override</button>`);
          document.querySelectorAll('[data-del-ov]').forEach((b) => b.addEventListener('click', async () => {
            await removeOverride(state.channel.id, parseInt(b.dataset.delOv, 10));
            settingsBtn.click();
          }));
          $('add-override')?.addEventListener('click', () => {
            openModal('Add Override',
              `<label class="muted">Role ID</label><input id="ov-role" type="number">
               <label class="muted">User ID</label><input id="ov-user" type="number">
               <label class="muted">Allow (bitmask)</label><input id="ov-allow" type="number" value="0">
               <label class="muted">Deny (bitmask)</label><input id="ov-deny" type="number" value="0">
               <button class="btn primary block" id="ov-save">Save</button>`);
            $('ov-save').addEventListener('click', async () => {
              const data = {
                allow: parseInt($('ov-allow').value || '0', 10),
                deny: parseInt($('ov-deny').value || '0', 10),
              };
              if ($('ov-role').value) data.role_id = parseInt($('ov-role').value, 10);
              if ($('ov-user').value) data.user_id = parseInt($('ov-user').value, 10);
              await setOverride(state.channel.id, data);
              $('modal-overlay').hidden = true;
              settingsBtn.click();
            });
          });
        });
      });
    }

    $('profile-popup')?.querySelector('[data-close]')?.addEventListener('click', closeProfile);
    $('profile-popup')?.addEventListener('click', (e) => { if (e.target === $('profile-popup')) closeProfile(); });
  }

  document.addEventListener('DOMContentLoaded', function() {
    setTimeout(wireNewFeatures, 500);
    setTimeout(wireNewFeatures2, 800);
  });

  init();

  // ── Group DMs ─────────────────────────────────────────────────────
  async function createGroupDm(name, userIds) {
    const r = await api('/api/community/group-dms', { method: 'POST', body: { name, user_ids: userIds } });
    if (r.ok) { Insyrium.toast('Group DM created', 'success'); loadGroupDms(); }
    else Insyrium.toast(r.data.error || 'Failed', 'error');
  }
  async function loadGroupDms() {
    const r = await api('/api/community/group-dms');
    if (!r.ok) return;
    const list = r.data.threads || [];
    const container = $('dm-list');
    list.forEach(t => {
      if (container.querySelector(`[data-gtid="${t.id}"]`)) return;
      const b = document.createElement('button');
      b.className = 'dm-btn'; b.dataset.gtid = t.id;
      b.textContent = '👥 ' + esc(t.name || 'Group');
      b.addEventListener('click', () => openGroupDm(t.id));
      container.appendChild(b);
    });
  }
  async function openGroupDm(tid) {
    state._groupDm = tid; state.channel = null; state.dmThread = null;
    $('channels-col').style.display = 'none'; $('members-col').style.display = 'none';
    $('chat-head').textContent = 'Group DM';
    const r = await api(`/api/community/group-dms/${tid}/messages`);
    if (!r.ok) return;
    const box = $('chat-messages'); box.innerHTML = '';
    (r.data.messages || []).forEach(m => appendGroupDmMessage(m));
    leaveRooms();
    state.socket.emit('group_dm:join', { thread_id: tid });
  }
  function appendGroupDmMessage(m) {
    const box = $('chat-messages');
    const div = document.createElement('div');
    div.className = 'msg';
    div.innerHTML = `<div class="msg-head"><span class="msg-author">${esc(m.sender_name || m.sender_id)}</span> <span class="msg-time">${Insyrium.humanDate(m.created_at)}</span></div><div class="msg-body">${esc(m.body)}</div>`;
    box.appendChild(div); box.scrollTop = box.scrollHeight;
  }
  async function sendGroupDmMessage(tid, text) {
    const r = await api(`/api/community/group-dms/${tid}/messages`, { method: 'POST', body: { body: text } });
    if (r.ok) appendGroupDmMessage(r.data.message);
  }

  // ── Screen Sharing ────────────────────────────────────────────────
  async function startScreenShare(channelId, title) {
    const r = await api(`/api/community/channels/${channelId}/screenshare`, { method: 'POST', body: { title: title || 'Screen Share' } });
    if (r.ok) { Insyrium.toast('Go Live!', 'success'); renderScreenShares(channelId); }
  }
  async function stopScreenShare(channelId) {
    await api(`/api/community/channels/${channelId}/screenshare`, { method: 'DELETE' });
  }
  async function loadScreenShares(channelId) {
    const r = await api(`/api/community/channels/${channelId}/screenshare`);
    return r.ok ? (r.data.shares || []) : [];
  }
  function renderScreenShares(shares) {
    const container = $('voice-presence');
    shares.forEach(s => {
      if (s.is_live) {
        const div = document.createElement('div');
        div.className = 'voice-row';
        div.innerHTML = `🔴 ${esc(s.title)} — ${esc(s.user_name || 'User')} (${s.viewer_count} viewers)`;
        container.appendChild(div);
      }
    });
  }

  // ── Stage Channels ────────────────────────────────────────────────
  async function createStage(serverId, channelId, topic) {
    const r = await api(`/api/community/servers/${serverId}/stages`, { method: 'POST', body: { channel_id: channelId, topic } });
    if (r.ok) { Insyrium.toast('Stage created', 'success'); selectServer(serverId); }
  }
  async function joinStage(stageId) {
    const r = await api(`/api/community/stages/${stageId}/join`, { method: 'POST' });
    if (r.ok) { Insyrium.toast('Joined stage', 'success'); renderStagePanel(stageId); }
  }
  async function leaveStage(stageId) {
    await api(`/api/community/stages/${stageId}/leave`, { method: 'POST' });
    $('thread-panel').hidden = true;
  }
  async function requestSpeaker(stageId) {
    const r = await api(`/api/community/stages/${stageId}/speaker`, { method: 'POST' });
    Insyrium.toast(r.ok ? 'Speaker request sent' : (r.data.error || 'Failed'), r.ok ? 'success' : 'error');
  }
  function renderStagePanel(stage) {
    const panel = $('thread-panel'); panel.hidden = false;
    $('thread-panel-title').textContent = 'Stage: ' + esc(stage.topic || 'Live');
    const body = $('thread-parent-msg');
    const speakers = (stage.speaker_ids || []);
    const listeners = (stage.listener_ids || []);
    body.innerHTML = `
      <div class="stage-info">
        <p><strong>Speakers:</strong> ${speakers.length}</p>
        <p><strong>Listeners:</strong> ${listeners.length}</p>
        <p>${stage.is_live ? '🔴 LIVE' : '⚪ Not live'}</p>
        <button class="btn primary small" onclick="requestSpeaker(${stage.id})">Request to Speak</button>
        <button class="btn danger small" onclick="leaveStage(${stage.id})">Leave Stage</button>
      </div>`;
  }

  // ── Nitro / Boosting ──────────────────────────────────────────────
  async function boostServer(serverId, tier) {
    const r = await api(`/api/community/servers/${serverId}/boost`, { method: 'POST', body: { tier } });
    if (r.ok) { Insyrium.toast(`Boosted at Tier ${tier}!`, 'success'); loadBoostInfo(serverId); }
    else Insyrium.toast(r.data.error || 'Failed', 'error');
  }
  async function loadBoostInfo(serverId) {
    const r = await api(`/api/community/servers/${serverId}/boost-info`);
    if (!r.ok) return;
    const info = r.data;
    renderBoostBar(info);
  }
  function renderBoostBar(info) {
    const tier = info.current_tier || 0;
    const boosts = info.boost_count || 0;
    const nextThresholds = [0, 2, 7, 14];
    const next = nextThresholds[tier + 1] || 999;
    const tierNames = ['None', 'Tier 1', 'Tier 2', 'Tier 3'];
    const perks = [
      [],
      ['Custom emoji everywhere', '100MB uploads', 'Animated server icon'],
      ['128kbps voice', 'Server banner', '150MB uploads'],
      ['384kbps voice', 'Vanity URL', '500MB uploads', 'Animated emoji', 'Custom splash'],
    ];
    openModal('Server Boost',
      `<div class="boost-info">
        <h3>${tierNames[tier]}</h3>
        <p>${boosts} boost${boosts !== 1 ? 's' : ''}</p>
        ${tier < 3 ? `<p>${next - boosts} more boost${(next - boosts) !== 1 ? 's' : ''} to Tier ${tier + 1}</p>` : '<p>Max tier reached!</p>'}
        <div class="boost-perks"><strong>Current perks:</strong><ul>${(perks[tier] || []).map(p => '<li>' + esc(p) + '</li>').join('')}</ul></div>
        ${tier < 3 ? `<div class="boost-actions"><button class="btn primary" onclick="boostServer(${info.server_id}, ${tier + 1})">Boost Server</button></div>` : ''}
      </div>`);
  }

  // ── Rich Presence ─────────────────────────────────────────────────
  async function updatePresence(statusText, appName, appDetails) {
    await api('/api/community/status/presence', { method: 'PATCH', body: { status_text: statusText, app_name: appName, app_details: appDetails } });
  }
  function renderPresence(presence) {
    if (!presence || (!presence.app_name && !presence.status_text)) return '';
    return `<div class="presence-info">${presence.app_name ? '🎮 ' + esc(presence.app_name) : ''} ${presence.status_text ? esc(presence.status_text) : ''}</div>`;
  }

  // ── Forum Channels ────────────────────────────────────────────────
  async function createForumPost(channelId, title, body, tags) {
    const r = await api(`/api/community/channels/${channelId}/forum/posts`, { method: 'POST', body: { title, body, tags } });
    if (r.ok) { Insyrium.toast('Post created', 'success'); loadForumPosts(channelId); }
  }
  async function loadForumPosts(channelId, sort, tag) {
    let url = `/api/community/channels/${channelId}/forum/posts?`;
    if (sort) url += `sort=${sort}&`;
    if (tag) url += `tag=${tag}`;
    const r = await api(url);
    if (!r.ok) return;
    renderForumPosts(r.data.posts || [], channelId);
  }
  function renderForumPosts(posts, channelId) {
    const box = $('chat-messages'); box.innerHTML = '';
    const createBtn = document.createElement('div');
    createBtn.className = 'forum-create-btn';
    createBtn.innerHTML = `<button class="btn primary" id="forum-new-post-btn">+ New Post</button>`;
    box.appendChild(createBtn);
    $('forum-new-post-btn')?.addEventListener('click', () => showForumCreateModal(channelId));
    posts.forEach(p => {
      const card = document.createElement('div');
      card.className = 'forum-card';
      card.innerHTML = `
        <div class="fc-title">${esc(p.title)}</div>
        <div class="fc-meta">${esc(p.author_name || 'Unknown')} · ${Insyrium.humanDate(p.created_at)} · ${p.reply_count || 0} replies</div>
        ${p.tags ? `<div class="fc-tags">${p.tags.split(',').map(t => '<span class="fc-tag">' + esc(t.trim()) + '</span>').join('')}</div>` : ''}
        ${p.is_pinned ? '<span class="pill">📌 Pinned</span>' : ''}
        ${p.is_locked ? '<span class="pill">🔒 Locked</span>' : ''}`;
      card.addEventListener('click', () => openForumPost(p.id));
      box.appendChild(card);
    });
  }
  async function openForumPost(postId) {
    const r = await api(`/api/community/forum/posts/${postId}`);
    if (!r.ok) return;
    const post = r.data.post;
    const replies = r.data.replies || [];
    const box = $('chat-messages'); box.innerHTML = '';
    const postEl = document.createElement('div');
    postEl.className = 'forum-post-full';
    postEl.innerHTML = `
      <h2>${esc(post.title)}</h2>
      <div class="fp-meta">${esc(post.author_name || 'Unknown')} · ${Insyrium.humanDate(post.created_at)}</div>
      <div class="fp-body">${esc(post.body)}</div>
      ${post.tags ? `<div class="fc-tags">${post.tags.split(',').map(t => '<span class="fc-tag">' + esc(t.trim()) + '</span>').join('')}</div>` : ''}
      <hr>
      <div class="fp-replies-count">${replies.length} replies</div>`;
    box.appendChild(postEl);
    replies.forEach(rep => {
      const el = document.createElement('div');
      el.className = 'forum-reply';
      el.innerHTML = `<div class="msg-head"><span class="msg-author">${esc(rep.author_name || 'Unknown')}</span> <span class="msg-time">${Insyrium.humanDate(rep.created_at)}</span></div><div class="msg-body">${esc(rep.body)}</div>`;
      box.appendChild(el);
    });
    const replyForm = document.createElement('div');
    replyForm.className = 'forum-reply-form';
    replyForm.innerHTML = `<form id="forum-reply-form" class="chat-form"><input id="forum-reply-input" maxlength="5000" placeholder="Write a reply..."><button class="btn primary" type="submit">Reply</button></form>`;
    box.appendChild(replyForm);
    $('forum-reply-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const text = $('forum-reply-input').value.trim();
      if (!text) return;
      await api(`/api/community/forum/posts/${postId}/replies`, { method: 'POST', body: { body: text } });
      $('forum-reply-input').value = '';
      openForumPost(postId);
    });
    box.scrollTop = box.scrollHeight;
  }
  function showForumCreateModal(channelId) {
    openModal('New Forum Post',
      `<label class="muted">Title</label><input id="fp-title" maxlength="100" placeholder="Post title">
       <label class="muted">Content</label><textarea id="fp-body" rows="6" maxlength="10000"></textarea>
       <label class="muted">Tags (comma-separated)</label><input id="fp-tags" maxlength="200" placeholder="question, help, announcement">
       <button class="btn primary block" id="fp-go">Create Post</button>`);
    $('fp-go').addEventListener('click', () => {
      createForumPost(channelId, $('fp-title').value.trim(), $('fp-body').value.trim(), $('fp-tags').value.trim());
      $('modal-overlay').hidden = true;
    });
  }

  // ── Verification Levels ───────────────────────────────────────────
  async function setVerificationLevel(serverId, level) {
    const r = await api(`/api/community/servers/${serverId}/verification`, { method: 'PATCH', body: { level } });
    if (r.ok) { Insyrium.toast('Verification level updated', 'success'); selectServer(serverId); }
  }
  function renderVerificationBadge(level) {
    const names = ['None', '📧 Email', '📱 Phone', '⏱ 5min', '📋 10min'];
    return `<span class="verification-badge" title="Verification level: ${names[level] || 'Unknown'}">${names[level] || '?'}</span>`;
  }

  // ── Bot Integration ───────────────────────────────────────────────
  async function createBot(serverId, name, description) {
    const r = await api(`/api/community/servers/${serverId}/bots`, { method: 'POST', body: { name, description } });
    if (r.ok) { openModal('Bot Token', `<p>Save this token — it won't be shown again:</p><div class="webhook-token">${esc(r.data.token)}</div><p class="muted">Use this token to authenticate API calls from your bot.</p>`); loadBots(serverId); }
    else Insyrium.toast(r.data.error || 'Failed', 'error');
  }
  async function loadBots(serverId) {
    const r = await api(`/api/community/servers/${serverId}/bots`);
    if (!r.ok) return;
    const bots = r.data.bots || [];
    openModal('Bot Management', bots.map(b => `
      <div class="webhook-card">
        <div><div class="wh-name">${esc(b.name)}</div><div class="wh-channel">${esc(b.description || '')}</div></div>
        <button class="btn small danger" onclick="deleteBot(${b.id}, ${serverId})">Remove</button>
      </div>`).join('') || '<p class="muted">No bots yet.</p>' +
      '<button class="btn primary block" id="bot-register-btn">+ Register Bot</button>');
    $('bot-register-btn')?.addEventListener('click', () => {
      openModal('Register Bot', `<label class="muted">Bot name</label><input id="bot-name" maxlength="80"><label class="muted">Description</label><input id="bot-desc" maxlength="500"><button class="btn primary block" id="bot-go">Register</button>`);
      $('bot-go').addEventListener('click', () => { createBot(serverId, $('bot-name').value.trim(), $('bot-desc').value.trim()); $('modal-overlay').hidden = true; });
    });
  }
  async function deleteBot(botId, serverId) {
    await api(`/api/community/bots/${botId}`, { method: 'DELETE' });
    loadBots(serverId);
  }

  // ── Onboarding Flow ───────────────────────────────────────────────
  async function createOnboardingStep(serverId, title, description, roleId, order) {
    const r = await api(`/api/community/servers/${serverId}/onboarding`, { method: 'POST', body: { title, description, required_role_id: roleId, step_order: order } });
    if (r.ok) { Insyrium.toast('Step created', 'success'); loadOnboardingSteps(serverId); }
  }
  async function loadOnboardingSteps(serverId) {
    const r = await api(`/api/community/servers/${serverId}/onboarding`);
    if (!r.ok) return;
    const steps = r.data.steps || [];
    openModal('Onboarding Steps', steps.map((s, i) => `
      <div class="onboard-step">
        <strong>${i + 1}. ${esc(s.title)}</strong> <span class="muted">${esc(s.description || '')}</span>
        ${s.required_role_id ? '<span class="pill">Auto-assign role</span>' : ''}
        <button class="btn small danger" onclick="deleteOnboardingStep(${s.id}, ${serverId})">Remove</button>
      </div>`).join('') || '<p class="muted">No steps yet.</p>' +
      '<button class="btn primary block" id="onboard-add-btn">+ Add Step</button>');
    $('onboard-add-btn')?.addEventListener('click', () => {
      openModal('Add Step', `<label class="muted">Title</label><input id="os-title" maxlength="80"><label class="muted">Description</label><textarea id="os-desc" rows="2" maxlength="300"></textarea><button class="btn primary block" id="os-go">Add</button>`);
      $('os-go').addEventListener('click', () => { createOnboardingStep(serverId, $('os-title').value.trim(), $('os-desc').value.trim(), null, steps.length + 1); $('modal-overlay').hidden = true; });
    });
  }
  async function deleteOnboardingStep(stepId, serverId) {
    await api(`/api/community/onboarding/${stepId}`, { method: 'DELETE' });
    loadOnboardingSteps(serverId);
  }
  function renderOnboardingCheck(required, steps) {
    if (!required || !steps || !steps.length) return;
    openModal('Welcome! Complete Onboarding', steps.map((s, i) => `
      <div class="onboard-step"><strong>Step ${i + 1}:</strong> ${esc(s.title)}<br><span class="muted">${esc(s.description || '')}</span></div>`).join('') +
      '<button class="btn primary block" id="onboard-complete-btn">I\'ve completed all steps</button>');
    $('onboard-complete-btn')?.addEventListener('click', async () => {
      if (state.server) {
        await api(`/api/community/servers/${state.server.id}/onboarding/complete`, { method: 'POST' });
        $('modal-overlay').hidden = true;
        Insyrium.toast('Onboarding complete!', 'success');
        selectServer(state.server.id);
      }
    });
  }

  // ── Raid Protection ───────────────────────────────────────────────
  async function loadRaidLogs(serverId) {
    const r = await api(`/api/community/servers/${serverId}/raid-logs`);
    return r.ok ? (r.data.logs || []) : [];
  }
  async function lockServer(serverId) {
    const r = await api(`/api/community/servers/${serverId}/raid-lock`, { method: 'POST' });
    if (r.ok) Insyrium.toast('Server locked (raid protection active)', 'success');
  }
  async function unlockServer(serverId) {
    const r = await api(`/api/community/servers/${serverId}/raid-unlock`, { method: 'POST' });
    if (r.ok) Insyrium.toast('Server unlocked', 'success');
  }
  function renderRaidPanel(serverId) {
    openModal('Raid Protection', `
      <div class="raid-controls">
        <button class="btn warn" onclick="lockServer(${serverId})">🔒 Lock Server</button>
        <button class="btn" onclick="unlockServer(${serverId})">🔓 Unlock Server</button>
      </div>
      <div id="raid-logs-list" class="raid-logs"><p class="muted">Loading...</p></div>`);
    loadRaidLogs(serverId).then(logs => {
      const el = $('raid-logs-list');
      if (el) el.innerHTML = logs.length ? logs.map(l => `
        <div class="raid-log">
          <span class="pill">${esc(l.trigger_type)}</span> — ${esc(l.action_taken)} <span class="muted">${Insyrium.humanDate(l.created_at)}</span>
        </div>`).join('') : '<p class="muted">No recent raids.</p>';
    });
  }

  // ── Notification Preferences ──────────────────────────────────────
  async function loadNotificationPrefs() {
    const r = await api('/api/community/notification-prefs');
    return r.ok ? (r.data.preferences || []) : [];
  }
  async function updateNotificationPrefs(prefs) {
    await api('/api/community/notification-prefs', { method: 'PUT', body: prefs });
    Insyrium.toast('Preferences saved', 'success');
  }
  function renderNotifPrefsModal() {
    openModal('Notification Preferences', `
      <div class="notif-prefs">
        <label class="switch-row"><span>Mentions</span><input type="checkbox" id="np-mentions" checked></label>
        <label class="switch-row"><span>Replies</span><input type="checkbox" id="np-replies" checked></label>
        <label class="switch-row"><span>DMs</span><input type="checkbox" id="np-dms" checked></label>
        <label class="switch-row"><span>Events</span><input type="checkbox" id="np-events" checked></label>
        <button class="btn primary block" id="np-save">Save</button>
      </div>`);
    $('np-save')?.addEventListener('click', () => {
      updateNotificationPrefs({
        notify_mentions: $('np-mentions').checked,
        notify_replies: $('np-replies').checked,
        notify_dms: $('np-dms').checked,
        notify_events: $('np-events').checked,
      });
      $('modal-overlay').hidden = true;
    });
  }

  // ── Account Recovery ──────────────────────────────────────────────
  async function initiateRecovery(email) {
    const r = await api('/api/auth/account-recovery', { method: 'POST', body: { email } });
    return r;
  }
  async function verifyRecovery(email, code) {
    return await api('/api/auth/account-recovery/verify', { method: 'POST', body: { email, code } });
  }
  async function resetPassword(token, newPassword) {
    return await api('/api/auth/account-recovery/reset', { method: 'POST', body: { token, password: newPassword } });
  }

  // ── Wire new feature event listeners (phase 2) ────────────────────
  function wireNewFeatures2() {
    const gdmBtn = $('group-dm-btn');
    if (gdmBtn) gdmBtn.addEventListener('click', () => {
      openModal('Create Group DM',
        `<label class="muted">Name</label><input id="gdm-name" maxlength="80" placeholder="Group Chat">
         <button class="btn primary block" id="gdm-go">Create</button>`);
      $('gdm-go').addEventListener('click', () => {
        createGroupDm($('gdm-name').value.trim(), []);
        $('modal-overlay').hidden = true;
      });
    });

    loadGroupDms();

    const boostBtn = $('boost-btn');
    if (boostBtn) boostBtn.addEventListener('click', () => {
      if (state.server) loadBoostInfo(state.server.id);
    });

    const botsBtn = $('bots-btn');
    if (botsBtn) botsBtn.addEventListener('click', () => {
      if (state.server) loadBots(state.server.id);
    });

    const onboardBtn = $('onboard-btn');
    if (onboardBtn) onboardBtn.addEventListener('click', () => {
      if (state.server) loadOnboardingSteps(state.server.id);
    });

    const raidBtn = $('raid-btn');
    if (raidBtn) raidBtn.addEventListener('click', () => {
      if (state.server) renderRaidPanel(state.server.id);
    });

    const npBtn = $('notif-prefs-btn');
    if (npBtn) npBtn.addEventListener('click', renderNotifPrefsModal);
  }
})();
