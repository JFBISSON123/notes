(function () {
  'use strict';

  const C = window.NotesCrypto;
  const $ = (id) => document.getElementById(id);
  const AUTO_LOCK_MS = 10 * 60 * 1000;   // idle time before the key is wiped
  const HIDDEN_LOCK_MS = 2 * 60 * 1000;  // time in background before the key is wiped
  const GARMIN_LIMIT = 160;               // inReach satellite message length

  let session = null;
  let idleTimer = null;
  let hiddenAt = 0;
  let lastCipher = '';

  // ---------- helpers ----------
  function toast(msg, ms) {
    const t = $('toast');
    t.textContent = msg; t.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => { t.hidden = true; }, ms || 2600);
  }

  async function copy(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch (e) { /* fall through */ }
    const ta = document.createElement('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove();
    return ok;
  }

  async function share(text) {
    if (!navigator.share) return false;
    try { await navigator.share({ text }); return true; }
    catch (e) { return e && e.name === 'AbortError' ? 'cancel' : false; }
  }

  function open(url) {
    const a = document.createElement('a');
    a.href = url; a.rel = 'noopener noreferrer';
    if (/^https:/.test(url)) a.target = '_blank';
    document.body.appendChild(a); a.click(); a.remove();
  }

  function stamp() {
    const d = new Date();
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  }

  function download(text) {
    const blob = new Blob([text + '\n'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'note-' + stamp() + '.txt';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  // ---------- views ----------
  function show(view) {
    document.querySelectorAll('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.view === view)));
    document.querySelectorAll('.view').forEach((v) => { v.hidden = v.id !== 'view-' + view; });
    if (view === 'key' && !session) $('key').focus();
  }
  document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => show(b.dataset.view)));

  function refreshKeyState() {
    document.body.classList.toggle('locked', !session);
    $('tab-key').textContent = session ? 'Key •' : 'Key';
    $('btn-send').textContent = session ? 'Send' : 'Set key';
    $('btn-lock').hidden = !session;
    $('btn-use').hidden = !!session;
  }

  // ---------- key ----------
  async function setKey() {
    const pass = $('key').value;
    if (!pass) return null;
    if (C.estimateBits(pass) < 50 && !confirm('This key is weak and could be guessed. Use it anyway?')) return null;
    if (session) session.destroy();
    session = C.createSession(pass);
    $('key').value = '';
    $('key').type = 'password'; $('btn-show').textContent = 'Show';
    $('key-strength').textContent = 'Preparing key…';
    try { await session.ready; } catch (e) { session = null; $('key-strength').textContent = 'Could not prepare key.'; refreshKeyState(); return null; }
    $('key-strength').textContent = 'Key set for this session.';
    refreshKeyState(); bumpIdle();
    return session;
  }

  function lock(reason) {
    if (session) session.destroy();
    session = null;
    $('key').value = '';
    $('key-strength').textContent = reason || '';
    closeOpened();
    refreshKeyState();
  }

  $('key').addEventListener('input', () => {
    const v = $('key').value;
    if (!v) { $('key-strength').textContent = ''; return; }
    const bits = C.estimateBits(v);
    $('key-strength').textContent = bits >= 80 ? 'Strong key.' : bits >= 50 ? 'Fair key. Longer is better.' : 'Weak key. Use Generate key or a long phrase.';
  });
  $('key').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); setKey().then((s) => { if (s) show('write'); }); } });
  $('btn-use').addEventListener('click', () => setKey().then((s) => { if (s) show('write'); }));
  $('btn-show').addEventListener('click', () => {
    const k = $('key');
    k.type = k.type === 'password' ? 'text' : 'password';
    $('btn-show').textContent = k.type === 'password' ? 'Show' : 'Hide';
  });
  $('btn-gen').addEventListener('click', () => {
    const k = $('key');
    k.value = C.generateKey(); k.type = 'text'; $('btn-show').textContent = 'Hide';
    k.dispatchEvent(new Event('input'));
    $('key-strength').textContent = 'Write this key down and give it to the other person in person. Then tap Use key.';
    k.focus(); k.select();
  });
  $('btn-lock').addEventListener('click', () => lock('Locked.'));

  // ---------- auto lock and privacy veil ----------
  function bumpIdle() {
    clearTimeout(idleTimer);
    if (session) idleTimer = setTimeout(() => lock('Locked after inactivity.'), AUTO_LOCK_MS);
  }
  ['pointerdown', 'keydown'].forEach((ev) => document.addEventListener(ev, bumpIdle, { passive: true }));
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      hiddenAt = Date.now();
      document.body.classList.add('veil');
    } else {
      document.body.classList.remove('veil');
      if (hiddenAt && Date.now() - hiddenAt > HIDDEN_LOCK_MS && session) lock('Locked while away.');
      hiddenAt = 0;
    }
  });
  window.addEventListener('pagehide', () => document.body.classList.add('veil'));
  window.addEventListener('pageshow', () => document.body.classList.remove('veil'));

  // ---------- write ----------
  const channelNote = {
    email: 'Encrypted. Your mail app should open with the note in the body. If not, copy it below.',
    sms: 'Encrypted. Your messages app should open with the note. If not, copy it below.',
    signal: 'Encrypted. Pick Signal in the share sheet, or copy below and paste into Signal.',
    whatsapp: 'Encrypted. WhatsApp should open so you can pick a contact. If not, copy below.',
    garmin: 'Encrypted. Send each part below as its own Garmin message (160 characters each).',
    file: 'Encrypted and saved as a text document. Copy below if the download did not start.'
  };

  function updateCount() {
    const n = $('title').value.length + $('message').value.length;
    const garmin = $('channel').value === 'garmin';
    $('count').textContent = n ? n + ' characters' + (garmin ? ' · short notes fit one Garmin message' : '') : '';
  }
  ['input', 'change'].forEach((ev) => { $('title').addEventListener(ev, updateCount); $('message').addEventListener(ev, updateCount); $('channel').addEventListener(ev, updateCount); });

  function renderOutput(cipher, channel) {
    const box = $('out-parts');
    box.textContent = '';
    const parts = channel === 'garmin' ? C.split(cipher, GARMIN_LIMIT) : [cipher];
    parts.forEach((p, i) => {
      const wrap = document.createElement('div'); wrap.className = 'part';
      const code = document.createElement('code'); code.textContent = p;
      const row = document.createElement('div'); row.className = 'row';
      if (parts.length > 1) { const s = document.createElement('span'); s.className = 'small muted'; s.textContent = 'Part ' + (i + 1) + ' of ' + parts.length; row.appendChild(s); }
      const sp = document.createElement('span'); sp.className = 'spacer'; row.appendChild(sp);
      if (navigator.share) {
        const sh = document.createElement('button'); sh.type = 'button'; sh.className = 'ghost'; sh.textContent = 'Share';
        sh.addEventListener('click', () => share(p));
        row.appendChild(sh);
      }
      const cp = document.createElement('button'); cp.type = 'button'; cp.className = 'ghost'; cp.textContent = 'Copy';
      cp.addEventListener('click', async () => { toast((await copy(p)) ? 'Copied' : 'Copy failed, select the text and copy'); });
      row.appendChild(cp);
      wrap.appendChild(code); wrap.appendChild(row); box.appendChild(wrap);
    });
    $('out-note').textContent = channelNote[channel];
    $('out').hidden = false;
    return parts;
  }

  async function send() {
    if (!C.supported()) { toast('This browser cannot encrypt. Open the app over https or from a file.', 5000); return; }
    if (!session && $('key').value) await setKey();
    if (!session) { show('key'); toast('Set the shared key first'); return; }
    const title = $('title').value.trim();
    const message = $('message').value.trim();
    if (!title && !message) { toast('Nothing to send'); return; }
    const channel = $('channel').value;
    let cipher;
    try { cipher = await session.encrypt(title, message); }
    catch (e) { toast(e.message === 'locked' ? 'Locked. Set the key again.' : 'Encryption failed'); return; }
    lastCipher = cipher;
    const parts = renderOutput(cipher, channel);
    const body = encodeURIComponent(cipher);

    switch (channel) {
      case 'email':
        open('mailto:?subject=' + encodeURIComponent('Note ' + stamp()) + '&body=' + body);
        break;
      case 'sms':
        open('sms:?&body=' + body);
        break;
      case 'whatsapp':
        open('https://wa.me/?text=' + body);
        break;
      case 'signal': {
        const r = await share(cipher);
        if (r !== true && r !== 'cancel') { if (await copy(cipher)) toast('Copied. Paste it into Signal.', 4000); }
        break;
      }
      case 'garmin': {
        if (parts.length === 1) {
          const r = await share(parts[0]);
          if (r !== true && r !== 'cancel' && await copy(parts[0])) toast('Copied. Paste it into Garmin Messenger.', 4000);
        } else {
          toast(parts.length + ' parts. Send them in order.', 4000);
        }
        break;
      }
      case 'file':
        download(cipher);
        break;
    }
  }

  $('btn-send').addEventListener('click', send);
  $('btn-clear').addEventListener('click', () => {
    $('title').value = ''; $('message').value = '';
    $('out').hidden = true; $('out-parts').textContent = ''; lastCipher = '';
    updateCount(); $('title').focus();
  });

  // ---------- read ----------
  function closeOpened() {
    $('opened').hidden = true;
    $('opened-title').textContent = ''; $('opened-body').textContent = ''; $('opened-date').textContent = '';
  }

  async function openNote() {
    const text = $('incoming').value;
    if (!text.trim()) { toast('Paste a note first'); return; }
    if (!session) { show('key'); toast('Set the shared key first'); return; }
    closeOpened();
    $('btn-open').disabled = true; $('btn-open').textContent = 'Opening…';
    try {
      const n = await session.decrypt(text);
      $('opened-title').textContent = n.title || '(no title)';
      $('opened-date').textContent = isNaN(n.date) ? '' : n.date.toLocaleString();
      $('opened-body').textContent = n.message;
      $('opened').hidden = false;
      $('incoming').value = '';
    } catch (e) {
      const why = { key: 'Could not open. Wrong key, a missing part, or the note was changed.', format: 'That does not look like a complete note.', empty: 'Paste a note first', nocompress: 'This browser is too old to open this note.', locked: 'Locked. Set the key again.' };
      toast(why[e.message] || 'Could not open this note.', 4500);
    } finally {
      $('btn-open').disabled = false; $('btn-open').textContent = 'Open';
    }
  }
  $('btn-open').addEventListener('click', openNote);
  $('btn-close').addEventListener('click', closeOpened);
  $('file-in').addEventListener('change', async (e) => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    if (f.size > 1024 * 1024) { toast('File is too large'); return; }
    $('incoming').value = await f.text();
    e.target.value = '';
    openNote();
  });

  // ---------- start ----------
  refreshKeyState();
  updateCount();
  if (!C.supported()) toast('Open this app over https or from a saved file to enable encryption.', 6000);

  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
})();
