/* Notes crypto: AES-256-GCM with a PBKDF2-SHA-256 derived key.
 *
 * Wire format v2 (base64url, no padding):
 *   [0]      version (2)
 *   [1]      flags   (bit0 = payload deflate-raw compressed)
 *   [2..5]   key id  (first 4 bytes of the key check value, see checkCode)
 *   [6..21]  salt    (16 random bytes, PBKDF2)
 *   [22..33] iv      (12 random bytes, AES-GCM nonce)
 *   [34..]   ciphertext + 16-byte GCM tag
 * Version 1 notes (no key id, 30-byte header, key not normalized) still open.
 * The header bytes are bound to the ciphertext as additional data, so any
 * change to them makes decryption fail.
 *
 * Plaintext: "<unix minutes>\x1f<title>\x1f<message>" as UTF-8.
 */
(function (global) {
  'use strict';

  const ITERATIONS = 600000; // OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
  const SALT_LEN = 16;
  const IV_LEN = 12;
  const ID_LEN = 4;
  const HEADER_V1 = 2 + SALT_LEN + IV_LEN;
  const HEADER_V2 = 2 + ID_LEN + SALT_LEN + IV_LEN;
  const SEP = '\x1f';
  const CHECK_SALT = 'notes/key-check/v2';
  const WORD_KEY_LEN = 7; // 7 x 11 bits = 77 bits, on top of 600,000 PBKDF2 rounds

  const subtle = global.crypto && global.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder('utf-8', { fatal: true });
  const WORDS = global.NotesWords || [];
  const WORD_SET = new Set(WORDS);
  const BY_PREFIX = new Map(WORDS.map((w) => [w.slice(0, 4), w]));

  function supported() {
    return !!(subtle && global.crypto.getRandomValues);
  }

  function random(n) {
    return global.crypto.getRandomValues(new Uint8Array(n));
  }

  // Version 1 treated the key exactly as typed.
  function legacyKey(pass) {
    return String(pass).normalize('NFKC').trim();
  }

  // A key word, or the unique word its first four or more letters start.
  function resolveWord(t) {
    if (WORD_SET.has(t)) return t;
    if (t.length >= 4) {
      const w = BY_PREFIX.get(t.slice(0, 4));
      if (w && w.startsWith(t)) return w;
    }
    return null;
  }

  // Forgiving form of a key: case, extra spaces and dashes do not matter, and
  // word keys accept the first four letters of each word.
  function analyzeKey(pass) {
    const s = String(pass).normalize('NFKC').toLowerCase().trim();
    const tokens = s.split(/[^a-z0-9]+/).filter(Boolean);
    const resolved = tokens.map(resolveWord);
    const known = resolved.filter(Boolean).length;
    if (tokens.length >= 2 && known === tokens.length) {
      return { canonical: resolved.join(' '), kind: 'words', words: tokens.length, unknown: [] };
    }
    const compact = s.replace(/[\s-]+/g, '');
    if (/^[a-hjkmnp-z2-9]{20}$/.test(compact)) {
      return { canonical: compact.match(/.{5}/g).join('-'), kind: 'code', unknown: [] };
    }
    const unknown = tokens.length >= 4 && known >= tokens.length - 2 ? tokens.filter((t, i) => !resolved[i]) : [];
    return { canonical: s.replace(/\s+/g, ' '), kind: 'phrase', unknown };
  }

  function normalizeKey(pass) {
    return analyzeKey(pass).canonical;
  }

  async function pbkdf2(pass, salt, bits) {
    const base = await subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
    if (bits) return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, base, bits));
    return subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // "word · word · 00" from the 4-byte key id: 11 + 11 bits and two digits.
  function codeFromId(id) {
    const x = ((id[0] << 24) | (id[1] << 16) | (id[2] << 8) | id[3]) >>> 0;
    const n = String((x & 1023) % 100).padStart(2, '0');
    return WORDS[x >>> 21] + ' · ' + WORDS[(x >>> 10) & 2047] + ' · ' + n;
  }

  // A session holds one derived key and its salt so each Send is instant
  // (keeps the tap "fresh" for the share sheet). Every note still gets a new
  // random 96-bit IV. Decryption derives (and caches) keys per salt.
  function createSession(pass) {
    const passphrase = normalizeKey(pass);
    const legacy = legacyKey(pass);
    const salt = random(SALT_LEN);
    const cache = new Map();
    let keyId = null;
    const idReady = pbkdf2(passphrase, enc.encode(CHECK_SALT), ID_LEN * 8).then((b) => { keyId = b; return b; });
    const keyReady = pbkdf2(passphrase, salt).then((k) => { cache.set('2' + hex(salt), Promise.resolve(k)); return k; });
    const ready = Promise.all([keyReady, idReady]).then(() => codeFromId(keyId));
    let destroyed = false;

    function keyFor(version, s) {
      if (destroyed) throw new Error('locked');
      const id = version + hex(s);
      if (!cache.has(id)) cache.set(id, pbkdf2(version === 1 ? legacy : passphrase, s));
      return cache.get(id);
    }

    return {
      ready,
      get code() { return keyId ? codeFromId(keyId) : ''; },
      async encrypt(title, message) {
        const key = await keyReady; await idReady;
        if (destroyed) throw new Error('locked');
        const minutes = Math.floor(Date.now() / 60000);
        let data = enc.encode(minutes + SEP + title + SEP + message);
        let flags = 0;
        const packed = await deflate(data);
        if (packed && packed.length < data.length) { data = packed; flags |= 1; }
        const iv = random(IV_LEN);
        const header = new Uint8Array(HEADER_V2);
        header[0] = 2; header[1] = flags;
        header.set(keyId, 2); header.set(salt, 2 + ID_LEN); header.set(iv, 2 + ID_LEN + SALT_LEN);
        const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: header, tagLength: 128 }, key, data));
        data.fill(0);
        const out = new Uint8Array(HEADER_V2 + ct.length);
        out.set(header, 0); out.set(ct, HEADER_V2);
        return b64url(out);
      },
      async decrypt(text) {
        const bytes = fromB64url(extract(text));
        const version = bytes[0];
        const hl = version === 2 ? HEADER_V2 : version === 1 ? HEADER_V1 : 0;
        if (!hl || bytes.length < hl + 16) throw new Error('format');
        const header = bytes.subarray(0, hl);
        if (version === 2) {
          await idReady;
          const theirs = bytes.subarray(2, 2 + ID_LEN);
          if (theirs.some((b, i) => b !== keyId[i])) {
            const err = new Error('otherkey'); err.theirs = codeFromId(theirs); err.mine = codeFromId(keyId); throw err;
          }
        }
        const s = bytes.slice(hl - IV_LEN - SALT_LEN, hl - IV_LEN);
        const iv = bytes.slice(hl - IV_LEN, hl);
        const key = await keyFor(version, s);
        let pt;
        try {
          pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: header, tagLength: 128 }, key, bytes.subarray(hl)));
        } catch (e) { throw new Error(version === 2 ? 'changed' : 'key'); }
        if (header[1] & 1) pt = await inflate(pt);
        const str = dec.decode(pt);
        pt.fill(0);
        const i = str.indexOf(SEP), j = str.indexOf(SEP, i + 1);
        if (i < 0 || j < 0) throw new Error('format');
        return { date: new Date(parseInt(str.slice(0, i), 10) * 60000), title: str.slice(i + 1, j), message: str.slice(j + 1) };
      },
      destroy() { destroyed = true; cache.clear(); }
    };
  }

  // Accepts a pasted blob, a file, or several "1/3 xxxx" parts in any order.
  function extract(text) {
    const tokens = String(text).split(/\s+/).filter(Boolean);
    const parts = [];
    let loose = '';
    for (let i = 0; i < tokens.length; i++) {
      const m = /^(\d+)\/(\d+)$/.exec(tokens[i]);
      if (m && i + 1 < tokens.length) { parts.push([+m[1], tokens[++i]]); continue; }
      loose += tokens[i];
    }
    const body = parts.length ? parts.sort((a, b) => a[0] - b[0]).map((p) => p[1]).join('') + loose : loose;
    const clean = body.replace(/[^A-Za-z0-9_-]/g, '');
    if (!clean) throw new Error('empty');
    return clean;
  }

  // Splits a note into chunks that fit a per-message character limit,
  // each prefixed "n/N " so they can be pasted back in any order.
  function split(cipher, limit) {
    if (cipher.length <= limit) return [cipher];
    let n = Math.ceil(cipher.length / (limit - 6));
    for (;;) {
      const prefix = (n + '/' + n + ' ').length;
      const size = limit - prefix;
      const need = Math.ceil(cipher.length / size);
      if (need <= n) {
        const out = [];
        for (let i = 0; i < need; i++) out.push((i + 1) + '/' + need + ' ' + cipher.slice(i * size, (i + 1) * size));
        return out;
      }
      n = need;
    }
  }

  async function pipe(data, stream) {
    const s = new Blob([data]).stream().pipeThrough(stream);
    return new Uint8Array(await new Response(s).arrayBuffer());
  }
  async function deflate(data) {
    if (typeof CompressionStream === 'undefined') return null;
    try { return await pipe(data, new CompressionStream('deflate-raw')); } catch (e) { return null; }
  }
  async function inflate(data) {
    if (typeof DecompressionStream === 'undefined') throw new Error('nocompress');
    return pipe(data, new DecompressionStream('deflate-raw'));
  }

  function b64url(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function fromB64url(str) {
    const s = str.replace(/-/g, '+').replace(/_/g, '/');
    let bin;
    try { bin = atob(s + '==='.slice((s.length + 3) % 4)); } catch (e) { throw new Error('format'); }
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function hex(b) { return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''); }

  // Seven random words from the 2048-word list (77 bits).
  function generateKey() {
    const out = [];
    const r = new Uint16Array(WORD_KEY_LEN);
    global.crypto.getRandomValues(r);
    for (const x of r) out.push(WORDS[x & 2047]);
    return out.join(' ');
  }

  // Rough strength estimate in bits, for the strength hint only.
  function estimateBits(pass) {
    const a = analyzeKey(pass);
    if (a.kind === 'words') return a.words * 11;
    if (a.kind === 'code') return 99;
    const p = a.canonical;
    let pool = 0;
    if (/[a-z]/.test(p)) pool += 26;
    if (/[0-9]/.test(p)) pool += 10;
    if (/[^a-z0-9]/.test(p)) pool += 33;
    const unique = new Set(p).size;
    return Math.round(Math.min(p.length, unique * 1.5) * Math.log2(Math.max(pool, 1)) * 0.75);
  }

  global.NotesCrypto = { supported, createSession, split, extract, generateKey, estimateBits, analyzeKey, normalizeKey, ITERATIONS };
})(typeof window !== 'undefined' ? window : globalThis);
