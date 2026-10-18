/* Notes crypto: AES-256-GCM with a PBKDF2-SHA-256 derived key.
 *
 * Wire format (base64url, no padding):
 *   [0]      version (1)
 *   [1]      flags   (bit0 = payload deflate-raw compressed)
 *   [2..17]  salt    (16 random bytes, PBKDF2)
 *   [18..29] iv      (12 random bytes, AES-GCM nonce)
 *   [30..]   ciphertext + 16-byte GCM tag
 * The 30 header bytes are bound to the ciphertext as additional data, so any
 * change to version, flags, salt or iv makes decryption fail.
 *
 * Plaintext: "<unix minutes>\x1f<title>\x1f<message>" as UTF-8.
 */
(function (global) {
  'use strict';

  const VERSION = 1;
  const ITERATIONS = 600000; // OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
  const SALT_LEN = 16;
  const IV_LEN = 12;
  const HEADER_LEN = 2 + SALT_LEN + IV_LEN;
  const SEP = '\x1f';

  const subtle = global.crypto && global.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder('utf-8', { fatal: true });

  function supported() {
    return !!(subtle && global.crypto.getRandomValues);
  }

  function random(n) {
    return global.crypto.getRandomValues(new Uint8Array(n));
  }

  function normalizeKey(pass) {
    return String(pass).normalize('NFKC').trim();
  }

  async function deriveKey(pass, salt) {
    const base = await subtle.importKey('raw', enc.encode(normalizeKey(pass)), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // A session holds one derived key and its salt so each Send is instant
  // (keeps the tap "fresh" for the share sheet). Every note still gets a new
  // random 96-bit IV. Decryption derives (and caches) keys per salt.
  function createSession(pass) {
    const passphrase = normalizeKey(pass);
    const salt = random(SALT_LEN);
    const cache = new Map();
    const ready = deriveKey(passphrase, salt).then((k) => { cache.set(hex(salt), Promise.resolve(k)); return k; });
    let destroyed = false;

    function keyFor(s) {
      if (destroyed) throw new Error('locked');
      const id = hex(s);
      if (!cache.has(id)) cache.set(id, deriveKey(passphrase, s));
      return cache.get(id);
    }

    return {
      ready,
      async encrypt(title, message) {
        const key = await ready;
        if (destroyed) throw new Error('locked');
        const minutes = Math.floor(Date.now() / 60000);
        let data = enc.encode(minutes + SEP + title + SEP + message);
        let flags = 0;
        const packed = await deflate(data);
        if (packed && packed.length < data.length) { data = packed; flags |= 1; }
        const iv = random(IV_LEN);
        const header = new Uint8Array(HEADER_LEN);
        header[0] = VERSION; header[1] = flags;
        header.set(salt, 2); header.set(iv, 2 + SALT_LEN);
        const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: header, tagLength: 128 }, key, data));
        data.fill(0);
        const out = new Uint8Array(HEADER_LEN + ct.length);
        out.set(header, 0); out.set(ct, HEADER_LEN);
        return b64url(out);
      },
      async decrypt(text) {
        const bytes = fromB64url(extract(text));
        if (bytes.length < HEADER_LEN + 16 || bytes[0] !== VERSION) throw new Error('format');
        const header = bytes.subarray(0, HEADER_LEN);
        const s = bytes.slice(2, 2 + SALT_LEN);
        const iv = bytes.slice(2 + SALT_LEN, HEADER_LEN);
        const key = await keyFor(s);
        let pt;
        try {
          pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: header, tagLength: 128 }, key, bytes.subarray(HEADER_LEN)));
        } catch (e) { throw new Error('key'); }
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

  // 20 characters from a 31-symbol alphabet without look-alikes (~99 bits).
  function generateKey() {
    const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
    let out = '';
    while (out.length < 20) {
      const b = random(32);
      for (const x of b) { if (x < 248 && out.length < 20) out += alphabet[x % 31]; }
    }
    return out.match(/.{5}/g).join('-');
  }

  // Rough entropy estimate in bits, for the strength hint only.
  function estimateBits(pass) {
    const p = normalizeKey(pass);
    if (/^[a-hjkmnp-z2-9]{5}(-[a-hjkmnp-z2-9]{5}){3}$/.test(p)) return 99;
    let pool = 0;
    if (/[a-z]/.test(p)) pool += 26;
    if (/[A-Z]/.test(p)) pool += 26;
    if (/[0-9]/.test(p)) pool += 10;
    if (/[^A-Za-z0-9]/.test(p)) pool += 33;
    const unique = new Set(p).size;
    return Math.round(Math.min(p.length, unique * 1.5) * Math.log2(Math.max(pool, 1)) * 0.75);
  }

  global.NotesCrypto = { supported, createSession, split, extract, generateKey, estimateBits, ITERATIONS };
})(typeof window !== 'undefined' ? window : globalThis);
