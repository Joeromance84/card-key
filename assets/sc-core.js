/* SC Core — key handling shared by the site and the admin generator.
   No network calls except the registry fetch. No analytics. No dependencies. */
(function (root) {
  'use strict';

  var SC = {};

  /* ---------------- SHA-256 (pure JS, works on file:// and old WebViews) ------------- */

  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function utf8Bytes(str) {
    var out = [], i, c;
    for (i = 0; i < str.length; i++) {
      c = str.charCodeAt(i);
      if (c < 0x80) { out.push(c); }
      else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 63)); }
      else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        var c2 = str.charCodeAt(i + 1);
        var cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
        i++;
        out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
      } else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); }
    }
    return out;
  }

  SC.sha256hex = function (str) {
    var bytes = utf8Bytes(str);
    var bitLen = bytes.length * 8;
    bytes = bytes.slice();
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) { bytes.push(0); }
    var hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
    bytes.push((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255);
    bytes.push((lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255);

    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var w = new Array(64), i, t;

    for (i = 0; i < bytes.length; i += 64) {
      for (t = 0; t < 16; t++) {
        w[t] = (bytes[i + t * 4] << 24) | (bytes[i + t * 4 + 1] << 16) | (bytes[i + t * 4 + 2] << 8) | bytes[i + t * 4 + 3];
      }
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[t] + w[t]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    var hex = '';
    for (i = 0; i < 8; i++) {
      hex += ('00000000' + (H[i] >>> 0).toString(16)).slice(-8);
    }
    return hex;
  };

  /* ---------------- Key format ------------------------------------------------------ */

  /* Ambiguous characters (0 O 1 I L) are excluded so a key can be read aloud,
     written down, or retyped on a phone keyboard without guesswork. */
  SC.ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
  SC.PREFIX = 'SC';
  SC.LENGTH = 14;
  SC.DOMAIN = 'SC-KEY-v1:';

  SC.randomKey = function () {
    var out = '', n = SC.ALPHABET.length, buf, i, v;
    var max = 256 - (256 % n);
    while (out.length < SC.LENGTH) {
      buf = new Uint8Array(32);
      root.crypto.getRandomValues(buf);
      for (i = 0; i < buf.length && out.length < SC.LENGTH; i++) {
        v = buf[i];
        if (v < max) { out += SC.ALPHABET.charAt(v % n); }
      }
    }
    return SC.PREFIX + '-' + out;
  };

  /* Accepts sc 7k9m 2p5q..., SC-7K9M-2P5Q-..., or the bare 14 characters. */
  SC.normalizeKey = function (input) {
    var raw = String(input || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (raw.indexOf(SC.PREFIX) === 0) { raw = raw.slice(SC.PREFIX.length); }
    if (!raw) { return { ok: false, error: 'Enter your access key.' }; }
    if (raw.length !== SC.LENGTH) {
      return { ok: false, error: 'A key has ' + SC.LENGTH + ' characters after SC-. This one has ' + raw.length + '.' };
    }
    for (var i = 0; i < raw.length; i++) {
      if (SC.ALPHABET.indexOf(raw.charAt(i)) === -1) {
        return { ok: false, error: 'The character "' + raw.charAt(i) + '" is not used in keys. Keys never contain 0, O, 1, I or L.' };
      }
    }
    return { ok: true, key: SC.PREFIX + '-' + raw };
  };

  SC.formatKey = function (key) {
    var raw = key.replace(/[^A-Z0-9]/g, '').replace(/^SC/, '');
    return SC.PREFIX + '-' + raw.slice(0, 4) + '-' + raw.slice(4, 8) + '-' + raw.slice(8, 12) + '-' + raw.slice(12);
  };

  /* The registry publishes fingerprints, never keys. */
  SC.fingerprint = function (key) {
    return SC.sha256hex(SC.DOMAIN + key).slice(0, 32);
  };

  /* ---------------- Dates ----------------------------------------------------------- */

  SC.today = function () { return new Date().toISOString().slice(0, 10); };

  SC.addDays = function (days) {
    var d = new Date();
    d.setDate(d.getDate() + Number(days));
    return d.toISOString().slice(0, 10);
  };

  SC.daysLeft = function (expiry) {
    var a = new Date(SC.today() + 'T00:00:00Z').getTime();
    var b = new Date(expiry + 'T00:00:00Z').getTime();
    return Math.round((b - a) / 86400000);
  };

  /* ---------------- Registry + unlock ----------------------------------------------- */

  SC.STORE = 'sc.unlock.v1';

  SC.readToken = function () {
    try {
      var t = JSON.parse(root.localStorage.getItem(SC.STORE));
      if (t && t.key && t.expires) { return t; }
    } catch (e) { }
    return null;
  };

  SC.writeToken = function (t) {
    try { root.localStorage.setItem(SC.STORE, JSON.stringify(t)); } catch (e) { }
  };

  SC.clearToken = function () {
    try { root.localStorage.removeItem(SC.STORE); } catch (e) { }
  };

  /* A locally stored token is a cache, never the authority. It is good on its
     own only while the registry is unreachable, and only for a short while. */
  SC.GRACE_DAYS = 3;

  SC.activeToken = function () {
    var t = SC.readToken();
    if (!t) { return null; }
    if (SC.daysLeft(t.expires) < 0) { return null; }
    return t;
  };

  /* Re-check the stored token against the published list.
     cb(state, detail) where state is 'ok', 'revoked', 'expired', 'none' or 'stale'. */
  SC.verifyToken = function (cb) {
    var t = SC.readToken();
    if (!t) { cb('none'); return; }
    if (SC.daysLeft(t.expires) < 0) { SC.clearToken(); cb('expired', t); return; }

    SC.post({ action: 'check', key: t.key }, function (err, r) {
      if (err) {
        var since = t.checked ? -SC.daysLeft(t.checked) : 999;
        cb(since <= SC.GRACE_DAYS ? 'ok' : 'stale', t);
        return;
      }
      if (!r) { cb('stale', t); return; }
      if (r.reason === 'unknown') { SC.clearToken(); cb('revoked', t); return; }
      if (r.reason === 'expired') { SC.clearToken(); cb('expired', t); return; }
      if (r.reason === 'spent') {
        /* Spent by us is the finished card. Spent by someone else is a stolen key. */
        if (t.done) { t.checked = SC.today(); SC.writeToken(t); cb('ok', t); }
        else { SC.clearToken(); cb('spent_elsewhere', t); }
        return;
      }
      t.expires = r.expires;
      t.checked = SC.today();
      SC.writeToken(t);
      cb('ok', t);
    });
  };

  SC.API = 'api/key';

  /* Everything that decides anything happens on the server now. */
  SC.post = function (payload, cb) {
    try {
      var x = new XMLHttpRequest();
      x.open('POST', SC.API, true);
      x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () {
        try { cb(null, JSON.parse(x.responseText)); }
        catch (e) { cb('The key service gave an answer this page could not read.'); }
      };
      x.onerror = function () { cb('The key service could not be reached.'); };
      x.send(JSON.stringify(payload));
    } catch (e) { cb('The key service could not be reached.'); }
  };

  /* cb(result): {ok:true, token} or {ok:false, error, reason, cardUrl} */
  SC.redeem = function (input, cb) {
    var norm = SC.normalizeKey(input);
    if (!norm.ok) { cb({ ok: false, error: norm.error }); return; }

    SC.post({ action: 'check', key: norm.key }, function (err, r) {
      if (err) { cb({ ok: false, error: err }); return; }
      if (!r || !r.ok) {
        cb({ ok: false, reason: r && r.reason, cardUrl: r && r.cardUrl,
             error: (r && r.error) || 'That key cannot be used.' });
        return;
      }
      var token = {
        key: norm.key, fp: SC.fingerprint(norm.key), expires: r.expires,
        label: r.label || '', redeemed: SC.today(), checked: SC.today()
      };
      SC.writeToken(token);
      cb({ ok: true, token: token, daysLeft: r.daysLeft });
    });
  };

  root.SC = SC;
})(typeof window !== 'undefined' ? window : this);
