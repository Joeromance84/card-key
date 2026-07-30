/* Card Key — Worker entry point.
 *
 * Static files are served by the ASSETS binding. Anything under /api is
 * handled here. The browser can lie about everything; this is the only
 * thing that decides whether a key is good and whether it is already spent.
 */

const ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
const PREFIX = 'SC';
const LENGTH = 14;
const DOMAIN = 'SC-KEY-v1:';

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

/* Must match SC.normalizeKey in assets/sc-core.js exactly. */
function normalizeKey(input) {
  let raw = String(input || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (raw.indexOf(PREFIX) === 0) { raw = raw.slice(PREFIX.length); }
  if (raw.length !== LENGTH) { return null; }
  for (const ch of raw) {
    if (ALPHABET.indexOf(ch) === -1) { return null; }
  }
  return PREFIX + '-' + raw;
}

/* Must match SC.fingerprint in assets/sc-core.js exactly. */
async function fingerprint(key) {
  const bytes = new TextEncoder().encode(DOMAIN + key);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 32);
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

function daysLeft(expiry) {
  const a = Date.parse(today() + 'T00:00:00Z');
  const b = Date.parse(expiry + 'T00:00:00Z');
  return Math.round((b - a) / 86400000);
}

/* Issuance still lives in keys.json in the repo. Only consumption lives in KV. */
async function loadRegistry(env, request) {
  const url = new URL('/keys.json', new URL(request.url).origin);
  const res = await env.ASSETS.fetch(new Request(url.toString()));
  if (!res.ok) { throw new Error('registry unavailable'); }
  const data = await res.json();
  return (data && data.keys) || [];
}

async function handleKey(request, env) {
  if (request.method !== 'POST') {
    return json({ ok: false, error: 'POST only.' }, 405);
  }
  if (!env.SPENT) {
    return json({ ok: false, reason: 'unconfigured',
      error: 'The key service is not finished being set up. Nothing has been used.' }, 503);
  }

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ ok: false, reason: 'bad_request', error: 'Malformed request.' }, 400); }

  const action = body.action === 'spend' ? 'spend' : 'check';
  const key = normalizeKey(body.key);
  if (!key) {
    return json({ ok: false, reason: 'malformed',
      error: 'That does not look like a key. Keys are 14 characters after SC- and never contain 0, O, 1, I or L.' }, 400);
  }

  const fp = await fingerprint(key);

  let issued;
  try { issued = await loadRegistry(env, request); }
  catch (e) {
    return json({ ok: false, reason: 'unavailable',
      error: 'The key list could not be read just now. Try again in a moment.' }, 503);
  }

  const hit = issued.find(function (k) { return k.fp === fp; });
  if (!hit) {
    return json({ ok: false, reason: 'unknown',
      error: 'That key is not on the active list. If you have only just been sent it, wait a minute and try again.' });
  }

  const left = daysLeft(hit.expires);
  if (left < 0) {
    return json({ ok: false, reason: 'expired', expires: hit.expires,
      error: 'That key expired on ' + hit.expires + '.' });
  }

  const record = await env.SPENT.get(fp, { type: 'json' });

  if (action === 'check') {
    return json({
      ok: !record,
      reason: record ? 'spent' : 'available',
      expires: hit.expires,
      label: hit.label || '',
      daysLeft: left,
      spentAt: record ? record.at : null,
      error: record
        ? 'That key has already been used to make a card, on ' + record.at + '. Each key makes one card.'
        : null
    });
  }

  if (record) {
    return json({ ok: false, reason: 'spent', spentAt: record.at,
      error: 'That key was already used on ' + record.at + '. Each key makes one card.' });
  }

  await env.SPENT.put(fp, JSON.stringify({
    at: today(),
    label: hit.label || '',
    expires: hit.expires
  }));

  return json({ ok: true, reason: 'spent_now', spentAt: today(), expires: hit.expires, label: hit.label || '' });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/key') { return handleKey(request, env); }

    /* A quick way to confirm the Worker is live and wired to KV. */
    if (url.pathname === '/api/health') {
      return json({
        ok: true,
        worker: 'card-key',
        kvBound: !!env.SPENT,
        assetsBound: !!env.ASSETS,
        time: new Date().toISOString()
      });
    }

    if (url.pathname.startsWith('/api/')) {
      return json({ ok: false, error: 'No such endpoint.' }, 404);
    }

    return env.ASSETS.fetch(request);
  }
};
