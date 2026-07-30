/* Server-side key enforcement for Card Key.
 *
 * The browser can lie about everything. This endpoint is the only thing that
 * decides whether a key is good and whether it has already been used.
 *
 * POST /api/key   { action: "check" | "spend", key: "SC-..." }
 *
 * Requires a KV binding named SPENT (namespace: card-key-spent).
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

/* The issued list still lives in the repo; only consumption lives in KV. */
async function loadRegistry(request) {
  const url = new URL('/keys.json', request.url);
  const res = await fetch(url.toString(), { cf: { cacheTtl: 30 } });
  if (!res.ok) { throw new Error('registry unavailable'); }
  const data = await res.json();
  return (data && data.keys) || [];
}

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.SPENT) {
    return json({ ok: false, reason: 'unconfigured',
      error: 'The key service is not finished being set up. Nothing has been charged or used.' }, 503);
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
  try { issued = await loadRegistry(request); }
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

  /* action === 'spend' */
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

/* Anything other than POST gets a clear answer rather than a stack trace. */
export async function onRequest(context) {
  if (context.request.method === 'POST') { return onRequestPost(context); }
  if (context.request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Allow': 'POST, OPTIONS' } });
  }
  return json({ ok: false, error: 'POST only.' }, 405);
}
