/* Card Key — Worker entry point.
 *
 * Static files are served by the ASSETS binding. Anything under /api is
 * handled here, and /c/<slug> serves a hosted contact card.
 *
 * The browser can lie about everything; this is the only thing that decides
 * whether a key is good, whether it is already spent, and what a card holds.
 */

const ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
const PREFIX = 'SC';
const LENGTH = 14;
const DOMAIN = 'SC-KEY-v1:';

/* A photo at 250px/JPEG lands around 8-20 KB once base64'd. 400 KB is a
   generous ceiling that still refuses anything pathological. */
const MAX_CARD_BYTES = 400 * 1024;
const SLUG_LENGTH = 10;

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

/* Unguessable in practice: 31^10 is about 8 x 10^14. */
function makeSlug() {
  const buf = new Uint8Array(SLUG_LENGTH * 2);
  crypto.getRandomValues(buf);
  let out = '';
  const max = 256 - (256 % ALPHABET.length);
  for (let i = 0; i < buf.length && out.length < SLUG_LENGTH; i++) {
    if (buf[i] < max) { out += ALPHABET.charAt(buf[i] % ALPHABET.length); }
  }
  return out.toLowerCase();
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

/* The edit token is the only thing standing between a stranger and the
   details on somebody's printed cards. It is shown once and stored hashed. */
function makeToken() {
  const buf = new Uint8Array(48);
  crypto.getRandomValues(buf);
  let out = '';
  const max = 256 - (256 % ALPHABET.length);
  for (let i = 0; i < buf.length && out.length < 20; i++) {
    if (buf[i] < max) { out += ALPHABET.charAt(buf[i] % ALPHABET.length); }
  }
  return out;
}

async function hashToken(token) {
  const bytes = new TextEncoder().encode('SC-EDIT-v1:' + token);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

/* Constant-time compare, so a wrong token leaks nothing by how long it took. */
function sameHash(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) { return false; }
  let diff = 0;
  for (let i = 0; i < a.length; i++) { diff |= a.charCodeAt(i) ^ b.charCodeAt(i); }
  return diff === 0;
}

function daysLeft(expiry) {
  const a = Date.parse(today() + 'T00:00:00Z');
  const b = Date.parse(expiry + 'T00:00:00Z');
  return Math.round((b - a) / 86400000);
}

async function loadRegistry(env, request) {
  const url = new URL('/keys.json', new URL(request.url).origin);
  const res = await env.ASSETS.fetch(new Request(url.toString()));
  if (!res.ok) { throw new Error('registry unavailable'); }
  const data = await res.json();
  return (data && data.keys) || [];
}

/* A hosted card is only accepted if it really is a vCard. */
function validateCard(vcf) {
  if (typeof vcf !== 'string' || !vcf) { return 'A card must be supplied as text.'; }
  const bytes = new TextEncoder().encode(vcf).length;
  if (bytes > MAX_CARD_BYTES) {
    return 'That card is ' + Math.round(bytes / 1024) + ' KB, over the ' +
           Math.round(MAX_CARD_BYTES / 1024) + ' KB limit. Use a smaller photo.';
  }
  if (!/^BEGIN:VCARD/.test(vcf.trim())) { return 'That does not look like a contact card.'; }
  if (!/END:VCARD\s*$/.test(vcf.trim())) { return 'That contact card is incomplete.'; }
  return null;
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
  const origin = new URL(request.url).origin;

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
      /* Returned so somebody who lost the link can get it back with their key. */
      slug: record && record.slug ? record.slug : null,
      cardUrl: record && record.slug ? origin + '/c/' + record.slug : null,
      error: record
        ? 'That key has already been used to make a card, on ' + record.at + '. Each key makes one card.'
        : null
    });
  }

  /* action === 'spend' */
  if (record) {
    return json({ ok: false, reason: 'spent', spentAt: record.at,
      slug: record.slug || null,
      cardUrl: record.slug ? origin + '/c/' + record.slug : null,
      error: 'That key was already used on ' + record.at + '. Each key makes one card.' });
  }

  /* Hosting the card is optional: a card with no photo works fine embedded
     in the QR itself, and never needs us at all. */
  let slug = null;
  let editToken = null;
  if (body.vcf) {
    const bad = validateCard(body.vcf);
    if (bad) { return json({ ok: false, reason: 'bad_card', error: bad }, 400); }

    slug = makeSlug();
    editToken = makeToken();
    await env.SPENT.put('card:' + slug, JSON.stringify({
      vcf: body.vcf,
      name: typeof body.name === 'string' ? body.name.slice(0, 120) : '',
      at: today(),
      updated: today(),
      revision: 1,
      tokenHash: await hashToken(editToken),
      fp: fp
    }));
  }

  await env.SPENT.put(fp, JSON.stringify({
    at: today(),
    label: hit.label || '',
    expires: hit.expires,
    slug: slug
  }));

  return json({
    ok: true,
    reason: 'spent_now',
    spentAt: today(),
    expires: hit.expires,
    label: hit.label || '',
    slug: slug,
    cardUrl: slug ? origin + '/c/' + slug : null,
    /* Shown once. Not recoverable, by design. */
    editToken: editToken
  });
}

/* Update a hosted card. The printed QR never changes; what it serves does. */
async function handleCardUpdate(request, env) {
  if (request.method !== 'POST') { return json({ ok: false, error: 'POST only.' }, 405); }
  if (!env.SPENT) { return json({ ok: false, reason: 'unconfigured', error: 'Not set up yet.' }, 503); }

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ ok: false, error: 'Malformed request.' }, 400); }

  const slug = String(body.slug || '').replace(/\.vcf$/i, '').toLowerCase();
  if (!/^[a-z0-9]{4,20}$/.test(slug)) {
    return json({ ok: false, reason: 'not_found', error: 'No such card.' }, 404);
  }

  const rec = await env.SPENT.get('card:' + slug, { type: 'json' });
  if (!rec) { return json({ ok: false, reason: 'not_found', error: 'No such card.' }, 404); }

  if (!rec.tokenHash) {
    return json({ ok: false, reason: 'not_editable',
      error: 'This card was made before editing existed and cannot be changed.' }, 409);
  }

  const given = await hashToken(String(body.token || ''));
  if (!sameHash(given, rec.tokenHash)) {
    return json({ ok: false, reason: 'denied',
      error: 'That edit code does not match this card.' }, 403);
  }

  const bad = validateCard(body.vcf);
  if (bad) { return json({ ok: false, reason: 'bad_card', error: bad }, 400); }

  const updated = {
    vcf: body.vcf,
    name: typeof body.name === 'string' && body.name ? body.name.slice(0, 120) : rec.name,
    at: rec.at,
    updated: today(),
    revision: (rec.revision || 1) + 1,
    tokenHash: rec.tokenHash,
    fp: rec.fp
  };
  await env.SPENT.put('card:' + slug, JSON.stringify(updated));

  return json({
    ok: true,
    slug: slug,
    revision: updated.revision,
    updated: updated.updated,
    cardUrl: new URL(request.url).origin + '/c/' + slug
  });
}

/* Serve a hosted card. This is what a phone hits when the QR is scanned. */
async function handleCard(request, env, slug) {
  slug = slug.replace(/\.vcf$/i, '').toLowerCase();
  if (!/^[a-z0-9]{4,20}$/.test(slug)) {
    return new Response('Not found.', { status: 404, headers: { 'Content-Type': 'text/plain' } });
  }

  const rec = await env.SPENT.get('card:' + slug, { type: 'json' });
  if (!rec) {
    return new Response(
      'This contact card is no longer available.',
      { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
    );
  }

  const name = (rec.name || 'contact').toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-|-$/g, '') || 'contact';

  return new Response(rec.vcf, {
    headers: {
      /* text/x-vcard is what phones actually act on. */
      'Content-Type': 'text/x-vcard; charset=utf-8',
      'Content-Disposition': 'attachment; filename="' + name + '.vcf"',
      /* Cards can be edited after printing, so revalidate often.
         A long cache here would strand people on stale details. */
      'Cache-Control': 'public, max-age=60, must-revalidate',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/key') { return handleKey(request, env); }

    if (url.pathname === '/api/card') { return handleCardUpdate(request, env); }

    if (url.pathname === '/api/health') {
      return json({
        ok: true,
        worker: 'card-key',
        kvBound: !!env.SPENT,
        assetsBound: !!env.ASSETS,
        hostedCards: true,
        maxCardKB: Math.round(MAX_CARD_BYTES / 1024),
        time: new Date().toISOString()
      });
    }

    if (url.pathname.startsWith('/api/')) {
      return json({ ok: false, error: 'No such endpoint.' }, 404);
    }

    if (url.pathname.startsWith('/c/')) {
      return handleCard(request, env, url.pathname.slice(3));
    }

    /* Pages and scripts must never be served from a stale cache. A phone
       holding yesterday's JavaScript looks exactly like a broken site, and
       the person seeing it has no way to tell the difference. */
    const asset = await env.ASSETS.fetch(request);
    if (/\.(html|js|css|json)$/.test(url.pathname) || url.pathname === '/' || url.pathname.endsWith('/')) {
      const fresh = new Response(asset.body, asset);
      fresh.headers.set('Cache-Control', 'no-cache, must-revalidate');
      return fresh;
    }
    return asset;
  }
};
