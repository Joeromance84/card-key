# Card Key

A key-gated QR code tool. Static files only — no server, no database, no accounts, no third-party requests.

Live at **https://joeromance84.github.io/card-key/**

```
index.html          Landing page, key entry, access request
tool.html           The generator (locked until a key is redeemed)
share.html          Codes to hand out: contact card, tool link, generator link
card.vcf            Logan's contact card as an importable file
keys.json           The published list of live key fingerprints
assets/             Styles, key handling, QR encoder
.github/workflows/  issue-key.yml — publish or withdraw a key from anywhere
```

The key generator lives in its own repo: **[card-key-admin](https://github.com/Joeromance84/card-key-admin)** → https://joeromance84.github.io/card-key-admin/

## Issuing a key

1. Open the generator, set the term, hit **Generate key**.
2. **Copy fingerprint.**
3. **Open the publish form** → Run workflow → action `issue`, paste the fingerprint, set the expiry date, add a reference.
4. Email the key. Live in about a minute.

Works from a phone. The key itself never goes through the workflow, so the run log stays safe to leave public.

Withdrawing is the same form with action `withdraw`. Access dies on the next page load. Codes a customer already downloaded keep working — they carry the details directly and never call back here.

The workflow also prunes anything that expired more than 30 days ago, and refuses duplicate fingerprints, past dates, and malformed input.

## Getting a card onto someone's phone

Three routes, in order of how reliably they land:

1. **Send the `.vcf`.** Text or email the file. They open it, it goes into Contacts complete and spelled right. No camera involved. `Save contact file` in the tool, `Save to this phone` on the share page.
2. **Scan the link code** (33 × 33). Holds `card.vcf`'s address rather than the card itself, so it is easy for an old camera to catch. Downloads the contact file on scan. Needs a signal at that moment.
3. **Scan the card code** (53 × 53). Holds the whole card, so it works with no signal, forever. Denser, so it wants a steadier hand.

## How the gate works

- A key is 14 characters from a 31-character alphabet — about 10²⁰ possibilities.
- `0`, `O`, `1`, `I` and `L` are excluded, so a key survives being read aloud or retyped on a phone.
- `keys.json` publishes `SHA-256("SC-KEY-v1:" + key)` truncated to 128 bits. Keys cannot be recovered from it.
- Once redeemed, the browser stores a token and the tool works offline until expiry.

**What this is not.** The check runs in the customer's browser. Anyone comfortable with developer tools can bypass it, and no client-side scheme can prevent that. What you get is a receipt, an expiry you control, a revocation path, and a git-committed audit trail. If you ever need enforcement instead of accounting, `SC.redeem` in `assets/sc-core.js` is the one function to point at a server.

## Scanning

Verified end to end: an independent decoder reads the generated codes back byte-for-byte at all four damage-tolerance settings.

| Contents | Modules |
|---|---|
| Name, phone, email | 53 × 53 |
| A single link | 33 × 33 |
| Full card with socials, title, address (Medium) | 89 × 89 |

A full contact card is dense. Print it at least 4 cm across and test it before ordering a hundred. The meter under the preview says which band you are in. When density bites, switch to **One link** mode.

## Printing

The print sheet renders the code as a PNG on purpose. Browsers routinely drop SVG images out of a print job with no warning, which produces cards with a blank square where the code should be. Use the SVG for a designer or a sign shop.

## Third-party code

`assets/qrcode.js` is qrcode-generator 2.0.4 by Kazuhiko Arase, MIT licensed, vendored in full so the site makes no external requests. Everything else is original.
