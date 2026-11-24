# OAuth2 Forwarders — Specification

**Spec version:** 1 (2026-11-24)
**State format version:** 5
**Status:** draft — Worker not built yet

This document is the contract for the forwarder. The plugin side
(TrayDigita Mailer, Gmail provider) implements the other half; anything
marked *plugin* here is the plugin's job, stated so the forwarder can rely
on it.

## 1. Actors

| Actor | Role |
| --- | --- |
| Plugin (WordPress site) | Starts the flow, holds the PKCE verifier, validates the returned state, exchanges the code for tokens. |
| Google | Authorization server. Issues the code, returns `state` verbatim. |
| Forwarder (this repo) | The `redirect_uri` registered with Google. Validates the state, forwards the browser to the site. Holds nothing. |
| Browser | Carries the user through Google and back. |

## 2. Endpoints

| Path | Purpose |
| --- | --- |
| `GET /google/callback` | The `redirect_uri` registered with Google. The only live endpoint in v1. |
| `GET /<provider>/callback` | Reserved pattern for a future provider (e.g. `/microsoft/callback`). Not implemented. |

Any other path → the error page with HTTP 404. Any non-GET request →
the error page with HTTP 405.

## 3. State format (v5)

`state` is a base64url-encoded JSON object. No padding, URL-safe alphabet
(`-` and `_`, no `+`, `/`, or `=`). The JSON is the stored format —
base64url is only the transport envelope so the payload survives the URL;
the forwarder decodes it and reads proper named fields.

```json
{
  "v": 1,
  "n": "9f2c4a1e7b8d0a3f5c6e9d1a2b3c4d5e",
  "exp": 1732425600,
  "u": "https://example.com/wp-admin/admin-post.php?action=traydigita_mailer_gmail_callback",
  "s": "a3f9c2...64 hex chars"
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `v` | number | State format version. Must be `1`. |
| `n` | string | Random nonce, 32 lowercase hex chars (16 random bytes). |
| `exp` | number | Unix expiry timestamp (seconds). Plugin sets `now + 600` (10 minutes). |
| `u` | string | The site's fallback callback URL — where the forwarder redirects to. |
| `s` | string | `sign`: HMAC-SHA-256 hex (lowercase, 64 chars). See §3.1. |

Rules:

- **No `provider` field.** v1 is Google-only. A future provider is
  distinguished by the endpoint path (§2), not by the state.
- **No `algo` field.** The algorithm is fixed to SHA-256 in code. (MD5 is
  not available in the Workers runtime, SHA-1 should not be offered, and
  an attacker-controlled algorithm field would only invite a downgrade to
  the weakest hash.)
- **Size:** ~320 characters after base64url. The OAuth spec sets no maximum
  for `state`; the practical limit is URL length (keep well under ~2 KB).
  Google documents no specific cap.

### 3.1 `sign`

```
s = HMAC-SHA-256(key = n, message = u)   # hex, lowercase
```

The key is the random nonce `n` itself — the only self-contained option,
because the forwarder only receives what is inside the state.

**`s` is a corruption checksum, not tamper protection.** Anyone who sees
the state can recompute it (the key rides inside the state). Real tamper
protection would need a secret the attacker does not have — per-site keys
plus registration — which this design deliberately does not have (see
§10). State authenticity is established by the plugin's own nonce check
plus PKCE, not by the forwarder.

## 4. Forwarder validation (on return from Google)

On `GET /google/callback?code=...&state=...` (or `?error=...&state=...`),
the forwarder runs these checks, in order. **Any failure → HTTP 400 +
the error page (§6). No redirect, no forward.**

1. `state` is present and decodes as base64url to valid UTF-8 JSON.
2. `v` is the number `1`.
3. `n` matches `/^[0-9a-f]{32}$/`.
4. `exp` is a number and `exp > now` (seconds).
5. `u` matches the strict callback pattern:
   - scheme `https`,
   - any host,
   - path exactly `/wp-admin/admin-post.php`,
   - query contains `action=traydigita_mailer_gmail_callback`.
6. `s` equals `HMAC-SHA-256(key = n, message = u)`, compared in constant
   time where the runtime allows.

The forwarder does **not** check whether the nonce was ever issued — it
has no database and no memory. The plugin does that check on return (§8).

## 5. Forwarding

On success, the forwarder responds **HTTP 302** with a `Location` header:

```
<u> + ("&" if u already has "?" else "?")
    + "code=" + encodeURIComponent(code)
    + "&state=" + encodeURIComponent(state)   # the FULL state, verbatim
```

On the error path (Google returned `error` instead of `code`):

```
<u> + "&error=" + encodeURIComponent(error)
    + "&error_description=" + encodeURIComponent(error_description)   # if present
    + "&state=" + encodeURIComponent(state)
```

Rules:

- The **full state is returned verbatim** — the OAuth contract is that
  `state` comes back exactly as sent. The plugin validates the whole
  payload itself (§8); the forwarder stays a dumb forwarder and does not
  strip or rewrite the state.
- The forwarder **never calls the token endpoint** and never touches,
  stores, or logs the `code`. Codes are single-use secrets.
- The forwarder **never stores anything**: no sessions, no database, no
  cookies. Every request is validated from the state alone.

## 6. Error page

The forwarder serves **no HTML page at all** on the happy path — that path
is a pure HTTP 302. The only body it ever returns is a minimal error page
when validation fails (§4) or the path is unknown (§2).

- HTTP status: 400 (bad state) / 404 (unknown path) / 405 (wrong method).
- Content: a minimal page with a generic message, e.g. "Invalid or expired
  authorization request. Please start again from your WordPress admin."
- **No detail** about which check failed — a specific message would give
  an attacker a probe oracle.
- Branding: Pentagonal logo (`public/pentagonal-logo.svg`) — asset pending;
  the page design is tracked separately and is not part of this spec.

## 7. Google error behavior

Per RFC 6749 §4.1.2.1, when the user denies consent (or another error
occurs), Google redirects to the `redirect_uri` with `error` (+ optional
`error_description`) **and the same `state`**, e.g.
`error=access_denied&state=...`. The forwarder forwards `error` + `state`
to the fallback URL exactly like `code` (§5); the plugin shows a friendly
"you declined" message.

Exception: if the `redirect_uri` itself is invalid or unregistered,
Google shows its own error page and does **not** redirect at all — nothing
reaches the forwarder.

## 8. Plugin responsibilities

(Stated here so the forwarder can rely on them; implemented in the plugin,
not in this repo.)

- Generate `n` (16 random bytes → 32 hex chars) and `exp` (`now + 600`)
  per flow; compute `s`; build the state.
- Generate a PKCE `code_verifier` + `code_challenge` (S256) per flow.
- Store the pending flow server-side (e.g. a WordPress transient) keyed by
  `n`: the PKCE verifier and the issuing admin context.
- Build the Google authorization URL with `client_id` (shared relay
  client), `redirect_uri` = `https://transistor.pentagonal.org/google/callback`,
  `scope` = `https://www.googleapis.com/auth/gmail.send` only,
  `response_type=code`, `access_type=offline`, `prompt=consent`,
  `state`, `code_challenge`, `code_challenge_method=S256`.
- On return to its callback URL: decode the state, check `n` against the
  stored pending flow (unknown nonce → reject), check `exp` and `s`,
  then exchange `code` + `code_verifier` with Google directly.
- On `error=access_denied`: show a friendly "authorization declined"
  message; never treat it as a system error.

## 9. Shared Google OAuth client

One Google Cloud OAuth client serves all sites (see
`docs/google-cloud-setup.md`):

- Type: **Web application**.
- Authorized redirect URI: `https://transistor.pentagonal.org/google/callback`
  (exactly — scheme, host, path, and trailing slash must all match).
- Scope: `https://www.googleapis.com/auth/gmail.send` only. This is a
  **sensitive scope**: Google verification is required before public use
  (weeks); until then the client runs with test users only.

### 9.1 Client secret handling

The `client_secret` must be sent by the plugin when it exchanges the code
(Google requires it for Web application clients), so it ships inside the
public plugin code. **Treat it as a Google API requirement, not as a
security boundary.** It is effectively public and buys no security: an
attacker who holds it can do nothing that a public (PKCE-only) client
could not already do. The real security boundaries are the PKCE verifier
(§8), the consent screen (the user sees the app name before allowing),
and the state validation (§4 + §8). Never claim the client secret
protects anything in this design.

## 10. Security model

| Threat | Guard |
| --- | --- |
| Forwarder used as an open redirect to anywhere | §4 check 5: strict callback-URL pattern. |
| Corrupted / mangled state | §3.1 checksum + JSON parse + strict field validation. |
| Replayed / stale state | `exp` (10 min) + plugin nonce check (§8). |
| Stolen authorization code | PKCE — the code is useless without the verifier, held only by the plugin that started the flow. |
| Forged state | **Not prevented.** The state carries its own key, so anyone can build a valid-looking one. The damage is bounded: the forwarder only redirects to a wp-admin callback URL, and the plugin rejects any nonce it never issued. |
| Token theft through the forwarder | **Impossible by construction.** The forwarder never receives, stores, or exchanges tokens. |
| Phishing (victim bounced to a fake page, or tricked into authorizing the shared app) | **Residual risk, accepted.** The consent screen shows the shared app name; users should only authorize a flow they started from their own WordPress admin. |

What this design deliberately does **not** have: shared secrets, per-site
keys, key registration, a database, sessions, or server-side state. Adding
any of those would change the trust model and is out of scope for v1.

## 11. Limits & operations

- **Hosting:** Cloudflare Workers Free — 100,000 requests/day account-wide
  (resets midnight UTC), 10 ms CPU per request. Traffic is ~1 request per
  user connect; the validation logic runs in < 1 ms.
- **Custom domain:** `transistor.pentagonal.org` (Workers custom domain / route).
  The domain is the trust anchor users see — it must stay on the
  pentagonal.org zone.
- **Logging:** never log `code` or tokens. Request logs, if any, must not
  include query strings carrying `code`.
- **Rate limiting:** not implemented in v1; the Worker may add a simple
  per-IP limit later if abuse appears.
- **No build:** plain JavaScript, no npm dependencies, no bundler.
  Deploy with `npx wrangler deploy` or by pasting `src/index.js` in the
  Cloudflare dashboard.

## 12. Versioning

- The **state format** is versioned by the `v` field. A new state version
  means a new `v` value; the forwarder must keep accepting the previous
  version until every shipped plugin has moved on.
- This **spec** is versioned by the header at the top of this file.
