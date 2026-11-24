# OAuth2 Forwarders

Stateless, public OAuth2 authorization-code forwarder running on Cloudflare Workers.

It lets a WordPress site offer one-click Google sign-in ("Login with Gmail")
without every site registering its own Google Cloud OAuth client. The
forwarder holds **no tokens, no codes, no sessions, and no database** — it
only validates the `state` and forwards the browser on.

> **Status:** spec + docs. The Worker itself is not built yet.

## How it works

1. The plugin builds a `state` (base64url JSON, see `docs/spec.md`) and
   redirects the user to Google's authorization endpoint. The `redirect_uri`
   is the forwarder: `https://transistor.pentagonal.org/google/callback`.
2. The user signs in and allows the app (scope: `gmail.send` only).
3. Google redirects back to the forwarder with `code` + `state`
   (or `error` + `state` if the user denies).
4. The forwarder validates the state and issues an HTTP 302 to the site's
   own callback URL, appending `code` and the full `state` verbatim.
5. The plugin validates the returned state itself (nonce, expiry, signature)
   and exchanges the code with Google directly, using its own PKCE verifier.
   The forwarder never sees the tokens.

## No provider field

Version 1 is Google-only. There is no `provider` field in the state. If a
second provider is ever added, it gets its own path
(`https://transistor.pentagonal.org/microsoft/callback`), not a field in the state.

## Supported providers

Updated as providers are added.

| Provider | Status | Callback path | Scope |
| --- | --- | --- | --- |
| Google | ✅ Supported (v1) | `/google/callback` | `gmail.send` |
| Microsoft | Planned | `/microsoft/callback` | — |
| Yahoo | Planned | `/yahoo/callback` | — |

## Repo layout

```
wrangler.toml            # Worker name, custom domain, compatibility date
src/index.js             # the Worker (not built yet)
public/
  site.css               # shared styles for the public pages
  about.html             # about the service (English)
  privacy.html           # privacy policy (English)
  terms.html             # terms of service (English)
  error.html             # minimal error page (design pending logo asset)
  error.css
  pentagonal-logo.svg    # pending — logo file not in the repo yet
docs/
  spec.md                # full specification (state format, checks, forward, errors)
  google-cloud-setup.md  # creating the shared Google OAuth client
```

Legal pages: `https://transistor.pentagonal.org/privacy` and
`/terms` (English). The privacy policy URL is the one Google's OAuth verification
asks for.

## Deploy

No build step, no npm dependencies — plain JavaScript + static files.

- With Wrangler: `npx wrangler deploy`
- Or paste `src/index.js` in the Cloudflare dashboard.

## Security model (short version)

- The forwarder only forwards to a strict callback-URL pattern
  (`/wp-admin/admin-post.php?action=traydigita_mailer_gmail_callback`).
- The plugin validates its own state nonce + expiry on return.
- PKCE binds the authorization code to the plugin that started the flow —
  a stolen code is useless without the verifier.
- The `sign` field in the state is a corruption checksum only, not tamper
  protection (the key rides inside the state). See `docs/spec.md`.
- Residual risk, accepted: open-redirect phishing — a victim could be
  bounced to a fake page. No token theft is possible through the forwarder.

## Limits

Cloudflare Workers Free: 100,000 requests/day (account-wide, resets midnight
UTC), 10 ms CPU per request. This service makes ~1 request per user connect,
logic < 1 ms.
