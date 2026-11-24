# Transistor

Stateless, public OAuth2 authorization-code forwarder running on Cloudflare Workers.

It lets a WordPress site offer one-click Google sign-in ("Login with Gmail")
without every site registering its own Google Cloud OAuth client. The
forwarder holds **no tokens, no codes, no sessions, and no database** — it
only validates the `state` and forwards the browser on.

> **Status:** Deployed and verified live at
> `https://transistor.pentagonal.org` (Worker version `70e8817f`).
> The Google client for this project is set up for **email (Gmail)** —
> see [Gmail scopes](#gmail-scopes-email) below.

## How it works

1. The plugin builds a `state` (base64url JSON, see `docs/spec.md`) and
   redirects the user to Google's authorization endpoint. The `redirect_uri`
   is the forwarder: `https://transistor.pentagonal.org/oauth2`.
2. The user signs in and allows the app (Gmail scopes — see
   [Gmail scopes](#gmail-scopes-email)).
3. Google redirects back to the forwarder with `code` + `state`
   (or `error` + `state` if the user denies).
4. The forwarder validates the state and issues an HTTP 302 to the site's
   own callback URL, appending `code` and the full `state` verbatim.
5. The plugin validates the returned state itself (nonce, expiry, signature)
   and exchanges the code with Google directly, using its own PKCE verifier.
   The forwarder never sees the tokens.

## Who can use it

Anyone. There is no registration, no API key, and no per-site setup:
any WordPress site running a compatible plugin can use
`https://transistor.pentagonal.org` as its forwarder. The relay itself
needs only its own deployment config (`wrangler.toml`: the domain) and
the one shared Google client — nothing per site, no database, no key
management.

## One callback, no provider

There is exactly one callback path: `/oauth2`. The forwarder is
provider-agnostic — it does not know or care which provider the flow
came from. There is no `provider` field in the state and no provider
in the path: the plugin knows which provider it started, the
forwarder only validates the state and forwards. A second provider
reuses the same path.

## Supported providers

Updated as providers are added.

| Provider | Status | Callback path | Scope |
| --- | --- | --- | --- |
| Google | ✅ Supported (v1) | `/oauth2` | Gmail: send + read-only + userinfo (see below) |

## Gmail scopes (email)

The Google client for this project (`oauth2-transistor`) is set up
specifically for **email (Gmail)**. These are the 4 scopes registered
on its consent screen (Google Auth Platform → Data Access):

| Scope | What it allows | Google class |
| --- | --- | --- |
| `https://www.googleapis.com/auth/userinfo.email` | See the user's primary Google Account email address | Non-sensitive |
| `https://www.googleapis.com/auth/userinfo.profile` | See the user's personal info | Non-sensitive |
| `https://www.googleapis.com/auth/gmail.send` | Send email on the user's behalf | Sensitive |
| `https://www.googleapis.com/auth/gmail.readonly` | View the user's email messages and settings | Restricted |

Together they cover a basic webmail: identify the user
(`userinfo.email` + `userinfo.profile`), read the inbox
(`gmail.readonly`), and send mail (`gmail.send`). The forwarder
itself is scope-agnostic — it never reads or checks scopes; these
are the scopes this Google client requests.

Note: `gmail.readonly` is a **restricted** scope, so opening this
client to the public requires completing Google's verification
process. Until then only listed test users can sign in.

## Repo layout

```
wrangler.toml            # Worker name, custom domain, compatibility date
src/index.js             # the Worker
public/
  index.html             # home page — minimal: the animated Transistor
                         # logo, name, slogan ("Where Modules Connect."),
                         # footer links. Nothing else.
  about.html             # about the service (English)
  privacy.html           # privacy policy (English)
  terms.html             # terms of service (English)
  error.html             # modern error page (big gradient status code,
                         # logo, button); {{ERROR_CODE}} / {{ERROR_TITLE}}
                         # / {{ERROR_MESSAGE}} placeholders the Worker
                         # fills in per status (400/404/405)
  robots.txt             # disallows callback paths; public pages noindex via meta + header
  assets/images/logo/    # Transistor logo: SVG + PNG 1024 + sizes
                         # 16/32/48/120/180/192/512 (120px = Google OAuth icon)
docs/
  spec.md                # full specification (state format, checks, forward, errors)
  google-cloud-setup.md  # creating the shared Google OAuth client
```

Pages are plain static HTML with **inline CSS** (no separate stylesheet,
no build step). The logo is the Transistor icon; the favicon is the 32px
PNG (16px + 180px Apple touch icon also linked).

Legal pages: `https://transistor.pentagonal.org/privacy` and
`/terms` (English). The privacy policy URL is the one Google's OAuth verification
asks for.

## Deploy

No build step, no npm dependencies — plain JavaScript + static files.

- With Wrangler: `npx wrangler deploy`
- Or paste `src/index.js` in the Cloudflare dashboard.

## Analytics (Google Tag Manager)

Set `GTM_ID` in `wrangler.toml` `[vars]` to a GTM container ID
(`GTM-...`) and the Worker injects the Google Tag Manager snippet
into `<head>` (plus the `<noscript>` fallback after `<body>`) of
every HTML page it serves (home, about, privacy, terms, error page).
Empty or missing = no snippet, pages served as-is. The ID is public
(it ships in the page source), so it is a plain var, not a secret.
Non-HTML assets (images, robots.txt) are never touched, and the
`/oauth2` redirect is unaffected.

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
