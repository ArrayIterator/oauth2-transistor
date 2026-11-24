# Google Cloud setup — the shared OAuth client

One Google Cloud OAuth client serves every site that uses the forwarder.
This is a **one-time, human task** in the Google Cloud Console. It is not
part of the Worker code.

> **Scope requested:** `https://www.googleapis.com/auth/gmail.send` only —
> send mail, no mailbox read. This is a **sensitive scope**, so Google
> verification is required before the client can be used publicly (see
> step 5). Until verification completes, the client only works for test
> users.

## 1. Create the project

1. Go to [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project (name it e.g. `Pentagonal OAuth Relay`).
3. No billing is needed for OAuth sign-in.

## 2. Configure the OAuth consent screen

APIs & Services → OAuth consent screen.

- User type: **External**.
- App name: `TrayDigita Mailer` (this is what users see on the consent
  screen — it must match what they expect when connecting Gmail from
  their WordPress admin).
- User support email: your support address.
- App domain / authorized domains: add `pentagonal.org`.
- Developer contact email: your address.
- Scopes → Add: `https://www.googleapis.com/auth/gmail.send`. Nothing
  else. Do not add `userinfo.email`, `gmail.readonly`, or any other scope.
- Test users (while the app is in Testing): add your own Google account(s).
  Only test users can authorize until verification completes.

## 3. Create the OAuth client

APIs & Services → Credentials → Create Credentials → OAuth client ID.

- Application type: **Web application**.
- Name: e.g. `TrayDigita Mailer Relay`.
- Authorized redirect URIs — add exactly this one (no trailing slash):

```
https://transistor.pentagonal.org/google/callback
```

Google matches the redirect URI **exactly** — scheme, host, path, and
trailing slash must all match the value the plugin sends. If it does not
match, Google returns `redirect_uri_mismatch` and shows its own error
page instead of redirecting.

Save the resulting **Client ID** and **Client secret**.

## 4. Where the credentials go

| Credential | Where it goes | Secrecy |
| --- | --- | --- |
| Client ID | Shipped in the public plugin code (it appears in the authorization URL anyway). | Public. |
| Client secret | Shipped in the public plugin code — the plugin must send it when exchanging the code. | **Effectively public.** See `spec.md` §9.1: it is a Google API requirement, not a security boundary. Do not claim otherwise. |

## 5. Verification (before public use)

Because `gmail.send` is a sensitive scope, Google requires app
verification before the client leaves Testing mode:

1. In the consent screen, click **Publish app** → **Prepare for
   verification**.
2. Provide the requested information (app description, why the scope is
   needed, a privacy policy URL, a demo video of the flow).
3. Verification typically takes **days to weeks**. Until it passes, only
   test users can authorize — everyone else sees an "unverified app"
   warning (and, after the test-user cap, an error).

Plan the launch around this: the forwarder can be tested end-to-end with
test users immediately, but public rollout waits for verification.

## 6. Smoke test (test user)

1. In the plugin, start "Login with Gmail".
2. Authorize with a test-user Google account.
3. Confirm the browser lands back on the site's callback URL and the
   plugin reports the account connected.
4. Send a test mail through the plugin and confirm it arrives.

If the flow stops at Google with `redirect_uri_mismatch`, re-check step 3
character by character. If it stops with `access_denied`, the test user
declined (or is not on the test-user list).
