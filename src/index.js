/**
 * Transistor — OAuth2 forwarder (Cloudflare Worker).
 *
 * One job: be the redirect_uri the identity provider sends the browser
 * back to, validate the state, and forward the browser to the
 * application that started the flow. It holds no tokens, no codes, no
 * sessions, no database. It is provider- and app-agnostic: any app
 * that can build a state (spec §3) can use it, WordPress or not.
 *
 * Contract: docs/spec.md (spec v1, state format v5).
 *
 * Endpoints:
 *   GET /oauth2   — the only live endpoint. Validates state, 302s to the
 *                    app's callback URL with code (or error)
 *                    + the full state, verbatim.
 *   GET /, /about, /privacy, /terms, /robots.txt, ... — static files
 *                    served from public/ via the assets binding.
 *   Anything else — the error page, HTTP 404.
 *   Any non-GET — the error page, HTTP 405.
 *
 * Pages are plain static HTML with inline CSS (no build step, no
 * separate stylesheet). The error page is one file (public/error.html)
 * with {{ERROR_TITLE}} / {{ERROR_MESSAGE}} placeholders the Worker
 * fills in per status, so a 404 says "Page not found" instead of the
 * authorization message.
 */

const ROBOTS_TAG = 'noindex, noarchive, noodp, noydir';
const NO_STORE = 'no-store, no-cache, must-revalidate';
const NONCE_RE = /^[0-9a-f]{32}$/;

// What the error page says, per status. The 400 message stays generic
// on purpose — no detail about which check failed, so it can't be used
// as a probe oracle. The 404/405 messages say what actually happened.
const ERROR_PAGES = {
  400: {
    code: '400',
    title: 'Something went wrong',
    message:
      'Invalid or expired authorization request. ' +
      'Please start again from the application that sent you here.',
  },
  404: {
    code: '404',
    title: 'Page not found',
    message:
      'The page you are looking for does not exist. ' +
      'If you followed a link here, it may be outdated.',
  },
  405: {
    code: '405',
    title: 'Method not allowed',
    message: 'This service only accepts GET requests.',
  },
};

// Minimal fallback if the static error page cannot be served (e.g. the
// Worker is deployed without the assets binding). Same generic message,
// no detail about which check failed.
const MINIMAL_ERROR_HTML =
  '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
  '<meta name="viewport" content="width=device-width, initial-scale=1">' +
  '<meta name="robots" content="noindex, noarchive, noodp, noydir">' +
  '<title>Something went wrong — Transistor</title></head>' +
  '<body><h1>Something went wrong</h1>' +
  '<p>Invalid or expired authorization request. ' +
  'Please start again from the application that sent you here.</p></body></html>';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // The forwarder only ever serves GET. Everything else is a 405.
    if (request.method !== 'GET') {
      return errorResponse(env, request, 405);
    }

    if (url.pathname === '/oauth2') {
      return handleOAuth2(env, request, url);
    }

    // Static page or asset; unknown paths get the error page (404).
    const staticRes = await serveStatic(env, request);
    if (staticRes) {
      return staticRes;
    }
    return errorResponse(env, request, 404);
  },
};

/**
 * GET /oauth2 — the redirect_uri registered with the provider.
 * Validates the state (spec §4), then 302s to the app's callback URL
 * with the code (or error) and the full state, verbatim (spec §5).
 */
async function handleOAuth2(env, request, url) {
  const state = url.searchParams.get('state');
  const code = url.searchParams.get('code');
  const error = url.searchParams.get('error');
  const errorDescription = url.searchParams.get('error_description');

  // Any validation failure → 400 + error page. No redirect, no forward.
  const valid = await validateState(state);
  if (!valid.ok) {
    return errorResponse(env, request, 400);
  }

  // Success: the provider issued a code.
  if (code) {
    const target = new URL(valid.u);
    target.searchParams.set('code', code);
    target.searchParams.set('state', state);
    return redirectResponse(target.toString());
  }

  // Provider error (e.g. the user declined consent): forward it as-is and
  // let the app show a friendly message.
  if (error) {
    const target = new URL(valid.u);
    target.searchParams.set('error', error);
    if (errorDescription) {
      target.searchParams.set('error_description', errorDescription);
    }
    target.searchParams.set('state', state);
    return redirectResponse(target.toString());
  }

  // Valid state but neither a code nor an error — nothing to forward.
  return errorResponse(env, request, 400);
}

/**
 * State validation (spec §4), in order. Returns { ok: true, u } or
 * { ok: false }. Never throws on bad input — a malformed state is just
 * a 400.
 */
async function validateState(state) {
  if (typeof state !== 'string' || state.length === 0) {
    return { ok: false };
  }

  let payload;
  try {
    payload = JSON.parse(base64urlDecode(state));
  } catch {
    return { ok: false };
  }
  if (!payload || typeof payload !== 'object') {
    return { ok: false };
  }

  // v must be the number 1.
  if (payload.v !== 1) {
    return { ok: false };
  }

  // n must be 32 lowercase hex chars (16 random bytes).
  if (typeof payload.n !== 'string' || !NONCE_RE.test(payload.n)) {
    return { ok: false };
  }

  // exp must be a number in the future (seconds).
  if (typeof payload.exp !== 'number' || !(payload.exp > Date.now() / 1000)) {
    return { ok: false };
  }

  // u must be an https callback URL. No app-specific path or action is
  // required — Transistor is global: any app (WordPress, a plain web
  // app, a mobile backend) can point the state at its own callback.
  // The state HMAC is a corruption checksum, not tamper protection,
  // so the real guard is the app's own state/nonce check on return.
  if (typeof payload.u !== 'string' || !isValidCallbackUrl(payload.u)) {
    return { ok: false };
  }

  // s must be the HMAC-SHA-256 of u, keyed by n (spec §3.1). The sign is
  // a corruption checksum, not tamper protection — anyone holding the
  // state can recompute it. Real authenticity comes from the app's
  // own nonce check plus PKCE.
  if (typeof payload.s !== 'string') {
    return { ok: false };
  }
  const expected = await hmacSha256Hex(payload.n, payload.u);
  if (!timingSafeEqual(payload.s, expected)) {
    return { ok: false };
  }

  return { ok: true, u: payload.u };
}

/**
 * Callback-URL check (spec §4): any https URL with a hostname. No
 * app-specific path, action or host is required — Transistor is a
 * global forwarder, not a WordPress/TrayDigita-only one. The https
 * requirement is the only transport rule (no plain-http callbacks).
 */
function isValidCallbackUrl(u) {
  let parsed;
  try {
    parsed = new URL(u);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:') {
    return false;
  }
  return parsed.hostname.length > 0;
}

/** 302 to the site. Never cached — the URL carries a single-use code. */
function redirectResponse(location) {
  return new Response(null, {
    status: 302,
    headers: {
      Location: location,
      'Cache-Control': NO_STORE,
      Pragma: 'no-cache',
      'X-Robots-Tag': ROBOTS_TAG,
    },
  });
}

/**
 * The error page (spec §6): public/error.html served from the assets
 * binding, with the {{ERROR_TITLE}} / {{ERROR_MESSAGE}} placeholders
 * filled in for this status, plus the right status and headers. Falls
 * back to an inline minimal page if the asset cannot be served.
 */
async function errorResponse(env, request, status) {
  const page = ERROR_PAGES[status] ?? ERROR_PAGES[400];
  let body = null;
  let contentType = 'text/html; charset=utf-8';
  const assetRes = await fetchAssetRaw(env, request, '/error.html');
  if (assetRes && assetRes.ok) {
    body = (await assetRes.text())
      .replaceAll('{{ERROR_CODE}}', page.code)
      .replaceAll('{{ERROR_TITLE}}', page.title)
      .replaceAll('{{ERROR_MESSAGE}}', page.message);
    contentType = assetRes.headers.get('Content-Type') || contentType;
  }

  const headers = new Headers({
    'Content-Type': contentType,
    'Cache-Control': NO_STORE,
    Pragma: 'no-cache',
    'X-Robots-Tag': ROBOTS_TAG,
  });
  return new Response(body ?? MINIMAL_ERROR_HTML, { status, headers });
}

/**
 * Serve a static file from public/ via the assets binding. Returns null
 * when the file does not exist (caller turns that into the 404 error
 * page) or when no assets binding is configured.
 *
 * Friendly page URLs (/about, /privacy, /terms) 301-redirect to their
 * .html files — the .html URL is the canonical one. The home page /
 * serves public/index.html directly (no redirect to /index.html).
 */
async function serveStatic(env, request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // The home page: / serves public/index.html.
  if (pathname === '/') {
    return fetchAsset(env, request, '/index.html');
  }

  // Friendly page URL: if the .html file exists, 301 to it; if it does
  // not exist, this is a genuine 404 (caller handles it).
  if (!pathname.includes('.') && !pathname.endsWith('/')) {
    const htmlPath = pathname + '.html';
    const exists = await assetExists(env, request, htmlPath);
    if (exists) {
      return redirectPermanent(new URL(htmlPath, request.url).toString());
    }
    return null;
  }

  return fetchAsset(env, request, pathname);
}

/** Fetch one asset path. Returns the response, or null if not found. */
async function fetchAsset(env, request, path) {
  const res = await fetchAssetRaw(env, request, path);
  if (!res || res.status === 404) {
    return null;
  }
  const headers = new Headers(res.headers);
  headers.set('X-Robots-Tag', ROBOTS_TAG);
  return new Response(res.body, { status: res.status, headers });
}

/** True when the asset path exists (status anything but 404). */
async function assetExists(env, request, path) {
  const res = await fetchAssetRaw(env, request, path);
  return !!res && res.status !== 404;
}

/**
 * Fetch an asset from the assets binding, following one redirect if
 * the asset store answers with one. The store canonicalises .html
 * URLs to clean URLs (e.g. /terms.html -> /terms), so a plain fetch
 * of an .html file comes back 301, not 200 — follow it once to get
 * the file's content. Returns null when the binding is missing or
 * the fetch fails.
 */
async function fetchAssetRaw(env, request, path) {
  let res;
  try {
    res = await env.ASSETS.fetch(
      new Request(new URL(path, request.url), { method: 'GET' }),
    );
  } catch {
    return null;
  }
  if (res && res.status >= 300 && res.status < 400) {
    const location = res.headers.get('Location');
    if (location) {
      try {
        const next = await env.ASSETS.fetch(
          new Request(new URL(location, request.url), { method: 'GET' }),
        );
        if (next) {
          res = next;
        }
      } catch {
        // Keep the redirect response; the caller decides.
      }
    }
  }
  return res;
}

/** 301 to the canonical URL. Never cached (the target may change). */
function redirectPermanent(location) {
  return new Response(null, {
    status: 301,
    headers: {
      Location: location,
      'Cache-Control': NO_STORE,
      Pragma: 'no-cache',
      'X-Robots-Tag': ROBOTS_TAG,
    },
  });
}

/** base64url → UTF-8 string. Throws on bad alphabet or bad UTF-8. */
function base64urlDecode(input) {
  let s = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4;
  if (pad) {
    s += '='.repeat(4 - pad);
  }
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/** HMAC-SHA-256, hex, lowercase. */
async function hmacSha256Hex(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign(
    'HMAC',
    cryptoKey,
    new TextEncoder().encode(message),
  );
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Constant-time string comparison (no timingSafeEqual in Workers). */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
