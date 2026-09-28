// A minimal OpenID Connect Public client for a browser page: Authorization Code + S256 PKCE
// against SignaCore, with every token held only in this module's memory.
//
// Every browser capability (fetch, crypto, sessionStorage, location, history, and the clock) is
// injected so the behavior can be exercised under `node --test` without a browser. This module
// never touches localStorage, cookies, or the URL fragment, and it never logs or returns a raw
// token or the PKCE verifier.

const PENDING_KEY = 'signacore.publicSpa.pendingLogin';
const PENDING_LIFETIME_MS = 10 * 60 * 1000;
const RANDOM_BYTES = 32;
const CLOCK_SKEW_SECONDS = 60;
const FORM_CONTENT_TYPE = 'application/x-www-form-urlencoded';
// RFC 6749 section 5.2: the characters an error code may contain.
const ERROR_CODE_PATTERN = /^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/u;

/** An error whose `code` is safe to display: it never carries a token, code, or verifier. */
export class PublicClientError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = 'PublicClientError';
    this.code = code;
  }
}

/**
 * Checks a Discovery document against the configured authority and returns the endpoints this
 * client uses. The issuer must equal the authority exactly; nothing is normalized.
 */
export function validateDiscovery(document, authority) {
  if (typeof authority !== 'string' || authority.length === 0) {
    throw new PublicClientError('invalid_configuration', 'The authority is required.');
  }

  if (document === null || typeof document !== 'object' || document.issuer !== authority) {
    throw new PublicClientError('issuer_mismatch', 'The Discovery issuer does not match the authority.');
  }

  const metadata = { issuer: document.issuer };
  for (const [name, key] of [
    ['authorization_endpoint', 'authorizationEndpoint'],
    ['token_endpoint', 'tokenEndpoint'],
    ['userinfo_endpoint', 'userinfoEndpoint'],
  ]) {
    const value = document[name];
    if (typeof value !== 'string' || !URL.canParse(value)) {
      throw new PublicClientError('invalid_discovery', 'The Discovery document is incomplete.');
    }

    metadata[key] = value;
  }

  return metadata;
}

/** Reads `<authority>/.well-known/openid-configuration` and validates it. */
export async function discover({ fetch, authority, signal }) {
  let document;
  try {
    const response = await fetch(`${authority}/.well-known/openid-configuration`, {
      method: 'GET',
      credentials: 'omit',
      cache: 'no-store',
      signal,
    });
    if (response.status !== 200) {
      throw new Error('Unexpected status.');
    }

    document = await response.json();
  } catch {
    throw new PublicClientError('discovery_failed', 'The Discovery document could not be read.');
  }

  return validateDiscovery(document, authority);
}

export function base64UrlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function base64UrlDecodeToString(value) {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new PublicClientError('invalid_id_token', 'The ID token is malformed.');
  }

  const padded = value.replaceAll('-', '+').replaceAll('_', '/')
    + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/** RFC 7636 S256: BASE64URL(SHA-256(ASCII(code_verifier))). */
export async function computeS256Challenge(verifier, crypto) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

function randomValue(crypto) {
  const bytes = new Uint8Array(RANDOM_BYTES);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function hasOpenIdScope(scope) {
  return typeof scope === 'string' && scope.split(' ').includes('openid');
}

function isBearer(tokenType) {
  return typeof tokenType === 'string' && tokenType.toLowerCase() === 'bearer';
}

/**
 * Creates one client instance. `metadata` is the result of `discover`/`validateDiscovery`;
 * `config` carries `clientId`, `redirectUri`, and `scope` (which must contain `openid`). `now`
 * returns the current time in milliseconds.
 */
export function createPublicClient({
  config,
  metadata,
  fetch,
  crypto,
  sessionStorage,
  location,
  history,
  now = () => Date.now(),
}) {
  if (!config || typeof config.clientId !== 'string' || config.clientId.length === 0
    || typeof config.redirectUri !== 'string' || !URL.canParse(config.redirectUri)
    || !hasOpenIdScope(config.scope)) {
    throw new PublicClientError('invalid_configuration', 'The client configuration is invalid.');
  }

  if (!metadata || typeof metadata.issuer !== 'string') {
    throw new PublicClientError('invalid_configuration', 'The Discovery metadata is required.');
  }

  // The only copy of any token. A page reload or close discards it.
  let session = null;
  // Bumped on every session replacement or clear, so a late response never revives a session
  // that logout (or another failure) already cleared.
  let generation = 0;
  let refreshInFlight = null;

  function clearSession() {
    session = null;
    generation += 1;
  }

  function takePendingLogin() {
    let raw = null;
    try {
      raw = sessionStorage.getItem(PENDING_KEY);
    } finally {
      // Removed before any validation or network request, whatever the outcome.
      sessionStorage.removeItem(PENDING_KEY);
    }

    if (raw === null) {
      return null;
    }

    try {
      const pending = JSON.parse(raw);
      if (typeof pending?.state === 'string' && typeof pending.nonce === 'string'
        && typeof pending.codeVerifier === 'string' && Number.isFinite(pending.createdAt)) {
        return pending;
      }
    } catch {
      // A malformed record is treated as absent.
    }

    return null;
  }

  function readIdToken(idToken, { nonce, subject }) {
    if (typeof idToken !== 'string') {
      throw new PublicClientError('invalid_id_token', 'The ID token is missing.');
    }

    const parts = idToken.split('.');
    if (parts.length !== 3) {
      throw new PublicClientError('invalid_id_token', 'The ID token is malformed.');
    }

    let claims;
    try {
      claims = JSON.parse(base64UrlDecodeToString(parts[1]));
    } catch {
      throw new PublicClientError('invalid_id_token', 'The ID token is malformed.');
    }

    // The ID token arrives directly from the token endpoint over TLS, so its issuer, audience,
    // lifetime, and nonce are checked but its signature is not (OpenID Connect Core 1.0,
    // section 3.1.3.7, item 6). It is never used as an API credential and is discarded here.
    const audience = Array.isArray(claims?.aud) && claims.aud.length === 1 ? claims.aud[0] : claims?.aud;
    const nowSeconds = now() / 1000;
    if (claims?.iss !== metadata.issuer
      || audience !== config.clientId
      || typeof claims.exp !== 'number' || claims.exp + CLOCK_SKEW_SECONDS <= nowSeconds
      || typeof claims.sub !== 'string' || claims.sub.length === 0
      || (nonce !== undefined && claims.nonce !== nonce)
      || (subject !== undefined && claims.sub !== subject)) {
      throw new PublicClientError('invalid_id_token', 'The ID token was rejected.');
    }

    return { sub: claims.sub, name: typeof claims.name === 'string' ? claims.name : null };
  }

  function tokenRequest(fields, signal) {
    return fetch(metadata.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': FORM_CONTENT_TYPE },
      body: new URLSearchParams(fields).toString(),
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      signal,
    });
  }

  function accessTokenExpiry(expiresIn) {
    if (typeof expiresIn !== 'number' || !Number.isFinite(expiresIn) || expiresIn <= 0) {
      throw new PublicClientError('invalid_token_response', 'The token response is invalid.');
    }

    return now() + expiresIn * 1000;
  }

  /** Starts a login: stores one pending transaction and navigates to the authorize endpoint. */
  async function beginLogin() {
    const state = randomValue(crypto);
    const nonce = randomValue(crypto);
    const codeVerifier = randomValue(crypto);
    const codeChallenge = await computeS256Challenge(codeVerifier, crypto);
    sessionStorage.setItem(PENDING_KEY, JSON.stringify({ state, nonce, codeVerifier, createdAt: now() }));

    const url = new URL(metadata.authorizationEndpoint);
    for (const [name, value] of [
      ['response_type', 'code'],
      ['client_id', config.clientId],
      ['redirect_uri', config.redirectUri],
      ['scope', config.scope],
      ['state', state],
      ['nonce', nonce],
      ['code_challenge', codeChallenge],
      ['code_challenge_method', 'S256'],
    ]) {
      url.searchParams.append(name, value);
    }

    location.assign(url.toString());
    return url.toString();
  }

  /**
   * Completes a login on the callback page. The pending transaction and the callback query are
   * removed before anything is validated or sent, and every validation failure sends no request.
   */
  async function completeLogin({ signal } = {}) {
    const pending = takePendingLogin();
    const current = new URL(location.href);
    const parameters = current.searchParams;
    history.replaceState(null, '', current.pathname);
    clearSession();

    const single = (name) => {
      const values = parameters.getAll(name);
      if (values.length > 1) {
        throw new PublicClientError('invalid_callback', 'The callback is malformed.');
      }

      return values.length === 1 ? values[0] : null;
    };

    const age = pending === null ? Number.NaN : now() - pending.createdAt;
    if (!(age >= 0 && age <= PENDING_LIFETIME_MS)) {
      throw new PublicClientError('no_pending_login', 'No login is pending; start again.');
    }

    const code = single('code');
    const error = single('error');
    const state = single('state');
    const issuer = single('iss');
    if ((code === null) === (error === null) || code === '') {
      throw new PublicClientError('invalid_callback', 'The callback is malformed.');
    }

    if (state !== pending.state) {
      throw new PublicClientError('state_mismatch', 'The callback state does not match.');
    }

    if (issuer !== metadata.issuer) {
      throw new PublicClientError('issuer_mismatch', 'The callback issuer does not match.');
    }

    if (error !== null) {
      // Only the error code is surfaced; error_description is not displayed.
      throw new PublicClientError(ERROR_CODE_PATTERN.test(error) ? error : 'authorization_error',
        'The authorization request was not completed.');
    }

    const attempt = generation;
    try {
      const response = await tokenRequest([
        ['grant_type', 'authorization_code'],
        ['client_id', config.clientId],
        ['code', code],
        ['redirect_uri', config.redirectUri],
        ['code_verifier', pending.codeVerifier],
      ], signal);
      if (response.status !== 200) {
        throw new PublicClientError('token_request_failed', 'The code exchange was rejected.');
      }

      let body;
      try {
        body = await response.json();
      } catch {
        throw new PublicClientError('invalid_token_response', 'The token response is invalid.');
      }

      if (!isBearer(body?.token_type) || typeof body.access_token !== 'string' || body.access_token.length === 0) {
        throw new PublicClientError('invalid_token_response', 'The token response is invalid.');
      }

      const identity = readIdToken(body.id_token, { nonce: pending.nonce });
      const expiresAt = accessTokenExpiry(body.expires_in);
      if (attempt !== generation) {
        throw new PublicClientError('login_cancelled', 'The login was superseded.');
      }

      session = {
        accessToken: body.access_token,
        refreshToken: typeof body.refresh_token === 'string' && body.refresh_token.length > 0
          ? body.refresh_token
          : null,
        expiresAt,
        sub: identity.sub,
        name: identity.name,
      };
      generation += 1;
    } catch (failure) {
      if (attempt === generation) {
        clearSession();
      }

      throw failure instanceof PublicClientError
        ? failure
        : new PublicClientError('token_request_failed', 'The code exchange failed.');
    }

    return getSession();
  }

  /**
   * Rotates the refresh token once. Concurrent callers share the same request. Any outcome other
   * than a valid 200 clears the session: the consumed refresh token is never sent again, because
   * a replay would revoke the whole family.
   */
  function refresh({ signal } = {}) {
    if (refreshInFlight !== null) {
      return refreshInFlight;
    }

    if (session === null || session.refreshToken === null) {
      clearSession();
      return Promise.reject(new PublicClientError('login_required', 'Sign in again.'));
    }

    const current = session;
    const refreshToken = current.refreshToken;
    // Forget the token before sending it: it is single-use whatever the outcome.
    current.refreshToken = null;
    const attempt = generation;

    refreshInFlight = (async () => {
      try {
        const response = await tokenRequest([
          ['grant_type', 'refresh_token'],
          ['client_id', config.clientId],
          ['refresh_token', refreshToken],
        ], signal);
        if (response.status !== 200) {
          throw new PublicClientError('login_required', 'Sign in again.');
        }

        const body = await response.json();
        if (!isBearer(body?.token_type) || typeof body.access_token !== 'string' || body.access_token.length === 0
          || typeof body.refresh_token !== 'string' || body.refresh_token.length === 0) {
          throw new PublicClientError('login_required', 'Sign in again.');
        }

        const identity = body.id_token === undefined
          ? { sub: current.sub, name: current.name }
          : readIdToken(body.id_token, { subject: current.sub });
        const expiresAt = accessTokenExpiry(body.expires_in);
        if (attempt !== generation) {
          throw new PublicClientError('login_required', 'Sign in again.');
        }

        session = {
          accessToken: body.access_token,
          refreshToken: body.refresh_token,
          expiresAt,
          sub: identity.sub,
          name: identity.name ?? current.name,
        };
        generation += 1;
        return getSession();
      } catch {
        if (attempt === generation) {
          clearSession();
        }

        throw new PublicClientError('login_required', 'Sign in again.');
      } finally {
        refreshInFlight = null;
      }
    })();

    return refreshInFlight;
  }

  function sendUserInfo(signal) {
    return fetch(metadata.userinfoEndpoint, {
      method: 'GET',
      headers: { Authorization: `Bearer ${session.accessToken}` },
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      signal,
    });
  }

  /** Reads UserInfo; a 401 triggers at most one refresh and one retry. */
  async function userInfo({ signal } = {}) {
    if (session === null) {
      throw new PublicClientError('login_required', 'Sign in first.');
    }

    try {
      let response = await sendUserInfo(signal);
      if (response.status === 401) {
        await refresh({ signal });
        response = await sendUserInfo(signal);
        if (response.status === 401) {
          clearSession();
          throw new PublicClientError('login_required', 'Sign in again.');
        }
      }

      if (response.status !== 200) {
        throw new PublicClientError('userinfo_failed', 'UserInfo could not be read.');
      }

      const claims = await response.json();
      if (session === null || claims?.sub !== session.sub) {
        clearSession();
        throw new PublicClientError('login_required', 'Sign in again.');
      }

      return { sub: claims.sub, name: typeof claims.name === 'string' ? claims.name : null };
    } catch (failure) {
      throw failure instanceof PublicClientError
        ? failure
        : new PublicClientError('userinfo_failed', 'UserInfo could not be read.');
    }
  }

  /**
   * Forgets this page's tokens and any pending login. It does not revoke the refresh family and
   * does not end the SignaCore identity session.
   */
  function logout() {
    sessionStorage.removeItem(PENDING_KEY);
    clearSession();
  }

  /** A display-safe view of the session: never a token value. */
  function getSession() {
    if (session === null) {
      return null;
    }

    return {
      sub: session.sub,
      name: session.name,
      expiresAt: session.expiresAt,
      canRefresh: session.refreshToken !== null,
    };
  }

  return { beginLogin, completeLogin, refresh, userInfo, logout, getSession };
}
