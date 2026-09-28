// Test doubles for the browser capabilities that public-client.js receives by injection.
import { webcrypto } from 'node:crypto';
import { createPublicClient } from '../public-client.js';

export const ISSUER = 'https://signacore.example.test';
export const CLIENT_ID = 'public-spa-sample';
export const REDIRECT_URI = 'http://127.0.0.1:5173/callback';
export const PAGE = 'http://127.0.0.1:5173/';
export const METADATA = {
  issuer: ISSUER,
  authorizationEndpoint: `${ISSUER}/oauth2/authorize`,
  tokenEndpoint: `${ISSUER}/oauth2/token`,
  userinfoEndpoint: `${ISSUER}/oauth2/userinfo`,
};

export function base64Url(value) {
  return Buffer.from(value).toString('base64url');
}

export function idToken(claims) {
  return `${base64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${base64Url(JSON.stringify(claims))}.c2lnbmF0dXJl`;
}

export function json(status, body) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Builds a client over recording doubles. `respond(request)` answers each fetch; the default
 * answers nothing and fails the test if the client sends a request.
 */
export function createHarness({ respond, randomBlocks = [], scope = 'openid profile offline_access' } = {}) {
  const store = new Map();
  const storageWrites = [];
  const sessionStorage = {
    getItem: (key) => (store.has(key) ? store.get(key) : null),
    setItem: (key, value) => {
      storageWrites.push(String(value));
      store.set(key, String(value));
    },
    removeItem: (key) => store.delete(key),
  };

  const navigations = [];
  const historyUrls = [];
  const location = {
    href: PAGE,
    assign: (url) => navigations.push(url),
  };
  const history = {
    replaceState: (_state, _title, url) => {
      historyUrls.push(String(url));
      location.href = new URL(url, location.href).href;
    },
  };

  const pendingBlocks = [...randomBlocks];
  const crypto = {
    subtle: webcrypto.subtle,
    getRandomValues: (array) => {
      const block = pendingBlocks.shift();
      if (block === undefined) {
        return webcrypto.getRandomValues(array);
      }

      array.set(block);
      return array;
    },
  };

  const requests = [];
  const clock = { now: Date.UTC(2026, 0, 1, 12, 0, 0) };
  const fetch = async (url, init = {}) => {
    const request = {
      url: String(url),
      method: init.method,
      headers: { ...init.headers },
      credentials: init.credentials,
      form: typeof init.body === 'string' ? [...new URLSearchParams(init.body)] : null,
      signal: init.signal,
    };
    requests.push(request);
    if (respond === undefined) {
      throw new Error('Unexpected request.');
    }

    return respond(request, requests.length);
  };

  const client = createPublicClient({
    config: { clientId: CLIENT_ID, redirectUri: REDIRECT_URI, scope },
    metadata: METADATA,
    fetch,
    crypto,
    sessionStorage,
    location,
    history,
    now: () => clock.now,
  });

  return { client, store, storageWrites, navigations, historyUrls, location, requests, clock };
}

/** Starts a login and returns the authorize request parameters the page navigated to. */
export async function beginLogin(harness) {
  await harness.client.beginLogin();
  return new URL(harness.navigations.at(-1)).searchParams;
}

/** Simulates SignaCore's redirect back to the callback with the given query parameters. */
export function arriveAtCallback(harness, parameters) {
  const url = new URL(REDIRECT_URI);
  for (const [name, value] of parameters) {
    url.searchParams.append(name, value);
  }

  harness.location.href = url.href;
}

export function tokenResponse({ nonce, suffix = '1', claims = {}, refresh = true, clock }) {
  return {
    access_token: `access-token-${suffix}`,
    token_type: 'Bearer',
    expires_in: 300,
    scope: 'openid profile offline_access',
    id_token: idToken({
      iss: ISSUER,
      sub: 'subject-1',
      aud: CLIENT_ID,
      exp: Math.floor(clock.now / 1000) + 300,
      iat: Math.floor(clock.now / 1000),
      name: 'Sample User',
      ...(nonce === undefined ? {} : { nonce }),
      ...claims,
    }),
    ...(refresh ? { refresh_token: `refresh-token-${suffix}` } : {}),
  };
}

/** Drives a complete successful login and returns the authorize parameters. */
export async function signIn(harness, state) {
  const authorize = await beginLogin(harness);
  arriveAtCallback(harness, [['code', 'authorization-code-1'], ['state', state ?? authorize.get('state')], ['iss', ISSUER]]);
  await harness.client.completeLogin();
  return authorize;
}
