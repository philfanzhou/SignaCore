import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { computeS256Challenge, createPublicClient, PublicClientError, validateDiscovery } from '../public-client.js';
import { webcrypto } from 'node:crypto';
import {
  arriveAtCallback, beginLogin, CLIENT_ID, createHarness, ISSUER, json, METADATA, REDIRECT_URI,
  signIn, tokenResponse,
} from './harness.mjs';

// RFC 7636 appendix B: the verifier octets, the verifier, and its S256 challenge.
const APPENDIX_B_OCTETS = Uint8Array.from([
  116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186,
  22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
]);
const APPENDIX_B_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const APPENDIX_B_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const PENDING_KEY = 'signacore.publicSpa.pendingLogin';

function tokenRequests(harness) {
  return harness.requests.filter((request) => request.url === METADATA.tokenEndpoint);
}

async function rejectsWith(promise, code) {
  await assert.rejects(promise, (error) => error instanceof PublicClientError && error.code === code);
}

/** A harness whose code exchange answers with the pending login's nonce, then `after(request)`. */
function signedInHarness({ after, scope } = {}) {
  let nonce;
  const harness = createHarness({
    scope,
    respond: (request, index) => {
      if (request.form?.[0]?.[1] === 'authorization_code') {
        return json(200, tokenResponse({ nonce, clock: harness.clock }));
      }

      return after(request, index);
    },
  });
  const originalBegin = harness.client.beginLogin;
  harness.client.beginLogin = async () => {
    const url = await originalBegin();
    nonce = new URL(url).searchParams.get('nonce');
    return url;
  };
  return harness;
}

describe('discovery', () => {
  test('requires the issuer to equal the authority exactly', () => {
    const document = {
      issuer: ISSUER,
      authorization_endpoint: METADATA.authorizationEndpoint,
      token_endpoint: METADATA.tokenEndpoint,
      userinfo_endpoint: METADATA.userinfoEndpoint,
    };
    assert.deepEqual(validateDiscovery(document, ISSUER), METADATA);
    for (const authority of [`${ISSUER}/`, ISSUER.toUpperCase(), 'https://other.example.test']) {
      assert.throws(() => validateDiscovery(document, authority), (error) => error.code === 'issuer_mismatch');
    }

    assert.throws(() => validateDiscovery({ ...document, token_endpoint: undefined }, ISSUER),
      (error) => error.code === 'invalid_discovery');
  });

  test('rejects a configuration whose scope lacks openid', () => {
    assert.throws(() => createPublicClient({
      config: { clientId: CLIENT_ID, redirectUri: REDIRECT_URI, scope: 'profile offline_access' },
      metadata: METADATA,
    }), (error) => error.code === 'invalid_configuration');
  });
});

describe('authorization request', () => {
  test('uses the RFC 7636 appendix B S256 vector', async () => {
    assert.equal(await computeS256Challenge(APPENDIX_B_VERIFIER, webcrypto), APPENDIX_B_CHALLENGE);

    const harness = createHarness({
      randomBlocks: [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), APPENDIX_B_OCTETS],
    });
    const authorize = await beginLogin(harness);
    assert.equal(authorize.get('code_challenge'), APPENDIX_B_CHALLENGE);
    assert.equal(JSON.parse(harness.store.get(PENDING_KEY)).codeVerifier, APPENDIX_B_VERIFIER);
  });

  test('carries exactly the authorize parameter set', async () => {
    const harness = createHarness();
    await harness.client.beginLogin();
    assert.equal(harness.navigations.length, 1);
    const url = new URL(harness.navigations[0]);
    assert.equal(`${url.origin}${url.pathname}`, METADATA.authorizationEndpoint);
    assert.equal(url.hash, '');
    assert.deepEqual([...url.searchParams.keys()], [
      'response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge',
      'code_challenge_method',
    ]);
    assert.equal(url.searchParams.get('response_type'), 'code');
    assert.equal(url.searchParams.get('client_id'), CLIENT_ID);
    assert.equal(url.searchParams.get('redirect_uri'), REDIRECT_URI);
    assert.equal(url.searchParams.get('scope'), 'openid profile offline_access');
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    for (const name of ['state', 'nonce', 'code_challenge']) {
      assert.match(url.searchParams.get(name), /^[A-Za-z0-9_-]{43}$/u);
    }

    assert.notEqual(url.searchParams.get('state'), url.searchParams.get('nonce'));
    assert.doesNotMatch(harness.navigations[0], /secret|response_mode|#/u);

    const pending = JSON.parse(harness.store.get(PENDING_KEY));
    assert.deepEqual(Object.keys(pending), ['state', 'nonce', 'codeVerifier', 'createdAt']);
    assert.equal(pending.state, url.searchParams.get('state'));
    assert.equal(pending.nonce, url.searchParams.get('nonce'));
    assert.equal(await computeS256Challenge(pending.codeVerifier, webcrypto), url.searchParams.get('code_challenge'));
    assert.equal(harness.requests.length, 0);
  });
});

describe('callback failures send no token request and delete the pending login', () => {
  const cases = [
    ['missing state', (a) => [['code', 'c'], ['iss', ISSUER]], 'state_mismatch'],
    ['different state', (a) => [['code', 'c'], ['state', `${a.get('state')}x`], ['iss', ISSUER]], 'state_mismatch'],
    ['missing iss', (a) => [['code', 'c'], ['state', a.get('state')]], 'issuer_mismatch'],
    ['different iss', (a) => [['code', 'c'], ['state', a.get('state')], ['iss', `${ISSUER}/`]], 'issuer_mismatch'],
    ['code and error', (a) => [['code', 'c'], ['error', 'access_denied'], ['state', a.get('state')], ['iss', ISSUER]], 'invalid_callback'],
    ['neither code nor error', (a) => [['state', a.get('state')], ['iss', ISSUER]], 'invalid_callback'],
    ['duplicate code', (a) => [['code', 'c'], ['code', 'd'], ['state', a.get('state')], ['iss', ISSUER]], 'invalid_callback'],
    ['access_denied', (a) => [['error', 'access_denied'], ['error_description', 'denied'], ['state', a.get('state')], ['iss', ISSUER]], 'access_denied'],
  ];

  for (const [name, parameters, code] of cases) {
    test(name, async () => {
      const harness = createHarness();
      const authorize = await beginLogin(harness);
      arriveAtCallback(harness, parameters(authorize));
      await rejectsWith(harness.client.completeLogin(), code);
      assert.equal(harness.requests.length, 0);
      assert.equal(harness.store.has(PENDING_KEY), false);
      assert.deepEqual(harness.historyUrls, ['/callback']);
      assert.equal(harness.client.getSession(), null);
    });
  }

  test('an expired pending login', async () => {
    const harness = createHarness();
    const authorize = await beginLogin(harness);
    harness.clock.now += 10 * 60 * 1000 + 1;
    arriveAtCallback(harness, [['code', 'c'], ['state', authorize.get('state')], ['iss', ISSUER]]);
    await rejectsWith(harness.client.completeLogin(), 'no_pending_login');
    assert.equal(harness.requests.length, 0);
    assert.equal(harness.store.has(PENDING_KEY), false);
  });

  test('a replayed callback finds no pending login', async () => {
    const harness = signedInHarness({ after: () => { throw new Error('Unexpected request.'); } });
    const authorize = await signIn(harness);
    assert.equal(tokenRequests(harness).length, 1);
    arriveAtCallback(harness, [['code', 'authorization-code-1'], ['state', authorize.get('state')], ['iss', ISSUER]]);
    await rejectsWith(harness.client.completeLogin(), 'no_pending_login');
    assert.equal(tokenRequests(harness).length, 1);
    assert.equal(harness.client.getSession(), null);
  });
});

describe('code exchange', () => {
  test('sends exactly the Public redemption form without credentials', async () => {
    const harness = signedInHarness({ after: () => { throw new Error('Unexpected request.'); } });
    const authorize = await signIn(harness);
    const [exchange] = tokenRequests(harness);
    assert.equal(exchange.method, 'POST');
    assert.equal(exchange.credentials, 'omit');
    assert.deepEqual(exchange.headers, { 'Content-Type': 'application/x-www-form-urlencoded' });
    assert.deepEqual(exchange.form.map(([name]) => name),
      ['grant_type', 'client_id', 'code', 'redirect_uri', 'code_verifier']);
    const form = Object.fromEntries(exchange.form);
    assert.equal(form.grant_type, 'authorization_code');
    assert.equal(form.client_id, CLIENT_ID);
    assert.equal(form.code, 'authorization-code-1');
    assert.equal(form.redirect_uri, REDIRECT_URI);
    assert.equal(await computeS256Challenge(form.code_verifier, webcrypto), authorize.get('code_challenge'));

    const session = harness.client.getSession();
    assert.deepEqual(session, {
      sub: 'subject-1', name: 'Sample User', expiresAt: harness.clock.now + 300_000, canRefresh: true,
    });
  });

  const rejectedIdTokens = [
    ['nonce', (nonce) => ({ nonce: `${nonce}x` })],
    ['missing nonce', () => ({ nonce: undefined })],
    ['audience', () => ({ aud: 'OrderService' })],
    ['multi-valued audience', () => ({ aud: [CLIENT_ID, 'OrderService'] })],
    ['issuer', () => ({ iss: 'https://other.example.test' })],
    ['expired', (_nonce, clock) => ({ exp: Math.floor(clock.now / 1000) - 61 })],
  ];

  for (const [name, claims] of rejectedIdTokens) {
    test(`discards the result when the ID token ${name} does not match`, async () => {
      let nonce;
      const harness = createHarness({
        respond: () => json(200, tokenResponse({ nonce, claims: claims(nonce, harness.clock), clock: harness.clock })),
      });
      const authorize = await beginLogin(harness);
      nonce = authorize.get('nonce');
      arriveAtCallback(harness, [['code', 'c'], ['state', authorize.get('state')], ['iss', ISSUER]]);
      await rejectsWith(harness.client.completeLogin(), 'invalid_id_token');
      assert.equal(harness.client.getSession(), null);
      await rejectsWith(harness.client.refresh(), 'login_required');
      assert.equal(tokenRequests(harness).length, 1);
    });
  }

  test('a rejected exchange leaves the page signed out', async () => {
    const harness = createHarness({ respond: () => json(400, { error: 'invalid_grant' }) });
    const authorize = await beginLogin(harness);
    arriveAtCallback(harness, [['code', 'c'], ['state', authorize.get('state')], ['iss', ISSUER]]);
    await rejectsWith(harness.client.completeLogin(), 'token_request_failed');
    assert.equal(harness.client.getSession(), null);
  });
});

describe('storage probe', () => {
  test('a complete flow with refresh writes no token to any browser store or URL', async () => {
    const touched = [];
    const spy = (name) => new Proxy({}, {
      get: (_target, property) => { touched.push(`${name}.${String(property)}`); return undefined; },
      set: (_target, property) => { touched.push(`${name}.${String(property)}`); return true; },
    });
    const cookieWrites = [];
    const previous = { localStorage: globalThis.localStorage, document: globalThis.document };
    Object.defineProperty(globalThis, 'localStorage', { value: spy('localStorage'), configurable: true, writable: true });
    Object.defineProperty(globalThis, 'document', {
      value: { get cookie() { touched.push('document.cookie'); return ''; }, set cookie(value) { cookieWrites.push(value); } },
      configurable: true,
      writable: true,
    });

    try {
      let refreshes = 0;
      const harness = signedInHarness({
        after: (request) => {
          if (request.url === METADATA.userinfoEndpoint) {
            return json(200, { sub: 'subject-1', name: 'Sample User' });
          }

          refreshes += 1;
          return json(200, tokenResponse({ suffix: String(refreshes + 1), clock: harness.clock }));
        },
      });
      await signIn(harness);
      await harness.client.userInfo();
      await harness.client.refresh();
      await harness.client.userInfo();
      harness.client.logout();

      const secrets = ['access-token-', 'refresh-token-', 'eyJ'];
      for (const value of [...harness.storageWrites, ...harness.navigations, ...harness.historyUrls, harness.location.href]) {
        for (const secret of secrets) {
          assert.equal(value.includes(secret), false);
        }
      }

      assert.equal(harness.storageWrites.length, 1);
      assert.equal(harness.store.size, 0);
      assert.deepEqual(touched, []);
      assert.deepEqual(cookieWrites, []);
      assert.equal(harness.requests.every((request) => request.credentials === 'omit'), true);
      assert.equal(harness.client.getSession(), null);
    } finally {
      for (const [name, value] of Object.entries(previous)) {
        if (value === undefined) {
          delete globalThis[name];
        } else {
          Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
        }
      }
    }
  });
});

describe('refresh', () => {
  test('a 200 replaces both tokens', async () => {
    const harness = signedInHarness({
      after: (request) => {
        if (request.url === METADATA.userinfoEndpoint) {
          return json(200, { sub: 'subject-1' });
        }

        const presented = Object.fromEntries(request.form).refresh_token;
        return json(200, tokenResponse({ suffix: presented === 'refresh-token-1' ? '2' : '3', clock: harness.clock }));
      },
    });
    await signIn(harness);
    await harness.client.refresh();
    await harness.client.userInfo();
    await harness.client.refresh();

    const refreshes = tokenRequests(harness).slice(1);
    assert.deepEqual(refreshes.map((request) => request.form.map(([name]) => name)),
      [['grant_type', 'client_id', 'refresh_token'], ['grant_type', 'client_id', 'refresh_token']]);
    assert.deepEqual(refreshes.map((request) => Object.fromEntries(request.form).refresh_token),
      ['refresh-token-1', 'refresh-token-2']);
    assert.equal(refreshes.every((request) => request.headers.Authorization === undefined), true);
    const userInfo = harness.requests.find((request) => request.url === METADATA.userinfoEndpoint);
    assert.equal(userInfo.headers.Authorization, 'Bearer access-token-2');
  });

  test('concurrent calls share one request', async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const harness = signedInHarness({
      after: async () => {
        await gate;
        return json(200, tokenResponse({ suffix: '2', clock: harness.clock }));
      },
    });
    await signIn(harness);
    const first = harness.client.refresh();
    const second = harness.client.refresh();
    release();
    assert.deepEqual(await first, await second);
    assert.equal(tokenRequests(harness).length, 2);
  });

  const failures = [
    ['a 400', () => json(400, { error: 'invalid_grant' })],
    ['a network failure', () => { throw new TypeError('Failed to fetch'); }],
    ['an unparsable body', () => json(200, 'not json')],
    ['a body without a refresh token', (clock) => json(200, tokenResponse({ suffix: '2', refresh: false, clock }))],
  ];

  for (const [name, answer] of failures) {
    test(`${name} clears the session and never resends the token`, async () => {
      const harness = signedInHarness({ after: () => answer(harness.clock) });
      await signIn(harness);
      await rejectsWith(harness.client.refresh(), 'login_required');
      assert.equal(harness.client.getSession(), null);
      await rejectsWith(harness.client.refresh(), 'login_required');
      await rejectsWith(harness.client.userInfo(), 'login_required');
      assert.equal(tokenRequests(harness).length, 2);
      assert.equal(harness.requests.length, 2);
    });
  }

  test('a 401 from UserInfo refreshes at most once', async () => {
    const harness = signedInHarness({
      after: (request) => (request.url === METADATA.userinfoEndpoint
        ? json(401, {})
        : json(200, tokenResponse({ suffix: '2', clock: harness.clock }))),
    });
    await signIn(harness);
    await rejectsWith(harness.client.userInfo(), 'login_required');
    assert.deepEqual(harness.requests.slice(1).map((request) => request.url),
      [METADATA.userinfoEndpoint, METADATA.tokenEndpoint, METADATA.userinfoEndpoint]);
    assert.equal(harness.client.getSession(), null);
  });

  test('a 401 from UserInfo followed by a successful refresh retries once', async () => {
    let userInfoCalls = 0;
    const harness = signedInHarness({
      after: (request) => {
        if (request.url === METADATA.userinfoEndpoint) {
          userInfoCalls += 1;
          return userInfoCalls === 1 ? json(401, {}) : json(200, { sub: 'subject-1', name: 'Sample User' });
        }

        return json(200, tokenResponse({ suffix: '2', clock: harness.clock }));
      },
    });
    await signIn(harness);
    assert.deepEqual(await harness.client.userInfo(), { sub: 'subject-1', name: 'Sample User' });
    assert.equal(tokenRequests(harness).length, 2);
    assert.equal(harness.requests.at(-1).headers.Authorization, 'Bearer access-token-2');
  });
});

describe('cancellation', () => {
  function abortable(request) {
    return new Promise((_resolve, reject) => {
      request.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
    });
  }

  test('an aborted exchange leaves the page signed out', async () => {
    const harness = createHarness({ respond: abortable });
    const authorize = await beginLogin(harness);
    arriveAtCallback(harness, [['code', 'c'], ['state', authorize.get('state')], ['iss', ISSUER]]);
    const controller = new AbortController();
    const completion = harness.client.completeLogin({ signal: controller.signal });
    controller.abort();
    await rejectsWith(completion, 'token_request_failed');
    assert.equal(harness.client.getSession(), null);
    assert.equal(harness.store.size, 0);
  });

  test('an aborted refresh leaves the page signed out', async () => {
    const harness = signedInHarness({ after: abortable });
    await signIn(harness);
    const controller = new AbortController();
    const refresh = harness.client.refresh({ signal: controller.signal });
    controller.abort();
    await rejectsWith(refresh, 'login_required');
    assert.equal(harness.client.getSession(), null);
    await rejectsWith(harness.client.refresh(), 'login_required');
    assert.equal(tokenRequests(harness).length, 2);
  });

  test('logout during a refresh is not undone by its response', async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const harness = signedInHarness({
      after: async () => {
        await gate;
        return json(200, tokenResponse({ suffix: '2', clock: harness.clock }));
      },
    });
    await signIn(harness);
    const refresh = harness.client.refresh();
    harness.client.logout();
    release();
    await rejectsWith(refresh, 'login_required');
    assert.equal(harness.client.getSession(), null);
  });
});
