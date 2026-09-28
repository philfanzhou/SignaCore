import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer, request as httpRequest } from 'node:http';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { contentSecurityPolicy, createSampleServer, loadConfiguration } from '../serve.mjs';

const SERVE = fileURLToPath(new URL('../serve.mjs', import.meta.url));
const CLIENT_ID = 'public-spa-sample';

/** A stand-in SignaCore that serves only a Discovery document. */
async function startDiscovery(document) {
  const server = createServer((request, response) => {
    if (request.url === '/.well-known/openid-configuration') {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(document(server.address().port)));
      return;
    }

    response.writeHead(404);
    response.end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { server, authority: `http://127.0.0.1:${server.address().port}` };
}

function discoveryFor(origin, issuer = origin) {
  return {
    issuer,
    authorization_endpoint: `${origin}/oauth2/authorize`,
    token_endpoint: `${origin}/oauth2/token`,
    userinfo_endpoint: `${origin}/oauth2/userinfo`,
    jwks_uri: `${origin}/.well-known/jwks`,
  };
}

function send({ port, method = 'GET', path = '/', host = `127.0.0.1:${port}` }) {
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest({ host: '127.0.0.1', port, method, path, headers: { Host: host } }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString() }));
    });
    outgoing.on('error', reject);
    outgoing.end();
  });
}

async function runServe(env) {
  const child = spawn(process.execPath, [SERVE], {
    env: { PATH: process.env.PATH, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const [code] = await once(child, 'exit');
  return { code, stdout, stderr };
}

describe('serve.mjs', () => {
  let discovery;
  let sample;
  let port;
  let expectedPolicy;

  before(async () => {
    discovery = await startDiscovery((discoveryPort) => discoveryFor(`http://127.0.0.1:${discoveryPort}`));
    const loaded = await loadConfiguration({
      SIGNACORE_AUTHORITY: discovery.authority,
      SIGNACORE_SPA_CLIENT_ID: CLIENT_ID,
    });
    sample = await createSampleServer(loaded);
    sample.listen(0, '127.0.0.1');
    await once(sample, 'listening');
    port = sample.address().port;
    expectedPolicy = "default-src 'none'; script-src 'self'; "
      + `connect-src 'self' ${discovery.authority}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
  });

  after(async () => {
    sample?.close();
    discovery?.server.close();
  });

  function assertSecurityHeaders(response) {
    assert.equal(response.headers['content-security-policy'], expectedPolicy);
    assert.equal(response.headers['referrer-policy'], 'no-referrer');
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
    assert.deepEqual(Object.keys(response.headers).sort(), [
      'cache-control', 'connection', 'content-length', 'content-security-policy', 'content-type', 'date',
      'keep-alive', 'referrer-policy', 'x-content-type-options',
    ]);
  }

  test('serves the allow-listed files with the exact security headers', async () => {
    for (const [path, type] of [
      ['/', 'text/html; charset=utf-8'],
      ['/callback?code=abc&state=def&iss=ghi', 'text/html; charset=utf-8'],
      ['/app.js', 'text/javascript; charset=utf-8'],
      ['/public-client.js', 'text/javascript; charset=utf-8'],
      ['/config.json', 'application/json; charset=utf-8'],
    ]) {
      const response = await send({ port, path });
      assert.equal(response.status, 200, path);
      assert.equal(response.headers['content-type'], type);
      assertSecurityHeaders(response);
    }

    const page = await send({ port, path: '/' });
    assert.doesNotMatch(page.body, /<script>|<style|style=|on[a-z]+=/iu);
    assert.match(page.body, /<script type="module" src="\/app\.js"><\/script>/u);
  });

  test('publishes only non-sensitive configuration', async () => {
    const config = JSON.parse((await send({ port, path: '/config.json' })).body);
    assert.deepEqual(config, {
      authority: discovery.authority,
      clientId: CLIENT_ID,
      redirectUri: 'http://127.0.0.1:5173/callback',
      scope: 'openid profile',
      discovery: {
        issuer: discovery.authority,
        authorization_endpoint: `${discovery.authority}/oauth2/authorize`,
        token_endpoint: `${discovery.authority}/oauth2/token`,
        userinfo_endpoint: `${discovery.authority}/oauth2/userinfo`,
      },
    });
  });

  test('answers 404 for any other path, method, or host', async () => {
    const attempts = [
      { path: '/index.html' }, { path: '/serve.mjs' }, { path: '/package.json' }, { path: '/README.md' },
      { path: '/test/serve.test.mjs' }, { path: '/../README.md' }, { path: '/%2e%2e/serve.mjs' },
      { path: '/favicon.ico' }, { path: '/callback/' }, { path: '/App.js' },
      { method: 'POST' }, { method: 'HEAD' }, { method: 'PUT', path: '/app.js' }, { method: 'OPTIONS' },
      { method: 'DELETE', path: '/config.json' },
      { host: `localhost:${port}` }, { host: 'attacker.example.test' },
    ];
    for (const attempt of attempts) {
      const response = await send({ port, ...attempt });
      assert.equal(response.status, 404, JSON.stringify(attempt));
      assertSecurityHeaders(response);
    }
  });

  test('the policy admits the token and UserInfo origins only', () => {
    assert.equal(contentSecurityPolicy({
      tokenEndpoint: 'https://id.example.test/oauth2/token',
      userinfoEndpoint: 'https://id.example.test/oauth2/userinfo',
    }), "default-src 'none'; script-src 'self'; connect-src 'self' https://id.example.test; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  });

  test('exits non-zero without echoing Discovery values when the issuer differs', async () => {
    const canary = 'issuer-canary-0123456789';
    const mismatched = await startDiscovery((discoveryPort) => ({
      ...discoveryFor(`http://127.0.0.1:${discoveryPort}/${canary}-endpoints`, `https://${canary}.example.test`),
    }));
    try {
      const result = await runServe({
        SIGNACORE_AUTHORITY: mismatched.authority,
        SIGNACORE_SPA_CLIENT_ID: `client-${canary}`,
      });
      assert.notEqual(result.code, 0);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /does not equal SIGNACORE_AUTHORITY/u);
      assert.equal(result.stderr.includes(mismatched.authority), true);
      assert.equal(result.stderr.includes(canary), false);
    } finally {
      mismatched.server.close();
    }
  });

  test('exits non-zero for an incomplete environment', async () => {
    for (const env of [
      { SIGNACORE_SPA_CLIENT_ID: CLIENT_ID },
      { SIGNACORE_AUTHORITY: discovery.authority },
      { SIGNACORE_AUTHORITY: discovery.authority, SIGNACORE_SPA_CLIENT_ID: CLIENT_ID, SIGNACORE_SPA_SCOPE: 'profile' },
      { SIGNACORE_AUTHORITY: discovery.authority, SIGNACORE_SPA_CLIENT_ID: CLIENT_ID, SIGNACORE_SPA_PORT: '70000' },
    ]) {
      const result = await runServe(env);
      assert.notEqual(result.code, 0);
      assert.equal(result.stdout, '');
      assert.equal(result.stderr.includes(CLIENT_ID), false);
    }
  });
});
