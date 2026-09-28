// A development-only static server for the Public SPA sample. It binds 127.0.0.1, serves a fixed
// allow list of files over GET, and publishes the non-sensitive client configuration at
// /config.json. It is not a production web server.
//
//   SIGNACORE_AUTHORITY=http://localhost:5002 SIGNACORE_SPA_CLIENT_ID=<appId> node serve.mjs
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { discover } from './public-client.js';

const HOST = '127.0.0.1';
const DEFAULT_PORT = 5173;
const DEFAULT_SCOPE = 'openid profile';

const STATIC_FILES = [
  ['/', 'index.html', 'text/html; charset=utf-8'],
  ['/callback', 'index.html', 'text/html; charset=utf-8'],
  ['/app.js', 'app.js', 'text/javascript; charset=utf-8'],
  ['/public-client.js', 'public-client.js', 'text/javascript; charset=utf-8'],
];

export class ConfigurationError extends Error {}

/** The page policy: scripts from this origin only, and reads only from itself and SignaCore. */
export function contentSecurityPolicy(metadata) {
  const origins = [...new Set([
    new URL(metadata.tokenEndpoint).origin,
    new URL(metadata.userinfoEndpoint).origin,
  ])];
  return `default-src 'none'; script-src 'self'; connect-src 'self' ${origins.join(' ')}; `
    + "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
}

/**
 * Reads the environment and SignaCore's Discovery document. Error messages name the variable at
 * fault and never echo any value other than the configured authority.
 */
export async function loadConfiguration(env, fetchImplementation = fetch) {
  const authority = env.SIGNACORE_AUTHORITY ?? '';
  let authorityUrl = null;
  if (URL.canParse(authority)) {
    authorityUrl = new URL(authority);
  }

  if (authorityUrl === null || !['http:', 'https:'].includes(authorityUrl.protocol)) {
    throw new ConfigurationError('SIGNACORE_AUTHORITY must be an absolute http or https URL.');
  }

  const clientId = env.SIGNACORE_SPA_CLIENT_ID ?? '';
  if (clientId.trim().length === 0) {
    throw new ConfigurationError('SIGNACORE_SPA_CLIENT_ID is required.');
  }

  const portText = env.SIGNACORE_SPA_PORT ?? String(DEFAULT_PORT);
  const port = /^[0-9]{1,5}$/u.test(portText) ? Number(portText) : Number.NaN;
  if (!(port >= 1 && port <= 65535)) {
    throw new ConfigurationError('SIGNACORE_SPA_PORT must be a port number between 1 and 65535.');
  }

  const scope = env.SIGNACORE_SPA_SCOPE ?? DEFAULT_SCOPE;
  if (!scope.split(' ').includes('openid')) {
    throw new ConfigurationError('SIGNACORE_SPA_SCOPE must contain openid.');
  }

  let metadata;
  try {
    metadata = await discover({ fetch: fetchImplementation, authority });
  } catch (failure) {
    throw new ConfigurationError(failure?.code === 'issuer_mismatch'
      ? `The Discovery issuer of ${authority} does not equal SIGNACORE_AUTHORITY exactly.`
      : `The Discovery document of ${authority} could not be read or is incomplete.`);
  }

  return {
    port,
    csp: contentSecurityPolicy(metadata),
    config: {
      authority,
      clientId,
      redirectUri: `http://${HOST}:${port}/callback`,
      scope,
      discovery: {
        issuer: metadata.issuer,
        authorization_endpoint: metadata.authorizationEndpoint,
        token_endpoint: metadata.tokenEndpoint,
        userinfo_endpoint: metadata.userinfoEndpoint,
      },
    },
  };
}

async function loadFiles(config) {
  const directory = fileURLToPath(new URL('.', import.meta.url));
  const files = new Map();
  for (const [path, name, contentType] of STATIC_FILES) {
    files.set(path, { body: await readFile(`${directory}${name}`), contentType });
  }

  files.set('/config.json', {
    body: Buffer.from(JSON.stringify(config)),
    contentType: 'application/json; charset=utf-8',
  });
  return files;
}

/** Creates (but does not start) the server. Every response carries the same security headers. */
export async function createSampleServer({ config, csp }) {
  const files = await loadFiles(config);
  const server = createServer((request, response) => {
    const headers = {
      'Content-Security-Policy': csp,
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    };
    const expectedHost = `${HOST}:${server.address().port}`;
    const path = URL.canParse(request.url ?? '', 'http://sample.invalid')
      ? new URL(request.url, 'http://sample.invalid').pathname
      : null;
    const file = request.method === 'GET' && request.headers.host === expectedHost && path !== null
      ? files.get(path)
      : undefined;

    if (file === undefined) {
      const body = Buffer.from('Not found\n');
      response.writeHead(404, { ...headers, 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': body.length });
      response.end(body);
      return;
    }

    response.writeHead(200, { ...headers, 'Content-Type': file.contentType, 'Content-Length': file.body.length });
    response.end(file.body);
  });
  return server;
}

export async function main(env = process.env) {
  let loaded;
  try {
    loaded = await loadConfiguration(env);
  } catch (failure) {
    const message = failure instanceof ConfigurationError ? failure.message : 'Startup failed.';
    process.stderr.write(`SignaCore Public SPA sample: ${message}\n`);
    process.exitCode = 1;
    return;
  }

  const server = await createSampleServer(loaded);
  server.on('error', () => {
    process.stderr.write(`SignaCore Public SPA sample: cannot listen on ${HOST}:${loaded.port}.\n`);
    process.exitCode = 1;
  });
  server.listen(loaded.port, HOST, () => {
    process.stdout.write(`SignaCore Public SPA sample: open http://${HOST}:${loaded.port}/\n`);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
