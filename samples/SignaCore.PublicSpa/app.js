// Page wiring for the Public SPA sample. All protocol behavior lives in public-client.js; this
// file only connects buttons to it and renders display-safe values (never a token).
import { createPublicClient, validateDiscovery } from './public-client.js';

const elements = {
  status: document.getElementById('status'),
  error: document.getElementById('error'),
  claims: document.getElementById('claims'),
  login: document.getElementById('login'),
  userinfo: document.getElementById('userinfo'),
  refresh: document.getElementById('refresh'),
  logout: document.getElementById('logout'),
};

function showError(failure) {
  elements.error.textContent = failure?.code ? `Error: ${failure.code}` : 'Error: unexpected_failure';
}

function render(client) {
  const session = client?.getSession() ?? null;
  if (session === null) {
    elements.status.textContent = 'Signed out.';
  } else {
    const who = session.name ? `${session.sub} (${session.name})` : session.sub;
    elements.status.textContent =
      `Signed in as ${who}. Access token expires at ${new Date(session.expiresAt).toISOString()}.`;
  }

  elements.login.disabled = client === null;
  elements.userinfo.disabled = session === null;
  elements.refresh.disabled = session === null || !session.canRefresh;
  elements.logout.disabled = client === null;
}

async function run(client, action) {
  elements.error.textContent = '';
  try {
    await action();
  } catch (failure) {
    showError(failure);
  }

  render(client);
}

async function start() {
  render(null);
  const response = await fetch('/config.json', { credentials: 'omit', cache: 'no-store' });
  const config = await response.json();
  const metadata = validateDiscovery(config.discovery, config.authority);
  const client = createPublicClient({
    config,
    metadata,
    fetch: window.fetch.bind(window),
    crypto: window.crypto,
    sessionStorage: window.sessionStorage,
    location: window.location,
    history: window.history,
  });

  elements.login.addEventListener('click', () => run(client, () => client.beginLogin()));
  elements.refresh.addEventListener('click', () => run(client, () => client.refresh()));
  elements.userinfo.addEventListener('click', () => run(client, async () => {
    const claims = await client.userInfo();
    elements.claims.textContent = JSON.stringify(claims, null, 2);
  }));
  elements.logout.addEventListener('click', () => run(client, () => {
    client.logout();
    elements.claims.textContent = '';
  }));

  if (window.location.pathname === new URL(config.redirectUri).pathname) {
    await run(client, () => client.completeLogin());
    window.history.replaceState(null, '', '/');
  }

  render(client);
}

start().catch(showError);
