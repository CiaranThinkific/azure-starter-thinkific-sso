const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { Issuer, custom } = require('openid-client');
const { startLogin, finishLogin } = require('../lib/flow');
const { clientFromIssuer, getClient, resetClientCache, CLOCK_TOLERANCE_SECONDS } = require('../lib/oidc');
const { serialize } = require('../lib/cookie');

const config = {
  missing: [],
  invalid: [],
  issuer: 'https://idp.example/realms/test',
  clientId: 'client-id',
  clientSecret: 'synthetic-client-secret',
  redirectUri: 'https://app.example/api/callback',
  subdomain: 'demo',
  ssoSecret: 'synthetic-sso-secret',
  returnTo: '',
  errorUrl: '',
  scopes: 'openid profile email',
  externalId: false,
};

const cookieHeader = (state, nonce) => [
  serialize('oidc_state', state, { maxAge: 600 }),
  serialize('oidc_nonce', nonce, { maxAge: 600 }),
].join('; ');

const callbackUrl = (state) => `https://app.example/api/callback?code=synthetic-code&state=${state}`;

test('login stores the same state and nonce it sends to the provider', () => {
  const result = startLogin({
    config,
    client: {
      authorizationUrl({ state, nonce, scope }) {
        const url = new URL('https://idp.example/authorize');
        url.searchParams.set('state', state);
        url.searchParams.set('nonce', nonce);
        url.searchParams.set('scope', scope);
        return url.toString();
      },
    },
  });
  const location = new URL(result.headers.location);
  const cookies = Object.fromEntries(result.cookies.map((cookie) => [cookie.name, cookie.value]));

  assert.equal(result.status, 302);
  assert.equal(location.searchParams.get('state'), cookies.oidc_state);
  assert.equal(location.searchParams.get('nonce'), cookies.oidc_nonce);
  assert.equal(location.searchParams.get('scope'), 'openid profile email');
});

test('rejects a state mismatch before exchanging the code', async () => {
  let called = false;
  const result = await finishLogin({
    requestUrl: callbackUrl('attacker-state'),
    cookieHeader: cookieHeader('stored-state', 'stored-nonce'),
    config,
    client: { callback: async () => { called = true; } },
  });

  assert.equal(called, false);
  assert.equal(result.status, 400);
  assert.equal(result.body, 'Invalid state');
  assert.equal(result.cookies[0].options.maxAge, 0);
});

test('redirects callback failures to the optional error URL', async () => {
  const result = await finishLogin({
    requestUrl: callbackUrl('attacker-state'),
    cookieHeader: cookieHeader('stored-state', 'stored-nonce'),
    config: { ...config, errorUrl: 'https://demo.thinkific.com/sso-error?source=sso' },
    client: { callback: async () => { throw new Error('should not exchange'); } },
  });
  const location = new URL(result.headers.location);

  assert.equal(result.status, 302);
  assert.equal(location.origin + location.pathname, 'https://demo.thinkific.com/sso-error');
  assert.equal(location.searchParams.get('source'), 'sso');
  assert.equal(location.searchParams.get('kind'), 'state_mismatch');
});

test('rejects a missing nonce cookie and a mismatched verified nonce', async () => {
  let called = false;
  const missing = await finishLogin({
    requestUrl: callbackUrl('stored-state'),
    cookieHeader: serialize('oidc_state', 'stored-state', { maxAge: 600 }),
    config,
    client: { callback: async () => { called = true; } },
  });
  const mismatched = await finishLogin({
    requestUrl: callbackUrl('stored-state'),
    cookieHeader: cookieHeader('stored-state', 'stored-nonce'),
    config,
    client: {
      callback: async () => ({ claims: () => ({ nonce: 'other-nonce', email: 'learner@example.com', sub: 'subject-1' }) }),
    },
  });
  const thrown = await finishLogin({
    requestUrl: callbackUrl('stored-state'),
    cookieHeader: cookieHeader('stored-state', 'stored-nonce'),
    config,
    client: { callback: async () => { throw new Error('nonce mismatch, expected stored-nonce, got: other-nonce'); } },
  });

  assert.equal(called, false);
  assert.equal(missing.body, 'Invalid nonce');
  assert.equal(mismatched.body, 'Invalid nonce');
  assert.equal(thrown.status, 400);
  assert.equal(thrown.body, 'Invalid nonce');
});

test('returns a Thinkific redirect for verified claims in both external_id modes', async () => {
  const claims = {
    nonce: 'stored-nonce',
    email: 'learner@example.com',
    given_name: 'Ada',
    family_name: 'Lovelace',
    sub: 'subject-1',
  };
  const client = {
    callback: async (redirectUri, params, checks) => {
      assert.equal(redirectUri, config.redirectUri);
      assert.equal(params.code, 'synthetic-code');
      assert.equal(checks.state, 'stored-state');
      assert.equal(checks.nonce, 'stored-nonce');
      return { claims: () => claims };
    },
  };

  const disabled = await finishLogin({
    requestUrl: callbackUrl('stored-state'),
    cookieHeader: cookieHeader('stored-state', 'stored-nonce'),
    config,
    client,
    now: () => 1700000000000,
  });
  const enabled = await finishLogin({
    requestUrl: callbackUrl('stored-state'),
    cookieHeader: cookieHeader('stored-state', 'stored-nonce'),
    config: { ...config, externalId: true },
    client,
    now: () => 1700000000000,
  });
  const disabledToken = jwt.verify(new URL(disabled.headers.location).searchParams.get('jwt'), config.ssoSecret);
  const enabledToken = jwt.verify(new URL(enabled.headers.location).searchParams.get('jwt'), config.ssoSecret);

  assert.equal(disabledToken.email, 'learner@example.com');
  assert.equal(Object.hasOwn(disabledToken, 'external_id'), false);
  assert.equal(enabledToken.external_id, 'subject-1');
  assert.equal(enabled.cookies[0].options.maxAge, 0);
});

test('rejects a verified token without sub when external_id is enabled', async () => {
  const result = await finishLogin({
    requestUrl: callbackUrl('stored-state'),
    cookieHeader: cookieHeader('stored-state', 'stored-nonce'),
    config: { ...config, externalId: true },
    client: {
      callback: async () => ({
        claims: () => ({ nonce: 'stored-nonce', email: 'learner@example.com', given_name: 'Ada', family_name: 'Lovelace' }),
      }),
    },
  });

  assert.equal(result.status, 400);
  assert.equal(result.body, 'Subject required');
});

test('builds a provider authorization URL from discovered metadata', () => {
  const issuer = new Issuer({
    issuer: 'https://idp.example/realms/test',
    authorization_endpoint: 'https://idp.example/authorize',
    token_endpoint: 'https://idp.example/token',
    jwks_uri: 'https://idp.example/jwks',
  });
  const client = clientFromIssuer(issuer, config);
  const location = new URL(client.authorizationUrl({
    scope: config.scopes,
    state: 'state-1',
    nonce: 'nonce-1',
    response_type: 'code',
  }));

  assert.equal(client[custom.clock_tolerance], CLOCK_TOLERANCE_SECONDS);
  assert.equal(location.origin + location.pathname, 'https://idp.example/authorize');
  assert.equal(location.searchParams.get('client_id'), 'client-id');
  assert.equal(location.searchParams.get('redirect_uri'), config.redirectUri);
  assert.equal(location.searchParams.get('state'), 'state-1');
  assert.equal(location.searchParams.get('nonce'), 'nonce-1');
  assert.equal(location.searchParams.get('response_type'), 'code');
});

test('uses explicit endpoint URLs without reading discovery', async () => {
  resetClientCache();
  let discovered = false;
  const explicit = {
    ...config,
    authorizationEndpoint: 'https://login.social.example/authorize',
    tokenEndpoint: 'https://login.social.example/token',
    jwksUri: 'https://login.social.example/jwks',
    userinfoEndpoint: 'https://login.social.example/userinfo',
  };
  const client = await getClient(explicit, async () => {
    discovered = true;
    throw new Error('discovery should not run');
  });
  const location = new URL(client.authorizationUrl({ scope: 'openid', state: 's', nonce: 'n' }));

  assert.equal(discovered, false);
  assert.equal(location.origin + location.pathname, 'https://login.social.example/authorize');
  assert.equal(client.issuer.token_endpoint, 'https://login.social.example/token');
  assert.equal(client.issuer.jwks_uri, 'https://login.social.example/jwks');
  assert.equal(client.issuer.userinfo_endpoint, 'https://login.social.example/userinfo');
  assert.equal(client.issuer.issuer, config.issuer);
  resetClientCache();
});

test('replaces one discovered endpoint when only that URL is set', async () => {
  resetClientCache();
  const client = await getClient({
    ...config,
    authorizationEndpoint: 'https://login.social.example/authorize',
  }, async () => new Issuer({
    issuer: 'https://idp.example/realms/test',
    authorization_endpoint: 'https://idp.example/authorize',
    token_endpoint: 'https://idp.example/token',
    jwks_uri: 'https://idp.example/jwks',
    userinfo_endpoint: 'https://idp.example/userinfo',
  }));

  assert.equal(client.issuer.authorization_endpoint, 'https://login.social.example/authorize');
  assert.equal(client.issuer.token_endpoint, 'https://idp.example/token');
  assert.equal(client.issuer.userinfo_endpoint, 'https://idp.example/userinfo');
  resetClientCache();
});

test('fills missing profile claims from the configured userinfo endpoint', async () => {
  let profileCalls = 0;
  const result = await finishLogin({
    requestUrl: callbackUrl('stored-state'),
    cookieHeader: cookieHeader('stored-state', 'stored-nonce'),
    config: { ...config, externalId: true },
    client: {
      issuer: { userinfo_endpoint: 'https://login.social.example/userinfo' },
      callback: async () => ({
        access_token: 'synthetic-access-token',
        claims: () => ({ nonce: 'stored-nonce', sub: 'subject-1' }),
      }),
      userinfo: async (accessToken) => {
        profileCalls += 1;
        assert.equal(accessToken, 'synthetic-access-token');
        return {
          email: 'learner@example.com',
          given_name: 'Ada',
          family_name: 'Lovelace',
          sub: 'profile-subject',
        };
      },
    },
    now: () => 1700000000000,
  });
  const token = jwt.verify(new URL(result.headers.location).searchParams.get('jwt'), config.ssoSecret);

  assert.equal(profileCalls, 1);
  assert.equal(token.email, 'learner@example.com');
  assert.equal(token.first_name, 'Ada');
  assert.equal(token.external_id, 'subject-1');
});

test('retries OIDC discovery after a failed attempt', async () => {
  resetClientCache();
  let calls = 0;
  const discover = async () => {
    calls += 1;
    throw new Error('discovery unavailable');
  };

  await assert.rejects(() => getClient(config, discover));
  await assert.rejects(() => getClient(config, discover));
  assert.equal(calls, 2);
  resetClientCache();
});

test('loads the Azure Functions entry points', () => {
  require('../api/login');
  require('../api/callback');
  require('../api/health');
});
