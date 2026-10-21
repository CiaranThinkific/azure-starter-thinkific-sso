const test = require('node:test');
const assert = require('node:assert/strict');
const { loadConfig, configError, healthReport } = require('../lib/config');

const validEnv = {
  OIDC_ISSUER: 'https://login.microsoftonline.com/tenant-id/v2.0/',
  OIDC_CLIENT_ID: 'client-id',
  OIDC_CLIENT_SECRET: 'synthetic-client-secret',
  OIDC_REDIRECT_URI: 'https://app.example/api/callback',
  THINKIFIC_SUBDOMAIN: 'https://Demo.thinkific.com/pages',
  THINKIFIC_SSO_SECRET: 'synthetic-sso-secret',
  RETURN_TO_URL: 'https://demo.thinkific.com/enrollments',
  ERROR_URL: 'https://demo.thinkific.com/sso-error',
  OIDC_SCOPES: 'profile email',
  EXTERNAL_ID: 'on',
};

test('loads the generic OIDC and Thinkific settings', () => {
  const config = loadConfig(validEnv);

  assert.deepEqual(config.missing, []);
  assert.deepEqual(config.invalid, []);
  assert.equal(config.issuer, 'https://login.microsoftonline.com/tenant-id/v2.0');
  assert.equal(config.subdomain, 'demo');
  assert.equal(config.scopes, 'openid profile email');
  assert.equal(config.externalId, true);
  assert.equal(config.ssoSecret, 'synthetic-sso-secret');
});

test('reports missing settings by name and enables external_id only for on', () => {
  const config = loadConfig({
    OIDC_CLIENT_SECRET: 'synthetic-client-secret',
    EXTERNAL_ID: 'off',
  });
  const error = configError(config);

  assert.equal(config.externalId, false);
  assert.ok(config.missing.includes('OIDC_ISSUER'));
  assert.ok(config.missing.includes('THINKIFIC_SSO_SECRET'));
  assert.match(error.body, /Missing env vars: /);
  assert.equal(error.body.includes('synthetic-client-secret'), false);
});

test('accepts optional endpoint URLs and rejects malformed ones', () => {
  const config = loadConfig({
    ...validEnv,
    OIDC_AUTHORIZATION_ENDPOINT: 'https://login.social.example/authorize',
    OIDC_TOKEN_ENDPOINT: 'https://login.social.example/token',
    OIDC_JWKS_URI: 'https://login.social.example/jwks',
    OIDC_USERINFO_ENDPOINT: 'https://login.social.example/userinfo',
  });
  const invalid = loadConfig({
    ...validEnv,
    OIDC_TOKEN_ENDPOINT: 'token-is-not-a-url',
  });

  assert.equal(config.authorizationEndpoint, 'https://login.social.example/authorize');
  assert.equal(config.tokenEndpoint, 'https://login.social.example/token');
  assert.equal(config.jwksUri, 'https://login.social.example/jwks');
  assert.equal(config.userinfoEndpoint, 'https://login.social.example/userinfo');
  assert.deepEqual(invalid.invalid, ['OIDC_TOKEN_ENDPOINT']);
  assert.equal(invalid.tokenEndpoint, '');
});

test('rejects a subdomain that could change the Thinkific host', () => {
  const config = loadConfig({ ...validEnv, THINKIFIC_SUBDOMAIN: 'https://evil.example' });

  assert.deepEqual(config.invalid, ['THINKIFIC_SUBDOMAIN']);
  assert.equal(config.subdomain, '');
});

test('health reports presence without values, and external_id only when enabled', () => {
  const report = healthReport(validEnv);
  const disabled = healthReport({ ...validEnv, EXTERNAL_ID: 'yes' });

  assert.equal(report.OIDC_CLIENT_SECRET, true);
  assert.equal(report.THINKIFIC_SSO_SECRET, true);
  assert.equal(report.EXTERNAL_ID, true);
  assert.equal(report.OIDC_AUTHORIZATION_ENDPOINT, false);
  assert.equal(disabled.EXTERNAL_ID, false);
  assert.equal(JSON.stringify(report).includes('synthetic-client-secret'), false);
  assert.equal(JSON.stringify(report).includes('synthetic-sso-secret'), false);
});
