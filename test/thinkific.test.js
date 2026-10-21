const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { buildPayload, signPayload, buildSsoUrl } = require('../lib/thinkific');

const secret = 'synthetic-sso-secret';
const now = () => 1700000000000;

test('maps standard claims and leaves external_id out by default', () => {
  const { payload } = buildPayload({
    email: 'learner@example.com',
    given_name: 'Ada',
    family_name: 'Lovelace',
    sub: 'subject-1',
  }, { now });

  assert.deepEqual(payload, {
    email: 'learner@example.com',
    first_name: 'Ada',
    last_name: 'Lovelace',
    iat: 1700000000,
  });
});

test('uses provider fallbacks for email and names', () => {
  const fromUsername = buildPayload({
    preferred_username: 'learner@example.com',
    name: 'Grace Hopper',
  }, { now });
  const fromUpn = buildPayload({ upn: 'learner@example.com' }, { now });
  const namedOnly = buildPayload({
    email: 'learner@example.com',
    given_name: 'Ada',
  }, { now });

  assert.equal(fromUsername.payload.first_name, 'Grace');
  assert.equal(fromUsername.payload.last_name, 'Hopper');
  assert.equal(fromUpn.payload.first_name, 'learner');
  assert.equal(fromUpn.payload.last_name, 'User');
  assert.equal(namedOnly.payload.first_name, 'Ada');
  assert.equal(namedOnly.payload.last_name, 'User');
});

test('maps sub to external_id only when enabled and sub is present', () => {
  const claims = { email: 'learner@example.com', given_name: 'Ada', family_name: 'Lovelace', sub: 'subject-1' };
  const enabled = buildPayload(claims, { externalId: true, now });
  const missing = buildPayload({ email: 'learner@example.com' }, { externalId: true, now });

  assert.equal(enabled.payload.external_id, 'subject-1');
  assert.equal(missing.error, 'no_sub');
  assert.equal(buildPayload({ preferred_username: 'not-an-email' }).error, 'no_email');
});

test('signs the Thinkific JWT with the raw secret and optional return parameters', () => {
  const { payload } = buildPayload({
    email: 'learner@example.com',
    given_name: 'Ada',
    family_name: 'Lovelace',
  }, { now });
  const token = signPayload(payload, secret);
  const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
  const location = new URL(buildSsoUrl({
    subdomain: 'demo',
    returnTo: 'https://demo.thinkific.com/enrollments',
    errorUrl: 'https://demo.thinkific.com/sso-error',
  }, token));
  const minimal = new URL(buildSsoUrl({ subdomain: 'demo', returnTo: '', errorUrl: '' }, token));

  assert.equal(jwt.decode(token, { complete: true }).header.alg, 'HS256');
  assert.equal(decoded.email, 'learner@example.com');
  assert.equal(decoded.iat, 1700000000);
  assert.equal(Object.hasOwn(decoded, 'external_id'), false);
  assert.throws(() => jwt.verify(token, Buffer.from(secret).toString('base64'), { algorithms: ['HS256'] }));
  assert.equal(location.origin, 'https://demo.thinkific.com');
  assert.equal(location.pathname, '/api/sso/v2/sso/jwt');
  assert.equal(location.searchParams.get('jwt'), token);
  assert.equal(location.searchParams.get('return_to'), 'https://demo.thinkific.com/enrollments');
  assert.equal(location.searchParams.get('error_url'), 'https://demo.thinkific.com/sso-error');
  assert.equal(minimal.searchParams.get('return_to'), null);
  assert.equal(minimal.searchParams.get('error_url'), null);
});
