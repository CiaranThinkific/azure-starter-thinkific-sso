const test = require('node:test');
const assert = require('node:assert/strict');
const {
  serialize,
  parse,
  clearTransactionCookies,
  transactionCookies,
} = require('../lib/cookie');
const { toAzureCookie } = require('../lib/http');

test('serializes a zero Max-Age so the browser clears the cookie', () => {
  const header = serialize('oidc_state', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    path: '/',
    maxAge: 0,
  });

  assert.match(header, /^oidc_state=;/);
  assert.match(header, /Max-Age=0/);
  assert.match(header, /HttpOnly/);
  assert.match(header, /Secure/);
  assert.match(header, /SameSite=Lax/);
});

test('parses transaction cookies and preserves encoded values', () => {
  const cookies = transactionCookies('state-value', 'nonce=value');
  const header = cookies.map((cookie) => serialize(cookie.name, cookie.value, cookie.options)).join('; ');
  const parsed = parse(header);

  assert.equal(parsed.oidc_state, 'state-value');
  assert.equal(parsed.oidc_nonce, 'nonce=value');
});

test('clearing cookies reaches the Azure response with Max-Age zero', () => {
  for (const cookie of clearTransactionCookies()) {
    assert.match(serialize(cookie.name, cookie.value, cookie.options), /Max-Age=0/);
    assert.equal(toAzureCookie(cookie).maxAge, 0);
  }
});
