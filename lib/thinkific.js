const jwt = require('jsonwebtoken');

const text = (value) => (typeof value === 'string' ? value.trim() : '');

const emailFrom = (claims = {}) => {
  for (const value of [claims.email, claims.preferred_username, claims.upn]) {
    const email = text(value);
    if (email.includes('@') && email.split('@')[0]) return email;
  }
  return '';
};

const namesFrom = (claims, email) => {
  const localPart = email.split('@')[0] || 'User';
  const given = text(claims.given_name);
  const family = text(claims.family_name);
  if (given || family) {
    return { first: given || localPart, last: family || 'User' };
  }

  const parts = text(claims.name).split(/\s+/).filter(Boolean);
  if (parts.length) {
    return { first: parts[0], last: parts.slice(1).join(' ') || 'User' };
  }
  return { first: localPart, last: 'User' };
};

const buildPayload = (claims = {}, { externalId = false, now = Date.now } = {}) => {
  const email = emailFrom(claims);
  if (!email) return { error: 'no_email' };

  const sub = text(claims.sub);
  if (externalId && !sub) return { error: 'no_sub' };

  const { first, last } = namesFrom(claims, email);
  const payload = {
    email,
    first_name: first,
    last_name: last,
    iat: Math.floor(now() / 1000),
  };
  if (externalId) payload.external_id = sub;
  return { payload };
};

const signPayload = (payload, secret) => jwt.sign(payload, secret, {
  algorithm: 'HS256',
});

const buildSsoUrl = (config, token) => {
  const url = new URL(`https://${config.subdomain}.thinkific.com/api/sso/v2/sso/jwt`);
  url.searchParams.set('jwt', token);
  if (config.returnTo) url.searchParams.set('return_to', config.returnTo);
  if (config.errorUrl) url.searchParams.set('error_url', config.errorUrl);
  return url.toString();
};

module.exports = { buildPayload, signPayload, buildSsoUrl, emailFrom, namesFrom };
