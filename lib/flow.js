const crypto = require('crypto');
const { parse, transactionCookies, clearTransactionCookies } = require('./cookie');
const { configError } = require('./config');
const { buildPayload, signPayload, buildSsoUrl, emailFrom } = require('./thinkific');

const textResponse = (status, body) => ({
  status,
  body,
  contentType: 'text/plain; charset=utf-8',
});

const sameValue = (left, right) => {
  const first = Buffer.from(String(left));
  const second = Buffer.from(String(right));
  if (first.length !== second.length) return false;
  return crypto.timingSafeEqual(first, second);
};

const fail = (config, kind, status, message) => {
  const cookies = clearTransactionCookies();
  if (config.errorUrl) {
    const location = new URL(config.errorUrl);
    location.searchParams.set('kind', kind);
    return { status: 302, headers: { location: location.toString() }, cookies };
  }
  return { ...textResponse(status, message), cookies };
};

const failureKind = (error) => {
  const message = String(error && error.message || '').toLowerCase();
  if (message.includes('nonce mismatch')) return 'nonce_mismatch';
  if (message.includes('state mismatch')) return 'state_mismatch';
  if (message.includes('iss mismatch') || message.includes('iss missing')) return 'provider_error';
  return 'token_exchange_failed';
};

const startLogin = ({ config, client, randomBytes = crypto.randomBytes }) => {
  const problem = configError(config);
  if (problem) return problem;

  const state = randomBytes(16).toString('hex');
  const nonce = randomBytes(16).toString('hex');
  let location;
  try {
    location = client.authorizationUrl({
      scope: config.scopes,
      state,
      nonce,
      response_type: 'code',
    });
  } catch {
    return textResponse(502, 'OIDC authorization failed');
  }
  if (typeof location !== 'string' || !location) {
    return textResponse(502, 'OIDC authorization failed');
  }

  return {
    status: 302,
    headers: { location },
    cookies: transactionCookies(state, nonce),
  };
};

const authorizationParams = (requestUrl) => {
  const url = new URL(requestUrl);
  const params = {};
  for (const key of ['code', 'state', 'error', 'iss', 'session_state']) {
    const value = url.searchParams.get(key);
    if (value !== null) params[key] = value;
  }
  return { url, params };
};

const hasName = (claims) => ['given_name', 'family_name', 'name'].some((key) => {
  const value = claims[key];
  return typeof value === 'string' && value.trim();
});

const claimsWithProfile = async (client, tokenSet, claims) => {
  const endpoint = client.issuer && client.issuer.userinfo_endpoint;
  if ((emailFrom(claims) && hasName(claims)) || !endpoint || typeof client.userinfo !== 'function' || !tokenSet.access_token) {
    return claims;
  }

  try {
    const profile = await client.userinfo(tokenSet.access_token);
    if (!profile || typeof profile !== 'object') return claims;
    const merged = { ...profile };
    for (const [key, value] of Object.entries(claims)) {
      if (value !== undefined && value !== null && value !== '') merged[key] = value;
    }
    merged.sub = claims.sub;
    merged.nonce = claims.nonce;
    return merged;
  } catch {
    return claims;
  }
};

const finishLogin = async ({ requestUrl, cookieHeader = '', config, client, now }) => {
  const problem = configError(config);
  if (problem) return problem;

  let parsed;
  try {
    parsed = authorizationParams(requestUrl);
  } catch {
    return textResponse(400, 'Invalid callback URL');
  }

  const { params } = parsed;
  const cookies = parse(cookieHeader);
  if (params.error) return fail(config, 'provider_error', 400, 'Sign-in was not completed');

  const code = params.code || '';
  const state = params.state || '';
  if (!code || !state) return fail(config, 'missing_code', 400, 'Missing code/state');
  if (!cookies.oidc_state || !sameValue(state, cookies.oidc_state)) {
    return fail(config, 'state_mismatch', 400, 'Invalid state');
  }
  if (!cookies.oidc_nonce) return fail(config, 'nonce_mismatch', 400, 'Invalid nonce');

  let tokenSet;
  try {
    tokenSet = await client.callback(config.redirectUri, params, {
      state: cookies.oidc_state,
      nonce: cookies.oidc_nonce,
    });
  } catch (error) {
    const kind = failureKind(error);
    const messages = {
      nonce_mismatch: 'Invalid nonce',
      state_mismatch: 'Invalid state',
      provider_error: 'Sign-in was not completed',
      token_exchange_failed: 'Token exchange failed',
    };
    const status = kind === 'token_exchange_failed' ? 502 : 400;
    return fail(config, kind, status, messages[kind]);
  }

  const idTokenClaims = typeof tokenSet.claims === 'function' ? tokenSet.claims() : tokenSet.claims;
  if (!idTokenClaims || typeof idTokenClaims.nonce !== 'string' || !sameValue(idTokenClaims.nonce, cookies.oidc_nonce)) {
    return fail(config, 'nonce_mismatch', 400, 'Invalid nonce');
  }

  const claims = await claimsWithProfile(client, tokenSet, idTokenClaims);
  const built = buildPayload(claims, { externalId: config.externalId, now });
  if (built.error === 'no_email') return fail(config, 'no_email', 400, 'Email required');
  if (built.error === 'no_sub') return fail(config, 'no_sub', 400, 'Subject required');

  return {
    status: 302,
    headers: { location: buildSsoUrl(config, signPayload(built.payload, config.ssoSecret)) },
    cookies: clearTransactionCookies(),
  };
};

module.exports = { startLogin, finishLogin, failureKind };
