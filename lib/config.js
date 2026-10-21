const REQUIRED = [
  'OIDC_ISSUER',
  'OIDC_CLIENT_ID',
  'OIDC_CLIENT_SECRET',
  'OIDC_REDIRECT_URI',
  'THINKIFIC_SUBDOMAIN',
  'THINKIFIC_SSO_SECRET',
];

const isHttpUrl = (value) => {
  try {
    const url = new URL(value);
    if (url.username || url.password) return false;
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch {
    return false;
  }
};

const normalizeIssuer = (value) => value.trim().replace(/\/+$/, '');

const normalizeSubdomain = (value) => {
  let subdomain = value.trim().toLowerCase();
  subdomain = subdomain.replace(/^https?:\/\//, '');
  subdomain = subdomain.split(/[/?#]/)[0];
  if (subdomain.endsWith('.thinkific.com')) {
    subdomain = subdomain.slice(0, -'.thinkific.com'.length);
  }
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(subdomain)) return '';
  return subdomain;
};

const normalizeScopes = (value) => {
  const scopes = String(value || 'openid profile email').split(/[\s,]+/).filter(Boolean);
  if (!scopes.includes('openid')) scopes.unshift('openid');
  return [...new Set(scopes)].join(' ');
};

const loadConfig = (env = process.env) => {
  const missing = [];
  const invalid = [];
  const read = (name) => {
    const value = String(env[name] == null ? '' : env[name]).trim();
    if (!value) missing.push(name);
    return value;
  };

  const issuerRaw = read('OIDC_ISSUER');
  const clientId = read('OIDC_CLIENT_ID');
  const clientSecret = read('OIDC_CLIENT_SECRET');
  const redirectUri = read('OIDC_REDIRECT_URI');
  const subdomainRaw = read('THINKIFIC_SUBDOMAIN');
  const ssoSecret = read('THINKIFIC_SSO_SECRET');
  const issuer = issuerRaw ? normalizeIssuer(issuerRaw) : '';
  const subdomain = subdomainRaw ? normalizeSubdomain(subdomainRaw) : '';

  if (issuerRaw && !isHttpUrl(issuer)) invalid.push('OIDC_ISSUER');
  if (redirectUri && !isHttpUrl(redirectUri)) invalid.push('OIDC_REDIRECT_URI');
  if (subdomainRaw && !subdomain) invalid.push('THINKIFIC_SUBDOMAIN');

  const readOptionalUrl = (name) => {
    const value = String(env[name] || '').trim();
    if (!value) return '';
    if (!isHttpUrl(value)) {
      invalid.push(name);
      return '';
    }
    return value;
  };

  const returnTo = readOptionalUrl('RETURN_TO_URL');
  const errorUrl = readOptionalUrl('ERROR_URL');

  return {
    missing,
    invalid,
    issuer,
    clientId,
    clientSecret,
    redirectUri,
    subdomain,
    ssoSecret,
    returnTo,
    errorUrl,
    authorizationEndpoint: readOptionalUrl('OIDC_AUTHORIZATION_ENDPOINT'),
    tokenEndpoint: readOptionalUrl('OIDC_TOKEN_ENDPOINT'),
    jwksUri: readOptionalUrl('OIDC_JWKS_URI'),
    userinfoEndpoint: readOptionalUrl('OIDC_USERINFO_ENDPOINT'),
    scopes: normalizeScopes(env.OIDC_SCOPES),
    externalId: String(env.EXTERNAL_ID || '').trim().toLowerCase() === 'on',
  };
};

const configError = (config) => {
  if (!config.missing.length && !config.invalid.length) return null;
  const parts = [];
  if (config.missing.length) parts.push(`Missing env vars: ${config.missing.join(', ')}`);
  if (config.invalid.length) parts.push(`Invalid env vars: ${config.invalid.join(', ')}`);
  return {
    status: 500,
    body: parts.join('\n'),
    contentType: 'text/plain; charset=utf-8',
  };
};

const healthReport = (env = process.env) => {
  const report = Object.fromEntries(
    [...REQUIRED, 'RETURN_TO_URL', 'ERROR_URL', 'OIDC_SCOPES',
      'OIDC_AUTHORIZATION_ENDPOINT', 'OIDC_TOKEN_ENDPOINT', 'OIDC_JWKS_URI', 'OIDC_USERINFO_ENDPOINT',
    ].map((key) => [key, Boolean(String(env[key] || '').trim())]),
  );
  report.EXTERNAL_ID = String(env.EXTERNAL_ID || '').trim().toLowerCase() === 'on';
  return report;
};

module.exports = {
  loadConfig,
  configError,
  healthReport,
  normalizeScopes,
  normalizeSubdomain,
};
