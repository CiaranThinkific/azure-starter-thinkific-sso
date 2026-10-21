const crypto = require('crypto');
const { Issuer, custom } = require('openid-client');

const clients = new Map();
const CLOCK_TOLERANCE_SECONDS = 60;

const cacheKey = (config) => {
  const secretTag = crypto.createHash('sha256').update(config.clientSecret).digest('hex');
  return [
    config.issuer,
    config.clientId,
    config.redirectUri,
    config.authorizationEndpoint || '',
    config.tokenEndpoint || '',
    config.jwksUri || '',
    config.userinfoEndpoint || '',
    secretTag,
  ].join('\n');
};

const endpointOverrides = (config) => {
  const overrides = {};
  if (config.authorizationEndpoint) overrides.authorization_endpoint = config.authorizationEndpoint;
  if (config.tokenEndpoint) overrides.token_endpoint = config.tokenEndpoint;
  if (config.jwksUri) overrides.jwks_uri = config.jwksUri;
  if (config.userinfoEndpoint) overrides.userinfo_endpoint = config.userinfoEndpoint;
  return overrides;
};

const hasExplicitEndpoints = (config) => Boolean(
  config.authorizationEndpoint && config.tokenEndpoint && config.jwksUri,
);

const resolveIssuer = async (config, discover) => {
  const overrides = endpointOverrides(config);
  if (hasExplicitEndpoints(config)) {
    return new Issuer({ issuer: config.issuer, ...overrides });
  }

  const discovered = await discover(config.issuer);
  if (!Object.keys(overrides).length) return discovered;
  return new Issuer({ ...discovered.metadata, ...overrides });
};

const clientFromIssuer = (issuer, config) => {
  const client = new issuer.Client({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uris: [config.redirectUri],
    response_types: ['code'],
  });
  client[custom.clock_tolerance] = CLOCK_TOLERANCE_SECONDS;
  return client;
};

const getClient = (config, discover = Issuer.discover.bind(Issuer)) => {
  const key = cacheKey(config);
  const existing = clients.get(key);
  if (existing) return existing;

  const pending = Promise.resolve()
    .then(() => resolveIssuer(config, discover))
    .then((issuer) => clientFromIssuer(issuer, config))
    .catch((error) => {
      clients.delete(key);
      throw error;
    });
  clients.set(key, pending);
  return pending;
};

const resetClientCache = () => {
  clients.clear();
};

module.exports = {
  getClient,
  clientFromIssuer,
  resetClientCache,
  hasExplicitEndpoints,
  CLOCK_TOLERANCE_SECONDS,
};
