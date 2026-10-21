const serialize = (name, value, options = {}) => {
  let cookie = `${name}=${encodeURIComponent(value)}`;
  if (options.maxAge !== undefined && options.maxAge !== null) {
    cookie += `; Max-Age=${Math.floor(options.maxAge)}`;
  }
  if (options.domain) cookie += `; Domain=${options.domain}`;
  cookie += `; Path=${options.path || '/'}`;
  if (options.httpOnly !== false) cookie += '; HttpOnly';
  if (options.secure !== false) cookie += '; Secure';
  cookie += `; SameSite=${options.sameSite || 'Lax'}`;
  return cookie;
};

const parse = (cookieHeader = '') => {
  return String(cookieHeader).split(';').reduce((acc, part) => {
    const trimmed = part.trim();
    if (!trimmed) return acc;
    const separator = trimmed.indexOf('=');
    if (separator <= 0) return acc;
    const key = trimmed.slice(0, separator).trim();
    const rawValue = trimmed.slice(separator + 1).trim();
    try {
      acc[key] = decodeURIComponent(rawValue);
    } catch {
      acc[key] = rawValue;
    }
    return acc;
  }, {});
};

const TRANSACTION_MAX_AGE = 600;

const cookieOptions = (maxAge) => ({
  httpOnly: true,
  secure: true,
  sameSite: 'Lax',
  path: '/',
  maxAge,
});

const transactionCookies = (state, nonce, maxAge = TRANSACTION_MAX_AGE) => {
  const options = cookieOptions(maxAge);
  return [
    { name: 'oidc_state', value: state, options },
    { name: 'oidc_nonce', value: nonce, options },
  ];
};

const clearTransactionCookies = () => transactionCookies('', '', 0);

module.exports = {
  serialize,
  parse,
  transactionCookies,
  clearTransactionCookies,
  TRANSACTION_MAX_AGE,
};
