const toAzureCookie = ({ name, value, options = {} }) => ({
  name,
  value,
  path: options.path || '/',
  httpOnly: options.httpOnly !== false,
  secure: options.secure !== false,
  sameSite: options.sameSite || 'Lax',
  maxAge: options.maxAge,
});

const toHttpResponse = (result) => {
  const headers = {
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    ...(result.headers || {}),
  };
  if (result.contentType) headers['content-type'] = result.contentType;

  const response = { status: result.status, headers };
  if (result.body !== undefined) response.body = result.body;
  if (result.jsonBody !== undefined) response.jsonBody = result.jsonBody;
  if (result.cookies) response.cookies = result.cookies.map(toAzureCookie);
  return response;
};

module.exports = { toAzureCookie, toHttpResponse };
