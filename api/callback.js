const { app } = require('@azure/functions');
const { loadConfig, configError } = require('../lib/config');
const { getClient } = require('../lib/oidc');
const { finishLogin } = require('../lib/flow');
const { toHttpResponse } = require('../lib/http');

app.http('callback', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'callback',
  handler: async (request, context) => {
    const config = loadConfig();
    const problem = configError(config);
    if (problem) return toHttpResponse(problem);

    try {
      const client = await getClient(config);
      return toHttpResponse(await finishLogin({
        requestUrl: request.url,
        cookieHeader: request.headers.get('cookie') || '',
        config,
        client,
      }));
    } catch (error) {
      context.error(`Callback failed: ${error && error.name ? error.name : 'Error'}`);
      return toHttpResponse({
        status: 500,
        body: 'Sign-in failed',
        contentType: 'text/plain; charset=utf-8',
      });
    }
  },
});
