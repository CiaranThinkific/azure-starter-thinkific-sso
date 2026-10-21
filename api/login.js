const { app } = require('@azure/functions');
const { loadConfig, configError } = require('../lib/config');
const { getClient } = require('../lib/oidc');
const { startLogin } = require('../lib/flow');
const { toHttpResponse } = require('../lib/http');

app.http('login', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'login',
  handler: async (request, context) => {
    const config = loadConfig();
    const problem = configError(config);
    if (problem) return toHttpResponse(problem);

    try {
      const client = await getClient(config);
      return toHttpResponse(await startLogin({ config, client }));
    } catch (error) {
      context.error(`Login failed: ${error && error.name ? error.name : 'Error'}`);
      return toHttpResponse({
        status: 502,
        body: 'OIDC discovery failed',
        contentType: 'text/plain; charset=utf-8',
      });
    }
  },
});
