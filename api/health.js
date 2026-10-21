const { app } = require('@azure/functions');
const { healthReport } = require('../lib/config');
const { toHttpResponse } = require('../lib/http');

app.http('health', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'health',
  handler: async () => toHttpResponse({
    status: 200,
    jsonBody: healthReport(),
  }),
});
