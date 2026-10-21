# Thinkific OIDC SSO for Azure Functions

This Function App signs a user in with any standard OpenID Connect provider, then redirects the browser to Thinkific with a signed SSO JWT.

The provider’s authorization, token, signing-key, and user-info endpoints normally come from `{OIDC_ISSUER}/.well-known/openid-configuration`. That document is read once per Function instance. Set the endpoint URLs below when a provider publishes them on different hosts, or when the discovery document is not available. If the authorization, token, and signing-key URLs are all set, discovery is skipped. A single URL replaces only that discovered endpoint. The ID token `iss` claim is still checked against `OIDC_ISSUER` when discovery is skipped.

## Settings

Required:

| Setting | Purpose |
| --- | --- |
| `OIDC_ISSUER` | Issuer URL, without the well-known path |
| `OIDC_CLIENT_ID` | Confidential client ID |
| `OIDC_CLIENT_SECRET` | Client secret |
| `OIDC_REDIRECT_URI` | Public callback, exactly as registered with the provider |
| `THINKIFIC_SUBDOMAIN` | School subdomain, such as `demo` |
| `THINKIFIC_SSO_SECRET` | Thinkific SSO signing secret |

Optional:

| Setting | Purpose |
| --- | --- |
| `RETURN_TO_URL` | Page Thinkific opens after a successful sign-in |
| `ERROR_URL` | Page Thinkific opens when SSO fails |
| `OIDC_SCOPES` | Defaults to `openid profile email`. `openid` is added when it is missing |
| `EXTERNAL_ID` | Set to `on` to include the verified `sub` claim as Thinkific `external_id` |
| `OIDC_AUTHORIZATION_ENDPOINT` | Authorization URL. Overrides discovery |
| `OIDC_TOKEN_ENDPOINT` | Token URL. Overrides discovery |
| `OIDC_JWKS_URI` | Signing-key URL. Overrides discovery |
| `OIDC_USERINFO_ENDPOINT` | UserInfo URL. Used when the ID token omits the email or name |

`EXTERNAL_ID` is off unless the value is `on`. Leave it unset when any Thinkific user was created outside this SSO flow. Thinkific treats `external_id` as the user’s unique identifier, and an existing user without one can fail with an email-already-taken error.

The signing secret is the API access token SSO signing secret from Thinkific Admin → Settings → Code & Analytics. An existing site can use its API key. Use the secret exactly as issued; do not base64-encode it.

Put these values in the Function App application settings, or in an uncommitted `local.settings.json` for local development. This repository’s [`.env.example`](.env.example) lists the names only.

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "",
    "FUNCTIONS_WORKER_RUNTIME": "node",
    "OIDC_ISSUER": "https://login.microsoftonline.com/{tenant-id}/v2.0",
    "OIDC_CLIENT_ID": "",
    "OIDC_CLIENT_SECRET": "",
    "OIDC_REDIRECT_URI": "http://localhost:7071/api/callback",
    "THINKIFIC_SUBDOMAIN": "",
    "THINKIFIC_SSO_SECRET": "",
    "RETURN_TO_URL": "",
    "ERROR_URL": "",
    "OIDC_SCOPES": "openid profile email",
    "OIDC_AUTHORIZATION_ENDPOINT": "",
    "OIDC_TOKEN_ENDPOINT": "",
    "OIDC_JWKS_URI": "",
    "OIDC_USERINFO_ENDPOINT": "",
    "EXTERNAL_ID": ""
  }
}
```

## Provider registration

Create a confidential web client that allows the Authorization Code flow. Register this redirect URI:

`https://YOUR-FUNCTION-APP.azurewebsites.net/api/callback`

Request the `openid`, `profile`, and `email` scopes. The ID token must contain an email address. The function reads `email`, then `preferred_username`, then `upn`, and uses the first value that contains `@`. It reads `given_name` and `family_name`, and falls back to the `name` claim or the mailbox name when a provider omits one of them.

Entra issuer:

`https://login.microsoftonline.com/{tenant-id}/v2.0`

In the Entra app registration, add the email, given name, and family name optional claims to the ID token when they are not already present. Leave the Function App’s built-in Authentication feature off. This app performs the OIDC flow itself, and platform authentication would intercept the callback.

Okta issuer:

`https://{your-domain}/oauth2/default`

Assign the Okta application and allow the Authorization Code grant for `openid`, `profile`, and `email`.

## Thinkific redirect

After the ID token is verified, the function signs this payload with HS256:

```json
{
  "email": "learner@example.com",
  "first_name": "Ada",
  "last_name": "Lovelace",
  "iat": 1700000000
}
```

`external_id` is added only when `EXTERNAL_ID=on`. The browser is then redirected to:

`https://{subdomain}.thinkific.com/api/sso/v2/sso/jwt?jwt={payload}`

`return_to` and `error_url` are added when those settings are present. Thinkific Plus is required for SSO. Thinkific accepts the token only while `iat` is recent.

## Deploy

1. Create a Function App running Node.js 20 or 22 on Azure Functions runtime v4.
2. Add the settings above. Do not enable built-in Authentication.
3. Deploy this directory with Azure Functions Core Tools: `func azure functionapp publish YOUR-FUNCTION-APP`.
4. Register the deployed `/api/callback` URL with the OIDC provider.
5. Open `https://YOUR-FUNCTION-APP.azurewebsites.net/api/login`.

`/api/health` returns booleans for whether each setting is present. It does not return setting values. `EXTERNAL_ID` is true only when the feature is enabled.

## Local development

Install [Azure Functions Core Tools](https://learn.microsoft.com/azure/azure-functions/functions-run-local), then:

```sh
npm install
npm test
npm start
```

`npm start` reads `local.settings.json`. The local login URL is `http://localhost:7071/api/login`. Register that callback with a development client. Transaction cookies are `HttpOnly`, `Secure`, and `SameSite=Lax`; current browsers accept the `Secure` attribute on `http://localhost`.

## Flow

1. `GET /api/login` stores `state` and `nonce` cookies and redirects to the provider.
2. The provider returns the browser to `GET /api/callback`.
3. The function checks `state`, exchanges the code, and verifies the ID token signature, issuer, audience, expiry, and `nonce`. If the ID token has no email or name, and a UserInfo URL is known, it fills those claims from UserInfo. The verified `sub` always comes from the ID token.
4. It clears the transaction cookies and redirects to Thinkific with the signed JWT.

A failed callback redirects to `ERROR_URL` with a `kind` parameter when that setting exists. Otherwise it returns a short text error. Provider error details and secrets are not included in the response.
